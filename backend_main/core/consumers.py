import hashlib
import logging

# Dedicated logger for consumers, logs to file in this directory
import os
from logging.handlers import RotatingFileHandler
from typing import Any, Coroutine, Dict, Optional

import jwt
from asgiref.sync import async_to_sync, sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.layers import get_channel_layer
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .cache import get_cached_upload_payload
from .models import Upload
from .serializers import UploadSerializer

logger = logging.getLogger("core.consumers")
logger.setLevel(logging.INFO)

_logfile = os.path.join(os.path.dirname(__file__), "consumers.log")
if not logger.handlers:
    file_handler = RotatingFileHandler(
        _logfile, maxBytes=2 * 1024 * 1024, backupCount=2
    )
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

User = get_user_model()

# Constants
MODEL_NAME = "Upload"
GROUP_ALL = f"{MODEL_NAME}_all"
EVENT_STATUS = f"{MODEL_NAME}.status"
EVENT_CREATED = f"{MODEL_NAME}.created"
EVENT_UPDATED = f"{MODEL_NAME}.updated"
EVENT_DELETED = f"{MODEL_NAME}.deleted"
EVENT_LIST = f"{MODEL_NAME}.list"
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for file hashing
MAX_LIST_RESULTS = 100


def extract_token_from_query_string(query_string: str) -> Optional[str]:
    """
    Extracts and cleans a JWT token from a query string.

    Supports formats:
    - "token=abc123"
    - "abc123"
    - "token=abc123&other=param"
    """
    if not query_string:
        return None

    token = query_string
    # Remove "token=" prefix if present
    if token.startswith("token="):
        token = token[6:]
    # Remove query parameters after &
    if "&" in token:
        token = token.split("&")[0]
    # Remove URL fragments
    if "#" in token:
        token = token.split("#")[0]

    return token if token else None


def get_user_from_token(token: Optional[str]) -> Optional[Any]:
    """
    Decodes a JWT token and returns the associated user object, or None.

    Args:
        token: JWT token string (may include "token=" prefix)

    Returns:
        User object if token is valid and user exists, None otherwise
    """
    if not token:
        return None

    # Clean the token
    clean_token = extract_token_from_query_string(token)
    if not clean_token:
        return None

    try:
        payload = jwt.decode(clean_token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id") or payload.get("sub")
        if not user_id:
            return None

        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None
    except (jwt.InvalidTokenError, jwt.DecodeError, jwt.ExpiredSignatureError):
        return None
    except Exception:
        # Log unexpected errors in production
        return None


class UploadStatusConsumer(AsyncJsonWebsocketConsumer):
    """
    WebSocket consumer for CRUD + status updates for the Upload model.

    On connection, each authenticated user joins a unique group based on their user ID.
    All CRUD operations and status updates are communicated through the user's group.

    Supported commands:
      - subscribe: Subscribe to status updates
      - retrieve: Get a specific upload instance (by id in message)
      - create: Create a new upload
      - update: Update an existing upload (by id in message)
      - delete: Delete an upload (by id in message)
      - list: List all uploads for authenticated user (max 100)
      - task: Perform a task (if needed, for later extension)
    """

    @staticmethod
    def _is_authenticated_user(user: Optional[Any]) -> bool:
        """
        Checks if a user is authenticated, handling both method and property cases.

        Args:
            user: User object to check

        Returns:
            True if user is authenticated, False otherwise
        """
        if user is None:
            return False
        is_auth = getattr(user, "is_authenticated", None)
        if callable(is_auth):
            return is_auth()
        return bool(is_auth)

    def _get_user_from_scope(self) -> Optional[Any]:
        """Extract user from WebSocket scope."""
        if hasattr(self.scope, "user"):
            return getattr(self.scope, "user", None)
        return self.scope.get("user", None)

    async def _authenticate_user(self) -> Optional[Any]:
        """
        Authenticate user from scope or token.
        Updates scope if authentication succeeds.

        Returns:
            Authenticated user object or None
        """
        user = self._get_user_from_scope()
        if user and self._is_authenticated_user(user):
            return user

        # Try to authenticate from token
        token = extract_token_from_query_string(self.token)
        if token:
            user = await sync_to_async(get_user_from_token)(token)
            if user:
                self.scope["user"] = user
                return user
        return None

    def _get_user_group_name(self, user: Any) -> str:
        """Return the channel group name for this user."""
        return f"{MODEL_NAME}_user_{user.id}"

    async def _safe_send_json(self, content: Dict[str, Any]) -> bool:
        if hasattr(self, "close_code") and self.close_code is not None:
            logger.debug(f"Skipping send - connection closed (code: {self.close_code})")
            return False

        try:
            await self.send_json(content)
            return True
        except (RuntimeError, ConnectionError, OSError) as e:
            error_msg = str(e)
            if (
                "ClientDisconnected" in error_msg
                or "ConnectionClosed" in error_msg
                or "already completed" in error_msg
            ):
                logger.debug(f"Client disconnected during send: {e}")
                if not hasattr(self, "close_code") or self.close_code is None:
                    self.close_code = 1001
                return False
            raise

    async def connect(self):
        try:
            logger.info("WebSocket connection attempt")
            self.close_code = None
            self.token = self.scope.get("query_string", b"").decode()

            user = await self._authenticate_user()
            logger.info(
                f"User authenticated: {user is not None}, User ID: {user.id if user else None}"
            )

            if not user or not self._is_authenticated_user(user):
                await self.accept()
                await self.send_json({"error": "Authentication required"})
                await self.close()
                return

            self.user = user
            self.user_group_name = self._get_user_group_name(user)

            logger.info(f"Joining user group: {self.user_group_name}")
            await self.channel_layer.group_add(self.user_group_name, self.channel_name)

            await self.accept()
            logger.info("WebSocket connection accepted")

            # Optionally, send initial list of uploads on connect
            data = await self.get_user_uploads(user)
            await self.send_json({"type": EVENT_LIST, "list": data})

        except Exception as e:
            logger.error(f"Error in connect: {e}", exc_info=True)
            try:
                await self.accept()
                await self.send_json({"error": f"Connection error: {str(e)}"})
            except Exception:
                pass
            raise

    async def disconnect(self, close_code):
        logger.info(f"WebSocket disconnecting, close_code: {close_code}")
        self.close_code = close_code
        if hasattr(self, "user_group_name"):
            try:
                await self.channel_layer.group_discard(
                    self.user_group_name, self.channel_name
                )
                logger.info(f"Left group: {self.user_group_name}")
            except Exception as e:
                logger.error(f"Error leaving group: {e}", exc_info=True)

    async def receive_json(self, content: Dict[str, Any], **kwargs):
        """
        Handle incoming WebSocket JSON messages.

        Commands:
            - subscribe: Subscribe to status updates
            - retrieve: Get upload instance data
            - create: Create new upload
            - update: Update existing upload
            - delete: Delete upload
            - list: List user's uploads
        """
        try:
            command = content.get("type")
            logger.info(
                f"Received command: {command}, content keys: {list(content.keys())}"
            )

            if not command:
                logger.warning("Missing 'type' field in message")
                await self.send_json({"error": "Missing 'type' field in message"})
                return

            # Re-authenticate on each message (allows token updates)
            user = await self._authenticate_user()
            logger.info(f"User for command: {user.id if user else None}")

            # Route command to appropriate handler
            if command == "subscribe":
                await self._handle_subscribe()
            elif command == "retrieve":
                await self._handle_retrieve(content)
            elif command == "list":
                await self._handle_list(user)
            elif command == "create":
                logger.info("Handling create command")
                await self._handle_create(content, user)
            elif command == "update":
                await self._handle_update(content)
            elif command == "delete":
                await self._handle_delete(content)
            elif command == "question":
                await self._handle_question(content)
            else:
                logger.warning(f"Unsupported command: {command}")
                await self.send_json({"error": "Unsupported command", "type": command})
        except Exception as e:
            # Catch any unexpected errors to prevent disconnection
            logger.error(f"Error processing command: {e}", exc_info=True)
            await self.send_json(
                {
                    "error": f"Error processing command: {str(e)}",
                    "type": content.get("type", "unknown"),
                }
            )

    async def _handle_subscribe(self):
        """Handle subscribe command."""
        # instance_id may not exist; send None or omit if needed.
        instance_id = getattr(self, "instance_id", None)
        await self.send_json(
            {
                "message": "subscribed",
                "model": MODEL_NAME,
                "instance_id": instance_id,
            }
        )

    async def _handle_retrieve(self, content: Dict[str, Any]):
        """Handle retrieve command."""
        instance_id = content.get("instance_id", None)
        payload = await self.get_instance_data(instance_id)
        await self.send_json(payload)

    async def _handle_list(self, user: Optional[Any]):
        """Handle list command."""
        try:
            if not user or not self._is_authenticated_user(user):
                await self.send_json(
                    {"type": EVENT_LIST, "error": "Authentication required"}
                )
                return

            data = await self.get_user_uploads(user)
            await self.send_json({"type": EVENT_LIST, "list": data})
        except Exception as e:
            await self.send_json(
                {
                    "type": EVENT_LIST,
                    "error": f"Failed to list uploads: {str(e)}",
                    "list": [],
                }
            )

    async def _handle_create(self, content: Dict[str, Any], user: Optional[Any]):
        """Handle create command."""
        try:
            data = content.get("data", {})
            logger.info(
                f"Create command - data keys: {list(data.keys())}, has image_base64: {'image_base64' in data}"
            )
            logger.info(f"User: {user.id if user else None}")

            result = await self.create_instance(data, user)
            logger.info(
                f"Create result - has instance: {bool(result.get('instance'))}, has error: {bool(result.get('error'))}"
            )

            # Always send response first (safely)
            if await self._safe_send_json(result):
                logger.info("Create response sent")
            else:
                logger.debug("Create response not sent - connection closed")
                return

            # Only broadcast if creation was successful (has instance, not error)
            if result.get("instance") and not result.get("error"):
                try:
                    await self.model_broadcast("created", result)
                    logger.info("Broadcast sent for created upload")
                except Exception as broadcast_error:
                    # Log broadcast error but don't fail the request
                    logger.error(f"Broadcast error: {broadcast_error}", exc_info=True)
        except Exception as e:
            # Catch any exception to prevent disconnection
            error_msg = str(e)
            # Check if it's a connection-related error
            if (
                "ClientDisconnected" in error_msg
                or "ConnectionClosed" in error_msg
                or "already completed" in error_msg
            ):
                logger.debug(f"Client disconnected during create: {e}")
                # Mark as closed
                if not hasattr(self, "close_code") or self.close_code is None:
                    self.close_code = 1001
                return

            logger.error(f"Error in _handle_create: {e}", exc_info=True)
            error_result = {
                "type": EVENT_CREATED,
                "error": {"error": f"Failed to process create command: {str(e)}"},
            }
            # Try to send error response (safely)
            if not await self._safe_send_json(error_result):
                logger.debug("Error response not sent - connection closed")

    async def _handle_update(self, content: Dict[str, Any]):
        """Handle update command."""
        instance_id = content.get("instance_id", None)
        result = await self.update_instance(instance_id, content.get("data", {}))
        await self.send_json(result)
        await self.model_broadcast("updated", result)

    async def _handle_delete(self, content: Dict[str, Any]):
        """Handle delete command."""
        instance_id = content.get("instance_id", None)
        result = await self.delete_instance(instance_id)
        await self.send_json(result)
        await self.model_broadcast("deleted", result)

    async def _handle_question(self, content):
        instance_id = content.get("instance_id", None)
        question = content.get("question", None)
        result = await self.question_upload(instance_id, question)
        await self.send_json(result)

    @sync_to_async
    def question_upload(self, instance_id: Optional[str], question: Optional[str]):
        """
        Add a user question to the followup_qa of an Upload and trigger the background QnA task.
        """
        if not instance_id:
            return {"type": EVENT_UPDATED, "error": "instance_id_required"}
        if not question or not isinstance(question, str) or not question.strip():
            return {"type": EVENT_UPDATED, "error": "question_required"}

        try:
            # Do not allow question on soft-deleted upload
            instance: Upload = Upload.objects.get(id=instance_id, is_deleted=False)
        except Upload.DoesNotExist:
            return {"type": EVENT_UPDATED, "error": "not_found"}

        # Add question to followup_qa history (role: "user")
        followup_qa = instance.followup_qa if instance.followup_qa is not None else []
        followup_qa.append({"role": "user", "content": question})
        instance.followup_qa = followup_qa
        instance.save(update_fields=["followup_qa", "updated_at"])

        # Trigger Celery qna task (async - will answer user's question)
        try:
            from core.tasks import process_question

            process_question.delay(str(instance.id))
        except Exception as e:
            logger.error(f"Failed to trigger process_question({instance.id}) task: {e}")

        # Minimal return: echo question, instance, and info
        return {
            "type": EVENT_UPDATED,
            "instance_id": str(instance.id),
            "question": question,
            "status": "queued",
        }

    @sync_to_async
    def get_user_uploads(self, user: Any) -> list:
        """
        Fetch up to MAX_LIST_RESULTS most recent Uploads for the authenticated user.

        Args:
            user: Authenticated user object

        Returns:
            List of serialized upload data
        """
        try:
            # Filter by owner if user is provided, and skip soft deleted
            if user and hasattr(user, "id"):
                queryset = Upload.objects.filter(owner=user, is_deleted=False).order_by(
                    "-created_at"
                )[:MAX_LIST_RESULTS]
            else:
                # If no user, return empty list
                return []

            data = []
            for upload in queryset:
                try:
                    cached = get_cached_upload_payload(
                        str(upload.id),
                        image_hash=None,
                        owner_id=str(user.id) if user else None,
                    )
                    if cached:
                        data.append(cached)
                    else:
                        serializer = UploadSerializer(upload)
                        data.append(serializer.data)
                except Exception as e:
                    # Skip uploads that can't be serialized
                    continue
            return data
        except Exception as e:
            # Return empty list on error
            return []

    @sync_to_async
    def get_instance_data(self, instance_id: Optional[str]) -> Dict[str, Any]:
        """
        Get serialized Upload data for a specific instance.

        Args:
            instance_id: UUID of the upload instance

        Returns:
            Dict with type, instance data, and optional error
        """
        if not instance_id:
            return {
                "type": EVENT_STATUS,
                "instance": None,
                "error": "instance_id_required",
            }

        try:
            # Don't return soft deleted uploads
            instance = Upload.objects.get(id=instance_id, is_deleted=False)
            data = get_cached_upload_payload(instance_id)
            if not data:
                data = UploadSerializer(instance).data
            return {"type": EVENT_STATUS, "instance": data}
        except Upload.DoesNotExist:
            return {"type": EVENT_STATUS, "instance": None, "error": "not_found"}

    @sync_to_async
    def create_instance(
        self, data: Dict[str, Any], user: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Create a new Upload object or return existing if duplicate by hash for same user.

        Supports:
        - image_path: Server-side file path
        - image_base64: Base64 encoded image data (will be saved to server)
        - image_hash: Pre-computed hash (optional)

        Args:
            data: Upload data dictionary
            user: Optional user to set as owner

        Returns:
            Dict with type, instance data, and optional error
        """
        import base64
        import imghdr
        import os
        import uuid

        def _find_duplicate_upload(image_hash, user):
            """
            Check if an upload exists with the given image_hash for this user.
            """
            # No hash: cannot check duplicates
            # Added logging for duplicate upload lookup
            if not image_hash:
                logger.debug("No image_hash provided for duplicate upload check.")
                return None
            query = Upload.objects.filter(image_hash=image_hash)
            if user and hasattr(user, "id"):
                logger.debug(
                    f"Checking duplicate upload for user ID: {user.id}, image_hash: {image_hash}"
                )
                query = query.filter(owner=user)
            else:
                logger.debug(
                    f"Checking duplicate upload for anonymous user, image_hash: {image_hash}"
                )
            try:
                result = query.first() or None
                if result:
                    logger.info(
                        f"Duplicate upload found: ID={result.id} (user={getattr(user, 'id', None)}, image_hash={image_hash})"
                    )
                else:
                    logger.debug(
                        f"No duplicate upload found for image_hash: {image_hash}, user: {getattr(user, 'id', None)}"
                    )
                return result
            except Exception as e:
                logger.error(
                    f"Error while checking for duplicate upload (user={getattr(user, 'id', None)}, image_hash={image_hash}): {e}",
                    exc_info=True,
                )
                return None

        try:
            data = dict(data or {})
            data.pop("id", None)  # Prevent ID override

            # Pre-extract and pre-compute hash if possible
            image_hash = data.get("image_hash")
            image_path = data.get("image_path")
            image_base64 = data.get("image_base64", None)

            # If image_base64 is provided and no hash, try to compute hash from raw data
            base64_hash = None
            image_data = None
            if image_base64:
                if isinstance(image_base64, str):
                    # Remove data URL prefix if present (e.g., "data:image/png;base64,...")
                    if "," in image_base64:
                        image_base64_body = image_base64.split(",", 1)[1]
                    else:
                        image_base64_body = image_base64
                    try:
                        image_data = base64.b64decode(image_base64_body, validate=True)
                    except Exception:
                        image_data = None
                if image_data:
                    hasher = hashlib.sha256()
                    hasher.update(image_data)
                    base64_hash = hasher.hexdigest()
            # Prefer given hash, otherwise hash from predecoded base64, otherwise compute from path later
            hash_for_dup_check = image_hash or base64_hash

            # Try duplicate detection as early as possible, before saving/creating any files/instances
            duplicate_instance = _find_duplicate_upload(hash_for_dup_check, user)
            if duplicate_instance:
                result_serializer = UploadSerializer(instance=duplicate_instance)
                result_data = result_serializer.data
                return {
                    "type": EVENT_CREATED,
                    "instance": result_data,
                    "duplicate": True,
                    "message": "Duplicate found by hash. Returning existing upload for this user.",
                }

            # If no duplicate found, continue with saving/uploading file

            destination_path = None
            if image_base64:
                try:
                    # image_data may be None if previous decode failed (should rarely happen at this point)
                    if image_data is None:
                        # Remove data URL prefix if present
                        if "," in image_base64:
                            image_base64_body = image_base64.split(",", 1)[1]
                        else:
                            image_base64_body = image_base64
                        try:
                            image_data = base64.b64decode(
                                image_base64_body, validate=True
                            )
                        except Exception as decode_error:
                            return {
                                "type": EVENT_CREATED,
                                "error": {
                                    "image_base64": f"Invalid base64 encoding: {str(decode_error)}"
                                },
                            }

                    if not image_data or len(image_data) == 0:
                        return {
                            "type": EVENT_CREATED,
                            "error": {"image_base64": "Empty image data."},
                        }

                    # Save to server storage
                    storage_dir = getattr(settings, "UPLOAD_STORAGE_DIR", None)
                    if not storage_dir:
                        return {
                            "type": EVENT_CREATED,
                            "error": {
                                "image_base64": "File storage location is not configured on server. "
                                "Please set UPLOAD_STORAGE_DIR in settings."
                            },
                        }

                    # Ensure storage directory exists and is writable
                    try:
                        os.makedirs(storage_dir, exist_ok=True)
                        # Test write permissions
                        test_file = os.path.join(storage_dir, ".test_write")
                        try:
                            with open(test_file, "w") as f:
                                f.write("test")
                            os.remove(test_file)
                        except (OSError, IOError, PermissionError) as perm_error:
                            return {
                                "type": EVENT_CREATED,
                                "error": {
                                    "image_base64": f"Storage directory is not writable: {str(perm_error)}"
                                },
                            }
                    except (OSError, IOError, PermissionError) as dir_error:
                        return {
                            "type": EVENT_CREATED,
                            "error": {
                                "image_base64": f"Cannot create storage directory: {str(dir_error)}"
                            },
                        }

                    # Detect file extension from image data
                    extension = ".jpg"  # Default
                    try:
                        # Try to detect image type from header
                        image_type = imghdr.what(None, h=image_data)
                        if image_type:
                            extension = f".{image_type}"
                        else:
                            # Fallback: check magic bytes
                            if image_data.startswith(b"\x89PNG"):
                                extension = ".png"
                            elif image_data.startswith(b"\xff\xd8\xff"):
                                extension = ".jpg"
                            elif image_data.startswith(b"GIF"):
                                extension = ".gif"
                            elif (
                                image_data.startswith(b"RIFF")
                                and b"WEBP" in image_data[:12]
                            ):
                                extension = ".webp"
                    except Exception:
                        pass  # Use default .jpg if detection fails

                    filename = f"{uuid.uuid4()}{extension}"
                    destination_path = os.path.join(storage_dir, filename)

                    # Write file and compute hash simultaneously (hash is already computed, but keep logic for completeness)
                    hasher = hashlib.sha256()
                    try:
                        with open(destination_path, "wb") as f:
                            chunk_size = CHUNK_SIZE
                            for i in range(0, len(image_data), chunk_size):
                                chunk = image_data[i : i + chunk_size]
                                f.write(chunk)
                                hasher.update(chunk)
                    except (OSError, IOError, PermissionError) as write_error:
                        # Cleanup partial file
                        if destination_path and os.path.exists(destination_path):
                            try:
                                os.remove(destination_path)
                            except Exception:
                                pass
                        return {
                            "type": EVENT_CREATED,
                            "error": {
                                "image_base64": f"Failed to write image file: {str(write_error)}"
                            },
                        }
                    data["image_path"] = destination_path
                    data["image_hash"] = hasher.hexdigest()
                except Exception as e:
                    # Cleanup on any error
                    if destination_path and os.path.exists(destination_path):
                        try:
                            os.remove(destination_path)
                        except Exception:
                            pass
                    return {
                        "type": EVENT_CREATED,
                        "error": {
                            "image_base64": f"Failed to process base64 image: {str(e)}"
                        },
                    }

            # Compute image_hash if image_path provided but hash missing
            image_path = data.get("image_path")
            if image_path and not data.get("image_hash"):
                hash_result = self._compute_image_hash(image_path)
                if hash_result is None:
                    return {
                        "type": EVENT_CREATED,
                        "error": {
                            "image_path": f"Unable to read or hash image file at '{image_path}'. "
                            "Ensure the file exists on the server or use image_base64 to upload."
                        },
                    }
                data["image_hash"] = hash_result

            # After base64, check again as user could have sent server-side image_path only (edge case)
            # But we already checked at top if hash present
            # Duplicate detection must happen BEFORE any instance is created/saved!

            # Validate required fields
            if not data.get("image_path"):
                return {
                    "type": EVENT_CREATED,
                    "error": {"image_path": "image_path is required after processing."},
                }

            if not data.get("image_hash"):
                return {
                    "type": EVENT_CREATED,
                    "error": {"image_hash": "image_hash is required after processing."},
                }

            # Final double-check for duplicate (extremely rare, but covers any race condition!)
            image_hash_for_final = data.get("image_hash")
            final_duplicate_instance = _find_duplicate_upload(
                image_hash_for_final, user
            )
            if final_duplicate_instance:
                # Clean up file if we just saved it
                if destination_path and os.path.exists(destination_path):
                    try:
                        os.remove(destination_path)
                    except Exception:
                        pass
                result_serializer = UploadSerializer(instance=final_duplicate_instance)
                result_data = result_serializer.data
                return {
                    "type": EVENT_CREATED,
                    "instance": result_data,
                    "duplicate": True,
                    "message": "Duplicate found by hash. Returning existing upload for this user.",
                }

            # Create serializer (owner is read-only, so we pass it to save())
            logger.info(f"Creating serializer with data keys: {list(data.keys())}")
            serializer = UploadSerializer(data=data)
            if serializer.is_valid():
                logger.info("Serializer is valid, saving instance")
                # Save with owner if user is provided
                if user and hasattr(user, "id"):
                    instance = serializer.save(owner=user)
                    logger.info(
                        f"Upload created with owner: {user.id}, upload_id: {instance.id}"
                    )
                else:
                    instance = serializer.save()
                    logger.info(
                        f"Upload created without owner, upload_id: {instance.id}"
                    )

                # Re-serialize the saved instance to get complete data (including computed fields)
                result_serializer = UploadSerializer(instance=instance)
                result_data = result_serializer.data
                logger.info(f"Serialized data keys: {list(result_data.keys())}")
                return {"type": EVENT_CREATED, "instance": result_data}
            else:
                logger.error(f"Serializer validation failed: {serializer.errors}")
                return {"type": EVENT_CREATED, "error": serializer.errors}

        except Exception as e:
            # Catch any unexpected errors to prevent disconnection
            return {
                "type": EVENT_CREATED,
                "error": {"error": f"Unexpected error creating upload: {str(e)}"},
            }

    @staticmethod
    def _compute_image_hash(image_path: str) -> Optional[str]:
        """
        Compute SHA256 hash of an image file.

        Args:
            image_path: Path to the image file

        Returns:
            Hex digest of the hash, or None on error
        """
        try:
            hasher = hashlib.sha256()
            with open(image_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, IOError, FileNotFoundError, PermissionError):
            return None

    @sync_to_async
    def update_instance(
        self, instance_id: Optional[str], data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update an existing Upload instance.

        Args:
            instance_id: UUID of the upload to update
            data: Dictionary of fields to update

        Returns:
            Dict with type, instance data, and optional error
        """
        if not instance_id:
            return {"type": EVENT_UPDATED, "error": "instance_id_required"}

        try:
            instance = Upload.objects.get(id=instance_id)
        except Upload.DoesNotExist:
            return {"type": EVENT_UPDATED, "error": "not_found"}

        serializer = UploadSerializer(instance, data=data or {}, partial=True)
        if serializer.is_valid():
            serializer.save()
            return {"type": EVENT_UPDATED, "instance": serializer.data}
        else:
            return {"type": EVENT_UPDATED, "error": serializer.errors}

    @sync_to_async
    def delete_instance(self, instance_id: Optional[str]) -> Dict[str, Any]:
        """
        Delete an Upload instance.

        Args:
            instance_id: UUID of the upload to delete

        Returns:
            Dict with type, instance_id, and optional error
        """
        if not instance_id:
            return {"type": EVENT_DELETED, "error": "instance_id_required"}

        try:
            instance = Upload.objects.get(id=instance_id)
        except Upload.DoesNotExist:
            return {"type": EVENT_DELETED, "error": "not_found"}
        # Use soft-delete by setting is_deleted=True and saving the instance instead of hard-delete
        instance.is_deleted = True
        instance.save(update_fields=["is_deleted", "updated_at"])
        return {"type": EVENT_DELETED, "instance_id": instance_id}

    async def model_update(self, event: Dict[str, Any]):
        """
        Receive update from signal/broadcast and send it over this WebSocket.

        Args:
            event: Event dictionary with 'event' or 'type' and 'instance' keys
        """
        try:
            message = {
                "type": event.get("event", event.get("type", EVENT_STATUS)),
                "instance": event.get("instance"),
            }
            # Use safe send method
            if not await self._safe_send_json(message):
                logger.debug("model_update message not sent - connection closed")
        except Exception as e:
            # Catch any other unexpected errors
            error_msg = str(e)
            if (
                "ClientDisconnected" not in error_msg
                and "ConnectionClosed" not in error_msg
            ):
                logger.error(f"Error in model_update: {e}", exc_info=True)
            else:
                logger.debug(f"Connection closed in model_update: {e}")

    async def model_broadcast(self, crud_type: str, payload: Dict[str, Any]):
        """
        Broadcast changes (created/updated/deleted) to relevant channel groups.

        Args:
            crud_type: Type of operation ("created", "updated", "deleted")
            payload: Response payload containing instance data
        """
        try:
            groups = {GROUP_ALL}

            # If the consumer has a user, add that user's group
            if hasattr(self, "user") and self.user and hasattr(self.user, "id"):
                user_group = self._get_user_group_name(self.user)
                groups.add(user_group)

            # Add all relevant user group(s) corresponding to instance owners if known
            instance_data = payload.get("instance")
            if instance_data and isinstance(instance_data, dict):
                owner_id = instance_data.get("owner")
                if owner_id:
                    groups.add(f"{MODEL_NAME}_user_{owner_id}")

            for group in groups:
                try:
                    await self.channel_layer.group_send(
                        group,
                        {
                            "type": "model_update",
                            "event": f"{MODEL_NAME}.{crud_type}",
                            "instance": instance_data,
                        },
                    )
                except Exception as group_error:
                    logger.error(
                        f"Error broadcasting to group {group}: {group_error}",
                        exc_info=True,
                    )
        except Exception as e:
            logger.error(f"Error in model_broadcast: {e}", exc_info=True)
            # Don't raise - just log the error


# Signal handlers to broadcast Upload changes to connected WebSocket clients


def broadcast_upload_status(instance_id: str):
    """
    Broadcast Upload's current data to all relevant WebSocket groups.

    Args:
        instance_id: UUID string of the upload instance
    """
    channel_layer = get_channel_layer()

    # Get instance data (cached or fresh)
    try:
        instance = Upload.objects.get(id=instance_id)
        data = get_cached_upload_payload(instance_id)
        if not data:
            data = UploadSerializer(instance).data
    except Upload.DoesNotExist:
        data = None
    except Exception:
        # Log error in production
        data = None

    # Broadcast to instance-specific group
    async_to_sync(channel_layer.group_send)(
        f"{MODEL_NAME}_{instance_id}",
        {
            "type": "model_update",
            "event": EVENT_STATUS,
            "instance": data,
        },
    )

    # Also notify the "all" group (for list updates)
    async_to_sync(channel_layer.group_send)(
        GROUP_ALL,
        {
            "type": "model_update",
            "event": EVENT_STATUS,
            "instance": data,
        },
    )


@receiver(post_save, sender=Upload)
def ws_upload_refresh(sender, instance: Upload, **kwargs):
    """Signal handler: broadcast upload status on save."""
    broadcast_upload_status(str(instance.id))


@receiver(post_delete, sender=Upload)
def ws_upload_remove(sender, instance: Upload, **kwargs):
    """Signal handler: broadcast upload status on delete."""
    broadcast_upload_status(str(instance.id))
