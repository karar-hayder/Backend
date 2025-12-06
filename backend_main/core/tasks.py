import logging

from asgiref.sync import async_to_sync
from celery import shared_task
from channels.layers import get_channel_layer
from django.conf import settings

from core.cache import (
    cache_upload_payload,
    clear_upload_cache,
)

logger = logging.getLogger("core.tasks.ocr")


# Specify a dedicated Celery queue for OCR processing tasks
@shared_task(queue="ocr")
def process_upload_ocr(upload_id):
    """
    Send upload image data to AI OCR endpoint (which streams markdown via HTTP response),
    update Upload object with results.
    Stream incremental OCR text back to websocket as it arrives.
    Uses markdown text extraction from backend_main/core/utils.py for parsing AI output.
    """
    import requests
    from core.models import Upload
    from core.utils import extract_markdown_text

    logger.info(f"Starting OCR processing for Upload ID: {upload_id}")

    try:
        upload = Upload.objects.get(id=upload_id)
        logger.debug(
            f"Upload {upload_id} loaded from database: image_path={upload.image_path}"
        )
    except Upload.DoesNotExist:
        logger.error(f"Upload with id={upload_id} does not exist, aborting OCR task.")
        clear_upload_cache(upload_id=upload_id)
        return

    # Set status to processing and notify websocket
    upload.status = Upload.STATUS_PROCESSING
    upload.save(update_fields=["status", "updated_at"])
    logger.info(f"Set Upload {upload_id} status to PROCESSING")
    # Cache status for upload (for real-time & long-running status lookup)
    cache_upload_payload(upload_id, {"status": Upload.STATUS_PROCESSING})

    # Get channel layer - handle case where it might not be available
    try:
        channel_layer = get_channel_layer()
        if channel_layer is None:
            logger.warning(
                f"Channel layer is None for upload {upload_id}, WebSocket updates will be disabled"
            )
            channel_layer = None
    except Exception as layer_e:
        logger.warning(
            f"Could not get channel layer for upload {upload_id}: {layer_e}. WebSocket updates disabled."
        )
        channel_layer = None

    # Only use a single group per user for all coms, if owner is set
    group_name = None
    if hasattr(upload, "owner") and upload.owner_id:
        group_name = f"User_{upload.owner_id}"
    else:
        logger.warning(
            f"Upload {upload_id} has no owner - cannot send websocket message to user group"
        )

    def send_ws_message(content):
        """
        Send WebSocket message via channel layer to the user's single group.
        If Redis/channel layer is unavailable, log but don't fail the task.
        """
        if channel_layer is None or not group_name:
            logger.debug(
                f"Skipping WebSocket message - channel layer or user group unavailable"
            )
            return

        try:
            async_to_sync(channel_layer.group_send)(
                group_name,
                {
                    "type": "model_update",
                    "event": "Upload.status",
                    "instance": content,
                },
            )
            logger.debug(f"WebSocket group_send to {group_name}: {content}")
        except Exception as ws_e:
            error_msg = str(ws_e)
            error_type = type(ws_e).__name__

            is_redis_error = (
                "redis" in error_msg.lower()
                or "6379" in error_msg
                or "connection" in error_msg.lower()
                or "ConnectionError" in error_type
                or "OSError" in error_type
                or "duplicate name" in error_msg.lower()
            )

            if is_redis_error:
                logger.warning(
                    f"Redis/channel layer unavailable for WebSocket message (upload {upload_id}): {ws_e}. "
                    "Task will continue, but clients won't receive real-time updates. "
                    "Check Redis connection: redis-cli ping"
                )
            else:
                logger.error(
                    f"Failed to send WebSocket message for upload {upload_id}: {ws_e}",
                    exc_info=True,
                )

    ai_host = getattr(settings, "AI_HOST", "http://localhost:5000")
    endpoint = f"{ai_host}/api/ocr/"
    logger.info(f"Sending image to OCR endpoint: {endpoint}")

    try:
        with open(upload.image_path, "rb") as image_file:
            logger.info(
                f"Opened image file for upload {upload_id}: {upload.image_path}"
            )
            files = {"image": image_file}
            response = requests.post(endpoint, files=files, stream=True, timeout=60)
            logger.info(
                f"Received HTTP response from OCR endpoint (status_code={response.status_code})"
            )

            if response.status_code == 200:
                streamed_content = ""
                # Stream chunks to websocket as they arrive
                for chunk in response.iter_content(
                    chunk_size=None, decode_unicode=True
                ):
                    if chunk:
                        logger.debug(
                            f"OCR stream chunk for upload {upload_id}: size={len(chunk)}"
                        )
                        streamed_content += chunk
                        # Use text extraction on streamed content so far (may be partial)
                        extracted_markdown = extract_markdown_text(streamed_content)
                        # Send partial result via websocket (both raw stream and extracted)
                        send_ws_message(
                            {
                                "id": str(upload.id),
                                "status": Upload.STATUS_PROCESSING,
                                "streamed_text": streamed_content,
                                "extracted_markdown": extracted_markdown,
                                "type": "Upload.status",
                            }
                        )
                        # Cache partial streamed text to allow polling for progress
                        cache_upload_payload(
                            upload_id,
                            {
                                "status": Upload.STATUS_PROCESSING,
                                "streamed_text": streamed_content,
                                "extracted_markdown": extracted_markdown,
                            },
                        )

                logger.info(
                    f"OCR stream complete for upload {upload_id}. Final stream length={len(streamed_content)}"
                )
                # Get only the markdown text, safe even if not present
                markdown_text = extract_markdown_text(streamed_content)
                upload.raw_text = streamed_content
                upload.processed_text = markdown_text
                upload.status = Upload.STATUS_PROCESSED
                upload.save(
                    update_fields=["raw_text", "processed_text", "status", "updated_at"]
                )
                logger.info(
                    f"Upload {upload_id} marked as PROCESSED, text saved. Markdown length={len(markdown_text)}"
                )
                # Send final result (status: processed) via websocket
                send_ws_message(
                    {
                        "id": str(upload.id),
                        "status": Upload.STATUS_PROCESSED,
                        "raw_text": streamed_content,
                        "processed_text": markdown_text,
                        "type": "Upload.status",
                    }
                )
                # Write final state to cache, too
                cache_upload_payload(
                    upload_id,
                    {
                        "status": Upload.STATUS_PROCESSED,
                        "raw_text": streamed_content,
                        "processed_text": markdown_text,
                    },
                )
            else:
                logger.error(
                    f"OCR endpoint returned non-200 ({response.status_code}) for upload {upload_id}: {getattr(response, 'text', None)}"
                )
                upload.status = Upload.STATUS_ERROR
                upload.save(update_fields=["status", "updated_at"])
                send_ws_message(
                    {
                        "id": str(upload.id),
                        "status": Upload.STATUS_ERROR,
                        "type": "Upload.status",
                        "error": f"AI endpoint error (HTTP {response.status_code})",
                    }
                )
                # Remove any stale result from cache now that error happened
                clear_upload_cache(upload_id=upload_id)
    except Exception as e:
        logger.exception(f"OCR task failed for upload {upload_id}: {e}")
        upload.status = Upload.STATUS_ERROR
        upload.save(update_fields=["status", "updated_at"])
        send_ws_message(
            {
                "id": str(upload.id),
                "status": Upload.STATUS_ERROR,
                "type": "Upload.status",
                "error": str(e),
            }
        )
        clear_upload_cache(upload_id=upload_id)


@shared_task(queue="qna")
def process_question(upload_id):
    """
    Process a user question related to an Upload by sending the appropriate content/history/image
    to a new Ollama/LLava chat endpoint, then append the answer to the Upload's followup_qa list.
    Also sends the generated answer through the websocket, per Upload.status event.
    """
    import base64
    import json

    import requests
    from core.models import Upload
    from django.conf import settings
    from django.core.files.storage import default_storage

    logger = logging.getLogger("core.tasks.qna")

    # Import send_ws_message from consumers for WebSocket broadcast.
    try:
        from core.consumers import send_ws_message
    except ImportError:

        def send_ws_message(msg):
            logger.error(
                "send_ws_message could not be imported for QnA WebSocket broadcast."
            )

    try:
        upload = Upload.objects.get(id=upload_id)
    except Upload.DoesNotExist:
        logger.error(f"Upload with id={upload_id} does not exist, aborting QnA task.")
        clear_upload_cache(upload_id=upload_id)
        return

    # Get the QA history as a list with user & assistant turns
    qa_history = upload.followup_qa if upload.followup_qa is not None else []
    # Only act if there is an unanswered user question.
    last_user_index = None
    for i in range(len(qa_history) - 1, -1, -1):
        entry = qa_history[i]
        if entry.get("role") == "user":
            # If there is not an immediately following "assistant" answer for this question
            if i + 1 >= len(qa_history) or qa_history[i + 1].get("role") != "assistant":
                last_user_index = i
                break
    if last_user_index is None:
        logger.info(
            f"All user questions for upload {upload_id} are already answered or no user question found."
        )
        return

    user_prompt = qa_history[last_user_index].get("content")
    if not user_prompt:
        logger.warning(
            f"User question at index {last_user_index} has no content for upload {upload_id}."
        )
        return

    # Try to get chat history up to this question, as plain text exchange for compatibility
    def format_history_for_prompt(history, up_to_index):
        # Only up to the last user prompt (exclusive)
        formatted = []
        for i in range(0, up_to_index):
            role = history[i].get("role", "")
            content = history[i].get("content", "")
            if role and content:
                formatted.append(f"{role.capitalize()}: {content}")
        return "\n".join(formatted) if formatted else None

    # Compose extracted OCR content if available
    extracted_content = upload.raw_text if upload.raw_text else None

    # Prepare image as base64 if present
    image_field_path = upload.image_path
    images = []
    try:
        image_bytes = None
        if default_storage.exists(image_field_path):
            with default_storage.open(image_field_path, "rb") as f:
                image_bytes = f.read()
        else:
            with open(image_field_path, "rb") as f:
                image_bytes = f.read()
        if image_bytes:
            images.append(base64.b64encode(image_bytes).decode("utf-8"))
    except Exception as e:
        logger.error(
            f"Failed to read image file {image_field_path} for upload {upload_id}: {e}"
        )
        # Continue without image.

    # Compose chat_history to text per API spec ("history" field)
    chat_history = format_history_for_prompt(qa_history, last_user_index)
    # Compose POST for new API
    ai_host = getattr(settings, "AI_HOST", "http://localhost:5000")
    api_url = ai_host.rstrip("/") + "/api/convo/"

    form_data = {
        "prompt": user_prompt,
    }
    if extracted_content:
        form_data["content"] = extracted_content
    if chat_history:
        form_data["history"] = chat_history

    # Compose files part if image available
    files = {}
    if images:
        # Only send one image as "image"
        files["image"] = ("image.jpg", base64.b64decode(images[0]))

    try:
        # Use stream to get the answer just like the Python client expects streaming markdown
        with requests.post(
            api_url,
            data=form_data,
            files=files if files else None,
            timeout=120,
            stream=True,
        ) as response:
            if response.status_code == 200:
                # Gather the streamed answer
                answer_parts = []
                for line in response.iter_lines():
                    if line:
                        try:
                            decoded_line = line.decode()
                        except Exception:
                            decoded_line = line
                        answer_parts.append(decoded_line)
                answer = "".join(answer_parts).strip()
                if not answer:
                    logger.warning(
                        f"No answer (empty streaming response) from /api/convo/ for upload {upload_id}."
                    )
                    return
                # Insert the answer as an assistant message
                qa_history.insert(
                    last_user_index + 1, {"role": "assistant", "content": answer}
                )
                upload.followup_qa = qa_history
                upload.save(update_fields=["followup_qa", "updated_at"])
                logger.info(
                    f"Appended assistant answer to Upload {upload_id} followup_qa."
                )

                # ---- Send answer through websocket ----
                ws_payload = {
                    "id": str(upload.id),
                    "instance_id": str(upload.id),
                    "question": user_prompt,
                    "answer": answer,
                    "status": "answered",
                    "type": "Upload.status",
                }
                try:
                    send_ws_message(ws_payload)
                    logger.info(
                        f"Sent answer through websocket for upload {upload_id}."
                    )
                except Exception as ws_exc:
                    logger.error(
                        f"Failed to send answer through websocket for upload {upload_id}: {ws_exc}"
                    )
                # Cache the new state for fast QnA lookup for this upload
                cache_upload_payload(
                    upload_id,
                    {
                        "status": "answered",
                        "followup_qa": qa_history,
                        "last_q": user_prompt,
                        "answer": answer,
                    },
                )

            else:
                logger.error(
                    f"QnA endpoint returned non-200 ({response.status_code}) for upload {upload_id}: {getattr(response, 'text', None)}"
                )
                # Optionally, notify websocket of error:
                ws_error_payload = {
                    "id": str(upload.id),
                    "instance_id": str(upload.id),
                    "status": "error",
                    "type": "Upload.status",
                    "error": f"AI QnA endpoint error (HTTP {response.status_code})",
                }
                try:
                    send_ws_message(ws_error_payload)
                except Exception:
                    pass
                # Clear any old QnA cache if error happened
                clear_upload_cache(upload_id=upload_id)
    except Exception as e:
        logger.exception(f"Failed to call /api/convo/ for upload {upload_id}: {e}")
        # Optionally, notify websocket of error:
        try:
            send_ws_message(
                {
                    "id": str(upload.id),
                    "instance_id": str(upload.id),
                    "status": "error",
                    "type": "Upload.status",
                    "error": str(e),
                }
            )
        except Exception:
            pass
        clear_upload_cache(upload_id=upload_id)
