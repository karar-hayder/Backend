import hashlib
import os
import uuid

from django.conf import settings
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .rates import DemoUserUploadRateThrottle, IPRateThrottle, APITokenRateThrottle
from .models import Upload
from .serializers import UploadSerializer
from .cache import (
    get_cached_upload_payload,
    cache_upload_payload,
    clear_upload_cache,
)

class UploadListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [DemoUserUploadRateThrottle, IPRateThrottle, APITokenRateThrottle]
    queryset = Upload.objects.all().order_by('-created_at')
    serializer_class = UploadSerializer

    def _set_request_value(self, request, key, value):
        if hasattr(request.data, "_mutable") and not request.data._mutable:
            request.data._mutable = True
        request.data[key] = value

    def _calculate_hash_from_path(self, image_path):
        try:
            hasher = hashlib.sha256()
            with open(image_path, "rb") as image_file:
                for chunk in iter(lambda: image_file.read(1024 * 1024), b""):
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            raise ValidationError({"image_path": "Unable to read image file from image_path."})

    def _persist_uploaded_file(self, uploaded_file):
        storage_dir = getattr(settings, "UPLOAD_STORAGE_DIR", None)
        if not storage_dir:
            raise ValidationError({"image_file": "File storage location is not configured."})
        try:
            os.makedirs(storage_dir, exist_ok=True)
        except Exception:
            raise ValidationError({"image_file": "Unable to store uploaded file."})

        extension = os.path.splitext(getattr(uploaded_file, "name", ""))[1] or ".img"
        filename = f"{uuid.uuid4()}{extension}"
        destination_path = os.path.join(storage_dir, filename)
        hasher = hashlib.sha256()
        try:
            with open(destination_path, "wb") as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
                    hasher.update(chunk)
        except Exception:
            self._cleanup_file(destination_path)
            raise ValidationError({"image_file": "Unable to store uploaded file."})
        return destination_path, hasher.hexdigest()

    def _cleanup_file(self, file_path):
        if not file_path:
            return
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError:
            pass

    def create(self, request, *args, **kwargs):
        # --- Custom: Check for token if present in URL/path or request ---
        # The url pattern is .../uploads/<str:token> or .../uploads/
        token = kwargs.get("token") or request.data.get("token")
        if "token" in kwargs and not token:
            raise ValidationError({"token": "Token is required in URL but was not provided."})
        if token:
            from userss.models import APIToken
            try:
                api_token = APIToken.objects.get(key=token, is_active=True)
            except APIToken.DoesNotExist:
                raise ValidationError({"token": "Provided API token is invalid or inactive."})

        uploaded_file = request.FILES.get("image_file") or request.FILES.get("image")
        new_file_created = False
        image_path = None

        if uploaded_file:
            image_path, image_hash = self._persist_uploaded_file(uploaded_file)
            self._set_request_value(request, "image_path", image_path)
            new_file_created = True
        else:
            image_path = request.data.get("image_path")
            if not image_path:
                raise ValidationError({"image_path": "This field is required when image_file is not provided."})
            image_hash = self._calculate_hash_from_path(image_path)

        self._set_request_value(request, "image_hash", image_hash)

        # -- Check for existing hash in cache first --
        cached_payload = get_cached_upload_payload(upload_id=None, image_hash=image_hash)
        if cached_payload is not None:
            if new_file_created:
                self._cleanup_file(image_path)
            return Response(cached_payload, status=status.HTTP_200_OK)

        # If not cached, check in DB for an upload with this hash
        existing_upload = Upload.objects.filter(image_hash=image_hash).order_by('-created_at').first()
        if existing_upload:
            if new_file_created:
                self._cleanup_file(image_path)
            serializer = self.get_serializer(existing_upload)
            # Cache with both id and hash
            cache_upload_payload(existing_upload.id, serializer.data, image_hash=image_hash)
            return Response(serializer.data, status=status.HTTP_200_OK)

        # No duplicate found, proceed to create
        try:
            response = super().create(request, *args, **kwargs)
        except Exception:
            if new_file_created:
                self._cleanup_file(image_path)
            raise
        created_upload = getattr(self, 'object', None)
        if not created_upload:
            # Fallback (DRF >= 3.0, return value needed)
            created_upload = self.get_queryset().filter(
                image_hash=request.data.get("image_hash")
            ).order_by('-created_at').first()
        upload_id = str(response.data.get("id")) if "id" in response.data else (
            str(created_upload.id) if created_upload else None
        )
        image_hash_final = response.data.get("image_hash") or image_hash
        if upload_id and image_hash_final:
            cache_upload_payload(upload_id, response.data, image_hash=image_hash_final)
        elif upload_id:
            cache_upload_payload(upload_id, response.data)
        return response

class UploadRetrieveUpdateView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Upload.objects.all()
    serializer_class = UploadSerializer
    lookup_field = 'id'

    def retrieve(self, request, *args, **kwargs):
        upload_id = kwargs.get(self.lookup_field)
        cached_payload = None
        if upload_id:
            cached_payload = get_cached_upload_payload(upload_id)
            if cached_payload is not None:
                return Response(cached_payload, status=status.HTTP_200_OK)
        if not cached_payload and upload_id:
            try:
                upload_obj = Upload.objects.get(id=upload_id)
                with open(upload_obj.image_path, "rb") as image_file:
                    file_content = image_file.read()
                    image_hash = hashlib.sha256(file_content).hexdigest()
                cached_payload = get_cached_upload_payload(upload_id=None, image_hash=image_hash)
                if cached_payload is not None:
                    return Response(cached_payload, status=status.HTTP_200_OK)
            except Upload.DoesNotExist:
                cached_payload = get_cached_upload_payload(upload_id)
                if cached_payload is not None:
                    return Response(cached_payload, status=status.HTTP_200_OK)
            except Exception:
                # Could be file missing, etc, just skip to next step
                pass
        response = super().retrieve(request, *args, **kwargs)
        # After retrieve, calculate image_hash from file and cache it
        try:
            image_path = response.data.get("image_path")
            if image_path:
                with open(image_path, "rb") as image_file:
                    file_content = image_file.read()
                    image_hash_to_cache = hashlib.sha256(file_content).hexdigest()
                cache_upload_payload(upload_id, response.data, image_hash=image_hash_to_cache)
            else:
                cache_upload_payload(upload_id, response.data)
        except Exception:
            cache_upload_payload(upload_id, response.data)
        return response

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        upload_id = kwargs.get(self.lookup_field)
        # Clear all caches first
        clear_upload_cache(upload_id)
        # After update, recalculate image hash and cache
        try:
            image_path = response.data.get("image_path")
            if image_path:
                with open(image_path, "rb") as image_file:
                    file_content = image_file.read()
                    image_hash = hashlib.sha256(file_content).hexdigest()
                clear_upload_cache(image_hash=image_hash)
                cache_upload_payload(upload_id, response.data, image_hash=image_hash)
            else:
                cache_upload_payload(upload_id, response.data)
        except Exception:
            cache_upload_payload(upload_id, response.data)
        return response
