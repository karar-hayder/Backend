from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
import hashlib
from .rates import DemoUserUploadRateThrottle, IPRateThrottle
from .models import Upload
from .serializers import UploadSerializer
from .cache import (
    get_cached_upload_payload,
    cache_upload_payload,
    clear_upload_cache,
    get_cached_upload_payload as get_cached_upload_payload_by_id_or_hash,
)

class UploadListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [DemoUserUploadRateThrottle, IPRateThrottle]
    queryset = Upload.objects.all().order_by('-created_at')
    serializer_class = UploadSerializer

    def create(self, request, *args, **kwargs):

        image_path = request.data.get("image_path")
        if not image_path:
            raise ValidationError({"image_path": "This field is required."})

        # Calculate the image hash from the file path content
        try:
            with open(image_path, "rb") as image_file:
                file_content = image_file.read()
                image_hash = hashlib.sha256(file_content).hexdigest()
        except Exception:
            raise ValidationError({"image_path": "Unable to read image file from image_path."})

        # If image_hash is not posted, inject it into the request data.
        if not request.data.get("image_hash"):
            # request.data might be immutable, so make it mutable if necessary
            if hasattr(request.data, "_mutable") and not request.data._mutable:
                request.data._mutable = True
            request.data["image_hash"] = image_hash

        # -- Check for existing hash in cache first --
        cached_payload = get_cached_upload_payload(upload_id=None, image_hash=image_hash)
        if cached_payload is not None:
            return Response(cached_payload, status=status.HTTP_200_OK)

        # If not cached, check in DB for an upload with this hash
        existing_upload = Upload.objects.filter(image_hash=image_hash).order_by('-created_at').first()
        if existing_upload:
            serializer = self.get_serializer(existing_upload)
            # Cache with both id and hash
            cache_upload_payload(existing_upload.id, serializer.data, image_hash=image_hash)
            return Response(serializer.data, status=status.HTTP_200_OK)

        # No duplicate found, proceed to create
        response = super().create(request, *args, **kwargs)
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
