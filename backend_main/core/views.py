import hashlib
import mimetypes
import os
import uuid

from django.conf import settings
from django.db.models import Q
from django.http import FileResponse, Http404
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .cache import cache_upload_payload, clear_upload_cache, get_cached_upload_payload
from .models import Upload
from .rates import APITokenRateThrottle, DemoUserUploadRateThrottle, IPRateThrottle
from .serializers import UploadSerializer


def _safe_calculate_file_hash(image_path):
    """Return a SHA256 hash for the given image path, or None if unavailable."""
    if not image_path:
        return None
    try:
        hasher = hashlib.sha256()
        with open(image_path, "rb") as image_file:
            for chunk in iter(lambda: image_file.read(1024 * 1024), b""):
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None


class UploadListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [
        DemoUserUploadRateThrottle,
        IPRateThrottle,
        APITokenRateThrottle,
    ]
    serializer_class = UploadSerializer

    def _base_queryset(self):
        return Upload.objects.filter(owner=self.request.user)

    def get_queryset(self):
        base_qs = self._base_queryset().order_by("-created_at")
        return self._apply_filters(base_qs)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user, image_path=self.request.data.get("image_path"))

    def _get_query_params(self):
        if hasattr(self.request, "query_params"):
            return self.request.query_params
        return self.request.GET

    def _extract_filter_values(self, params, key):
        values = []
        if hasattr(params, "getlist"):
            values.extend(params.getlist(key))
        else:
            single_value = params.get(key)
            if single_value:
                values.append(single_value)
        extracted = []
        for value in values:
            if not value:
                continue
            extracted.extend([segment.strip() for segment in value.split(",") if segment.strip()])
        return extracted

    def _parse_datetime(self, raw_value):
        if not raw_value:
            return None
        parsed = parse_datetime(raw_value)
        if parsed is None:
            return None
        if timezone.is_naive(parsed):
            parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
        return parsed

    def _apply_filters(self, queryset):
        params = self._get_query_params() or {}
        get_param = params.get if hasattr(params, "get") else (lambda key, default=None: None)
        statuses = self._extract_filter_values(params, "status")
        valid_statuses = {choice[0] for choice in Upload.STATUS_CHOICES}
        statuses = [status for status in statuses if status in valid_statuses]
        if statuses:
            queryset = queryset.filter(status__in=statuses)

        image_hash = get_param("image_hash")
        if image_hash:
            queryset = queryset.filter(image_hash=image_hash)

        search_term = get_param("search")
        if search_term:
            queryset = queryset.filter(
                Q(raw_text__icontains=search_term) | Q(processed_text__icontains=search_term)
            )

        created_after = self._parse_datetime(get_param("created_after"))
        if created_after:
            queryset = queryset.filter(created_at__gte=created_after)

        created_before = self._parse_datetime(get_param("created_before"))
        if created_before:
            queryset = queryset.filter(created_at__lte=created_before)

        return queryset

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

    def _persist_existing_file(self, source_path):
        if not source_path:
            raise ValidationError({"image_file": "Provide an image file to upload."})
        if not os.path.isfile(source_path):
            raise ValidationError(
                {"image_path": "Provided image_path does not exist on the server."}
            )
        storage_dir = getattr(settings, "UPLOAD_STORAGE_DIR", None)
        if not storage_dir:
            raise ValidationError({"image_file": "File storage location is not configured."})
        try:
            os.makedirs(storage_dir, exist_ok=True)
        except Exception:
            raise ValidationError({"image_file": "Unable to store uploaded file."})

        extension = os.path.splitext(source_path)[1] or ".img"
        filename = f"{uuid.uuid4()}{extension}"
        destination_path = os.path.join(storage_dir, filename)
        hasher = hashlib.sha256()
        try:
            with open(source_path, "rb") as source, open(destination_path, "wb") as destination:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    if not chunk:
                        break
                    destination.write(chunk)
                    hasher.update(chunk)
        except Exception:
            self._cleanup_file(destination_path)
            raise ValidationError({"image_path": "Unable to store uploaded file."})
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
                raise ValidationError(
                    {"image_path": "This field is required when image_file is not provided."}
                )
            image_hash = self._calculate_hash_from_path(image_path)

        self._set_request_value(request, "image_hash", image_hash)

        owner_id = str(request.user.id)
        base_queryset = self._base_queryset()

        cached_payload = get_cached_upload_payload(
            upload_id=None, image_hash=image_hash, owner_id=owner_id
        )
        if cached_payload is not None:
            if new_file_created:
                self._cleanup_file(image_path)
            return Response(cached_payload, status=status.HTTP_200_OK)

        existing_upload = (
            base_queryset.filter(image_hash=image_hash).order_by("-created_at").first()
        )
        if existing_upload:
            if new_file_created:
                self._cleanup_file(image_path)
            serializer = self.get_serializer(existing_upload)
            cache_upload_payload(
                existing_upload.id,
                serializer.data,
                image_hash=image_hash,
                owner_id=owner_id,
            )
            return Response(serializer.data, status=status.HTTP_200_OK)

        try:
            response = super().create(request, *args, **kwargs)
        except Exception:
            if new_file_created:
                self._cleanup_file(image_path)
            raise
        created_upload = getattr(self, "object", None)
        if not created_upload:
            created_upload = (
                base_queryset.filter(image_hash=request.data.get("image_hash"))
                .order_by("-created_at")
                .first()
            )
        upload_id = (
            str(response.data.get("id"))
            if "id" in response.data
            else (str(created_upload.id) if created_upload else None)
        )
        image_hash_final = response.data.get("image_hash") or image_hash
        if upload_id and image_hash_final:
            cache_upload_payload(
                upload_id, response.data, image_hash=image_hash_final, owner_id=owner_id
            )
        elif upload_id:
            cache_upload_payload(upload_id, response.data)
        return response


class UploadRetrieveUpdateView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UploadSerializer
    lookup_field = "id"

    def get_queryset(self):
        return Upload.objects.filter(owner=self.request.user)

    def _owns_cached_payload(self, request, payload):
        if not isinstance(payload, dict):
            return False
        cached_owner = payload.get("owner")
        if cached_owner is None:
            return False
        return str(cached_owner) == str(request.user.id)

    def retrieve(self, request, *args, **kwargs):
        upload_id = kwargs.get(self.lookup_field)
        owner_id = str(request.user.id)
        if upload_id:
            cached_payload = get_cached_upload_payload(upload_id)
            if cached_payload is not None and self._owns_cached_payload(request, cached_payload):
                return Response(cached_payload, status=status.HTTP_200_OK)

        try:
            instance = self.get_object()
        except Http404:
            if upload_id:
                cached_payload = get_cached_upload_payload(upload_id)
                if cached_payload is not None and self._owns_cached_payload(
                    request, cached_payload
                ):
                    return Response(cached_payload, status=status.HTTP_200_OK)
            # Remove the incorrect nested except
            # and do not indent further; allow normal flow after handling Http404.
        response = super().retrieve(request, *args, **kwargs)
        # After retrieve, calculate image_hash from file and cache it
        try:
            image_path = response.data.get("image_path")
            if image_path:
                with open(image_path, "rb") as image_file:
                    file_content = image_file.read()
                    image_hash_to_cache = hashlib.sha256(file_content).hexdigest()
                cache_upload_payload(
                    upload_id,
                    response.data,
                    image_hash=image_hash_to_cache,
                    owner_id=owner_id,
                )
            else:
                cache_upload_payload(upload_id, response.data)
            return Response(response.data, status=status.HTTP_200_OK)
        except Exception:
            cache_upload_payload(upload_id, response.data)
            return Response(response.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        upload_id = kwargs.get(self.lookup_field)
        clear_upload_cache(upload_id)
        owner_id = str(request.user.id)
        try:
            image_path = response.data.get("image_path")
            if image_path:
                with open(image_path, "rb") as image_file:
                    file_content = image_file.read()
                    image_hash = hashlib.sha256(file_content).hexdigest()
                clear_upload_cache(image_hash=image_hash, owner_id=owner_id)
                cache_upload_payload(
                    upload_id, response.data, image_hash=image_hash, owner_id=owner_id
                )
            else:
                cache_upload_payload(upload_id, response.data)
        except Exception:
            cache_upload_payload(upload_id, response.data)
        return response


class UploadImageView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    lookup_field = "id"

    def get_queryset(self):
        return Upload.objects.filter(owner=self.request.user)

    def get(self, request, *args, **kwargs):
        upload = self.get_object()
        image_path = upload.image_path
        if not image_path or not os.path.isfile(image_path):
            return Response({"detail": "Image file not found."}, status=status.HTTP_404_NOT_FOUND)
        content_type, _ = mimetypes.guess_type(image_path)
        response = FileResponse(
            open(image_path, "rb"), content_type=content_type or "application/octet-stream"
        )
        response["Content-Length"] = os.path.getsize(image_path)
        response["Content-Disposition"] = f'inline; filename="{os.path.basename(image_path)}"'
        return response
