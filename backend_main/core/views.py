from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from core.rates import DemoUserUploadRateThrottle, IPRateThrottle
from .models import Upload
from .serializers import UploadSerializer
from core.cache import get_cached_upload_payload, cache_upload_payload, clear_upload_cache

class UploadListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [DemoUserUploadRateThrottle, IPRateThrottle]
    queryset = Upload.objects.all().order_by('-created_at')
    serializer_class = UploadSerializer

class UploadRetrieveUpdateView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Upload.objects.all()
    serializer_class = UploadSerializer
    lookup_field = 'id'

    def retrieve(self, request, *args, **kwargs):
        upload_id = kwargs.get(self.lookup_field)
        cached_payload = get_cached_upload_payload(upload_id)
        if cached_payload is not None:
            return Response(cached_payload)
        response = super().retrieve(request, *args, **kwargs)
        cache_upload_payload(upload_id, response.data)
        return response

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        upload_id = kwargs.get(self.lookup_field)
        clear_upload_cache(upload_id)
        cache_upload_payload(upload_id, response.data)
        return response
