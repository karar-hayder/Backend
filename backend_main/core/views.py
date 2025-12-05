from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from core.rates import DemoUserUploadRateThrottle, IPRateThrottle
from .models import Upload
from .serializers import UploadSerializer

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
