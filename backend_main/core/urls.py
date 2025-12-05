from django.urls import path
from .views import UploadListCreateView, UploadRetrieveUpdateView, UploadImageView

urlpatterns = [
    path('uploads/', UploadListCreateView.as_view(), name='upload-list-create'),
    path('uploads/<str:token>/', UploadListCreateView.as_view(), name='upload-list-create'),
    path('uploads/<uuid:id>/', UploadRetrieveUpdateView.as_view(), name='upload-detail'),
    path('uploads/<uuid:id>/image/', UploadImageView.as_view(), name='upload-image'),
]
