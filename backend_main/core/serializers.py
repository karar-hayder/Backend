from rest_framework import serializers
from .models import Upload

class UploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Upload
        fields = [
            'id',
            'image_path',
            'image_hash',
            'raw_text',
            'processed_text',
            'created_at',
            'updated_at',
        ]
