from rest_framework import serializers

from .cache import cache_upload_payload, get_cached_upload_payload
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

    def to_representation(self, instance):
        cached_payload = get_cached_upload_payload(instance.id)
        if cached_payload is not None:
            return cached_payload

        representation = super().to_representation(instance)
        cache_upload_payload(instance.id, representation)
        return representation
