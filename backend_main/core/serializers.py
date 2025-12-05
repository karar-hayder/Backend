from rest_framework import serializers

from .cache import cache_upload_payload, get_cached_upload_payload
from .models import Upload


class UploadSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField()

    class Meta:
        model = Upload
        fields = [
            'id',
            'owner',
            'image_path',
            'image_hash',
            'raw_text',
            'processed_text',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['owner']

    def get_owner(self, instance):
        if instance.owner_id is None:
            return None
        return str(instance.owner_id)

    def to_representation(self, instance):
        cached_payload = get_cached_upload_payload(instance.id)
        if cached_payload is not None:
            return cached_payload

        representation = super().to_representation(instance)
        cache_upload_payload(instance.id, representation)
        return representation
