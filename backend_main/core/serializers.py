from django.urls import reverse
from rest_framework import serializers

from .cache import cache_upload_payload, get_cached_upload_payload
from .models import Upload


class UploadSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField()
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Upload
        fields = [
            'id',
            'owner',
            'image_url',
            'image_hash',
            'auto_language_detection',
            'language_hint',
            'output_format',
            'ocr_mode',
            'raw_text',
            'processed_text',
            'created_at',
            'updated_at',
            'image_path',
        ]
        read_only_fields = ['owner', 'image_url']
        extra_kwargs = {
            'image_path': {'write_only': True, 'required': False},
            'language_hint': {'allow_blank': True, 'required': False},
        }

    def get_owner(self, instance):
        if instance.owner_id is None:
            return None
        return str(instance.owner_id)

    def get_image_url(self, instance):
        if not instance.image_path:
            return None
        try:
            return reverse('upload-image', kwargs={'id': instance.id})
        except Exception:
            return None

    def to_representation(self, instance):
        cached_payload = get_cached_upload_payload(instance.id)
        if cached_payload is not None:
            return cached_payload

        representation = super().to_representation(instance)
        cache_upload_payload(instance.id, representation)
        return representation
