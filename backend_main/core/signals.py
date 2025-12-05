from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .cache import cache_upload_payload, clear_upload_cache
from .models import Upload
from .serializers import UploadSerializer


@receiver(post_save, sender=Upload)
def refresh_upload_cache(sender, instance, **kwargs):
    owner_id = str(instance.owner_id) if instance.owner_id else None
    clear_upload_cache(upload_id=instance.id, image_hash=instance.image_hash, owner_id=owner_id)
    serializer = UploadSerializer(instance)
    cache_upload_payload(
        instance.id,
        serializer.data,
        image_hash=instance.image_hash,
        owner_id=owner_id,
    )


@receiver(post_delete, sender=Upload)
def remove_upload_cache(sender, instance, **kwargs):
    owner_id = str(instance.owner_id) if instance.owner_id else None
    clear_upload_cache(upload_id=instance.id, image_hash=instance.image_hash, owner_id=owner_id)
