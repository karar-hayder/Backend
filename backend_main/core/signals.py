from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .cache import cache_upload_payload, clear_upload_cache
from .models import Upload
from .serializers import UploadSerializer


@receiver(post_save, sender=Upload)
def refresh_upload_cache(sender, instance, **kwargs):
    owner_id = str(instance.owner_id) if instance.owner_id else None
    clear_upload_cache(
        upload_id=instance.id, image_hash=instance.image_hash, owner_id=owner_id
    )
    serializer = UploadSerializer(instance)
    cache_upload_payload(
        instance.id,
        serializer.data,
        image_hash=instance.image_hash,
        owner_id=owner_id,
    )

    # Trigger OCR task for newly created uploads (not updates)
    if kwargs.get("created", False):
        from .tasks import process_upload_ocr

        # Trigger the task asynchronously
        try:
            process_upload_ocr.delay(str(instance.id))
        except Exception as e:
            # Log error but don't fail the save
            import logging

            logger = logging.getLogger(__name__)
            logger.error(
                f"Failed to trigger OCR task for upload {instance.id}: {e}",
                exc_info=True,
            )


@receiver(post_delete, sender=Upload)
def remove_upload_cache(sender, instance, **kwargs):
    owner_id = str(instance.owner_id) if instance.owner_id else None
    clear_upload_cache(
        upload_id=instance.id, image_hash=instance.image_hash, owner_id=owner_id
    )
