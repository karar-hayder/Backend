from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .cache import cache_upload_payload, clear_upload_cache
from .models import Upload
from .serializers import UploadSerializer

@receiver(post_save, sender=Upload)
def refresh_upload_cache(sender, instance, **kwargs):
    """
    Refresh the Upload payload cache on creation or update.
    Ensures all potential cache keys are cleared and repopulated, for better cache coherence,
    including future-friendly extra keys patterns.
    """
    # Construct all current/legacy/extra cache keys related to this Upload.
    owner_id = str(instance.owner_id) if getattr(instance, "owner_id", None) else None

    # Pre-clear all possible cache variants of this upload using all known IDs and hashes
    clear_upload_cache(
        upload_id=instance.id,
        image_hash=instance.image_hash,
        owner_id=owner_id,
        # Optionally extra_keys param if you use other keys (extended compatibility)
        # Example for future/legacy keys: extra_keys=["upload:data:legacy:{}:{}".format(owner_id, instance.image_hash)]
        extra_keys=None,
    )

    # Re-serialize and re-cache for all keys
    serializer = UploadSerializer(instance)
    cache_upload_payload(
        instance.id,
        serializer.data,
        image_hash=instance.image_hash,
        owner_id=owner_id,
        # Optionally store under extra cache keys for migration or multi-index
        extra_keys=None,
    )

    # For new uploads only, trigger OCR processing
    if kwargs.get("created", False):
        from .tasks import process_upload_ocr

        try:
            process_upload_ocr.delay(str(instance.id))
        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.error(
                f"Failed to trigger OCR task for upload {instance.id}: {e}",
                exc_info=True,
            )


@receiver(post_delete, sender=Upload)
def remove_upload_cache(sender, instance, **kwargs):
    """
    Remove all Upload cache entries for this upload on deletion.
    """
    owner_id = str(instance.owner_id) if getattr(instance, "owner_id", None) else None

    clear_upload_cache(
        upload_id=instance.id,
        image_hash=instance.image_hash,
        owner_id=owner_id,
        # Remove any additional/legacy keys as necessary here
        extra_keys=None,
    )
