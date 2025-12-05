import uuid

from django.conf import settings
from django.db import models


class Upload(models.Model):
    STATUS_UPLOADED = "uploaded"
    STATUS_PROCESSING = "processing"
    STATUS_PROCESSED = "processed"
    STATUS_ERROR = "error"
    STATUS_CHOICES = [
        (STATUS_UPLOADED, "Uploaded"),
        (STATUS_PROCESSING, "Processing"),
        (STATUS_PROCESSED, "Processed"),
        (STATUS_ERROR, "Error"),
    ]

    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, db_index=True
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="core_uploads",
        null=True,
        blank=True,
        db_index=True,
    )
    image_path = models.CharField(max_length=1024)
    image_hash = models.CharField(max_length=128, db_index=True)
    raw_text = models.TextField(blank=True, null=True)
    processed_text = models.TextField(blank=True, null=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_UPLOADED,
        help_text="Status of the image upload and processing",
        db_index=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["id"]),
            models.Index(fields=["image_hash"]),
            models.Index(fields=["owner"]),
        ]

    def __str__(self):
        return f"Upload {self.id} - {str(self.image_hash)[:10]}"
