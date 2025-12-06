import uuid

from django.conf import settings
from django.contrib.postgres.fields import JSONField
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

    OUTPUT_FORMAT_RAW = "raw"
    OUTPUT_FORMAT_PARAGRAPH = "paragraph"
    OUTPUT_FORMAT_CHOICES = [
        (OUTPUT_FORMAT_RAW, "Raw Text"),
        (OUTPUT_FORMAT_PARAGRAPH, "Structured Paragraphs"),
    ]

    OCR_MODE_FAST = "fast"
    OCR_MODE_ACCURATE = "high_accuracy"
    OCR_MODE_CHOICES = [
        (OCR_MODE_FAST, "Fast"),
        (OCR_MODE_ACCURATE, "High Accuracy"),
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
    auto_language_detection = models.BooleanField(
        default=True,
        help_text="Whether OCR should auto-detect the document language.",
    )
    language_hint = models.CharField(
        max_length=32,
        blank=True,
        null=True,
        help_text="Optional ISO language code when auto detection is disabled.",
    )
    output_format = models.CharField(
        max_length=32,
        choices=OUTPUT_FORMAT_CHOICES,
        default=OUTPUT_FORMAT_RAW,
        help_text="Controls whether OCR returns raw text or paragraph-structured output.",
    )
    ocr_mode = models.CharField(
        max_length=32,
        choices=OCR_MODE_CHOICES,
        default=OCR_MODE_FAST,
        help_text="Fast is lower latency; High Accuracy spends more time for better quality.",
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_UPLOADED,
        help_text="Status of the image upload and processing",
        db_index=True,
    )
    # Ollama/LLM-compatible history of user questions & answers about this upload.
    # Each item: {role: "user"|"assistant", content: "...", (optional keys...)}
    followup_qa = models.JSONField(
        blank=True,
        null=True,
        default=list,
        help_text="List of follow-up Q&A in Ollama/chat format: [{role, content, ...}, ...]",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(
        default=False, db_index=True, help_text="Soft-delete flag for the upload."
    )

    class Meta:
        indexes = [
            models.Index(fields=["id"]),
            models.Index(fields=["image_hash"]),
            models.Index(fields=["owner"]),
        ]

    def __str__(self):
        return f"Upload {self.id} - {str(self.image_hash)[:10]}"
