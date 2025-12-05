from django.db import models
import uuid

class Upload(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, db_index=True)
    image_path = models.CharField(max_length=1024)
    image_hash = models.CharField(max_length=128, db_index=True)
    raw_text = models.TextField(blank=True, null=True)
    processed_text = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['id']),
            models.Index(fields=['image_hash']),
        ]

    def __str__(self):
        return f"Upload {self.id} - {self.image_hash[:10]}"
