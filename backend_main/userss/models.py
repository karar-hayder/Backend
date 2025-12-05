from datetime import timedelta

# Patch for fernet_fields compatibility with Django 4+ (force_text -> force_str)
import django.utils.encoding
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import uuid

if not hasattr(django.utils.encoding, "force_text"):
    django.utils.encoding.force_text = django.utils.encoding.force_str

from fernet_fields import EncryptedTextField


class CustomUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField('email address', unique=True)

    def upload_count(self):
        """Return the number of uploads this user has performed."""
        if hasattr(self, 'uploads'):
            return self.uploads.count()
        return 0

    def upload_times(self):
        """Return a queryset of the upload times for this user's uploads."""
        if hasattr(self, 'uploads'):
            return self.uploads.values_list('created_at', flat=True)
        return []

    def __str__(self):
        return self.email if self.email else self.username