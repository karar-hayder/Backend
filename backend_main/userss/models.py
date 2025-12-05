import secrets
import uuid
from datetime import timedelta

# Patch for fernet_fields compatibility with Django 4+ (force_text -> force_str)
import django.utils.encoding
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

if not hasattr(django.utils.encoding, "force_text"):
    django.utils.encoding.force_text = django.utils.encoding.force_str


class CustomUser(AbstractUser):
    ROLE_ADMIN = "admin"
    ROLE_USER = "user"
    ROLE_DEMO_USER = "demo_user"
    ROLE_CHOICES = [
        (ROLE_ADMIN, "Admin"),
        (ROLE_USER, "User"),
        (ROLE_DEMO_USER, "Demo User"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField("email address", unique=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []  # As email is used as the main field

    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default=ROLE_DEMO_USER,
        help_text="Role of the user (admin, user, demo_user)",
    )

    last_ip = models.GenericIPAddressField(
        null=True, blank=True, help_text="Last known user IP address"
    )

    def get_username(self):
        # Django uses get_username in some places; we want email as the login/lookup
        return self.email

    def upload_count(self):
        """Return the number of uploads this user has performed."""
        if hasattr(self, "uploads"):
            return self.uploads.count()
        return 0

    def upload_times(self):
        """Return a queryset of the upload times for this user's uploads."""
        if hasattr(self, "uploads"):
            return self.uploads.values_list("created_at", flat=True)
        return []

    def __str__(self):
        return self.email if self.email else self.username


class APIToken(models.Model):
    """
    Token for authenticating and rate limiting user API usage.
    """

    from fernet_fields import EncryptedTextField

    key = EncryptedTextField(max_length=128)
    user = models.ForeignKey(
        CustomUser, related_name="api_tokens", on_delete=models.CASCADE
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(
        default=True, help_text="Whether this token is currently usable."
    )
    ip_address = models.GenericIPAddressField(
        null=True, blank=True, help_text="IP when token was last used"
    )
    rate_limit_count = models.IntegerField(
        default=0, help_text="Usage counter for this token since last window"
    )
    last_rate_limit_reset = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        super().save(*args, **kwargs)

    @staticmethod
    def generate_key():
        return secrets.token_hex(32)  # Returns 64 chars hex

    def __str__(self):
        return f"Token for {self.user.email} ({'active' if self.is_active else 'inactive'})"
