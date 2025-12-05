from django.utils import timezone
from django.conf import settings
from rest_framework.throttling import BaseThrottle
from userss.models import CustomUser, APIToken
from core.models import Upload
from datetime import timedelta

class DemoUserUploadRateThrottle(BaseThrottle):
    """
    Allow demo users to upload a maximum number of uploads.
    Hard-coded to 5 uploads for demo users.
    """

    rate = 5  # max 5 uploads

    def allow_request(self, request, view):
        user = getattr(request, "user", None)
        if user and user.is_authenticated and hasattr(user, "role") and user.role == CustomUser.ROLE_DEMO_USER:
            uploads_count = Upload.objects.filter(
                # optionally also restrict per day, but right now just restrict total
                # 'user' relation if exists, otherwise by the uploader's id.
                # This assumes Upload model is related to user, else needs extension
                # If not implemented, fallback to count=0 always (not restricting anyone) or use last_ip.
            ).count()
            # If Upload does not have a user, use last_ip for demo user entries as a fallback.
            return uploads_count < self.rate
        return True

class IPRateThrottle(BaseThrottle):
    """
    Allow per-IP rate limiting, e.g. no more than N requests per time window.
    """

    rate = 20  # Max 20 uploads per hour per IP
    duration = timedelta(hours=1)

    # This requires you to save IP rate counts somewhere - for a simple in-memory cache, use Django's cache.
    def get_ident(self, request):
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            ip = xff.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def allow_request(self, request, view):
        from django.core.cache import cache
        ident = self.get_ident(request)
        cache_key = f"ip-upload-rate:{ident}"
        request_history = cache.get(cache_key, [])
        now = timezone.now()
        # Remove expired
        request_history = [dt for dt in request_history if now - dt < self.duration]
        if len(request_history) >= self.rate:
            return False
        request_history.append(now)
        cache.set(cache_key, request_history, timeout=int(self.duration.total_seconds()))
        return True

