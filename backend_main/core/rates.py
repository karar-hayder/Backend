from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.throttling import BaseThrottle

from core.models import Upload
from userss.models import APIToken, CustomUser


class DemoUserUploadRateThrottle(BaseThrottle):
    """
    Allow demo users to upload a maximum number of uploads.
    Hard-coded to 5 uploads for demo users.
    """

    rate = 5  # max 5 uploads

    def allow_request(self, request, view):
        user = getattr(request, "user", None)
        if (
            user
            and user.is_authenticated
            and hasattr(user, "role")
            and user.role == CustomUser.ROLE_DEMO_USER
        ):
            uploads_count = Upload.objects.filter(owner=user).count()
            return uploads_count < self.rate
        return True


class IPRateThrottle(BaseThrottle):
    """
    Allow per-IP rate limiting, e.g. no more than N requests per time window.
    """

    rate = 20  # Max 20 uploads per hour per IP
    duration = timedelta(hours=1)

    def get_ident(self, request):
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            ip = xff.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
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
        cache.set(
            cache_key, request_history, timeout=int(self.duration.total_seconds())
        )
        return True


class APITokenRateThrottle(BaseThrottle):
    """
    Allow per-token rate limiting (API token).
    E.g., no more than N uploads per hour per APIToken.
    """

    rate = 30  # Max 30 uploads per hour per token
    duration = timedelta(hours=1)

    def get_token(self, request):
        """
        Retrieves the API token string from the request.
        Checks query param, POST data, or url kwargs.
        """
        # Token may be in the URL (kwargs), query params, or request.data
        token = None
        if hasattr(request, "parser_context"):
            # parser_context is set on DRF views, has 'kwargs'
            token = request.parser_context.get("kwargs", {}).get("token")
        if not token:
            token = request.query_params.get("token")
        if not token and hasattr(request, "data"):
            token = request.data.get("token")
        # As a final fallback, if DRF didn't parse, check GET/POST direct
        if not token:
            token = request.GET.get("token")
        if not token and hasattr(request, "POST"):
            token = request.POST.get("token")
        return token

    def allow_request(self, request, view):
        from django.core.cache import cache

        token_val = self.get_token(request)
        if not token_val:
            # No token, pass (this throttle is for tokened uploads)
            return True
        # Only throttle if token exists and is valid in DB
        try:
            token_obj = APIToken.objects.get(key=token_val, is_active=True)
        except APIToken.DoesNotExist:
            return True  # Not an active API token, don't limit here
        cache_key = f"token-upload-rate:{token_obj.key}"
        request_history = cache.get(cache_key, [])
        now = timezone.now()
        # Remove expired
        request_history = [dt for dt in request_history if now - dt < self.duration]
        if len(request_history) >= self.rate:
            return False
        request_history.append(now)
        cache.set(
            cache_key, request_history, timeout=int(self.duration.total_seconds())
        )
        return True
