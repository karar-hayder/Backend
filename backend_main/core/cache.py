from django.conf import settings
from django.core.cache import cache

UPLOAD_DATA_CACHE_TIMEOUT = getattr(settings, "UPLOAD_DATA_CACHE_TIMEOUT", 60 * 5)


def get_upload_cache_key(upload_id):
    return f"upload-data:{upload_id}"


def cache_upload_payload(upload_id, payload):
    cache.set(get_upload_cache_key(upload_id), payload, UPLOAD_DATA_CACHE_TIMEOUT)


def get_cached_upload_payload(upload_id):
    return cache.get(get_upload_cache_key(upload_id))


def clear_upload_cache(upload_id):
    cache.delete(get_upload_cache_key(upload_id))
