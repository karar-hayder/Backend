from django.conf import settings
from django.core.cache import cache

UPLOAD_DATA_CACHE_TIMEOUT = getattr(settings, "UPLOAD_DATA_CACHE_TIMEOUT", 60 * 5)


def get_upload_cache_key(upload_id):
    return f"upload-data:{upload_id}"

def get_upload_hash_cache_key(image_hash):
    return f"upload-data-hash:{image_hash}"


def cache_upload_payload(upload_id, payload, image_hash=None):
    """
    Cache payload by upload_id and, optionally, by file image_hash.
    """
    cache.set(get_upload_cache_key(upload_id), payload, UPLOAD_DATA_CACHE_TIMEOUT)
    if image_hash:
        cache.set(get_upload_hash_cache_key(image_hash), payload, UPLOAD_DATA_CACHE_TIMEOUT)


def get_cached_upload_payload(upload_id=None, image_hash=None):
    """
    Retrieve cached payload by upload_id or by image_hash.

    Prioritizes cache lookup by upload_id if both are provided.
    """
    if upload_id is not None:
        result = cache.get(get_upload_cache_key(upload_id))
        if result is not None:
            return result
    if image_hash is not None:
        return cache.get(get_upload_hash_cache_key(image_hash))
    return None


def clear_upload_cache(upload_id=None, image_hash=None):
    """
    Clear cached payload for upload_id and/or image_hash.
    """
    if upload_id is not None:
        cache.delete(get_upload_cache_key(upload_id))
    if image_hash is not None:
        cache.delete(get_upload_hash_cache_key(image_hash))
