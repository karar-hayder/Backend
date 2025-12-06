from django.conf import settings
from django.core.cache import cache

UPLOAD_DATA_CACHE_TIMEOUT = getattr(settings, "UPLOAD_DATA_CACHE_TIMEOUT", 60 * 5)


def get_upload_cache_key(upload_id):
    # Single canonical cache key for an upload ID
    return f"upload:data:id:{upload_id}"


def get_upload_hash_cache_key(image_hash, owner_id=None):
    # Scope hash cache to owner unless global
    owner_part = str(owner_id) if owner_id else "global"
    return f"upload:data:hash:{owner_part}:{image_hash}"


def cache_upload_payload(
    upload_id, payload, image_hash=None, owner_id=None, expire=None, extra_keys=None
):
    """
    Cache payload using upload_id and, optionally, by image_hash (scoped to owner).
    Allows for extra cache keys for broader compatibility.

    expires in seconds (can override default).
    """
    timeout = expire or UPLOAD_DATA_CACHE_TIMEOUT
    cache_key = get_upload_cache_key(upload_id)
    cache.set(cache_key, payload, timeout)

    # Optionally also cache by image_hash/owner combo
    if image_hash:
        hash_key = get_upload_hash_cache_key(image_hash, owner_id)
        cache.set(hash_key, payload, timeout)

    # If any other cache keys to index, also store (like legacy, alternate, ...).
    if extra_keys:
        for k in extra_keys:
            if k:
                cache.set(k, payload, timeout)


def get_cached_upload_payload(
    upload_id=None, image_hash=None, owner_id=None, extra_keys=None
):
    """
    Retrieve cached payload (by priority: upload_id, image_hash/owner, then extra_keys).
    Returns first hit.
    """
    # 1. Try upload ID (most specific/direct hit)
    if upload_id is not None:
        key = get_upload_cache_key(upload_id)
        val = cache.get(key)
        if val is not None:
            return val

    # 2. Try hash cache (scoped to owner)
    if image_hash is not None:
        key = get_upload_hash_cache_key(image_hash, owner_id)
        val = cache.get(key)
        if val is not None:
            return val

    # 3. Try any extra keys provided
    if extra_keys:
        for k in extra_keys:
            val = cache.get(k)
            if val is not None:
                return val

    return None


def clear_upload_cache(upload_id=None, image_hash=None, owner_id=None, extra_keys=None):
    """
    Clear cached payload entries for upload_id, image_hash/owner, and any extra cache keys.
    """
    if upload_id is not None:
        cache.delete(get_upload_cache_key(upload_id))
    if image_hash is not None:
        cache.delete(get_upload_hash_cache_key(image_hash, owner_id))
    if extra_keys:
        for k in extra_keys:
            cache.delete(k)
