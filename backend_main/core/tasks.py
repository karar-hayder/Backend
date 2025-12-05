import logging

from asgiref.sync import async_to_sync
from celery import shared_task
from channels.layers import get_channel_layer
from django.conf import settings

logger = logging.getLogger("core.tasks.ocr")


# Specify a dedicated Celery queue for OCR processing tasks
@shared_task(queue="ocr")
def process_upload_ocr(upload_id):
    """
    Send upload image data to AI OCR endpoint (which streams markdown via HTTP response),
    update Upload object with results.
    Stream incremental OCR text back to websocket as it arrives.
    """
    import requests

    from core.models import Upload

    logger.info(f"Starting OCR processing for Upload ID: {upload_id}")

    try:
        upload = Upload.objects.get(id=upload_id)
        logger.debug(
            f"Upload {upload_id} loaded from database: image_path={upload.image_path}"
        )
    except Upload.DoesNotExist:
        logger.error(f"Upload with id={upload_id} does not exist, aborting OCR task.")
        return

    # Set status to processing and notify websocket
    upload.status = Upload.STATUS_PROCESSING
    upload.save(update_fields=["status", "updated_at"])
    logger.info(f"Set Upload {upload_id} status to PROCESSING")

    # Get channel layer - handle case where it might not be available
    try:
        channel_layer = get_channel_layer()
        if channel_layer is None:
            logger.warning(
                f"Channel layer is None for upload {upload_id}, WebSocket updates will be disabled"
            )
            channel_layer = None
    except Exception as layer_e:
        logger.warning(
            f"Could not get channel layer for upload {upload_id}: {layer_e}. WebSocket updates disabled."
        )
        channel_layer = None

    group_name = f"Upload_{upload_id}"

    def send_ws_message(content):
        """
        Send WebSocket message via channel layer.
        If Redis/channel layer is unavailable, log but don't fail the task.
        """
        # Skip if channel layer is not available
        if channel_layer is None:
            logger.debug(f"Skipping WebSocket message - channel layer unavailable")
            return

        try:
            async_to_sync(channel_layer.group_send)(
                group_name,
                {
                    "type": "model_update",
                    "instance": content,
                },
            )
            logger.debug(f"WebSocket group_send to {group_name}: {content}")
        except Exception as ws_e:
            # Catch all exceptions - Redis connection issues, channel layer errors, etc.
            error_msg = str(ws_e)
            error_type = type(ws_e).__name__

            # Check if it's a Redis/connection error
            is_redis_error = (
                "redis" in error_msg.lower()
                or "6379" in error_msg
                or "connection" in error_msg.lower()
                or "ConnectionError" in error_type
                or "OSError" in error_type
                or "duplicate name" in error_msg.lower()
            )

            if is_redis_error:
                # Redis connection issues - log as warning but don't fail task
                logger.warning(
                    f"Redis/channel layer unavailable for WebSocket message (upload {upload_id}): {ws_e}. "
                    "Task will continue, but clients won't receive real-time updates. "
                    "Check Redis connection: redis-cli ping"
                )
            else:
                # Other WebSocket/channel layer errors - log as error but don't fail task
                logger.error(
                    f"Failed to send WebSocket message for upload {upload_id}: {ws_e}",
                    exc_info=True,
                )

    ai_host = getattr(settings, "AI_HOST", "http://localhost:5000")
    endpoint = f"{ai_host}/api/ocr/"
    logger.info(f"Sending image to OCR endpoint: {endpoint}")

    try:
        with open(upload.image_path, "rb") as image_file:
            logger.info(
                f"Opened image file for upload {upload_id}: {upload.image_path}"
            )
            files = {"image": image_file}
            response = requests.post(endpoint, files=files, stream=True, timeout=60)
            logger.info(
                f"Received HTTP response from OCR endpoint (status_code={response.status_code})"
            )

            if response.status_code == 200:
                markdown_text = ""
                # Stream chunks to websocket as they arrive
                for chunk in response.iter_content(
                    chunk_size=None, decode_unicode=True
                ):
                    if chunk:
                        logger.debug(
                            f"OCR stream chunk for upload {upload_id}: size={len(chunk)}"
                        )
                        markdown_text += chunk
                        # Send partial result via websocket
                        send_ws_message(
                            {
                                "id": str(upload.id),
                                "status": Upload.STATUS_PROCESSING,
                                "streamed_text": markdown_text,
                                "type": "Upload.status",
                            }
                        )

                logger.info(
                    f"OCR stream complete for upload {upload_id}. Final text length={len(markdown_text)}"
                )
                upload.raw_text = markdown_text
                upload.processed_text = markdown_text
                upload.status = Upload.STATUS_PROCESSED
                upload.save(
                    update_fields=["raw_text", "processed_text", "status", "updated_at"]
                )
                logger.info(f"Upload {upload_id} marked as PROCESSED, text saved.")
                # Send final result (status: processed) via websocket
                send_ws_message(
                    {
                        "id": str(upload.id),
                        "status": Upload.STATUS_PROCESSED,
                        "raw_text": markdown_text,
                        "processed_text": markdown_text,
                        "type": "Upload.status",
                    }
                )
            else:
                logger.error(
                    f"OCR endpoint returned non-200 ({response.status_code}) for upload {upload_id}: {getattr(response, 'text', None)}"
                )
                upload.status = Upload.STATUS_ERROR
                upload.save(update_fields=["status", "updated_at"])
                send_ws_message(
                    {
                        "id": str(upload.id),
                        "status": Upload.STATUS_ERROR,
                        "type": "Upload.status",
                        "error": f"AI endpoint error (HTTP {response.status_code})",
                    }
                )
    except Exception as e:
        logger.exception(f"OCR task failed for upload {upload_id}: {e}")
        upload.status = Upload.STATUS_ERROR
        upload.save(update_fields=["status", "updated_at"])
        send_ws_message(
            {
                "id": str(upload.id),
                "status": Upload.STATUS_ERROR,
                "type": "Upload.status",
                "error": str(e),
            }
        )
