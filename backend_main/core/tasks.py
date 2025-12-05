import requests
from django.conf import settings
from django.utils import timezone
from celery import shared_task

@shared_task
def process_upload_ocr(upload_id):
    """
    Send upload image data to AI OCR endpoint, update Upload object with results.
    """
    from core.models import Upload
    try:
        upload = Upload.objects.get(id=upload_id)
    except Upload.DoesNotExist:
        return

    # Set status to processing
    upload.status = Upload.STATUS_PROCESSING
    upload.save(update_fields=["status", "updated_at"])

    ai_host = getattr(settings, "AI_HOST", "http://localhost:5001")
    endpoint = f"{ai_host}/api/ocr/"

    try:
        with open(upload.image_path, "rb") as image_file:
            files = {"image": image_file}
            response = requests.post(endpoint, files=files, timeout=30)

        if response.status_code == 200:
            result = response.json()
            upload.raw_text = result.get("raw_text", "")
            upload.processed_text = result.get("processed_text", "")
            upload.status = Upload.STATUS_PROCESSED
            upload.save(update_fields=["raw_text", "processed_text", "status", "updated_at"])
        else:
            upload.status = Upload.STATUS_ERROR
            upload.save(update_fields=["status", "updated_at"])
    except Exception as e:
        upload.status = Upload.STATUS_ERROR
        upload.save(update_fields=["status", "updated_at"])
