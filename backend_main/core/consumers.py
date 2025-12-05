from channels.generic.websocket import AsyncJsonWebsocketConsumer
from asgiref.sync import sync_to_async

from .models import Upload
from .serializers import UploadSerializer
from .cache import get_cached_upload_payload

class UploadStatusConsumer(AsyncJsonWebsocketConsumer):
    """
    WebSocket consumer for upload status and updates.

    Clients should join the channel for a specific upload_id to receive status updates.
    """

    async def connect(self):
        self.upload_id = self.scope['url_route']['kwargs'].get('upload_id')
        if not self.upload_id:
            await self.close()
            return
        self.upload_group_name = f"upload_{self.upload_id}"
        await self.channel_layer.group_add(self.upload_group_name, self.channel_name)
        await self.accept()

        # Send current upload state on connect (if exists)
        upload_data = await self.get_upload_data(self.upload_id)
        if upload_data:
            await self.send_json(upload_data)

    async def disconnect(self, close_code):
        if hasattr(self, "upload_group_name"):
            await self.channel_layer.group_discard(self.upload_group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        # This consumer is push only; ignore client messages or handle 'subscribe' ping
        if content.get("type") == "subscribe":
            await self.send_json({"message": "subscribed", "upload_id": self.upload_id})

    @sync_to_async
    def get_upload_data(self, upload_id):
        try:
            upload = Upload.objects.get(id=upload_id)
            # Use cache if available
            data = get_cached_upload_payload(upload_id)
            if not data:
                data = UploadSerializer(upload).data
            return {"type": "upload.status", "upload": data}
        except Upload.DoesNotExist:
            return {"type": "upload.status", "upload": None, "error": "not_found"}

    async def upload_update(self, event):
        """
        Receive notification from signals and forward to WebSocket.
        """
        await self.send_json({
            "type": "upload.status",
            "upload": event["upload"],
        })

# Signal handling: send update to websocket on save/delete
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

def broadcast_upload_status(upload_id):
    """
    Utility to broadcast the current upload data to the websocket group.
    """
    channel_layer = get_channel_layer()
    try:
        upload = Upload.objects.get(id=upload_id)
        data = get_cached_upload_payload(upload_id)
        if not data:
            data = UploadSerializer(upload).data
    except Upload.DoesNotExist:
        data = None
    async_to_sync(channel_layer.group_send)(
        f"upload_{upload_id}",
        {
            "type": "upload_update",
            "upload": data
        }
    )

# Connect this to model signals (import here to ensure registration)
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

@receiver(post_save, sender=Upload)
def ws_upload_refresh(sender, instance, **kwargs):
    broadcast_upload_status(str(instance.id))

@receiver(post_delete, sender=Upload)
def ws_upload_remove(sender, instance, **kwargs):
    broadcast_upload_status(str(instance.id))
