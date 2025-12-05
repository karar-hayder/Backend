from channels.generic.websocket import AsyncJsonWebsocketConsumer
from asgiref.sync import sync_to_async

from .models import Upload
from .serializers import UploadSerializer
from .cache import get_cached_upload_payload

from django.apps import apps

class ModelStatusConsumer(AsyncJsonWebsocketConsumer):
    """
    Generic WebSocket consumer for model instance status and updates.

    Clients should join the channel for a specific model and instance_id to receive status updates.
    The URL route must supply `model` and `instance_id` as kwargs.
    """

    async def connect(self):
        self.model_name = self.scope['url_route']['kwargs'].get('model')
        self.instance_id = self.scope['url_route']['kwargs'].get('instance_id')
        if not self.model_name or not self.instance_id:
            await self.close()
            return

        self.model_group_name = f"{self.model_name}_{self.instance_id}"
        await self.channel_layer.group_add(self.model_group_name, self.channel_name)
        await self.accept()

        # Send current instance state on connect (if exists)
        instance_data = await self.get_instance_data(self.model_name, self.instance_id)
        if instance_data:
            await self.send_json(instance_data)

    async def disconnect(self, close_code):
        if hasattr(self, "model_group_name"):
            await self.channel_layer.group_discard(self.model_group_name, self.channel_name)

    async def receive_json(self, content, **kwargs):
        # Push only; ignore or acknowledge subscription requests
        if content.get("type") == "subscribe":
            await self.send_json({
                "message": "subscribed",
                "model": self.model_name,
                "instance_id": self.instance_id
            })

    @sync_to_async
    def get_instance_data(self, model_name, instance_id):
        """
        Resolve model by name, look up instance, return serialized data (possibly from cache).
        """
        Model = self._get_model_class(model_name)
        Serializer = self._get_serializer_class(model_name)
        get_cache = self._get_cache_function(model_name)
        cache_key = self._get_cache_key(instance_id, model_name)

        if not Model or not Serializer:
            return {"type": f"{model_name}.status", "instance": None, "error": "model_or_serializer_not_found"}

        try:
            instance = Model.objects.get(id=instance_id)
            data = get_cache(instance_id) if get_cache else None
            if not data:
                data = Serializer(instance).data
            return {"type": f"{model_name}.status", "instance": data}
        except Model.DoesNotExist:
            return {"type": f"{model_name}.status", "instance": None, "error": "not_found"}

    async def model_update(self, event):
        """
        Receive notification from signals and forward to WebSocket.
        """
        await self.send_json({
            "type": event.get("type", f"{self.model_name}.status"),
            "instance": event.get("instance"),
        })

    def _get_model_class(self, model_name):
        # Try local core.models first, then apps.get_model
        try:
            return getattr(__import__(f"{__package__}.models", fromlist=[model_name]), model_name)
        except (AttributeError, ImportError):
            try:
                return apps.get_model("core", model_name)
            except Exception:
                return None

    def _get_serializer_class(self, model_name):
        # Try local core.serializers first
        try:
            return getattr(__import__(f"{__package__}.serializers", fromlist=[f"{model_name}Serializer"]), f"{model_name}Serializer")
        except (AttributeError, ImportError):
            pass
        return None

    def _get_cache_function(self, model_name):
        # Only Upload currently supports cached payloads, but provide extension point
        if model_name.lower() == "upload":
            return get_cached_upload_payload
        return None

    def _get_cache_key(self, instance_id, model_name):
        # Only Upload supports hash key, so keep generic for possible future models
        return instance_id

# Signal handling: send update to websocket on save/delete for all models listed
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

def broadcast_model_status(model_name, instance_id):
    """
    Utility to broadcast the current model instance data to the websocket group.
    Used by all signal handlers.
    """
    channel_layer = get_channel_layer()
    consumer_class = ModelStatusConsumer
    Model = consumer_class._get_model_class(consumer_class, model_name)
    Serializer = consumer_class._get_serializer_class(consumer_class, model_name)
    get_cache = consumer_class._get_cache_function(consumer_class, model_name)

    try:
        instance = Model.objects.get(id=instance_id)
        data = get_cache(instance_id) if get_cache else None
        if not data:
            data = Serializer(instance).data if Serializer else None
    except Exception:
        data = None

    async_to_sync(channel_layer.group_send)(
        f"{model_name}_{instance_id}",
        {
            "type": "model_update",
            "instance": data,
        }
    )

# Register signal handlers for models you want to broadcast
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

# Example: for Upload model in core app (future: expand to other models)
@receiver(post_save, sender=Upload)
def ws_model_refresh(sender, instance, **kwargs):
    broadcast_model_status("Upload", str(instance.id))

@receiver(post_delete, sender=Upload)
def ws_model_remove(sender, instance, **kwargs):
    broadcast_model_status("Upload", str(instance.id))
