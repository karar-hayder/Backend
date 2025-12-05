"""
ASGI config for backend project.

This sets up ASGI application and integrates Django Channels for websocket support.
"""

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.settings")

from django.core.asgi import get_asgi_application
django_asgi_app = get_asgi_application()

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path

# Import *after* Django settings/configuration is ensured
from core.consumers import UploadStatusConsumer

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        URLRouter([
            path("ws/core/", UploadStatusConsumer.as_asgi()),
        ])
    ),
})
