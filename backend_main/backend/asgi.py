"""
ASGI config for backend project.

This sets up the ASGI application and integrates Django Channels for websocket support.
"""

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.settings")

from django.core.asgi import get_asgi_application

django_asgi_app = get_asgi_application()

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter

# Import the UploadStatusConsumer from core.consumers
from core.consumers import UploadStatusConsumer
from django.urls import path

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": AuthMiddlewareStack(
            URLRouter(
                [
                    # Pattern: /ws/core/upload/<uuid:instance_id>/
                    path(
                        "ws/core/upload/<uuid:instance_id>/",
                        UploadStatusConsumer.as_asgi(),
                    ),
                    # Pattern: /ws/core/upload/ for upload-wide ("all") updates
                    path("ws/core/upload/", UploadStatusConsumer.as_asgi()),
                ]
            )
        ),
    }
)
