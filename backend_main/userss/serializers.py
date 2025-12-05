from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import CustomUser

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            "id",
            "email",
            "role",
            "last_ip",
        ]
        read_only_fields = ["id"]
