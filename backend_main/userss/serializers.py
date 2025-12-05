from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Profile

User = get_user_model()

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            "id",
            "first_name",
            "last_name",
            "user"
        ]
        read_only_fields = ["id", "user"]

class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "is_staff",
            "is_active",
            "date_joined",
            "profile",
        ]
        read_only_fields = ["id", "is_staff", "is_active", "date_joined", "profile"]
