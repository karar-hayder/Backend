from django.http import JsonResponse
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth import logout, authenticate, get_user_model
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from .serializers import UserSerializer, ProfileSerializer
from .models import Profile

User = get_user_model()


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handles user registration, including profile creation.
        """
        email = request.data.get('email', '').strip()
        password = request.data.get('password')
        first_name = request.data.get('first_name', '').strip()
        last_name = request.data.get('last_name', '').strip()
        errors = {}

        # Password validation
        if not password:
            errors['password'] = ['Password is required.']
        elif len(password) < 8:
            errors['password'] = ['Password must be at least 8 characters long.']

        # Email validation
        if not email:
            errors['email'] = ['Email is required.']
        else:
            try:
                validate_email(email)
            except ValidationError:
                errors['email'] = ['Enter a valid email address.']
            email = User.objects.normalize_email(email)
            if User.objects.filter(email__iexact=email).exists():
                errors['email'] = ['A user with this email already exists.']

        if errors:
            return JsonResponse({'errors': errors}, status=status.HTTP_400_BAD_REQUEST)

        # User creation
        user = User.objects.create_user(
            email=email,
            password=password,
        )

        # Update first_name, last_name via Profile
        profile, _ = Profile.objects.get_or_create(user=user)
        profile.first_name = first_name
        profile.last_name = last_name
        profile.save()

        tokens = get_tokens_for_user(user)
        user_data = UserSerializer(user).data
        return JsonResponse({
            'message': 'User registered successfully.',
            'access': tokens['access'],
            'refresh': tokens['refresh'],
            'user': user_data,
        }, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email') or request.data.get('username')
        password = request.data.get('password')

        if email:
            email = User.objects.normalize_email(email.strip())

        if not email or not password:
            return JsonResponse(
                {'errors': {'__all__': ['Email and password are required.']}},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(request, username=email, password=password)

        if user is not None and user.is_active:
            tokens = get_tokens_for_user(user)
            user_data = UserSerializer(user).data
            return JsonResponse({
                'message': 'Login successful.',
                'access': tokens['access'],
                'refresh': tokens['refresh'],
                'user': user_data,
            }, status=status.HTTP_200_OK)
        else:
            return JsonResponse(
                {'message': 'Invalid email or password.'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return JsonResponse({'message': 'Logout successful.'}, status=status.HTTP_200_OK)


class RemoveAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        logout(request)
        user.delete()
        return JsonResponse({'message': 'Account removed successfully.'}, status=status.HTTP_204_NO_CONTENT)


class EditProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        """
        Allow updating first_name, last_name via the related Profile.
        """
        user = request.user
        profile = getattr(user, "profile", None)
        if not profile:
            profile = Profile.objects.create(user=user)

        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            user_data = UserSerializer(user).data
            return JsonResponse({'message': 'Profile updated successfully.', 'user': user_data}, status=status.HTTP_200_OK)
        return JsonResponse({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_data = UserSerializer(user).data
        return JsonResponse(user_data, status=status.HTTP_200_OK)
