from django.http import JsonResponse
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken, TokenError

from django.contrib.auth import logout, authenticate
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from .serializers import UserSerializer
from .models import CustomUser

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {'refresh': str(refresh), 'access': str(refresh.access_token)}


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handles user registration, using CustomUser only.
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
            email = CustomUser.objects.normalize_email(email)
            if CustomUser.objects.filter(email__iexact=email).exists():
                errors['email'] = ['A user with this email already exists.']

        if errors:
            return JsonResponse({'errors': errors}, status=status.HTTP_400_BAD_REQUEST)

        # User creation - use email for both username and email so that
        # authentication with `username=email` works with the default manager.
        user = CustomUser.objects.create_user(
            username=email,
            email=email,
            password=password,
        )
        if first_name:
            user.first_name = first_name
        if last_name:
            user.last_name = last_name
        user.save()

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
            email = CustomUser.objects.normalize_email(email.strip())

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


class RefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Accepts a refresh token, returns a new access token.
        """
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return JsonResponse({'errors': {'refresh': 'Refresh token required.'}}, status=status.HTTP_400_BAD_REQUEST)
        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            return JsonResponse({
                'access': access_token
            }, status=status.HTTP_200_OK)
        except TokenError:
            return JsonResponse({'errors': {'refresh': 'Invalid or expired refresh token.'}}, status=status.HTTP_401_UNAUTHORIZED)


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
        Allow updating first_name, last_name directly on CustomUser.
        """
        user = request.user
        first_name = request.data.get('first_name', '').strip()
        last_name = request.data.get('last_name', '').strip()
        updated = False

        if first_name:
            user.first_name = first_name
            updated = True
        if last_name:
            user.last_name = last_name
            updated = True

        if updated:
            user.save()
            user_data = UserSerializer(user).data
            return JsonResponse({'message': 'Profile updated successfully.', 'user': user_data}, status=status.HTTP_200_OK)
        else:
            return JsonResponse({'errors': {'__all__': ['No updates provided.']}}, status=status.HTTP_400_BAD_REQUEST)


class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_data = UserSerializer(user).data
        return JsonResponse(user_data, status=status.HTTP_200_OK)
