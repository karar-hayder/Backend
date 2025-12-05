import json
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate
from django.contrib.sessions.middleware import SessionMiddleware

from .models import CustomUser, APIToken
from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    EditProfileView,
    RemoveAccountView,
    CurrentUserView,
)


User = get_user_model()


class CustomUserModelTests(TestCase):
    def test_str_returns_email_if_present(self):
        user = CustomUser.objects.create_user(
            username="user1",
            email="user1@example.com",
            password="strongpassword",
        )
        self.assertEqual(str(user), "user1@example.com")

    def test_str_falls_back_to_username_if_no_email(self):
        user = CustomUser.objects.create_user(
            username="user2",
            password="strongpassword",
        )
        self.assertEqual(str(user), "user2")

    def test_upload_count_and_times_without_related_uploads(self):
        # When there is no related Upload model/attribute, these helpers
        # should safely fall back to zero / empty list.
        user = CustomUser.objects.create_user(
            username="user3",
            email="user3@example.com",
            password="strongpassword",
        )
        self.assertEqual(user.upload_count(), 0)
        self.assertEqual(list(user.upload_times()), [])


class APITokenModelTests(TestCase):
    def test_generate_key_returns_64_char_hex(self):
        key = APIToken.generate_key()
        self.assertEqual(len(key), 64)
        # All characters should be valid hexadecimal digits.
        int(key, 16)

    def test_save_populates_key_if_missing(self):
        user = CustomUser.objects.create_user(
            username="user4",
            email="user4@example.com",
            password="strongpassword",
        )
        token = APIToken(user=user)
        self.assertEqual(token.key, "")
        token.save()
        self.assertNotEqual(token.key, "")
        self.assertEqual(len(token.key), 64)


class RegisterViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_successful_registration_creates_user_and_returns_tokens(self):
        url = reverse("users:signup")
        payload = {
            "email": "newuser@example.com",
            "password": "strongpassword",
            "first_name": "New",
            "last_name": "User",
        }
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("access", response.json())
        self.assertIn("refresh", response.json())
        self.assertIn("user", response.json())
        self.assertTrue(
            CustomUser.objects.filter(email__iexact="newuser@example.com").exists()
        )

    def test_registration_fails_with_existing_email(self):
        CustomUser.objects.create_user(
            username="existing",
            email="existing@example.com",
            password="strongpassword",
        )
        url = reverse("users:signup")
        payload = {
            "email": "existing@example.com",
            "password": "strongpassword",
        }
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()
        self.assertIn("errors", data)
        self.assertIn("email", data["errors"])

    def test_registration_requires_valid_email_and_password(self):
        url = reverse("users:signup")
        payload = {
            "email": "not-an-email",
            "password": "short",
        }
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()
        self.assertIn("errors", data)
        self.assertIn("email", data["errors"])
        self.assertIn("password", data["errors"])


class LoginViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.password = "strongpassword"
        # Use email as the username to match authenticate(username=email, ...)
        self.user = CustomUser.objects.create_user(
            username="loginuser@example.com",
            email="loginuser@example.com",
            password=self.password,
        )

    def test_successful_login_returns_tokens(self):
        url = reverse("users:login")
        payload = {
            "email": "loginuser@example.com",
            "password": self.password,
        }
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("access", data)
        self.assertIn("refresh", data)
        self.assertIn("user", data)

    def test_login_fails_with_invalid_credentials(self):
        url = reverse("users:login")
        payload = {
            "email": "loginuser@example.com",
            "password": "wrongpassword",
        }
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_requires_email_and_password(self):
        url = reverse("users:login")
        response = self.client.post(url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()
        self.assertIn("errors", data)
        self.assertIn("__all__", data["errors"])


class AuthenticatedUserViewTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = CustomUser.objects.create_user(
            username="authuser",
            email="authuser@example.com",
            password="strongpassword",
        )

    def test_logout_view_logs_out_user(self):
        request = self.factory.post("/api/v1/userss/logout/")
        # Attach a session so django.contrib.auth.logout can operate.
        SessionMiddleware(lambda r: None).process_request(request)
        request.session.save()
        force_authenticate(request, user=self.user)
        response = LogoutView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_edit_profile_updates_first_and_last_name(self):
        request = self.factory.put(
            "/api/v1/userss/profile/edit/",
            {"first_name": "New", "last_name": "Name"},
            format="json",
        )
        force_authenticate(request, user=self.user)
        response = EditProfileView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "New")
        self.assertEqual(self.user.last_name, "Name")

    def test_edit_profile_without_changes_returns_error(self):
        request = self.factory.put(
            "/api/v1/userss/profile/edit/",
            {},
            format="json",
        )
        force_authenticate(request, user=self.user)
        response = EditProfileView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_remove_account_deletes_user(self):
        request = self.factory.delete("/api/v1/userss/profile/delete/")
        SessionMiddleware(lambda r: None).process_request(request)
        request.session.save()
        force_authenticate(request, user=self.user)
        response = RemoveAccountView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(CustomUser.objects.filter(pk=self.user.pk).exists())

    def test_current_user_view_returns_user_data(self):
        request = self.factory.get("/api/v1/userss/user/")
        force_authenticate(request, user=self.user)
        response = CurrentUserView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.content)
        self.assertEqual(data.get("email"), "authuser@example.com")
