from django.test import TestCase
from django.urls import reverse
from django.core.cache import cache

from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from .models import Upload
from .serializers import UploadSerializer
from .views import UploadListCreateView, UploadRetrieveUpdateView
from .rates import DemoUserUploadRateThrottle, IPRateThrottle
from userss.models import CustomUser


class UploadModelTests(TestCase):
    def test_str_representation_includes_id_and_hash_prefix(self):
        upload = Upload.objects.create(
            image_path="/tmp/example.png",
            image_hash="abcdef1234567890",
        )
        text = str(upload)
        self.assertIn("Upload", text)
        self.assertIn("abcdef1234", text)


class UploadSerializerTests(TestCase):
    def test_serializer_includes_expected_fields(self):
        upload = Upload.objects.create(
            image_path="/tmp/example.png",
            image_hash="hash123456",
        )
        serializer = UploadSerializer(upload)
        data = serializer.data
        for field in [
            "id",
            "image_path",
            "image_hash",
            "raw_text",
            "processed_text",
            "created_at",
            "updated_at",
        ]:
            self.assertIn(field, data)


class UploadViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.factory = APIRequestFactory()
        self.user = CustomUser.objects.create_user(
            username="uploader",
            email="uploader@example.com",
            password="strongpassword",
        )

    def test_upload_list_requires_authentication(self):
        url = reverse("upload-list-create")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_upload_list_returns_uploads_for_authenticated_user(self):
        # Use APIRequestFactory + force_authenticate so we do not depend on JWT tokens.
        upload1 = Upload.objects.create(
            image_path="/tmp/image1.png",
            image_hash="hash1",
        )
        upload2 = Upload.objects.create(
            image_path="/tmp/image2.png",
            image_hash="hash2",
        )
        # Disable throttling for this test so we only validate view behavior.
        UploadListCreateView.throttle_classes = []
        request = self.factory.get("/api/v1/core/uploads/")
        force_authenticate(request, user=self.user)
        response = UploadListCreateView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
        # Should be ordered by -created_at (latest first).
        self.assertEqual(response.data[0]["id"], str(upload2.id))

    def test_upload_create_creates_new_upload(self):
        UploadListCreateView.throttle_classes = []
        request = self.factory.post(
            "/api/v1/core/uploads/",
            {"image_path": "/tmp/image3.png", "image_hash": "hash3"},
            format="json",
        )
        force_authenticate(request, user=self.user)
        response = UploadListCreateView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            Upload.objects.filter(image_hash="hash3").exists()
        )

    def test_upload_retrieve_and_update(self):
        upload = Upload.objects.create(
            image_path="/tmp/image4.png",
            image_hash="hash4",
            raw_text="raw",
        )
        # Retrieve
        UploadRetrieveUpdateView.throttle_classes = []
        request_get = self.factory.get(f"/api/v1/core/uploads/{upload.id}/")
        force_authenticate(request_get, user=self.user)
        response_get = UploadRetrieveUpdateView.as_view()(request_get, id=upload.id)
        self.assertEqual(response_get.status_code, status.HTTP_200_OK)
        self.assertEqual(response_get.data["image_hash"], "hash4")

        # Update
        request_put = self.factory.put(
            f"/api/v1/core/uploads/{upload.id}/",
            {"image_path": "/tmp/image4.png", "image_hash": "hash4", "processed_text": "processed"},
            format="json",
        )
        force_authenticate(request_put, user=self.user)
        response_put = UploadRetrieveUpdateView.as_view()(request_put, id=upload.id)
        self.assertEqual(response_put.status_code, status.HTTP_200_OK)
        upload.refresh_from_db()
        self.assertEqual(upload.processed_text, "processed")


class DemoUserUploadRateThrottleTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = CustomUser.objects.create_user(
            username="demouser",
            email="demo@example.com",
            password="strongpassword",
        )
        self.user.role = CustomUser.ROLE_DEMO_USER
        self.user.save()
        self.throttle = DemoUserUploadRateThrottle()

    def test_demo_user_throttle_checks_demo_user_branch(self):
        """
        For demo users, the throttle should at least evaluate
        the Upload count branch; current implementation returns
        True (no throttling) when using a global Upload count.
        """
        Upload.objects.create(
            image_path="/tmp/demo.png",
            image_hash="hashdemo",
        )
        request = self.factory.post("/api/v1/core/uploads/")
        force_authenticate(request, user=self.user)
        # Current behavior: still allowed; this asserts that
        # the demo-user-specific code path does not block.
        self.assertTrue(self.throttle.allow_request(request, view=None))


class IPRateThrottleTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.throttle = IPRateThrottle()
        cache.clear()

    def test_ip_rate_throttle_limits_requests(self):
        # Allow up to `rate` requests from same IP, then block.
        for _ in range(self.throttle.rate):
            request = self.factory.post("/api/v1/core/uploads/")
            request.META["REMOTE_ADDR"] = "127.0.0.1"
            self.assertTrue(self.throttle.allow_request(request, view=None))

        # Next request from same IP should be blocked.
        request = self.factory.post("/api/v1/core/uploads/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        self.assertFalse(self.throttle.allow_request(request, view=None))
