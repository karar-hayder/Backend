import hashlib
import os
import tempfile
from datetime import timedelta

from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from userss.models import CustomUser

from .models import Upload
from .rates import DemoUserUploadRateThrottle, IPRateThrottle
from .serializers import UploadSerializer
from .views import UploadImageView, UploadListCreateView, UploadRetrieveUpdateView


def create_temp_image_file(content=b"dummy image data"):
    # Helper to create an actual file on disk
    fd, path = tempfile.mkstemp(suffix=".png")
    with os.fdopen(fd, "wb") as tmp:
        tmp.write(content)
    return path


def calc_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class UploadModelTests(TestCase):
    def test_str_representation_includes_id_and_hash_prefix(self):
        image_path = create_temp_image_file()
        owner = CustomUser.objects.create_user(
            username="modeluser",
            email="modeluser@example.com",
            password="strongpassword",
        )
        upload = Upload.objects.create(
            owner=owner,
            image_path=image_path,
            image_hash="abcdef1234567890",
        )
        text = str(upload)
        self.assertIn("Upload", text)
        self.assertIn("abcdef1234", text)
        os.remove(image_path)


class UploadSerializerTests(TestCase):
    def test_serializer_includes_expected_fields(self):
        image_path = create_temp_image_file()
        owner = CustomUser.objects.create_user(
            username="serializeruser",
            email="serializer@example.com",
            password="strongpassword",
        )
        upload = Upload.objects.create(
            owner=owner,
            image_path=image_path,
            image_hash="hash123456",
        )
        serializer = UploadSerializer(upload)
        data = serializer.data
        for field in [
            "id",
            "owner",
            "image_url",
            "image_hash",
            "auto_language_detection",
            "language_hint",
            "output_format",
            "ocr_mode",
            "raw_text",
            "processed_text",
            "created_at",
            "updated_at",
        ]:
            self.assertIn(field, data)
        self.assertEqual(str(owner.id), data["owner"])
        self.assertEqual(
            reverse("upload-image", kwargs={"id": upload.id}), data["image_url"]
        )
        self.assertTrue(data["auto_language_detection"])
        self.assertEqual(upload.output_format, data["output_format"])
        self.assertIn("image_path", serializer.fields)
        self.assertTrue(serializer.fields["image_path"].write_only)
        os.remove(image_path)


class UploadViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.factory = APIRequestFactory()
        self.user = CustomUser.objects.create_user(
            username="uploader",
            email="uploader@example.com",
            password="strongpassword",
        )
        self.other_user = CustomUser.objects.create_user(
            username="other",
            email="other@example.com",
            password="strongpassword",
        )
        self.image_path1 = create_temp_image_file(b"img1")
        self.image_path2 = create_temp_image_file(b"img2")
        self.image_path3 = create_temp_image_file(b"img3")
        self.image_path4 = create_temp_image_file(b"img4")

    def tearDown(self):
        for p in [
            self.image_path1,
            self.image_path2,
            self.image_path3,
            self.image_path4,
        ]:
            try:
                os.remove(p)
            except Exception:
                pass

    def test_upload_list_requires_authentication(self):
        url = reverse("upload-list-create")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_upload_list_returns_uploads_for_authenticated_user(self):
        upload1 = Upload.objects.create(
            owner=self.user,
            image_path=self.image_path1,
            image_hash="hash1",
        )
        upload2 = Upload.objects.create(
            owner=self.user,
            image_path=self.image_path2,
            image_hash="hash2",
        )
        other_path = create_temp_image_file(b"other")
        Upload.objects.create(
            owner=self.other_user,
            image_path=other_path,
            image_hash="hash-other",
        )
        os.remove(other_path)
        # Disable throttling for this test so we only validate view behavior.
        UploadListCreateView.throttle_classes = []
        request = self.factory.get("/api/v1/core/uploads/")
        force_authenticate(request, user=self.user)
        response = UploadListCreateView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
        # Should be ordered by -created_at (latest first).
        uploaded_ids = [item["id"] for item in response.data]
        actual_qs_order = list(
            Upload.objects.filter(owner=self.user)
            .order_by("-created_at")
            .values_list("id", flat=True)
        )
        self.assertListEqual(uploaded_ids, [str(uid) for uid in actual_qs_order])

    def test_upload_list_filters_by_status_and_hash(self):
        UploadListCreateView.throttle_classes = []
        match = Upload.objects.create(
            owner=self.user,
            image_path=self.image_path1,
            image_hash="hash-status",
            status=Upload.STATUS_PROCESSED,
        )
        Upload.objects.create(
            owner=self.user,
            image_path=self.image_path2,
            image_hash="hash-other-status",
            status=Upload.STATUS_PROCESSING,
        )
        request = self.factory.get(
            f"/api/v1/core/uploads/?status={Upload.STATUS_PROCESSED}&image_hash=hash-status"
        )
        force_authenticate(request, user=self.user)
        response = UploadListCreateView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["id"], str(match.id))

    def test_upload_list_filters_by_search_term(self):
        UploadListCreateView.throttle_classes = []
        match = Upload.objects.create(
            owner=self.user,
            image_path=self.image_path1,
            image_hash="hash-search-1",
            raw_text="Invoice 123",
        )
        Upload.objects.create(
            owner=self.user,
            image_path=self.image_path2,
            image_hash="hash-search-2",
            processed_text="Report 456",
        )
        request = self.factory.get("/api/v1/core/uploads/?search=invoice")
        force_authenticate(request, user=self.user)
        response = UploadListCreateView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["id"], str(match.id))

    def test_upload_list_filters_by_created_range(self):
        UploadListCreateView.throttle_classes = []
        recent = Upload.objects.create(
            owner=self.user,
            image_path=self.image_path1,
            image_hash="hash-recent",
        )
        older = Upload.objects.create(
            owner=self.user,
            image_path=self.image_path2,
            image_hash="hash-older",
        )
        now = timezone.now()
        Upload.objects.filter(pk=older.pk).update(created_at=now - timedelta(days=5))
        Upload.objects.filter(pk=recent.pk).update(created_at=now - timedelta(hours=1))

        created_after = (now - timedelta(days=1)).isoformat()
        created_before = now.isoformat()
        request = self.factory.get(
            "/api/v1/core/uploads/",
            {"created_after": created_after, "created_before": created_before},
        )
        force_authenticate(request, user=self.user)
        response = UploadListCreateView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["id"], str(recent.id))

    def test_user_cannot_access_other_users_upload(self):
        other_path = create_temp_image_file(b"other-access")
        other_hash = hashlib.sha256(b"other-access").hexdigest()
        foreign_upload = Upload.objects.create(
            owner=self.other_user,
            image_path=other_path,
            image_hash=other_hash,
        )
        UploadRetrieveUpdateView.throttle_classes = []
        request = self.factory.get(f"/api/v1/core/uploads/{foreign_upload.id}/")
        force_authenticate(request, user=self.user)
        response = UploadRetrieveUpdateView.as_view()(request, id=foreign_upload.id)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        os.remove(other_path)

    def test_upload_create_creates_new_upload(self):
        UploadListCreateView.throttle_classes = []
        # image_path must exist and should match the hash the API calculates
        with open(self.image_path3, "rb") as f:
            image_bytes = f.read()
        expected_hash = hashlib.sha256(image_bytes).hexdigest()
        request = self.factory.post(
            "/api/v1/core/uploads/",
            {"image_path": self.image_path3},
            format="json",
        )
        force_authenticate(request, user=self.user)
        response = UploadListCreateView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            Upload.objects.filter(image_hash=expected_hash, owner=self.user).exists()
        )

        # Also test: creating with a duplicate image_hash should return the existing upload, not create another
        request2 = self.factory.post(
            "/api/v1/core/uploads/",
            {"image_path": self.image_path3},
            format="json",
        )
        force_authenticate(request2, user=self.user)
        response2 = UploadListCreateView.as_view()(request2)
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertEqual(response2.data["image_hash"], expected_hash)
        self.assertEqual(
            Upload.objects.filter(image_hash=expected_hash, owner=self.user).count(), 1
        )

    def test_upload_create_accepts_binary_file(self):
        UploadListCreateView.throttle_classes = []
        image_bytes = b"binary-image"
        uploaded_file = SimpleUploadedFile(
            "binary.png", image_bytes, content_type="image/png"
        )
        request = self.factory.post(
            "/api/v1/core/uploads/",
            {"image_file": uploaded_file},
            format="multipart",
        )
        force_authenticate(request, user=self.user)
        response = UploadListCreateView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        expected_hash = hashlib.sha256(image_bytes).hexdigest()
        self.assertTrue(
            Upload.objects.filter(image_hash=expected_hash, owner=self.user).exists()
        )
        upload = Upload.objects.get(image_hash=expected_hash, owner=self.user)
        self.assertTrue(os.path.exists(upload.image_path))
        with open(upload.image_path, "rb") as stored_file:
            self.assertEqual(stored_file.read(), image_bytes)
        os.remove(upload.image_path)

    def test_upload_create_accepts_advanced_options(self):
        UploadListCreateView.throttle_classes = []
        with open(self.image_path2, "wb") as f:
            f.write(b"adv-bytes")
        payload = {
            "image_path": self.image_path2,
            "auto_language_detection": False,
            "language_hint": "fr",
            "output_format": Upload.OUTPUT_FORMAT_PARAGRAPH,
            "ocr_mode": Upload.OCR_MODE_ACCURATE,
        }
        request = self.factory.post("/api/v1/core/uploads/", payload, format="json")
        force_authenticate(request, user=self.user)
        response = UploadListCreateView.as_view()(request)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        upload = Upload.objects.get(id=response.data["id"])
        self.assertFalse(upload.auto_language_detection)
        self.assertEqual("fr", upload.language_hint)
        self.assertEqual(Upload.OUTPUT_FORMAT_PARAGRAPH, upload.output_format)
        self.assertEqual(Upload.OCR_MODE_ACCURATE, upload.ocr_mode)

    def test_upload_retrieve_and_update(self):
        # Make the file real; content for hashing
        with open(self.image_path4, "wb") as f:
            f.write(b"img4")
        expected_hash = hashlib.sha256(b"img4").hexdigest()
        upload = Upload.objects.create(
            owner=self.user,
            image_path=self.image_path4,
            image_hash=expected_hash,
            raw_text="raw",
        )
        # Retrieve
        UploadRetrieveUpdateView.throttle_classes = []
        request_get = self.factory.get(f"/api/v1/core/uploads/{upload.id}/")
        force_authenticate(request_get, user=self.user)
        response_get = UploadRetrieveUpdateView.as_view()(request_get, id=upload.id)
        self.assertEqual(response_get.status_code, status.HTTP_200_OK)
        self.assertEqual(response_get.data["image_hash"], expected_hash)

        # Update (also check it refreshes cache)
        request_put = self.factory.put(
            f"/api/v1/core/uploads/{upload.id}/",
            {
                "image_path": self.image_path4,
                "image_hash": expected_hash,
                "processed_text": "processed",
            },
            format="json",
        )
        force_authenticate(request_put, user=self.user)
        response_put = UploadRetrieveUpdateView.as_view()(request_put, id=upload.id)
        self.assertEqual(response_put.status_code, status.HTTP_200_OK)
        upload.refresh_from_db()
        self.assertEqual(upload.processed_text, "processed")

        # Now let's verify that cache is filled for both upload_id and image_hash
        from .cache import get_cached_upload_payload

        cache_by_id = get_cached_upload_payload(upload_id=str(upload.id))
        cache_by_hash = get_cached_upload_payload(
            upload_id=None,
            image_hash=expected_hash,
            owner_id=str(upload.owner_id),
        )
        self.assertIsNotNone(cache_by_id)
        self.assertIsNotNone(cache_by_hash)
        self.assertEqual(cache_by_id["processed_text"], "processed")
        self.assertEqual(cache_by_hash["processed_text"], "processed")

    def test_upload_detail_uses_cache_on_second_retrieve(self):
        # Prepare file and Upload in DB as usual
        with open(self.image_path1, "wb") as f:
            f.write(b"tobeduplicated")
        hash1 = hashlib.sha256(b"tobeduplicated").hexdigest()
        upload = Upload.objects.create(
            owner=self.user,
            image_path=self.image_path1,
            image_hash=hash1,
            raw_text="foo",
        )
        UploadRetrieveUpdateView.throttle_classes = []
        request = self.factory.get(f"/api/v1/core/uploads/{upload.id}/")
        force_authenticate(request, user=self.user)

        # First retrieve: hits DB, fills cache
        resp1 = UploadRetrieveUpdateView.as_view()(request, id=upload.id)
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp1.data["image_hash"], hash1)
        self.assertEqual(resp1.data["raw_text"], "foo")

        # Remove Uploads from DB (should only be in cache now)
        Upload.objects.all().delete()

        # Second retrieve: should fail, using cache (cashe should not have deleted things)
        resp2 = UploadRetrieveUpdateView.as_view()(request, id=upload.id)
        self.assertEqual(resp2.status_code, 404)

    def test_upload_image_endpoint_returns_stream(self):
        with open(self.image_path2, "wb") as f:
            f.write(b"img2-bytes")
        upload = Upload.objects.create(
            owner=self.user,
            image_path=self.image_path2,
            image_hash=hashlib.sha256(b"img2-bytes").hexdigest(),
        )
        request = self.factory.get(f"/api/v1/core/uploads/{upload.id}/image/")
        force_authenticate(request, user=self.user)
        response = UploadImageView.as_view()(request, id=upload.id)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        body = b"".join(response.streaming_content)
        self.assertEqual(body, b"img2-bytes")


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
        self.temp_image = create_temp_image_file()

    def tearDown(self):
        try:
            os.remove(self.temp_image)
        except Exception:
            pass

    def test_demo_user_throttle_checks_demo_user_branch(self):
        Upload.objects.create(
            owner=self.user,
            image_path=self.temp_image,
            image_hash="hashdemo",
        )
        request = self.factory.post(
            "/api/v1/core/uploads/", {"image_path": self.temp_image}, format="json"
        )
        force_authenticate(request, user=self.user)
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
