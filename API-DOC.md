# API Documentation

Comprehensive reference for the `text-extraction-backend` REST API that the frontend consumes. All paths listed below are prefixed with `/api/v1/`.

---

## Overview

- Content type: JSON (`application/json`) unless explicitly stated for file upload endpoints.
- Authentication: JWT access tokens issued by SimpleJWT. Supply them through `Authorization: Bearer <access_token>`.
- All responses are UTF-8 JSON. Error payloads always include either an `errors` object or a `message` string that can be surfaced to the user.
- Only resources owned by the authenticated user are ever returned.

### Authentication flow
1. `POST /users/signup/` or `POST /users/login/` – obtain `access` and `refresh` JWTs plus the user payload.
2. Include the provided access token in every subsequent request header: `Authorization: Bearer eyJ...`.
3. When the access token expires, ask for a new one via `POST /users/refresh/` (requires the refresh token in the body) or rotate both tokens via `POST /users/refresh/token/` (requires an authenticated request).
4. The backend never invalidates tokens automatically on logout; the frontend must drop them from storage on a successful `/users/logout/` response.

### Response patterns
- **Success with data** – JSON object/array containing the requested resource(s). Some endpoints also include a `message` string for display.
- **Validation errors** – `400 Bad Request` with `{ "errors": {<field>: [<message>, ...], "__all__": [<message>] } }`.
- **Authentication errors** – `401 Unauthorized` with `{ "message": "Invalid email or password." }` or `{ "errors": {"refresh": "..."} }`.
- **Forbidden or throttled** – `403`/`429` with `{ "detail": "Request was throttled." }` from DRF throttling.

### Rate limiting
- Demo accounts (`role = demo_user`) may create a maximum of **5 uploads total**.
- An IP address may start at most **20 uploads per hour** (`429 Too Many Requests` afterwards).
- When an API token is supplied, that token may start at most **30 uploads per hour**.

---

## Domain objects

### User
| Field | Type | Notes |
| --- | --- | --- |
| `id` | UUID string | Primary key of the account. |
| `email` | string | Unique login and contact identifier. |
| `role` | `admin` \| `user` \| `demo_user` | Controls rate limiting. |
| `last_ip` | string or `null` | Latest IP recorded on the backend. |

### Upload
| Field | Type | Notes |
| --- | --- | --- |
| `id` | UUID string | Stable identifier returned everywhere. |
| `owner` | UUID string \| `null` | The authenticated user ID. |
| `auto_language_detection` | boolean | Whether OCR should auto-detect the dominant language. |
| `language_hint` | string \| `null` | ISO 639 code to force a language when auto-detection is disabled. |
| `output_format` | `raw` \| `paragraph` | Controls whether text stays raw or is grouped into paragraphs. |
| `ocr_mode` | `fast` \| `high_accuracy` | `fast` prioritizes low latency, `high_accuracy` permits longer runs for better quality. |
| `image_url` | string \| `null` | Relative API path (`/api/v1/core/uploads/<id>/image/`) that streams the stored binary. |
| `image_hash` | hex string | SHA256 hash, used for deduplication. |
| `raw_text` | string \| `null` | OCR result before post-processing. |
| `processed_text` | string \| `null` | Cleaned-up text ready for rendering. |
| `created_at` | ISO-8601 string | Creation timestamp (UTC). |
| `updated_at` | ISO-8601 string | Last change (UTC). |

> **Note:** `image_path` is now an internal-only field stored on the backend so the API never leaks local filesystem paths. The database also tracks a `status` (`uploaded`, `processing`, `processed`, `error`) that you can use when filtering uploads, even though it is not exposed in the payloads yet.

Example:

```json
{
  "id": "b63e167b-df1d-45b9-9b80-4cb8b71a045d",
  "owner": "2c2c429f-bf17-4f8e-8da0-7cb7f5a698b0",
  "auto_language_detection": true,
  "language_hint": null,
  "output_format": "raw",
  "ocr_mode": "fast",
  "image_url": "/api/v1/core/uploads/b63e167b-df1d-45b9-9b80-4cb8b71a045d/image/",
  "image_hash": "7a4f14dcc5f7bc...",
  "raw_text": "Invoice #4932 ...",
  "processed_text": "Invoice 4932\nDate: 2024-06-01\n...",
  "created_at": "2024-06-01T21:40:21Z",
  "updated_at": "2024-06-01T21:45:03Z"
}
```

---

## Users API (`/users/`)

### `POST /users/signup/`
- **Auth:** none
- **Body:** `email` (required, valid email), `password` (required, min 8 chars), `first_name`/`last_name` (optional strings)
- **Success:** `201 Created`

```json
{
  "message": "User registered successfully.",
  "access": "<jwt>",
  "refresh": "<jwt>",
  "user": {
    "id": "1c1a...",
    "email": "user@example.com",
    "role": "demo_user",
    "last_ip": null
  }
}
```

### `POST /users/login/`
- **Auth:** none
- **Body:** `email` (or `username`, both map to the stored email), `password`
- **Success:** `200 OK` with the same payload shape as signup.
- **Failure:** `401 Unauthorized` when credentials are invalid.

### `POST /users/refresh/`
- **Auth:** none
- **Body:** `refresh` (string)
- **Success:** `200 OK` `{ "access": "<new access token>" }`
- **Failure:** `401 Unauthorized` with `errors.refresh` when the token is invalid or expired.

### `POST /users/refresh/token/`
- **Auth:** `Bearer` token required (must already be logged in).
- **Body:** none
- **Success:** `200 OK` `{ "message": "New refresh token issued.", "access": "<jwt>", "refresh": "<jwt>" }`
- Useful when the client wants to rotate both tokens without logging in again.

### `POST /users/logout/`
- **Auth:** required
- **Body:** none
- **Success:** `200 OK` `{ "message": "Logout successful." }`
- Backend simply clears the Django session; the frontend must delete stored JWTs.

### `GET /users/user/`
- **Auth:** required
- **Success:** `200 OK` returning the `User` object.

### `PUT /users/profile/edit/`
- **Auth:** required
- **Body:** `first_name`, `last_name` (both optional). Empty payload returns `400`.
- **Success:** `200 OK` `{ "message": "Profile updated successfully.", "user": <User> }`

### `DELETE /users/profile/delete/`
- **Auth:** required
- **Success:** `204 No Content` (server still sends `{ "message": "Account removed successfully." }`, but many HTTP clients drop the body for 204).
- Effects: logs out the user, deletes the account, and removes every upload owned by it.

---

## Core Upload API (`/core/`)

### `GET /core/uploads/`
- **Auth:** required
- **Query parameters:**

| Name | Type | Description |
| --- | --- | --- |
| `status` | string, repeatable or comma-separated | Filter by any of `uploaded`, `processing`, `processed`, `error`. Invalid values are ignored. |
| `image_hash` | string | Exact hash match. |
| `search` | string | Case-insensitive substring match on `raw_text` and `processed_text`. |
| `created_after` | ISO datetime | Return uploads created on/after this timestamp (naive dates are assumed to be in server TZ). |
| `created_before` | ISO datetime | Return uploads created on/before this timestamp. |

- **Response:** `200 OK` array of `Upload` objects ordered newest-first.
- **Notes for frontend:** use pagination client-side; the backend currently returns the full list in a single response.

### `POST /core/uploads/`
- **Auth:** required; the authenticated user becomes the `owner`.
- **Content-Type:** `multipart/form-data` (when sending `image_file`) or JSON (when referencing an existing `image_path`).
- **Request fields:**
  - `image_file` (binary) – optional; the API stores the file, calculates `image_hash`, and exposes it via `image_url`.
  - `image_path` (string) – optional fallback when the file already lives on the backend host (e.g., uploaded via another service). The backend will copy the file into its managed storage before persisting the upload, so the stored record never points to a user-local path.
  - `auto_language_detection` (boolean) – defaults to `true`. Set `false` to supply a manual `language_hint`.
  - `language_hint` (string) – ISO code used when auto detection is disabled.
  - `output_format` (enum) – `raw` (default) or `paragraph`.
  - `ocr_mode` (enum) – `fast` (default) or `high_accuracy`.
  - `token` (string, optional) – API token used solely for rate-limiting and auditing; it does **not** replace JWT auth.
- **Success:**
  - `201 Created` – brand-new upload. Payload is the newly created `Upload` object.
  - `200 OK` – when an upload with the same `image_hash` already exists for the user; the server returns the cached upload without recreating it.
- **Failure cases:** missing file/path (`400`), unreadable file path (`400`), too many uploads (`429`).
- **Cleanup:** when an uploaded file cannot be persisted, the backend deletes any partially written file before returning an error.

### `POST /core/uploads/<str:token>/`
- Same handler as above with the API token in the URL (still requires JWT auth). Prefer this when the token is part of the route configuration; internally it enables per-token throttling and auditing.

### `GET /core/uploads/<uuid:id>/`
- **Auth:** required; only succeeds if the upload belongs to the caller.
- **Response:** `200 OK` single `Upload` object.
- The backend caches serialized payloads by ID and `image_hash`, so repeated fetches are cheap. Each payload now includes an `image_url` for downloading/viewing the binary plus any advanced OCR options chosen at upload time.

### `GET /core/uploads/<uuid:id>/image/`
- **Auth:** required
- **Response:** `200 OK` streamed binary response with the correct `Content-Type` header (PNG, JPEG, etc.).
- **Usage:** use the `image_url` returned on upload objects as the `src` for `<img>` tags or download buttons; it is a relative path, so prepend your API host.
- **Errors:** `404` if the upload is missing or its file is no longer on disk.

### `PUT /core/uploads/<uuid:id>/`
### `PATCH /core/uploads/<uuid:id>/`
- **Auth:** required
- **Body:** any subset of the user-editable fields; most clients only update `raw_text` and/or `processed_text` after manual corrections. Updating the stored binary is not supported yet—upload a new file if the image needs to change. You can, however, revise the OCR preference fields (`auto_language_detection`, `language_hint`, `output_format`, `ocr_mode`) if those hints should change before reprocessing.
- **Response:** `200 OK` updated `Upload` object. Cache entries for that upload are refreshed.

### Unsupported operations
- There is **no** delete endpoint for uploads yet.
- Upload processing status changes are driven entirely on the backend; the frontend updates by polling or by using a future WebSocket channel.

---

## Error codes & handling checklist
- `400 Bad Request` – validation or missing data (inspect `errors`).
- `401 Unauthorized` – login required, invalid credentials, or expired tokens.
- `403 Forbidden` – user lacks permissions (rare because everything is scoped per user).
- `404 Not Found` – trying to access an upload that belongs to another user or does not exist.
- `429 Too Many Requests` – rate limits described above; surface a friendly retry message.
- `500 Internal Server Error` – unexpected failures (log client context to help troubleshoot).

---

## Frontend integration checklist
- Persist both `access` and `refresh` tokens after signup/login; refresh proactively before expiry.
- Attach `Authorization` headers to every `/core/` call and every `/users/` endpoint other than signup/login/refresh.
- Render `raw_text` and `processed_text` for textual previews, and use `image_url` when you need to show the original binary (e.g., as an `<img src>` or download link).
- Wire the advanced options UI (`auto_language_detection`, manual `language_hint`, `output_format`, `ocr_mode`) directly to the POST body so future AI workers can respect those preferences.
- When creating uploads, prefer sending `image_file` via `multipart/form-data`. Only fall back to `image_path` if the image already exists on the backend host.
- Handle duplicate upload responses (`200 OK` from the create endpoint) by updating the UI with the returned upload rather than assuming an error.
- After a `204` from `profile/delete/`, wipe local state and navigate the user back to onboarding; the backend account no longer exists.

---

This document reflects the current backend implementation (June 2024). Any server-side changes should be mirrored here so the frontend can stay in sync.
