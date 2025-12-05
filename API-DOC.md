# API Documentation

## API Base URL

All API endpoints are prefixed with:  
`/api/v1/`

---

## Authentication

Some endpoints require authentication using JWT (access and refresh tokens).  
Obtain tokens using the `/api/v1/users/login/` or `/api/v1/users/signup/` endpoints.

---

## User Endpoints

Base: `/api/v1/users/`

### POST `/signup/`

Register a new user.

**Request:**
- `email` (string, required)
- `password` (string, required, min 8 characters)
- `first_name` (string, optional)
- `last_name` (string, optional)

**Response:**  
- `201 Created`
- Returns user data and access/refresh tokens.

---

### POST `/login/`

Authenticate user and obtain tokens.

**Request:**
- `email` (string, required)
- `password` (string, required)

**Response:**  
- `200 OK`
- Returns access/refresh tokens and user info.

---

### POST `/refresh/`

Refresh your access token.

**Request:**
- `refresh` (string, required) - The refresh token.

**Response:**  
- `200 OK`
- Returns a new access token.

---

### POST `/refresh/token/` (Authenticated)

Issue a brand-new refresh/access token pair for the currently authenticated user (useful if you lose the original refresh token).

**Response:**
- `200 OK`
- Returns `{ "refresh": "...", "access": "..." }`.

---

### POST `/logout/` (Authenticated)

Log out current user.

**Response:**  
- `200 OK`
- Message of successful logout.

---

### GET `/user/` (Authenticated)

Get information about the currently logged in user.

**Response:**  
- `200 OK`
- User profile data.

---

### PUT `/profile/edit/` (Authenticated)

Update user profile (`first_name`, `last_name`).

**Request:**
- `first_name` (string, optional)
- `last_name` (string, optional)

**Response:**  
- `200 OK`
- Updated user info.

---

### DELETE `/profile/delete/` (Authenticated)

Delete your own account.

**Response:**  
- `204 No Content`

---

## Core Upload Endpoints

Base: `/api/v1/core/`

### GET `/uploads/` (Authenticated)

List uploads created by the authenticated user. Optional query parameters:
- `status`: filter by one or more statuses (repeat the parameter or comma-separate values, e.g. `status=processed,processing`).
- `image_hash`: return only the upload that matches a specific hash.
- `search`: case-insensitive substring match across `raw_text` and `processed_text`.
- `created_after` / `created_before`: ISO 8601 timestamps for bounding the creation date range.

**Response:**  
- `200 OK`
- List of upload objects.

---

### POST `/uploads/` (Authenticated)

Upload a new image file by path. The created upload automatically belongs to the authenticated user; other users will never see it.

**Request:**
- `image_path` (string, required if `image_file` not provided): local path to the image file on the server.
- `image_file` (binary, optional): raw uploaded image file. The API will persist it server-side and inject the resulting `image_path` and `image_hash`.
- Optionally: `token` for API token authentication.
  
**Response:**  
- `201 Created` with processed upload object.

---

### POST `/uploads/<str:token>/` (Authenticated or API token)

Alternate: upload with API token in the path.

- Same as the above, but for clients authenticating via API tokens.

---

### GET `/uploads/<uuid:id>/` (Authenticated)

Retrieve a specific upload object by its ID.

**Response:**  
- `200 OK`
- Upload object data.

---

### PUT/PATCH `/uploads/<uuid:id>/` (Authenticated)

Update a specific upload object.

---

## Example Upload Object

```json
{
  "id": "b63e167b-df1d-45b9-9b80-4cb8b71a045d",
  "owner": "2c2c429f-bf17-4f8e-8da0-7cb7f5a698b0",
  "image_path": "/tmp/myimg.png",
  "image_hash": "7a4f14d...",
  "raw_text": "...",
  "processed_text": "...",
  "created_at": "2024-06-01T21:40:21Z",
  "updated_at": "2024-06-01T21:40:21Z"
}
```

---

## Notes

- Some rate limiting is enforced for uploads: per user (demo: max 5), per IP, and per API token.
- Most endpoints require an `Authorization: Bearer <access_token>` header unless using an API token.
- For authentication, use JWT tokens obtained at signup or login.
- Uploads are scoped to the authenticated user; listing or retrieving by ID will only ever return your own files.

---
