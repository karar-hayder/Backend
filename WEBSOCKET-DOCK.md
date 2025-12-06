# Upload WebSocket API Reference  

**Live File Status & OCR Streaming for Django Channels**

> **Main entry:** [`backend_main/backend/asgi.py`](backend_main/backend/asgi.py)  
> **WebSocket Consumer:** [`backend_main/core/consumers.py`](backend_main/core/consumers.py)  
> **OCR Stream/Task:** [`backend_main/core/tasks.py`](backend_main/core/tasks.py)

---

## 📡 WebSocket Endpoints

Connect via:

```
ws://<server>/ws/core/upload/
ws://<server>/ws/core/upload/<uuid:instance_id>/
```

- `/ws/core/upload/` — subscribe for all your uploads, live.
- `/ws/core/upload/<id>/` — get live updates for a single upload.

**Authentication:**  

- Required.  
- Use JWT token as query param: `?token=<jwt_here>`  
- Only authenticated users can connect.

---

## 📑 Message Patterns & Commands

**All requests and responses are JSON. Every message includes a `"type"` string.**

### 1️⃣ Subscribe

_Request (client):_

```json
{ "type": "subscribe" }
```

_Response:_

```json
{
  "message": "subscribed",
  "model": "Upload",
  "instance_id": null
}
```

---

### 2️⃣ Create Upload

**Send either:**  

- `image_base64`,  
- or `image_path`,  
- or `image_hash`

_Request:_

```json
{
  "type": "create",
  "data": {
    "image_base64": "<base64-string>",
    "image_path": "/srv/uploads/optional.jpg",
    "image_hash": "optional-sha256"
  }
}
```

_Success:_

```json
{
  "type": "Upload.created",
  "instance": {
    "id": "...",
    "image_path": "...",
    "owner": "...",
    "status": "pending"
  },
  "duplicate": false
}
```

_Duplicate upload (by hash):_

```json
{
  "type": "Upload.created",
  "instance": { ... },
  "duplicate": true
}
```

_Error:_

```json
{
  "type": "Upload.created",
  "error": {
    "image_base64": "Invalid base64 encoding: ..."
  }
}
```

---

### 3️⃣ List Uploads

_Request:_

```json
{ "type": "list" }
```

_Response:_

```json
{
  "type": "Upload.list",
  "list": [ { /* Upload instance */ }, ... ]
}
```

---

### 4️⃣ Retrieve / Status

_Request (fetch by id):_

```json
{
  "type": "retrieve",
  "instance_id": "<upload-id>"
}
```

_Response:_

```json
{
  "type": "Upload.status",
  "instance": { /* status and metadata */ }
}
```

---

### 5️⃣ Update / Delete

_Update:_

```json
{
  "type": "update",
  "instance_id": "<id>",
  "data": { /* fields */ }
}
```

_Delete:_

```json
{
  "type": "delete",
  "instance_id": "<id>"
}
```

---

## 🔄 Live Status Events

All actions related to your uploads are broadcasted—**including creates, updates, deletes, and OCR status**:

```json
{
  "type": "Upload.created" | "Upload.updated" | "Upload.deleted" | "Upload.status",
  "instance": { /* latest upload state */ }
}
```

---

## 🧠 Live OCR Streaming

When OCR is triggered, the API streams status and text as events:

_Partial OCR (while processing):_

```json
{
  "id": "<upload-id>",
  "status": "processing",
  "streamed_text": "<streamed-markdown-so-far>",
  "type": "Upload.status"
}
```

_Finished OCR:_

```json
{
  "id": "<upload-id>",
  "status": "processed",
  "raw_text": "<whole-markdown>",
  "processed_text": "<optional-parsed>",
  "type": "Upload.status"
}
```

_Error:_

```json
{
  "id": "<upload-id>",
  "status": "error",
  "type": "Upload.status",
  "error": "Description of the issue"
}
```

- See [`backend_main/core/tasks.py`](backend_main/core/tasks.py) for backend details.

---

## 💡 Notes & Best Practices

- All file, OCR, and status changes are realtime and user-scoped.
- Duplicate detection (by hash + user) is enforced: see responses.
- Unlimited-sized base64 is supported (may impact latency).
- All `"instance"` fields follow your Upload model/serializer.
- All errors include the `"type"` field for easy handling.

---

## 🚦 Example: End-to-End Flow

1. **Connect** (JWT as query param).
2. **Send**:

    ```json
    { "type": "create", "data": { "image_base64": "<...>" } }
    ```

3. **Receive:**
    - `Upload.created` (with your instance)
    - Streaming `Upload.status` (with `"processing"` & `streamed_text`)
    - Final `Upload.status` (with OCR result and status `"processed"`)
4. **Listen for more events:** Any change to any of your uploads is pushed in real-time.

---

**See code in [`backend_main/backend/asgi.py`](backend_main/backend/asgi.py), [`core/consumers.py`](backend_main/core/consumers.py), and [`core/tasks.py`](backend_main/core/tasks.py) for API and group routing details.**

_If you need exact WebSocket host or JWT signing info, ask your backend team!_
