import os
import uuid
import json
from pathlib import Path
from hashlib import sha256
from flask import Flask, request, render_template, redirect, url_for, send_file, abort, jsonify, Response
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- CONFIG ---
BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "encrypted_files"
META_DIR = BASE_DIR / "metadata"
UPLOAD_DIR.mkdir(exist_ok=True)
META_DIR.mkdir(exist_ok=True)

# Use MASTER_KEY from env; must be 32 bytes for AES-256.
MASTER_KEY = os.environ.get("MASTER_KEY")
if not MASTER_KEY:
    # DEVELOPMENT fallback (do NOT use in production).
    print("WARNING: MASTER_KEY not set. Using a temporary key for development.")
    MASTER_KEY = get_random_bytes(32)
else:
    # if provided as hex or base64, adapt as needed; here we assume raw bytes length check
    if isinstance(MASTER_KEY, str):
        # try interpret as hex
        try:
            MASTER_KEY = bytes.fromhex(MASTER_KEY)
        except Exception:
            MASTER_KEY = MASTER_KEY.encode('utf-8')  # fallback (not ideal)

if len(MASTER_KEY) not in (16, 24, 32):
    raise RuntimeError("MASTER_KEY must be 16, 24, or 32 bytes (AES-128/192/256)")

# Flask config
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB max request (adjust as needed)
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "csv", "zip", "docx"}

def allowed_file(filename: str) -> bool:
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def save_metadata(file_id: str, meta: dict):
    meta_path = META_DIR / f"{file_id}.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f)

def load_metadata(file_id: str) -> dict:
    meta_path = META_DIR / f"{file_id}.json"
    if not meta_path.exists():
        return None
    with open(meta_path, "r") as f:
        return json.load(f)

# --- Encryption helpers (AES-GCM streaming) ---
CHUNK_SIZE = 64 * 1024

def encrypt_stream_and_save(file_stream, out_path: Path):
    """
    Encrypts incoming file_stream with AES-GCM and writes ciphertext to out_path.
    Returns (nonce_hex, tag_hex, size_ciphertext)
    """
    cipher = AES.new(MASTER_KEY, AES.MODE_GCM)
    nonce = cipher.nonce  # random nonce
    total = 0
    with open(out_path, "wb") as fout:
        while True:
            chunk = file_stream.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = cipher.encrypt(chunk)
            fout.write(ct)
            total += len(ct)
    tag = cipher.digest()
    return nonce.hex(), tag.hex(), total

def decrypt_stream_and_iter(in_path: Path, nonce_hex: str, tag_hex: str):
    """
    Generator: yields plaintext chunks after decrypting ciphertext in chunks.
    Raises ValueError if verification fails.
    """
    nonce = bytes.fromhex(nonce_hex)
    tag = bytes.fromhex(tag_hex)
    cipher = AES.new(MASTER_KEY, AES.MODE_GCM, nonce=nonce)
    with open(in_path, "rb") as fin:
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            pt = cipher.decrypt(chunk)
            yield pt
    # verify tag at end
    try:
        cipher.verify(tag)
    except ValueError as e:
        raise ValueError("Tag verification failed; file may be tampered") from e

# --- Routes ---
@app.route("/", methods=["GET"])
def index():
    # list files
    files = []
    for meta_file in META_DIR.glob("*.json"):
        meta = json.load(open(meta_file))
        fid = meta_file.stem
        files.append({
            "id": fid,
            "original_name": meta.get("original_name"),
            "size_encrypted": meta.get("size_encrypted"),
            "uploaded_at": meta.get("uploaded_at")
        })
    return render_template("index.html", files=files)

@app.route("/upload", methods=["POST"])
def upload():
    if 'file' not in request.files:
        return "no file", 400
    file = request.files['file']
    if file.filename == "":
        return "empty filename", 400
    if not allowed_file(file.filename):
        return "file type not allowed", 400

    original_name = secure_filename(file.filename)
    file_id = uuid.uuid4().hex
    stored_filename = f"{file_id}.bin"
    out_path = UPLOAD_DIR / stored_filename

    nonce_hex, tag_hex, size_ciphertext = encrypt_stream_and_save(file.stream, out_path)

    # metadata
    meta = {
        "id": file_id,
        "stored_filename": stored_filename,
        "original_name": original_name,
        "nonce": nonce_hex,
        "tag": tag_hex,
        "content_type": file.content_type,
        "size_encrypted": size_ciphertext,
        "uploaded_at": __import__("datetime").datetime.utcnow().isoformat() + "Z"
    }
    save_metadata(file_id, meta)
    return redirect(url_for("index"))

@app.route("/download/<file_id>", methods=["GET"])
def download(file_id):
    meta = load_metadata(file_id)
    if not meta:
        abort(404)
    stored_path = UPLOAD_DIR / meta["stored_filename"]
    if not stored_path.exists():
        abort(404)

    # Stream decrypted data
    def generate():
        try:
            for chunk in decrypt_stream_and_iter(stored_path, meta["nonce"], meta["tag"]):
                yield chunk
        except Exception:
            # In case of tag verification failure or decryption error
            abort(500)

    headers = {
        "Content-Disposition": f'attachment; filename="{meta["original_name"]}"',
        "X-Content-Type-Options": "nosniff"
    }
    # Use Response streaming with correct content-type (or force octet-stream)
    return Response(generate(), mimetype=meta.get("content_type") or "application/octet-stream", headers=headers)

@app.route("/info/<file_id>", methods=["GET"])
def info(file_id):
    meta = load_metadata(file_id)
    if not meta:
        return jsonify({"error":"not found"}), 404
    # Do not return sensitive key material
    sanitized = {k: v for k, v in meta.items() if k not in ("tag", "nonce")}
    return jsonify(sanitized)

if __name__ == "__main__":
    app.run(debug=True)

