
from flask import Flask, render_template, request, jsonify
import hashlib
import hmac

app = Flask(__name__)

# Daftar algoritma hashing
ALGORITHMS = {
    "md5": {
        "name": "MD5",
        "bits": 128,
        "description": "Message Digest 5"
    },
    "sha1": {
        "name": "SHA-1",
        "bits": 160,
        "description": "Secure Hash Algorithm 1"
    },
    "sha224": {
        "name": "SHA-224",
        "bits": 224,
        "description": "Secure Hash Algorithm 2"
    },
    "sha256": {
        "name": "SHA-256",
        "bits": 256,
        "description": "Secure Hash Algorithm 2"
    },
    "sha384": {
        "name": "SHA-384",
        "bits": 384,
        "description": "Secure Hash Algorithm 2"
    },
    "sha512": {
        "name": "SHA-512",
        "bits": 512,
        "description": "Secure Hash Algorithm 2"
    },
    "sha3_224": {
        "name": "SHA3-224",
        "bits": 224,
        "description": "Secure Hash Algorithm 3"
    },
    "sha3_256": {
        "name": "SHA3-256",
        "bits": 256,
        "description": "Secure Hash Algorithm 3"
    },
    "sha3_384": {
        "name": "SHA3-384",
        "bits": 384,
        "description": "Secure Hash Algorithm 3"
    },
    "sha3_512": {
        "name": "SHA3-512",
        "bits": 512,
        "description": "Secure Hash Algorithm 3"
    }
}


# Halaman utama
@app.route("/")
def index():
    return render_template("index.html")


# API untuk hashing dan verifikasi
@app.route("/api/hash", methods=["POST"])
def generate_hash():
    data = request.get_json(silent=True) or {}

    text = data.get("text", "")
    algorithm = data.get("algorithm", "sha256")
    action = data.get("action", "generate")
    expected_hash = data.get("expected_hash", "")

    if not isinstance(text, str) or not text.strip():
        return jsonify({
            "error": "Teks tidak boleh kosong!"
        }), 400

    if algorithm not in ALGORITHMS:
        return jsonify({
            "error": "Algoritma tidak tersedia!"
        }), 400

    if action not in ("generate", "verify"):
        return jsonify({
            "error": "Aksi tidak valid!"
        }), 400

    if action == "verify":
        if not isinstance(expected_hash, str) or not expected_hash.strip():
            return jsonify({
                "error": "Masukkan hash pembanding!"
            }), 400

    # Proses hashing
    result = hashlib.new(
        algorithm,
        text.encode("utf-8")
    ).hexdigest()

    response = {
        "algorithm": ALGORITHMS[algorithm]["name"],
        "bits": ALGORITHMS[algorithm]["bits"],
        "description": ALGORITHMS[algorithm]["description"],
        "hash": result
    }

    # Proses verifikasi
    if action == "verify":
        response["match"] = hmac.compare_digest(
            result,
            expected_hash.strip().lower()
        )

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True)
    
app = app 
