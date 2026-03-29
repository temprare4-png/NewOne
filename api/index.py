from flask import Flask, request, jsonify

app = Flask(__name__)

DELIM = "*****"

def preparing_key_array(s):
    return [ord(c) for c in s]

def KSA(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S, n):
    i = j = 0
    key = []
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        key.append(K)
    return key

def encryption(plaintext, key_text):
    key = preparing_key_array(key_text)
    S = KSA(key)
    keystream = PRGA(S, len(plaintext))
    return ''.join(chr(ord(p) ^ k) for p, k in zip(plaintext, keystream))

def decryption(ciphertext, key_text):
    return encryption(ciphertext, key_text)

@app.route("/")
def home():
    return jsonify({
        "message": "Python app is running on Vercel",
        "routes": ["/encrypt", "/decrypt"]
    })

@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    data = request.get_json(force=True)
    text = data.get("text", "")
    key = data.get("key", "")
    if not text or not key:
        return jsonify({"error": "text and key are required"}), 400
    return jsonify({"ciphertext": encryption(text, key)})

@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    data = request.get_json(force=True)
    text = data.get("text", "")
    key = data.get("key", "")
    if not text or not key:
        return jsonify({"error": "text and key are required"}), 400
    return jsonify({"plaintext": decryption(text, key)})

handler = app
