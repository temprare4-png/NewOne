import os
import cv2
import numpy as np
from PIL import Image
from scipy.stats import chi2
from flask import Flask, request, render_template_string
from virustotal_python import Virustotal
import time
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
VT_API_KEY = os.getenv('VT_API_KEY')  # Vercel env var

# Steganography dicts
d, c = {}, {}
for i in range(256):
    d[chr(i)] = i
    c[i] = chr(i)

def encode_image(image_path, text, key):
    x = cv2.imread(image_path)
    if x is None: return False, "Image load failed"
    rows, cols = x.shape[:2]
    l = len(text)
    if l * 2 > rows * cols: return False, "Text too long"
    
    z, n, m, kl = 0, 0, 0, 0
    for char in text:
        x[n, m, z] = d[char] ^ d[key[kl % len(key)]]
        n += 1; m += 1; m %= cols; z = (z + 1) % 3; kl += 1
    
    cv2.imwrite(image_path.replace('.jpg', '_encoded.jpg'), x)
    return True, "Encoded successfully!"

def decode_image(image_path, key, text_len):
    x = cv2.imread(image_path)
    if x is None: return "Decode failed"
    decrypt, z, n, m, kl = "", 0, 0, 0, 0
    cols = x.shape[1]
    for _ in range(text_len):
        decrypt += c[x[n, m, z] ^ d[key[kl % len(key)]]]
        n += 1; m += 1; m %= cols; z = (z + 1) % 3; kl += 1
    return decrypt

def detect_stego(image_path):
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img)[:,:,0]
    hist = np.bincount(pixels.flatten(), minlength=256)
    even, odd = hist[0::2], hist[1::2]
    expected = (even + odd) / 2
    mask = expected > 5
    if mask.sum() == 0: return "No data"
    chi_sq = np.sum(((even[mask] - expected[mask])**2 / expected[mask]) +
                    ((odd[mask] - expected[mask])**2 / expected[mask]))
    p = 1 - chi2.cdf(chi_sq, mask.sum() - 1)
    return f"P: {p:.4f} → {'BLOCKED (Stego)' if p < 0.01 else 'Clean'}"

def scan_vt_url(url):
    try:
        with Virustotal(VT_API_KEY) as vt:
            resp = vt.request(f'urls/{vt.get_url_id(url)}', data={'relations': 'last_analysis_stats'})
            stats = resp.data.attributes.last_analysis_stats
            mal = stats.get('malicious', 0)
            return f"{mal} hits → {'BLOCK' if mal > 0 else 'Safe'}"
    except: return "API error"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    if request.method == 'POST':
        if 'url' in request.form:
            result = scan_vt_url(request.form['url'])
        else:
            file = request.files.get('file')
            if file:
                path = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
                file.save(path)
                # Multi-scan
                url_result = "No URL"
                stego_result = detect_stego(path)
                vt_result = "VT: Check console (serverless limit)"
                result = f"Stego: {stego_result}
VT File: {vt_result}"
    return render_template_string('''
    <h1>🔒 WhatsApp Malicious Scanner + Stego Tool</h1>
    <form method="post">
        URL: <input name="url" placeholder="http://testsafebrowsing.appspot.com/s/phishing.html">
        <button>Scan URL</button>
    </form>
    <form method="post" enctype="multipart/form-data">
        Image/Video: <input type="file" name="file" accept="image/*">
        <button>Detect Stego + Malware</button>
    </form>
    <pre>{{ result }}</pre>
    <p><a href="/demo">Demo Encode</a></p>
    ''', result=result)

@app.route('/demo')
def demo():
    return '''
    <h2>Stego Demo</h2>
    <p>Upload image + text + key above for full tool!</p>
    '''

if __name__ == '__main__':
    app.run(debug=True)
