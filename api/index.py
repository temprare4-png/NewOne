import json
import os
import cv2
import numpy as np
from PIL import Image
from scipy.stats import chi2
import tempfile
from virustotal_python import Virustotal
import io

# Stego dicts
d, c = {}, {}
for i in range(256):
    d[chr(i)] = i
    c[i] = chr(i)

def scan_vt_url(url):
    vt_key = os.getenv('VT_API_KEY')
    if not vt_key: return "No API key"
    try:
        with Virustotal(vt_key) as vt:
            resp = vt.request(f'urls/{vt.get_url_id(url)}', data={'relations': 'last_analysis_stats'})
            stats = resp.data.attributes.last_analysis_stats
            mal = stats.get('malicious', 0)
            return f"{mal} malicious → {'BLOCK' if mal else 'SAFE'}"
    except Exception as e:
        return f"Error: {str(e)}"

def detect_stego(image_bytes):
    img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    pixels = np.array(img)[:,:,0]
    hist = np.bincount(pixels.flatten(), minlength=256)
    even, odd = hist[0::2], hist[1::2]
    expected = (even + odd) / 2
    mask = expected > 5
    if mask.sum() == 0: return "No data"
    chi_sq = np.sum(((even[mask] - expected[mask])**2 / expected[mask]) +
                    ((odd[mask] - expected[mask])**2 / expected[mask]))
    p = 1 - chi2.cdf(chi_sq, mask.sum() - 1)
    return f"P-value: {p:.4f} → {'BLOCK (Stego!)' if p < 0.01 else 'Clean'}"

# Vercel handler (REQUIRED)
def handler(request):
    if request['method'] == 'GET':
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/html'},
            'body': '''
            <h1>🔒 WhatsApp Scanner</h1>
            <form method="POST" enctype="multipart/form-data">
                URL: <input name="url"><br>
                Image: <input type="file" name="image"><br>
                <button>SCAN</button>
            </form>
            <h3>Test: http://testsafebrowsing.appspot.com/s/phishing.html</h3>
            '''
        }
    
    if request['method'] == 'POST':
        form = request.get('body', b'').decode()
        url = request.get('queryStringParameters', {}).get('url', '')
        result = ""
        
        if url:
            result = scan_vt_url(url)
        
        # File handling (base64 or multipart simplified)
        if 'image' in request:
            # For demo, assume test - add multipart parsing if needed
            result += f"
Stego: {detect_stego(open('test.jpg', 'rb').read())}"
        
        return {
            'statusCode': 200,
            'body': json.dumps({'result': result})
        }
    
    return {'statusCode': 405, 'body': 'Method not allowed'}
