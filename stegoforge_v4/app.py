from flask import (Flask, render_template, request, jsonify,
                   session, redirect, url_for, Response)
from PIL import Image
from PIL.ExifTags import TAGS
import io, base64, hashlib, os, json, time, struct, zipfile
from functools import wraps
from utils.encoder import encode_message
from utils.decoder import decode_message
from utils.ecdh import (generate_keypair, derive_shared_secret,
                        get_fingerprint)

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024

# ── LOGIN CONFIG ─────────────────────────────────────────────
# Change these credentials before deploying
VALID_USERS = {
    'agent': hashlib.sha256(b'stegoforge2024').hexdigest(),
    'admin': hashlib.sha256(b'admin@secure123').hexdigest(),
}
MAX_LOGIN_ATTEMPTS = 5
login_attempts: dict = {}   # {ip: [timestamp, count]}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if request.is_json:
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── AUTH ROUTES ───────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        ip = request.remote_addr
        now = time.time()
        rec = login_attempts.get(ip, [0, 0])
        if rec[1] >= MAX_LOGIN_ATTEMPTS and now - rec[0] < 300:
            return render_template('login.html', error='Too many attempts. Wait 5 minutes.')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        if VALID_USERS.get(username) == pwd_hash:
            session['logged_in'] = True
            session['username'] = username
            session['login_time'] = now
            login_attempts.pop(ip, None)
            return redirect(url_for('index'))
        else:
            login_attempts[ip] = [now, rec[1] + 1]
            remaining = MAX_LOGIN_ATTEMPTS - login_attempts[ip][1]
            error = f'Invalid credentials. {remaining} attempts remaining.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ── MAIN APP ───────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('username','agent'))

# ── ECDH ──────────────────────────────────────────────────────
@app.route('/ecdh/generate', methods=['POST'])
@login_required
def ecdh_generate():
    try:
        kp = generate_keypair()
        return jsonify({'success': True, 'private_pem': kp['private_pem'],
                        'public_pem': kp['public_pem'],
                        'fingerprint': get_fingerprint(kp['public_pem'])})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ecdh/shared-secret', methods=['POST'])
@login_required
def ecdh_shared():
    try:
        d = request.get_json()
        secret = derive_shared_secret(d['my_private_pem'], d['their_public_pem'])
        fp = get_fingerprint(d['their_public_pem'])
        return jsonify({'success': True, 'shared_secret_hex': secret, 'their_fingerprint': fp})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ecdh/fingerprint', methods=['POST'])
@login_required
def ecdh_fingerprint():
    try:
        f = request.files.get('public_key')
        pem = f.read().decode()
        return jsonify({'success': True, 'fingerprint': get_fingerprint(pem), 'public_pem': pem})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ── ENCODE ────────────────────────────────────────────────────
@app.route('/encode', methods=['POST'])
@login_required
def encode():
    try:
        file          = request.files.get('image')
        message       = request.form.get('message', '').strip()
        password      = request.form.get('password', '')
        decoy_pwd     = request.form.get('decoy_password', '')
        decoy_msg     = request.form.get('decoy_message', '')
        expiry_hours  = int(request.form.get('expiry_hours', 0))
        max_attempts  = int(request.form.get('max_attempts', 0))
        aes_bits      = int(request.form.get('aes_bits', 256))
        scrub_exif    = request.form.get('scrub_exif', 'false') == 'true'
        double_enc    = request.form.get('double_encrypt', 'false') == 'true'

        if not file or not message or not password:
            return jsonify({'error': 'Image, message and password required'}), 400

        img_bytes = file.read()
        result, info = encode_message(
            img_bytes, message, password,
            decoy_password=decoy_pwd, decoy_message=decoy_msg,
            expiry_hours=expiry_hours, max_attempts=max_attempts,
            aes_bits=aes_bits, double_encrypt=double_enc, scrub_exif=scrub_exif
        )
        return jsonify({'success': True, 'image': base64.b64encode(result).decode(), 'info': info})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── DECODE ────────────────────────────────────────────────────
@app.route('/decode', methods=['POST'])
@login_required
def decode():
    try:
        file     = request.files.get('image')
        password = request.form.get('password', '')
        if not file or not password:
            return jsonify({'error': 'Image and password required'}), 400
        result = decode_message(file.read(), password)
        return jsonify({'success': True, **result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── HISTOGRAM ─────────────────────────────────────────────────
@app.route('/histogram', methods=['POST'])
@login_required
def histogram():
    try:
        img    = Image.open(request.files.get('image').stream).convert('RGB')
        pixels = list(img.getdata())
        r0=r1=g0=g1=b0=b1=0
        for r,g,b in pixels:
            if r&1:r1+=1
            else:r0+=1
            if g&1:g1+=1
            else:g0+=1
            if b&1:b1+=1
            else:b0+=1
        t=len(pixels)
        return jsonify({'r':[round(r0/t*100,2),round(r1/t*100,2)],
                        'g':[round(g0/t*100,2),round(g1/t*100,2)],
                        'b':[round(b0/t*100,2),round(b1/t*100,2)],
                        'pixels':t,'width':img.width,'height':img.height})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── PIXEL INSPECT ─────────────────────────────────────────────
@app.route('/inspect-pixel', methods=['POST'])
@login_required
def inspect_pixel():
    try:
        file = request.files.get('image')
        x    = int(request.form.get('x', 0))
        y    = int(request.form.get('y', 0))
        img  = Image.open(file.stream).convert('RGB')
        if x >= img.width or y >= img.height:
            return jsonify({'error': 'Coordinates out of bounds'}), 400
        r, g, b = img.getpixel((x, y))
        return jsonify({
            'x': x, 'y': y,
            'r': r, 'g': g, 'b': b,
            'r_bin': format(r,'08b'), 'g_bin': format(g,'08b'), 'b_bin': format(b,'08b'),
            'r_lsb': r & 1, 'g_lsb': g & 1, 'b_lsb': b & 1,
            'hex': f'#{r:02x}{g:02x}{b:02x}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── EXIF SCRUB ────────────────────────────────────────────────
@app.route('/scrub-exif', methods=['POST'])
@login_required
def scrub_exif():
    try:
        file = request.files.get('image')
        img  = Image.open(file.stream)
        # Get original EXIF tags
        exif_data = {}
        if hasattr(img, '_getexif') and img._getexif():
            for tag_id, val in img._getexif().items():
                tag = TAGS.get(tag_id, tag_id)
                exif_data[str(tag)] = str(val)[:100]
        # Strip and save clean
        clean = Image.new(img.mode, img.size)
        clean.putdata(list(img.getdata()))
        out = io.BytesIO()
        clean.save(out, format='PNG')
        b64 = base64.b64encode(out.getvalue()).decode()
        return jsonify({'success': True, 'image': b64,
                        'removed_tags': list(exif_data.keys()),
                        'tag_count': len(exif_data)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── ATTACK SIMULATION ─────────────────────────────────────────
@app.route('/attack-sim', methods=['POST'])
@login_required
def attack_sim():
    try:
        file     = request.files.get('image')
        password = request.form.get('password', '')
        attack   = request.form.get('attack', 'jpeg')  # jpeg | crop | noise | resize

        img_bytes = file.read()
        img       = Image.open(io.BytesIO(img_bytes)).convert('RGB')

        if attack == 'jpeg':
            out = io.BytesIO()
            img.save(out, format='JPEG', quality=75)
            attacked = out.getvalue()
            label = 'JPEG Compression (quality=75)'
        elif attack == 'crop':
            w, h  = img.width, img.height
            box   = (w//8, h//8, w - w//8, h - h//8)
            cropped = img.crop(box)
            out = io.BytesIO(); cropped.save(out, format='PNG')
            attacked = out.getvalue()
            label = 'Center Crop (87.5% of original)'
        elif attack == 'noise':
            import random
            pixels = list(img.getdata())
            noisy  = [(min(255,r+random.randint(-5,5)),
                       min(255,g+random.randint(-5,5)),
                       min(255,b+random.randint(-5,5))) for r,g,b in pixels]
            img.putdata(noisy)
            out = io.BytesIO(); img.save(out, format='PNG')
            attacked = out.getvalue()
            label = 'Random Noise (+-5 per channel)'
        elif attack == 'resize':
            small = img.resize((img.width//2, img.height//2), Image.LANCZOS)
            back  = small.resize((img.width, img.height), Image.LANCZOS)
            out = io.BytesIO(); back.save(out, format='PNG')
            attacked = out.getvalue()
            label = 'Resize Attack (50% down, back up)'
        else:
            return jsonify({'error': 'Unknown attack'}), 400

        # Try to decode
        survived = False
        msg = ''
        if password:
            try:
                result   = decode_message(attacked, password)
                survived = True
                msg      = result['message'][:60] + ('...' if len(result['message']) > 60 else '')
            except Exception:
                survived = False

        attacked_b64 = base64.b64encode(attacked).decode()
        return jsonify({
            'success': True,
            'attack_label': label,
            'survived': survived,
            'preview_message': msg,
            'attacked_image': attacked_b64
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── AI SUGGESTION ─────────────────────────────────────────────
@app.route('/ai-suggest', methods=['POST'])
@login_required
def ai_suggest():
    try:
        file = request.files.get('image')
        msg_len = int(request.form.get('msg_len', 0))
        img = Image.open(file.stream).convert('RGB')
        total_bits = img.width * img.height * 3
        max_chars  = (total_bits // 8) - 45
        used_pct   = (msg_len / max_chars * 100) if max_chars > 0 else 0
        # Analyse image complexity (higher variance = better cover)
        import statistics
        sample = [r for r,g,b in list(img.getdata())[:2000]]
        variance = statistics.variance(sample) if len(sample) > 1 else 0
        complexity = min(100, variance / 20)
        suggestions = []
        if used_pct > 80:
            suggestions.append('Message is too large (>80% capacity). Use a bigger image.')
        if complexity < 30:
            suggestions.append('Image is too uniform (low complexity). Prefer natural/textured photos.')
        if img.width * img.height < 200000:
            suggestions.append('Image resolution is low. Use at least 500x400 for safety.')
        if not suggestions:
            suggestions.append('Image is well-suited for steganography.')
            suggestions.append(f'Optimal usage: keep message below {int(max_chars * 0.6)} chars for safety.')
        return jsonify({
            'success': True,
            'max_chars': max_chars,
            'used_pct': round(used_pct, 1),
            'complexity_score': round(complexity, 1),
            'suggestions': suggestions
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001, use_reloader=False)
