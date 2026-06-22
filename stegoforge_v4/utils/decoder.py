from PIL import Image
import io, struct, hashlib, random, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type

SALT_SIZE     = 16
NONCE_SIZE    = 12
HEADER_MAGIC  = b'STGF'
HEADER_BYTES  = 46
HEADER_PIXELS = (HEADER_BYTES * 8 + 2) // 3   # = 123

_attempt_store: dict = {}

def derive_key(password: str, salt: bytes, key_len: int = 32) -> bytes:
    return hash_secret_raw(
        password.encode('utf-8'), salt,
        time_cost=2, memory_cost=65536, parallelism=2,
        hash_len=key_len, type=Type.ID
    )

def bits_to_bytes(bits: list) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(''.join(str(b) for b in bits[i:i+8]), 2))
    return bytes(out)

def _fp(pixels):
    sample = bytes([ch for px in pixels[:200] for ch in px])
    return hashlib.sha256(sample).hexdigest()

def decode_message(img_bytes: bytes, password: str) -> dict:
    img    = Image.open(io.BytesIO(img_bytes)).convert('RGB')
    pixels = list(img.getdata())
    total  = len(pixels)

    # Extract header from first 123 pixels (sequential)
    hbits = []
    for i in range(HEADER_PIXELS):
        r, g, b = pixels[i]
        hbits += [r & 1, g & 1, b & 1]

    hbytes = bits_to_bytes(hbits[:HEADER_BYTES * 8])

    if hbytes[:4] != HEADER_MAGIC:
        raise ValueError(
            'No hidden message found. Use the PNG output from the Encode operation, '
            'not the original image.'
        )

    salt      = hbytes[4:20]
    nonce     = hbytes[20:32]
    ct_len    = struct.unpack('>I', hbytes[32:36])[0]
    expiry_ts = struct.unpack('>Q', hbytes[36:44])[0]
    max_att   = struct.unpack('>B', hbytes[44:45])[0]
    flags     = struct.unpack('>B', hbytes[45:46])[0]

    double_enc = bool(flags & 1)
    aes_128    = bool(flags & 2)
    key_len    = 16 if aes_128 else 32

    if expiry_ts > 0 and time.time() > expiry_ts:
        raise ValueError('This message has expired and can no longer be decoded.')

    img_fp = _fp(pixels)
    if max_att > 0:
        attempts = _attempt_store.get(img_fp, 0)
        if attempts >= max_att:
            raise ValueError(f'Maximum decode attempts ({max_att}) reached. Message self-destructed.')
        _attempt_store[img_fp] = attempts + 1

    key  = derive_key(password, salt, key_len)
    seed = int.from_bytes(hashlib.sha256(key).digest()[:8], 'big')
    rng  = random.Random(seed)
    pool = list(range(HEADER_PIXELS, total))
    rng.shuffle(pool)

    needed  = (ct_len + 300) * 8
    ct_bits = []
    for px_idx in pool:
        if len(ct_bits) >= needed: break
        r, g, b = pixels[px_idx]
        ct_bits += [r & 1, g & 1, b & 1]

    payload    = bits_to_bytes(ct_bits)
    ciphertext = payload[:ct_len]
    remainder  = payload[ct_len:]

    # --- Attempt decryption ---
    try:
        if double_enc:
            # FIX: parse the wrapper WITHOUT decrypting with first key.
            # Layout of ciphertext when double_enc=True:
            #   salt2(16) + nonce2(12) + d_len(4) + outer_ct
            # where outer_ct = AESGCM(key2).encrypt(nonce2, inner_ct, None)
            # and   inner_ct = AESGCM(key).encrypt(nonce, message, None)
            if len(ciphertext) < 32:
                raise InvalidTag
            d_salt   = ciphertext[:16]
            d_nonce  = ciphertext[16:28]
            d_len    = struct.unpack('>I', ciphertext[28:32])[0]
            outer_ct = ciphertext[32:]          # still encrypted, includes GCM tag
            key2     = derive_key(password + '_layer2', d_salt, key_len)
            inner_ct = AESGCM(key2).decrypt(d_nonce, outer_ct, None)  # decrypt outer
            plaintext = AESGCM(key).decrypt(nonce, inner_ct, None)    # decrypt inner
        else:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)

        if img_fp in _attempt_store and max_att > 0:
            _attempt_store[img_fp] = 0
        left = (max_att - _attempt_store.get(img_fp, 0)) if max_att > 0 else -1
        return {'message': plaintext.decode('utf-8'), 'is_decoy': False,
                'expiry_ts': expiry_ts, 'max_attempts': max_att, 'attempts_left': left}

    except Exception:
        pass

    # --- Try decoy password ---
    try:
        if len(remainder) >= 36:
            d_salt  = remainder[:16]
            d_nonce = remainder[16:28]
            d_len   = struct.unpack('>I', remainder[28:32])[0]
            d_ct    = remainder[32:32 + d_len]
            if len(d_ct) == d_len and d_len > 0:
                d_key   = derive_key(password, d_salt, key_len)
                d_plain = AESGCM(d_key).decrypt(d_nonce, d_ct, None)
                return {'message': d_plain.decode('utf-8'), 'is_decoy': True,
                        'expiry_ts': 0, 'max_attempts': 0, 'attempts_left': -1}
    except Exception:
        pass

    # --- Both failed ---
    att_used = _attempt_store.get(img_fp, 0)
    left     = max_att - att_used if max_att > 0 else -1
    att_note = f' ({left} attempts remaining)' if left >= 0 else ''
    raise ValueError(
        f'Wrong password or image has been tampered with.{att_note} '
        'Causes: wrong password / image re-saved as JPEG / image edited after encoding.'
    )