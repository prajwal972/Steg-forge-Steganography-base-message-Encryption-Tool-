from PIL import Image
import io, os, random, struct, hashlib, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

SALT_SIZE     = 16
NONCE_SIZE    = 12
HEADER_MAGIC  = b'STGF'
HEADER_BYTES  = 46   # MAGIC(4)+SALT(16)+NONCE(12)+CT_LEN(4)+EXPIRY(8)+MAX_ATT(1)+FLAGS(1)
HEADER_PIXELS = (HEADER_BYTES * 8 + 2) // 3


def derive_key(password: str, salt: bytes, key_len: int = 32) -> bytes:
    return hash_secret_raw(
        password.encode('utf-8'), salt,
        time_cost=2, memory_cost=65536, parallelism=2,
        hash_len=key_len, type=Type.ID
    )


def to_bits(data: bytes) -> list:
    return [int(b) for byte in data for b in format(byte, '08b')]


def embed_sequential(pixels, bits):
    new_pixels = list(pixels)
    bit_idx = 0
    for px_idx in range(HEADER_PIXELS):
        r, g, b = new_pixels[px_idx]
        if bit_idx < len(bits): r = (r & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits): g = (g & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits): b = (b & ~1) | bits[bit_idx]; bit_idx += 1
        new_pixels[px_idx] = (r, g, b)
    return new_pixels


def embed_random(pixels, bits, key):
    new_pixels = list(pixels)
    total = len(new_pixels)
    seed  = int.from_bytes(hashlib.sha256(key).digest()[:8], 'big')
    rng   = random.Random(seed)
    pool  = list(range(HEADER_PIXELS, total))
    rng.shuffle(pool)
    bit_idx = 0
    for px_idx in pool:
        if bit_idx >= len(bits): break
        r, g, b = new_pixels[px_idx]
        if bit_idx < len(bits): r = (r & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits): g = (g & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits): b = (b & ~1) | bits[bit_idx]; bit_idx += 1
        new_pixels[px_idx] = (r, g, b)
    return new_pixels


def strip_exif(img: Image.Image) -> Image.Image:
    """Return a clean copy of the image with no metadata."""
    clean = Image.new(img.mode, img.size)
    clean.putdata(list(img.getdata()))
    return clean


def encode_message(img_bytes: bytes, message: str, password: str,
                   decoy_password: str = '', decoy_message: str = '',
                   expiry_hours: int = 0, max_attempts: int = 0,
                   aes_bits: int = 256, double_encrypt: bool = False,
                   scrub_exif: bool = True):

    img = Image.open(io.BytesIO(img_bytes)).convert('RGB')

    # Scrub EXIF if requested
    if scrub_exif:
        img = strip_exif(img)

    pixels       = list(img.getdata())
    total_pixels = len(pixels)
    key_len      = 32 if aes_bits == 256 else 16   # AES-128 or AES-256

    expiry_ts = int(time.time()) + expiry_hours * 3600 if expiry_hours > 0 else 0
    max_att   = max(0, min(255, max_attempts))
    flags     = (1 if double_encrypt else 0) | (2 if aes_bits == 128 else 0)

    # Encrypt message
    salt  = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key   = derive_key(password, salt, key_len)
    ct    = AESGCM(key).encrypt(nonce, message.encode('utf-8'), None)

    # Optional double encryption (second layer with different salt)
    if double_encrypt:
        salt2  = os.urandom(SALT_SIZE)
        nonce2 = os.urandom(NONCE_SIZE)
        key2   = derive_key(password + '_layer2', salt2, key_len)
        ct     = AESGCM(key2).encrypt(nonce2, ct, None)
        ct     = salt2 + nonce2 + struct.pack('>I', len(ct) - 16) + ct  # prepend layer2 header

    # Optional decoy block
    decoy_block = b''
    if decoy_password and decoy_message:
        ds  = os.urandom(SALT_SIZE); dn = os.urandom(NONCE_SIZE)
        dk  = derive_key(decoy_password, ds, key_len)
        dct = AESGCM(dk).encrypt(dn, decoy_message.encode('utf-8'), None)
        decoy_block = ds + dn + struct.pack('>I', len(dct)) + dct

    header = (HEADER_MAGIC + salt + nonce
              + struct.pack('>I', len(ct))
              + struct.pack('>Q', expiry_ts)
              + struct.pack('>B', max_att)
              + struct.pack('>B', flags))
    assert len(header) == HEADER_BYTES

    header_bits  = to_bits(header)
    payload_bits = to_bits(ct + decoy_block)

    if HEADER_PIXELS + (len(payload_bits) + 2) // 3 > total_pixels:
        raise ValueError('Message too large for this image. Use a larger image.')

    new_pixels = embed_sequential(pixels, header_bits)
    new_pixels = embed_random(new_pixels, payload_bits, key)

    img.putdata(new_pixels)
    out = io.BytesIO()
    img.save(out, format='PNG')

    max_bits  = total_pixels * 3
    used_bits = len(header_bits) + len(payload_bits)
    return out.getvalue(), {
        'used_bits'     : used_bits,
        'total_bits'    : max_bits,
        'percent'       : round(used_bits / max_bits * 100, 2),
        'max_chars'     : (max_bits // 8) - HEADER_BYTES,
        'has_decoy'     : bool(decoy_password and decoy_message),
        'expiry_ts'     : expiry_ts,
        'max_attempts'  : max_att,
        'aes_bits'      : aes_bits,
        'double_encrypt': double_encrypt,
        'exif_scrubbed' : scrub_exif,
        'image_size'    : f'{img.width}x{img.height}'
    }
