import hashlib
import hmac
import socket
import base64
from typing import Tuple

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def _validate_ipv4(ip: str) -> None:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"IP غير صحيح: {ip}")
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            raise ValueError(f"IP غير صحيح: {ip}")

def derive_key(shared_secret: bytes, info: bytes = b"p2p-id-v2") -> bytes:
    if len(shared_secret) < 16:
        raise ValueError("السر المشترك يجب أن يكون 16 بايت على الأقل")
    salt = b"p2p-secure-salt-v2"
    prk = hmac.new(salt, shared_secret, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

def encode_id_final(ip: str, port: int, shared_secret: bytes) -> str:
    _validate_ipv4(ip)
    if not (1 <= port <= 65535):
        raise ValueError(f"المنفذ غير صحيح: {port}")
    
    octets = [int(x) for x in ip.split(".")]
    packed = bytes(octets) + port.to_bytes(2, "big")
    
    enc_key = derive_key(shared_secret, info=b"p2p-enc-v3")
    mac_key = derive_key(shared_secret, info=b"p2p-mac-v3")
    
    keystream = hashlib.sha256(enc_key + b"\x00\x00\x00\x00").digest()[:6]
    encrypted = bytes(a ^ b for a, b in zip(packed, keystream))
    
    mac = hmac.new(mac_key, encrypted, hashlib.sha256).digest()[:8]
    bundle = encrypted + mac
    
    return base64.b32encode(bundle).decode().rstrip("=").lower()

def decode_id_final(short_id: str, shared_secret: bytes) -> Tuple[str, int]:
    padded = short_id.upper()
    while len(padded) % 8 != 0:
        padded += "="
    
    bundle = base64.b32decode(padded)
    if len(bundle) < 14:
        raise ValueError("ID غير صالح")
    
    ciphertext = bundle[:6]
    mac = bundle[6:14]
    
    mac_key = derive_key(shared_secret, info=b"p2p-mac-v3")
    expected_mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()[:8]
    
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("HMAC فشل — ID أو السر خاطئ")
    
    enc_key = derive_key(shared_secret, info=b"p2p-enc-v3")
    keystream = hashlib.sha256(enc_key + b"\x00\x00\x00\x00").digest()[:6]
    packed = bytes(a ^ b for a, b in zip(ciphertext, keystream))
    
    ip = ".".join(str(b) for b in packed[:4])
    port = int.from_bytes(packed[4:6], "big")
    
    return ip, port
