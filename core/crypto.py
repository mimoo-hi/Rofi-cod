import os
import hashlib
import hmac
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError

def derive_session_key(shared_secret: bytes, salt: bytes = b"") -> bytes:
    info = b"p2p-session-key-v1"
    prk = hmac.new(salt or b"p2p-salt-v1", shared_secret, hashlib.sha256).digest()
    return hmac.new(prk, info, hashlib.sha256).digest()

class SecureChannel:
    def __init__(self, session_key: bytes, my_nonce_prefix: bytes = b""):
        if len(session_key) != 32:
            raise ValueError("مفتاح الجلسة يجب أن يكون 32 بايت")
        self._box = SecretBox(session_key)
        self._send_counter = 0
        self._last_received_counter = -1
        self._nonce_prefix = my_nonce_prefix or os.urandom(4)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        counter_bytes = self._send_counter.to_bytes(8, "big")
        random_part = os.urandom(12)
        nonce = self._nonce_prefix + counter_bytes + random_part
        self._send_counter += 1
        encrypted = self._box.encrypt(plaintext, nonce).ciphertext
        return counter_bytes + nonce + encrypted

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < 48:
            raise ValueError("بيانات التشفير غير مكتملة")
        
        recv_counter = int.from_bytes(data[:8], "big")
        # حماية من Replay Attack
        if recv_counter <= self._last_received_counter:
            raise ValueError("تحذير أمني: تم رصد حزمة معاد إرسالها (Replay Attack)!")
        
        nonce = data[8:32]
        ciphertext = data[32:]
        
        decrypted = self._box.decrypt(ciphertext, nonce)
        self._last_received_counter = recv_counter
        return decrypted
