"""
protocol.py - Shared wire protocol + authentication helpers (used by server AND client).

Wire format (TCP):
  * Control messages: 4-byte big-endian length prefix + UTF-8 JSON object.
  * File data:        raw bytes streamed right after a control message that
                      announces the exact byte count (no framing overhead).

Authentication (password is NEVER sent, not even hashed):
  1. client -> AUTH_START {user}
  2. server -> {salt, nonce, iterations}        (nonce is random, single use)
  3. client derives  key = PBKDF2-HMAC-SHA256(password, salt, iterations)
     client -> AUTH_PROOF {proof = HMAC-SHA256(key, nonce)}
  4. server recomputes the HMAC from its stored key and compares in constant time.
Because the nonce changes every attempt, a captured proof cannot be replayed.
"""
import hashlib
import hmac
import json
import socket
import struct

DEFAULT_PORT = 4450
CHUNK = 1024 * 1024            # 1 MiB chunks: big files are never loaded into memory
PBKDF2_ITERATIONS = 200_000
MAX_CONTROL_MSG = 1024 * 1024  # sanity limit for a JSON control message


def send_msg(sock: socket.socket, obj: dict) -> None:
    """Send one length-prefixed JSON control message."""
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise ConnectionError if the peer closes early."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        buf += chunk
    return bytes(buf)


def recv_msg(sock: socket.socket) -> dict:
    """Receive one length-prefixed JSON control message."""
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    if length > MAX_CONTROL_MSG:
        raise ConnectionError("Control message too large")
    return json.loads(recv_exact(sock, length).decode("utf-8"))


# ----------------------------------------------------------------- auth helpers
def derive_key(password: str, salt_hex: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """PBKDF2-HMAC-SHA256 -> hex key. The server stores only this (plus the salt)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt_hex), iterations).hex()


def make_proof(key_hex: str, nonce_hex: str) -> str:
    """HMAC(key, nonce) - proves knowledge of the password without revealing it."""
    return hmac.new(bytes.fromhex(key_hex), bytes.fromhex(nonce_hex), hashlib.sha256).hexdigest()


def sha256_file(path: str) -> str:
    """Chunked SHA-256 of a file on disk."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()
