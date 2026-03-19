import ctypes
import os
import sys

# Define the C struct mapping exactly to `pqc_types.h`
class CHiggaionKey(ctypes.Structure):
    _fields_ = [("pkey", ctypes.c_void_p)]

# Locate and dynamically load the compiled libpqc_crypto.so
_lib_name = "libpqc_crypto.so"
# In a real pip intallation, this would use pkg_resources or __file__ relative paths
_lib_path = os.path.join(os.path.dirname(__file__), "..", "..", "obj", _lib_name)
if not os.path.exists(_lib_path):
    raise ImportError(f"Cannot find compiled Higgaion shared library at {_lib_path}. Run 'make test-python' first.")

_lib = ctypes.CDLL(_lib_path)

# Map the C libc free() function to handle dynamically allocated signature buffers
_libc = ctypes.CDLL(None) # None loads the standard C library on POSIX

# ── Function Signatures ──

# void higgaion_key_init(HiggaionKey *key);
_lib.higgaion_key_init.argtypes = [ctypes.POINTER(CHiggaionKey)]

# void generate_keypair(HiggaionKey *key, const char *alg_name);
_lib.generate_keypair.argtypes = [ctypes.POINTER(CHiggaionKey), ctypes.c_char_p]

# void higgaion_key_free(HiggaionKey *key);
_lib.higgaion_key_free.argtypes = [ctypes.POINTER(CHiggaionKey)]

# int higgaion_key_up_ref(HiggaionKey *dst, const HiggaionKey *src);
# HIG-003: safe reference counting for shared EVP_PKEY
_lib.higgaion_key_up_ref.argtypes = [ctypes.POINTER(CHiggaionKey), ctypes.POINTER(CHiggaionKey)]
_lib.higgaion_key_up_ref.restype = ctypes.c_int

# void pqc_sign(uint8_t **signature, size_t *sig_len, const uint8_t *message, size_t msg_len, const char *domain, const HiggaionKey *sk);
_lib.pqc_sign.argtypes = [
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.POINTER(CHiggaionKey)
]

# bool pqc_verify(const uint8_t *message, size_t msg_len, const uint8_t *signature, size_t sig_len, const char *domain, const HiggaionKey *pk);
_lib.pqc_verify.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.POINTER(CHiggaionKey)
]
_lib.pqc_verify.restype = ctypes.c_bool

class HiggaionError(Exception):
    pass

class PrivateKey:
    """Wrapper for the mathematically proven PQC Migration Engine private key."""
    def __init__(self, c_key: CHiggaionKey):
        self._key = c_key
        # We uniquely hold the underlying EVP_PKEY memory allocation.
        self._owns_memory = True

    def __del__(self):
        """Invoke OpenSSL teardown natively when Python GC claims the object."""
        if hasattr(self, '_key') and self._key.pkey and self._owns_memory:
            _lib.higgaion_key_free(ctypes.byref(self._key))
            self._key.pkey = None

    def sign(self, message: bytes, domain: str) -> bytes:
        if not self._key.pkey:
            raise HiggaionError("Attempting to sign with an inactive or freed key.")

        c_msg = None
        c_msg_len = 0
        if message:
            c_msg = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
            c_msg_len = len(message)

        c_domain = domain.encode('utf-8')

        c_sig_ptr = ctypes.POINTER(ctypes.c_uint8)()
        c_sig_len = ctypes.c_size_t(0)

        _lib.pqc_sign(
            ctypes.byref(c_sig_ptr),
            ctypes.byref(c_sig_len),
            c_msg,
            c_msg_len,
            c_domain,
            ctypes.byref(self._key)
        )

        if not c_sig_ptr or c_sig_len.value == 0:
            raise HiggaionError("Cryptographic signature execution failed natively.")

        # Cast to bytes. This copies the buffer into a Python string/bytes object.
        sig_bytes = bytes(ctypes.cast(c_sig_ptr, ctypes.POINTER(ctypes.c_uint8 * c_sig_len.value)).contents)

        # Malloc was specifically called within pqc_sign, so we MUST instruct the libc wrapper to free the C heap pointer.
        _libc.free(c_sig_ptr)

        return sig_bytes

class PublicKey:
    def __init__(self, c_key: CHiggaionKey):
        self._key = c_key
        # HIG-003 FIX: PublicKey now independently owns its EVP_PKEY reference
        self._owns_memory = True

    def __del__(self):
        """HIG-003 FIX: Independently free the up-ref'd EVP_PKEY on GC."""
        if hasattr(self, '_key') and self._key.pkey and self._owns_memory:
            _lib.higgaion_key_free(ctypes.byref(self._key))
            self._key.pkey = None

    def verify(self, message: bytes, signature: bytes, domain: str) -> bool:
        if not self._key.pkey or not signature:
            return False

        c_msg = None
        c_msg_len = 0
        if message:
            c_msg = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
            c_msg_len = len(message)

        c_sig = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature)
        c_sig_len = len(signature)

        c_domain = domain.encode('utf-8')

        return _lib.pqc_verify(
            c_msg,
            c_msg_len,
            c_sig,
            c_sig_len,
            c_domain,
            ctypes.byref(self._key)
        )

def GenerateKeypair(alg_name: str = "ML-DSA-87") -> tuple[PrivateKey, PublicKey]:
    c_priv = CHiggaionKey()
    c_pub = CHiggaionKey()

    _lib.higgaion_key_init(ctypes.byref(c_priv))
    _lib.higgaion_key_init(ctypes.byref(c_pub))

    c_alg = alg_name.encode('utf-8')
    _lib.generate_keypair(ctypes.byref(c_priv), c_alg)

    if not c_priv.pkey:
        raise HiggaionError(f"Failed to securely construct PQC keypair for '{alg_name}'")

    # HIG-003 FIX: Up-ref the EVP_PKEY so the public key holds an independent
    # reference.  Both priv and pub can be garbage-collected independently
    # without triggering use-after-free or double-free.
    if _lib.higgaion_key_up_ref(ctypes.byref(c_pub), ctypes.byref(c_priv)) != 1:
        _lib.higgaion_key_free(ctypes.byref(c_priv))
        raise HiggaionError("Failed to up-ref EVP_PKEY for public key")

    priv = PrivateKey(c_priv)
    pub = PublicKey(c_pub)

    return priv, pub
