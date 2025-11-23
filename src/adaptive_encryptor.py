# adaptive_encryptor.py
"""
AdaptiveEncryptor - backward compatible version
"""

import os
import base64
import traceback
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# Try to import oqs (pyOQS). Many distributions exist; we will probe the API.
try:
    import oqs as _oqs  # may be pyOQS or some other package
    _oqs_imported = True
except Exception:
    _oqs = None
    _oqs_imported = False

# Sensitivity keywords (simple heuristic)
SENS_KEYWORDS = ["password", "secret", "confidential", "id", "report", "contract", "bank", "credit", "ssn", "tax"]

class AdaptiveEncryptor:
    def __init__(self, password: str):
        """
        password: master password (string). For a real system prompt for this securely.
        """
        if not password or len(password.strip()) == 0:
            raise ValueError("Password cannot be empty")
            
        self.password = password.encode()
        self.pqc_available = False
        self._pqc_mode = None

        # Create a consistent salt based on the password hash for NEW files
        password_hash = hashlib.sha256(self.password).digest()[:16]
        self.password_salt = password_hash

        # Probe pyOQS / oqs capabilities without throwing
        if _oqs_imported:
            try:
                if hasattr(_oqs, "KEM"):
                    self._pqc_mode = "oqs.KEM"
                    self.pqc_available = True
                elif hasattr(_oqs, "KeyEncapsulation"):
                    self._pqc_mode = "oqs.KeyEncapsulation"
                    self.pqc_available = True
                elif hasattr(_oqs, "create_kem") or hasattr(_oqs, "new_kem"):
                    self._pqc_mode = "oqs.factory"
                    self.pqc_available = True
                else:
                    print("[PQC] 'oqs' imported but API not recognized; PQC disabled.")
                    self.pqc_available = False
                    self._pqc_mode = None
            except Exception:
                print("[PQC] error while probing oqs API; PQC disabled.")
                traceback.print_exc()
                self.pqc_available = False
                self._pqc_mode = None
        else:
            self.pqc_available = False

        if self.pqc_available:
            print(f"[PQC] PQC support enabled, mode={self._pqc_mode}")
        else:
            print("[PQC] PQC not available. Running with classical wrapping only.")

    def classify_sensitivity(self, filename: str, content: bytes) -> str:
        """Return 'green'/'yellow'/'red' based on naive rules."""
        fname = filename.lower()
        
        # Check filename for sensitive keywords
        if any(k in fname for k in SENS_KEYWORDS):
            return "red"
            
        # Check file content for sensitive keywords (only for small files to avoid performance issues)
        if len(content) < 100000:
            try:
                text_content = content.decode("utf-8", errors="ignore").lower()
                if any(k in text_content for k in SENS_KEYWORDS):
                    return "red"
                if len(text_content) > 10000:
                    return "yellow"
            except:
                return "yellow"
                
        # Large files are medium sensitivity
        if len(content) > 1000000:
            return "yellow"
            
        return "green"

    def derive_key_old_method(self, mode: str) -> bytes:
        """
        OLD METHOD: Derive KEK bytes from password using Argon2id with old random salts.
        This is for backward compatibility with old files.
        """
        # Include password in salt to make it unique per password (OLD METHOD)
        password_hash = str(hash(self.password)).encode()[:8]
        
        if mode == "green":
            salt = b"green_salt_" + password_hash
            return hash_secret_raw(self.password, salt, time_cost=1, memory_cost=65536, parallelism=1, hash_len=16, type=Type.ID)
        elif mode == "yellow":
            salt = b"yellow_salt" + password_hash
            return hash_secret_raw(self.password, salt, time_cost=2, memory_cost=65536, parallelism=1, hash_len=32, type=Type.ID)
        else:  # red
            salt = b"red_salt____" + password_hash
            return hash_secret_raw(self.password, salt, time_cost=4, memory_cost=131072, parallelism=2, hash_len=32, type=Type.ID)

    def derive_key_new_method(self, mode: str) -> bytes:
        """
        NEW METHOD: Derive KEK bytes from password using Argon2id with consistent salt.
        This is for new files.
        """
        # Use consistent salt based on password + mode
        mode_salt = self.password_salt + mode.encode()
        
        if mode == "green":
            return hash_secret_raw(self.password, mode_salt, time_cost=1, memory_cost=65536, parallelism=1, hash_len=16, type=Type.ID)
        elif mode == "yellow":
            return hash_secret_raw(self.password, mode_salt, time_cost=2, memory_cost=65536, parallelism=1, hash_len=32, type=Type.ID)
        else:  # red
            return hash_secret_raw(self.password, mode_salt, time_cost=4, memory_cost=131072, parallelism=2, hash_len=32, type=Type.ID)

    def _try_pqc_wrap(self, dek: bytes):
        """
        Defensive PQC wrapping attempt. Returns base64-encoded PQC ciphertext or None.
        """
        if not self.pqc_available or self._pqc_mode is None:
            return None

        try:
            # Mode: oqs.KEM
            if self._pqc_mode == "oqs.KEM":
                kem = _oqs.KEM("Kyber768")
                pub = None
                if hasattr(kem, "generate_keypair"):
                    kp = kem.generate_keypair()
                    pub = kp[0] if isinstance(kp, tuple) else kp
                if pub is None and hasattr(kem, "generate_keypair_bytes"):
                    pub = kem.generate_keypair_bytes()
                if pub is None:
                    raise RuntimeError("Could not obtain public key from oqs.KEM instance")
                if hasattr(kem, "encap_secret"):
                    ct, ss = kem.encap_secret(pub)
                elif hasattr(kem, "encap"):
                    ct, ss = kem.encap(pub)
                else:
                    raise RuntimeError("oqs.KEM instance lacks encap method")
                return base64.b64encode(ct).decode()

            # Mode: oqs.KeyEncapsulation (older)
            if self._pqc_mode == "oqs.KeyEncapsulation":
                kem = _oqs.KeyEncapsulation("Kyber768")
                pub = kem.generate_keypair() if hasattr(kem, "generate_keypair") else None
                if pub is None:
                    raise RuntimeError("Could not obtain public key from KeyEncapsulation")
                if hasattr(kem, "encap_secret"):
                    ct, ss = kem.encap_secret(pub)
                elif hasattr(kem, "encapsulate"):
                    ct, ss = kem.encapsulate(pub)
                else:
                    raise RuntimeError("KeyEncapsulation instance lacks encap method")
                return base64.b64encode(ct).decode()

            # Mode: factory-style create_kem/new_kem
            if self._pqc_mode == "oqs.factory":
                kem = None
                if hasattr(_oqs, "create_kem"):
                    kem = _oqs.create_kem("Kyber768")
                elif hasattr(_oqs, "new_kem"):
                    kem = _oqs.new_kem("Kyber768")
                if kem is None:
                    raise RuntimeError("factory create_kem/new_kem failed")
                pub = kem.generate_keypair() if hasattr(kem, "generate_keypair") else None
                if pub is None:
                    raise RuntimeError("Could not obtain public key from factory KEM")
                if hasattr(kem, "encap_secret"):
                    ct, ss = kem.encap_secret(pub)
                elif hasattr(kem, "encap"):
                    ct, ss = kem.encap(pub)
                else:
                    raise RuntimeError("factory KEM lacks encap method")
                return base64.b64encode(ct).decode()

        except Exception:
            print("[PQC] PQC wrapping attempt failed; disabling PQC for this run.")
            traceback.print_exc()
            self.pqc_available = False
            self._pqc_mode = None
            return None

        return None

    def encrypt_file(self, plaintext: bytes, filename: str):
        """
        Encrypts plaintext bytes and returns (ciphertext_bytes, metadata_dict).
        Uses NEW method for consistent key derivation.
        """
        mode = self.classify_sensitivity(filename, plaintext)
        
        # create DEK - always use 32 bytes for AES-256
        dek = os.urandom(32)
        aes = AESGCM(dek)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, plaintext, None)

        # wrap DEK with KEK using NEW method
        kek = self.derive_key_new_method(mode)
        aes_kek = AESGCM(kek)
        wrap_nonce = os.urandom(12)
        wrapped = aes_kek.encrypt(wrap_nonce, dek, None)

        meta = {
            "mode": mode,
            "nonce": base64.b64encode(nonce).decode(),
            "wrap_nonce": base64.b64encode(wrap_nonce).decode(),
            "wrapped_dek": base64.b64encode(wrapped).decode(),
            "pqc": None,
            "key_version": "new"  # Mark as using new key derivation method
        }

        # Try PQC wrapping for high-sensitivity files only
        if mode == "red" and self.pqc_available:
            try:
                pqc_ct = self._try_pqc_wrap(dek)
                meta["pqc"] = pqc_ct
            except Exception:
                print("[PQC] Unexpected error during PQC wrapping attempt.")
                traceback.print_exc()
                meta["pqc"] = None
                self.pqc_available = False

        return ciphertext, meta

    def decrypt_file(self, ciphertext: bytes, meta: dict) -> bytes:
        """
        Decrypt ciphertext using the KEK-wrapped DEK stored in metadata.
        Tries both OLD and NEW key derivation methods for backward compatibility.
        """
        mode = meta.get("mode", "green")
        key_version = meta.get("key_version", "old")  # Default to "old" for backward compatibility
        
        # Try the appropriate key derivation method based on key_version
        if key_version == "new":
            # Use new consistent key derivation
            kek = self.derive_key_new_method(mode)
            print(f"Using NEW key derivation method for mode: {mode}")
        else:
            # Use old key derivation (for backward compatibility)
            kek = self.derive_key_old_method(mode)
            print(f"Using OLD key derivation method for mode: {mode}")
        
        aes_kek = AESGCM(kek)

        # Unwrap the DEK
        wrap_nonce = base64.b64decode(meta["wrap_nonce"])
        wrapped_dek = base64.b64decode(meta["wrapped_dek"])
        
        try:
            dek = aes_kek.decrypt(wrap_nonce, wrapped_dek, None)
        except Exception as e:
            # If the first method fails, try the other method
            print(f"First decryption attempt failed: {e}")
            print("Trying alternative key derivation method...")
            
            if key_version == "new":
                # First try failed with new method, try old method
                kek = self.derive_key_old_method(mode)
                print("Retrying with OLD key derivation method")
            else:
                # First try failed with old method, try new method  
                kek = self.derive_key_new_method(mode)
                print("Retrying with NEW key derivation method")
            
            aes_kek = AESGCM(kek)
            dek = aes_kek.decrypt(wrap_nonce, wrapped_dek, None)

        # Decrypt the file content
        aes = AESGCM(dek)
        nonce = base64.b64decode(meta["nonce"])
        plain = aes.decrypt(nonce, ciphertext, None)
        return plain