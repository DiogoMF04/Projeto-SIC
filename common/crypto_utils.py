# common/crypto_utils.py
"""
Utilitários criptográficos X.509, ECDH, DTLS-like
"""
import os
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Tuple, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import struct

class CryptoManager:
    def __init__(self):
        self.private_key = None
        self.certificate = None
        self.ca_certificate = None
        self.session_keys = {}  # nid -> (tx_key, rx_key, counter)
        
    def generate_keypair(self):
        """Gera par de chaves EC P-521"""
        self.private_key = ec.generate_private_key(
            ec.SECP521R1(), default_backend()
        )
        return self.private_key
    
    def create_csr(self, nid: bytes, is_sink: bool = False) -> bytes:
        """Cria Certificate Signing Request"""
        if not self.private_key:
            self.generate_keypair()
            
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, nid.hex()),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoTNetwork"),
        ])
        
        if is_sink:
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, nid.hex()),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoTNetwork"),
                x509.NameAttribute(NameOID.USER_ID, "SINK"),
            ])
            
        csr = x509.CertificateSigningRequestBuilder()
        csr = csr.subject_name(subject)
        csr = csr.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(nid)]),
            critical=False,
        )
        csr = csr.sign(self.private_key, hashes.SHA512(), default_backend())
        
        return csr.public_bytes(serialization.Encoding.PEM)
    
    def load_certificate(self, cert_pem: bytes):
        """Carrega certificado X.509"""
        self.certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
        return self.certificate
    
    def load_ca_certificate(self, cert_pem: bytes):
        """Carrega certificado da CA"""
        self.ca_certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
        
    def verify_certificate(self, cert_pem: bytes) -> Optional[bytes]:
        """Verifica certificado contra CA e retorna NID"""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            
            # Verifica assinatura da CA
            if self.ca_certificate:
                cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm)
                )
            
            # Extrai NID do CN
            nid_hex = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            nid = bytes.fromhex(nid_hex)
            
            # Verifica se é Sink
            is_sink = False
            try:
                user_id = cert.subject.get_attributes_for_oid(NameOID.USER_ID)
                if user_id and user_id[0].value == "SINK":
                    is_sink = True
            except:
                pass
                
            return nid, is_sink
            
        except Exception as e:
            print(f"Erro na verificação do certificado: {e}")
            return None, False
    
    def generate_session_key(self) -> bytes:
        """Gera chave de sessão de 256 bits"""
        return AESGCM.generate_key(bit_length=256)
    
    def key_exchange(self, other_public_key, my_nid: bytes, other_nid: bytes) -> bytes:
        """Troca de chaves Diffie-Hellman"""
        if not self.private_key:
            raise ValueError("Chave privada não inicializada")
            
        shared_key = self.private_key.exchange(ec.ECDH(), other_public_key)
        
        # Deriva chave usando HKDF-like simples
        derived = hashlib.sha3_256(shared_key + my_nid + other_nid).digest()
        return derived
    
    def encrypt_message(self, key: bytes, plaintext: bytes, associated_data: bytes) -> Tuple[bytes, bytes]:
        """Encripta mensagem com AES-256-GCM"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    
    def decrypt_message(self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
        """Desencripta mensagem"""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    
    def compute_mac(self, key: bytes, message: bytes, counter: int) -> bytes:
        """Calcula MAC da mensagem com contador anti-replay"""
        counter_bytes = struct.pack(">Q", counter)
        mac_data = counter_bytes + message
        return hmac.new(key, mac_data, hashlib.sha3_256).digest()[:16]
    
    def verify_mac(self, key: bytes, message: bytes, counter: int, mac: bytes) -> bool:
        """Verifica MAC"""
        computed = self.compute_mac(key, message, counter)
        return hmac.compare_digest(computed, mac)

class SimpleDTLS:
    """Implementação simplificada de DTLS para canal seguro end-to-end"""
    def __init__(self, crypto_manager: CryptoManager):
        self.crypto = crypto_manager
        self.session_established = False
        self.session_key = None
        self.remote_nonce = None
        self.local_nonce = None
        
    def initiate_handshake(self) -> bytes:
        """Inicia handshake DTLS-like"""
        self.local_nonce = os.urandom(32)
        # Envia nonce + public key
        pub_key = self.crypto.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return struct.pack(">I", len(pub_key)) + pub_key + self.local_nonce
    
    def respond_handshake(self, incoming: bytes) -> bytes:
        """Responde a handshake"""
        pub_key_len = struct.unpack(">I", incoming[:4])[0]
        remote_pub_key = incoming[4:4+pub_key_len]
        self.remote_nonce = incoming[4+pub_key_len:]
        
        # Gera chave de sessão
        remote_key = serialization.load_der_public_key(remote_pub_key, default_backend())
        shared = self.crypto.key_exchange(remote_key, b'local', b'remote')
        self.session_key = hashlib.sha3_256(shared + self.local_nonce + self.remote_nonce).digest()
        self.session_established = True
        
        # Responde com nossa chave pública e nonce
        pub_key = self.crypto.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.local_nonce = os.urandom(32)
        return struct.pack(">I", len(pub_key)) + pub_key + self.local_nonce
    
    def complete_handshake(self, response: bytes):
        """Completa handshake"""
        pub_key_len = struct.unpack(">I", response[:4])[0]
        remote_pub_key = response[4:4+pub_key_len]
        remote_nonce = response[4+pub_key_len:]
        
        remote_key = serialization.load_der_public_key(remote_pub_key, default_backend())
        shared = self.crypto.key_exchange(remote_key, b'local', b'remote')
        self.session_key = hashlib.sha3_256(shared + self.local_nonce + remote_nonce).digest()
        self.session_established = True
        
    def wrap_message(self, data: bytes) -> bytes:
        """Encapsula dados com cifra autenticada"""
        if not self.session_established:
            raise ValueError("Sessão não estabelecida")
        aesgcm = AESGCM(self.session_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct
    
    def unwrap_message(self, data: bytes) -> bytes:
        """Desencapsula dados"""
        if not self.session_established:
            raise ValueError("Sessão não estabelecida")
        aesgcm = AESGCM(self.session_key)
        nonce = data[:12]
        ct = data[12:]
        return aesgcm.decrypt(nonce, ct, None)