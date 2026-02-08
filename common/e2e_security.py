# common/e2e_security.py
import os
import struct
import hashlib
import secrets
from typing import Optional, Tuple, Callable
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class E2ESession:
    
    def __init__(self):
        self.session_key: Optional[bytes] = None
        self.salt: Optional[bytes] = None
        self.tx_counter: int = 0
        self.rx_counter: int = 0
        self.is_established: bool = False
        self.remote_public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.local_ephemeral: Optional[ec.EllipticCurvePrivateKey] = None
        
    def initiate_handshake(self, local_static_key: ec.EllipticCurvePrivateKey) -> bytes:
        """Inicia handshake - retorna mensagem ClientHello"""
        # Gera chave efêmera (ECDHE)
        self.local_ephemeral = ec.generate_private_key(ec.SECP384R1(), default_backend())
        local_pub = self.local_ephemeral.public_key()
        
        # Serializa chave pública efêmera
        pub_bytes = local_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Gera nonce
        nonce = secrets.token_bytes(32)
        
        # Guarda salt para derivação
        self.salt = nonce
        
        # Estrutura: [pubkey_len:2][pubkey][nonce:32]
        msg = struct.pack(">H", len(pub_bytes))
        msg += pub_bytes
        msg += nonce
        
        return msg
    
    def respond_handshake(self, remote_data: bytes, 
                         local_static_key: ec.EllipticCurvePrivateKey,
                         local_static_cert: bytes) -> Tuple[bytes, bytes]:
        """
        Responde a handshake (lado do Sink)
        Retorna: (resposta, chave_sessão)
        """
        try:
            offset = 0
            pub_len = struct.unpack(">H", remote_data[offset:offset+2])[0]
            offset += 2
            
            remote_pub_bytes = remote_data[offset:offset+pub_len]
            offset += pub_len
            
            remote_nonce = remote_data[offset:offset+32]
            
            # Carrega chave pública remota
            self.remote_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP384R1(), remote_pub_bytes
            )
            
            # Gera nossa chave efêmera
            self.local_ephemeral = ec.generate_private_key(ec.SECP384R1(), default_backend())
            local_pub = self.local_ephemeral.public_key()
            local_pub_bytes = local_pub.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            # Gera nonce local
            local_nonce = secrets.token_bytes(32)
            self.salt = local_nonce + remote_nonce
            
            # ECDHE shared secret
            shared_secret = self.local_ephemeral.exchange(ec.ECDH(), self.remote_public_key)
            
            # Deriva chave de sessão
            self.session_key = HKDF(
                algorithm=hashes.SHA384(),
                length=32,
                salt=self.salt,
                info=b'iot-e2e-session'
            ).derive(shared_secret)
            
            self.is_established = True
            
            # Constroi resposta: [cert_len:4][cert][pubkey_len:2][pubkey][nonce:32][signature]
            response = struct.pack(">I", len(local_static_cert))
            response += local_static_cert
            response += struct.pack(">H", len(local_pub_bytes))
            response += local_pub_bytes
            response += local_nonce
            
            # Assina o handshake completo para autenticação mútua
            sign_data = remote_pub_bytes + local_pub_bytes + remote_nonce + local_nonce
            signature = local_static_key.sign(sign_data, ec.ECDSA(hashes.SHA384()))
            response += struct.pack(">H", len(signature))
            response += signature
            
            return response, self.session_key
            
        except Exception as e:
            print(f"[E2E] Erro no respond_handshake: {e}")
            raise
    
    def complete_handshake(self, remote_data: bytes, 
                          local_static_key: ec.EllipticCurvePrivateKey,
                          ca_verify_callback) -> bytes:
        """
        Completa handshake (lado do Nó)
        Retorna chave de sessão
        """
        try:
            offset = 0
            
            # Extrai certificado do Sink
            cert_len = struct.unpack(">I", remote_data[offset:offset+4])[0]
            offset += 4
            sink_cert = remote_data[offset:offset+cert_len]
            offset += cert_len
            
            # Verifica certificado (callback)
            sink_pub_key = ca_verify_callback(sink_cert)
            if not sink_pub_key:
                raise ValueError("Certificado do Sink inválido")
            
            self.remote_public_key = sink_pub_key
            
            # Extrai chave pública efêmera do Sink
            pub_len = struct.unpack(">H", remote_data[offset:offset+2])[0]
            offset += 2
            remote_pub_bytes = remote_data[offset:offset+pub_len]
            offset += pub_len
            
            remote_ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP384R1(), remote_pub_bytes
            )
            
            # Nonce do Sink
            remote_nonce = remote_data[offset:offset+32]
            offset += 32
            
            # Assinatura
            sig_len = struct.unpack(">H", remote_data[offset:offset+2])[0]
            offset += 2
            signature = remote_data[offset:offset+sig_len]
            
            # Verifica assinatura
            local_pub = self.local_ephemeral.public_key()
            local_pub_bytes = local_pub.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            sign_data = local_pub_bytes + remote_pub_bytes + self.salt + remote_nonce
            try:
                sink_pub_key.verify(signature, sign_data, ec.ECDSA(hashes.SHA384()))
            except:
                raise ValueError("Assinatura do Sink inválida")
            
            # ECDHE
            shared_secret = self.local_ephemeral.exchange(ec.ECDH(), remote_ephemeral_pub)
            
            # Deriva chave
            self.salt = remote_nonce + self.salt  # salt = salt_server || salt_client
            self.session_key = HKDF(
                algorithm=hashes.SHA384(),
                length=32,
                salt=self.salt,
                info=b'iot-e2e-session'
            ).derive(shared_secret)
            
            self.is_established = True
            return self.session_key
            
        except Exception as e:
            print(f"[E2E] Erro no complete_handshake: {e}")
            raise
    
    def encrypt_payload(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """Encripta payload com AES-256-GCM"""
        if not self.is_established:
            raise ValueError("Sessão não estabelecida")
        
        self.tx_counter += 1
        
        # Nonce baseado em contador (96 bits)
        nonce = struct.pack(">Q", self.tx_counter) + b'\x00' * 4
        
        aesgcm = AESGCM(self.session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Retorna: [contador:8][ciphertext]
        return struct.pack(">Q", self.tx_counter) + ciphertext
    
    def decrypt_payload(self, data: bytes, associated_data: bytes = b"") -> Optional[bytes]:
        """Desencripta payload"""
        if not self.is_established or len(data) < 8:
            return None
        
        counter = struct.unpack(">Q", data[:8])[0]
        ciphertext = data[8:]
        
        # Anti-replay: verifica se contador é maior que último recebido
        if counter <= self.rx_counter:
            print(f"[E2E] Replay detectado! {counter} <= {self.rx_counter}")
            return None
        
        self.rx_counter = counter
        
        nonce = struct.pack(">Q", counter) + b'\x00' * 4
        aesgcm = AESGCM(self.session_key)
        
        try:
            return aesgcm.decrypt(nonce, ciphertext, associated_data)
        except:
            return None
    
    def get_security_parameters(self) -> dict:
        """Retorna parâmetros de segurança para debug"""
        return {
            "established": self.is_established,
            "tx_counter": self.tx_counter,
            "rx_counter": self.rx_counter,
            "key_fingerprint": hashlib.sha256(self.session_key or b'').hexdigest()[:16]
        }