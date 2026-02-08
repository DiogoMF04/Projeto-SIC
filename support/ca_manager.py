# support/ca_manager.py
"""
Gestor de Certificação Autoridade (CA) para provisionamento
"""
import os
import sys
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import uuid

class CertificationAuthority:
    def __init__(self, ca_dir: str = "ca_storage"):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(exist_ok=True)
        self.private_key = None
        self.certificate = None
        self.load_or_create_ca()
        
    def load_or_create_ca(self):
        """Carrega ou cria CA"""
        key_file = self.ca_dir / "ca_key.pem"
        cert_file = self.ca_dir / "ca_cert.pem"
        
        if key_file.exists() and cert_file.exists():
            with open(key_file, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), None, default_backend())
            with open(cert_file, "rb") as f:
                self.certificate = x509.load_pem_x509_certificate(f.read(), default_backend())
            print("CA carregada existente")
        else:
            print("Criando nova CA...")
            self._create_ca()
            
    def _create_ca(self):
        """Cria par de chaves e certificado da CA"""
        self.private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Porto"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Porto"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoTNetwork Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "IoTNetwork Root CA"),
        ])
        
        issuer = subject
        
        self.certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=3),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(self.private_key, hashes.SHA512(), default_backend())
        
        # Guarda ficheiros
        with open(self.ca_dir / "ca_key.pem", "wb") as f:
            f.write(self.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
            
        with open(self.ca_dir / "ca_cert.pem", "wb") as f:
            f.write(self.certificate.public_bytes(serialization.Encoding.PEM))
            
        print(f"CA criada e guardada em {self.ca_dir}")
    
    def issue_certificate(self, nid: bytes, is_sink: bool = False, csr_pem: bytes = None) -> Tuple[bytes, bytes]:
        """
        Emite certificado para dispositivo IoT
        
        Args:
            nid: Network ID (16 bytes)
            is_sink: Se é o Sink
            csr_pem: CSR em PEM (opcional)
            
        Returns:
            (certificado_pem, chave_privada_pem)
        """
        # Gera chaves do dispositivo
        device_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
        
        # Se tem CSR, usa-o, senão cria certifcado direto
        if csr_pem:
            csr = x509.load_pem_x509_csr(csr_pem, default_backend())
            subject = csr.subject
        else:
            attrs = [
                x509.NameAttribute(NameOID.COMMON_NAME, nid.hex()),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoTNetwork"),
            ]
            if is_sink:
                attrs.append(x509.NameAttribute(NameOID.USER_ID, "SINK"))
            subject = x509.Name(attrs)
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            device_key.public_key()
        ).serial_number(
            int.from_bytes(nid[:8], 'big')
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(nid)]),
            critical=False
        ).sign(self.private_key, hashes.SHA512(), default_backend())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = device_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
        
        # Guarda no CA
        device_file = self.ca_dir / f"device_{nid.hex()}.pem"
        with open(device_file, "wb") as f:
            f.write(cert_pem)
            
        return cert_pem, key_pem

    def revoke_certificate(self, nid: bytes):
        """Revoga certificado (simplificado - não usa CRL completo)"""
        device_file = self.ca_dir / f"device_{nid.hex()}.pem"
        if device_file.exists():
            device_file.rename(self.ca_dir / f"revoked_{nid.hex()}.pem")

def main():
    """CLI para gestão de certificados"""
    ca = CertificationAuthority()
    
    if len(sys.argv) < 2:
        print("Uso: python ca_manager.py <command> [args]")
        print("Commands: create-ca, issue <nid> [sink], list")
        return
    
    cmd = sys.argv[1]
    
    if cmd == "create-ca":
        print("CA inicializada")
    elif cmd == "issue":
        nid = bytes.fromhex(sys.argv[2])
        is_sink = len(sys.argv) > 3 and sys.argv[3] == "sink"
        cert, key = ca.issue_certificate(nid, is_sink)
        print(f"Certificado emitido para {nid.hex()}")
        print(f"\nCertificado:\n{cert.decode()}")
        print(f"\nChave Privada:\n{key.decode()}")
    elif cmd == "list":
        print("Certificados emitidos:")
        for f in sorted(ca.ca_dir.glob("device_*.pem")):
            nid = f.stem.replace("device_", "")
            print(f"  - {nid}")

if __name__ == "__main__":
    main()