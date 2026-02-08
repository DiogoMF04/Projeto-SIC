"""
Protocolos melhorados com Aging e Assinaturas
"""
import time
import struct
import hashlib
import hmac
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.exceptions import InvalidSignature

# Constants
DEFAULT_AGING_TIMEOUT = 300  # 5 minutos
HEARTBEAT_SIGNATURE_ALGORITHM = hashes.SHA256()

@dataclass
class RoutingEntry:
    """Entrada na tabela de encaminhamento com timestamp"""
    nid: bytes
    route: str  # interface/bluetooth address
    hops: int
    timestamp: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    is_active: bool = True

class ForwardingTableAging:
    """Tabela de encaminhamento com suporte a envelhecimento (aging)"""
    
    def __init__(self, aging_timeout: int = DEFAULT_AGING_TIMEOUT):
        self.table: Dict[bytes, RoutingEntry] = {}
        self.aging_timeout = aging_timeout  # segundos
        self.on_entry_expire: Optional[Callable[[bytes], None]] = None
        self.last_cleanup = time.time()
        
    def add_entry(self, nid: bytes, route: str, hops: int):
        """Adiciona ou atualiza entrada"""
        now = time.time()
        
        if nid in self.table:
            # Atualiza existente se melhor rota (menos hops) ou mesma rota
            existing = self.table[nid]
            if hops <= existing.hops or route == existing.route:
                existing.route = route
                existing.hops = hops
                existing.last_seen = now
                existing.is_active = True
                existing.packet_count += 1
        else:
            # Nova entrada
            self.table[nid] = RoutingEntry(
                nid=nid,
                route=route,
                hops=hops,
                timestamp=now,
                last_seen=now
            )
            print(f"[TABLE] Nova rota: {nid.hex()[:16]} via {route} ({hops} hops)")
    
    def update_activity(self, nid: bytes):
        """Atualiza timestamp de atividade"""
        if nid in self.table:
            self.table[nid].last_seen = time.time()
            self.table[nid].packet_count += 1
    
    def get_route(self, nid: bytes) -> Optional[str]:
        """Obtém rota se ativa e não expirada"""
        self._cleanup_expired()
        
        if nid in self.table:
            entry = self.table[nid]
            if entry.is_active and not self._is_expired(entry):
                return entry.route
            elif entry.is_active:
                # Marca como inativa mas não remove ainda (soft delete)
                entry.is_active = False
                print(f"[TABLE] Rota expirada: {nid.hex()[:16]}")
        return None
    
    def get_hops(self, nid: bytes) -> int:
        """Obtém número de hops"""
        if nid in self.table:
            entry = self.table[nid]
            if entry.is_active and not self._is_expired(entry):
                return entry.hops
        return -1
    
    def remove_entry(self, nid: bytes):
        """Remove entrada imediatamente"""
        if nid in self.table:
            del self.table[nid]
            print(f"[TABLE] Removido: {nid.hex()[:16]}")
    
    def _is_expired(self, entry: RoutingEntry) -> bool:
        """Verifica se entrada expirou"""
        return (time.time() - entry.last_seen) > self.aging_timeout
    
    def _cleanup_expired(self):
        """Limpa entradas expiradas (chamado periodicamente)"""
        now = time.time()
        if now - self.last_cleanup < 60:  # Verifica a cada minuto
            return
            
        expired = []
        for nid, entry in list(self.table.items()):
            if self._is_expired(entry):
                expired.append(nid)
                if self.on_entry_expire:
                    self.on_entry_expire(nid)
        
        for nid in expired:
            if nid in self.table:
                del self.table[nid]
                print(f"[TABLE] Auto-removido (aging): {nid.hex()[:16]}")
        
        self.last_cleanup = now
    
    def get_all_entries(self) -> List[Tuple[bytes, str, int, bool]]:
        """Retorna todas as entradas (nid, route, hops, is_active)"""
        self._cleanup_expired()
        return [(nid, e.route, e.hops, e.is_active) 
                for nid, e in self.table.items()]
    
    def mark_recovery(self, nid: bytes):
        """Marca entrada como em recuperação (hops = infinito)"""
        if nid in self.table:
            self.table[nid].hops = float('inf')
            self.table[nid].is_active = False
            print(f"[TABLE] Marcado RECOVERY: {nid.hex()[:16]}")
    
    def get_statistics(self) -> Dict:
        """Retorna estatísticas da tabela"""
        total = len(self.table)
        active = sum(1 for e in self.table.values() if e.is_active)
        expired = total - active
        
        return {
            "total_entries": total,
            "active": active,
            "expired": expired,
            "timeout_seconds": self.aging_timeout
        }

class HeartbeatManager:
    """Gestão de heartbeats com assinatura digital"""
    
    def __init__(self, crypto_manager):
        self.crypto = crypto_manager
        self.sequence_number = 0
        self.last_timestamp = 0
        
    def create_heartbeat(self) -> bytes:
        """Cria heartbeat assinado"""
        self.sequence_number += 1
        self.last_timestamp = time.time()
        
        # Estrutura: [seq:8][timestamp:8][padding:16] -> total 32 bytes antes da assinatura
        header = struct.pack(">Q", self.sequence_number)
        header += struct.pack(">d", self.last_timestamp)
        header += b'\x00' * 16  # Reservado para futuro uso
        
        # Assina com chave privada do Sink
        signature = self.crypto.private_key.sign(
            header,
            ec.ECDSA(HEARTBEAT_SIGNATURE_ALGORITHM)
        )
        
        # Formato final: [header][sig_len:4][signature]
        payload = header
        payload += struct.pack(">I", len(signature))
        payload += signature
        
        return payload
    
    def verify_heartbeat(self, data: bytes, sink_public_key) -> Tuple[bool, int, float]:
        """
        Verifica assinatura do heartbeat
        Retorna: (válido, sequence_number, timestamp)
        """
        try:
            if len(data) < 32:
                return False, 0, 0
            
            header = data[:32]
            sig_len = struct.unpack(">I", data[32:36])[0]
            signature = data[36:36+sig_len]
            
            # Verifica assinatura
            try:
                sink_public_key.verify(
                    signature,
                    header,
                    ec.ECDSA(HEARTBEAT_SIGNATURE_ALGORITHM)
                )
            except InvalidSignature:
                print("[HEARTBEAT] Assinatura inválida!")
                return False, 0, 0
            
            # Extrai dados
            seq = struct.unpack(">Q", header[:8])[0]
            ts = struct.unpack(">d", header[8:16])[0]
            
            # Verifica timestamp (anti-replay: não aceitar heartbeats antigos)
            if ts < self.last_timestamp - 60:  # Tolerância de 1 minuto para drift
                print("[HEARTBEAT] Timestamp muito antigo (possível replay)")
                return False, 0, 0
            
            self.last_timestamp = max(self.last_timestamp, ts)
            return True, seq, ts
            
        except Exception as e:
            print(f"[HEARTBEAT] Erro na verificação: {e}")
            return False, 0, 0

class CascadeProtocol:
    """Protocolo de desconexão em cascata"""
    
    DISCONNECT_MAGIC = b'CASCADE_DISCONNECT'
    
    @staticmethod
    def create_disconnect_message(nid: bytes, reason: str = "uplink_lost") -> bytes:
        """Cria mensagem de desconexão em cascata"""
        reason_bytes = reason.encode()[:32]  # Max 32 chars
        reason_bytes = reason_bytes.ljust(32, b'\x00')
        
        payload = CascadeProtocol.DISCONNECT_MAGIC
        payload += nid  # 16 bytes
        payload += reason_bytes  # 32 bytes
        payload += struct.pack(">d", time.time())  # Timestamp
        
        return payload
    
    @staticmethod
    def parse_disconnect_message(data: bytes) -> Optional[Tuple[bytes, str, float]]:
        """Parse da mensagem de desconexão"""
        try:
            if not data.startswith(CascadeProtocol.DISCONNECT_MAGIC):
                return None
            
            offset = len(CascadeProtocol.DISCONNECT_MAGIC)
            nid = data[offset:offset+16]
            offset += 16
            
            reason = data[offset:offset+32].rstrip(b'\x00').decode()
            offset += 32
            
            timestamp = struct.unpack(">d", data[offset:offset+8])[0]
            
            return nid, reason, timestamp
        except:
            return None
    
    @staticmethod
    def is_valid_disconnect(data: bytes) -> bool:
        """Verifica rapidamente se é mensagem de disconnect"""
        return data.startswith(CascadeProtocol.DISCONNECT_MAGIC)