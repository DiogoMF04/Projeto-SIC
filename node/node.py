#!/usr/bin/env python3


import sys
import os
import asyncio
import uuid
import struct
import time
import random
import json
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime

sys.path.append('..')

import dbus
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from common.constants import (
    MessageType, ControlCommand, 
    HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT, NETWORK_ID_SIZE
)
from common.crypto_utils import CryptoManager
from common.bluez_interface import BlueZInterface
from common.gui import NetworkGUI
from common.protocol import (
    ForwardingTableAging, HeartbeatManager, 
    CascadeProtocol, DEFAULT_AGING_TIMEOUT
)
from common.e2e_security import E2ESession
from common.network_control import NetworkDiagnosticTool, DiagnosticCommand
from common.protocol import NetworkMessage, RoutingEntry

class NodeState(Enum):
    DISCONNECTED = auto()
    SCANNING = auto()
    CONNECTING = auto()
    AUTHENTICATING = auto()
    CONNECTED = auto()
    NETWORK_JOINED = auto()
    RECOVERING = auto()  # NOVO: Estado de recuperação

@dataclass
class LinkInfo:
    address: str
    nid: Optional[bytes] = None
    hops: int = -1
    is_uplink: bool = False
    last_heartbeat: float = 0.0
    missed_heartbeats: int = 0
    e2e_session: Optional[E2ESession] = None  # Alterado para E2E
    session_established: bool = False
    state: str = "IDLE"  # IDLE, ACTIVE, RECOVERING

class IoTNode:
    def __init__(self, name: str):
        self.name = name
        self.nid = uuid.uuid4().bytes
        
        # Crypto
        self.crypto = CryptoManager()
        self.sink_public_key = None  # Cache da chave pública do Sink
        
        # BLE
        self.ble = BlueZInterface(name, is_sink=False)
        self.ble.data_callback = self._on_data_received
        
        # Estado
        self.state = NodeState.DISCONNECTED
        self.uplink: Optional[LinkInfo] = None
        self.downlinks: Dict[str, LinkInfo] = {}  # address -> LinkInfo
        
        # Tabela de encaminhamento com Aging
        self.forwarding_table = ForwardingTableAging(aging_timeout=DEFAULT_AGING_TIMEOUT)
        self.forwarding_table.on_entry_expire = self._on_route_expired
        
        # Heartbeat manager (para verificação de assinaturas)
        self.hb_manager = None  # Inicializado quando temos chave do Sink
        
        # Estatísticas
        self.messages_routed_uplink = 0
        self.lost_heartbeats_total = 0
        self.join_time: Optional[float] = None
        
        # Controlo
        self.running = False
        self.tasks: List[asyncio.Task] = []
        self.heartbeat_monitor_task: Optional[asyncio.Task] = None
        self.aging_cleanup_task: Optional[asyncio.Task] = None
        
        # GUI
        self.gui: Optional[NetworkGUI] = None
        self.gui_update_task: Optional[asyncio.Task] = None
        
        # Diagnóstico
        self.diagnostics: Optional[NetworkDiagnosticTool] = None
        
        # Recovery
        self.recovery_start_time: Optional[float] = None
        
    def enable_gui(self):
        """Ativa interface gráfica"""
        title = f"IoT Node - {self.name}"
        self.gui = NetworkGUI(title, is_sink=False)
        self.gui.on_send_message = self._gui_send_message
        self.gui.on_command = self._gui_command
        self.gui.on_scan_network = self._gui_scan
        
    async def initialize(self, cert_path: str, key_path: str, ca_path: str) -> bool:
        """Inicialização completa"""
        try:
            # Carrega certificados
            with open(cert_path, "rb") as f:
                self.crypto.load_certificate(f.read())
            with open(key_path, "rb") as f:
                self.crypto.private_key = serialization.load_pem_private_key(
                    f.read(), None, default_backend())
            with open(ca_path, "rb") as f:
                self.crypto.load_ca_certificate(f.read())
            
            # Inicia BLE
            self.ble.start_mainloop()
            self.running = True
            
            # Inicia diagnóstico
            self.diagnostics = NetworkDiagnosticTool(self.ble, self)
            
            # Inicia tasks de background
            self.heartbeat_monitor_task = asyncio.create_task(self._heartbeat_monitor())
            self.aging_cleanup_task = asyncio.create_task(self._aging_cleanup_loop())
            
            if self.gui:
                self.gui_update_task = asyncio.create_task(self._gui_update_loop())
                # Inicia GUI em thread separada
                gui_thread = threading.Thread(target=self.gui.run)
                gui_thread.daemon = True
                gui_thread.start()
            
            self._log(f"Nó inicializado: {self.nid.hex()}")
            return True
            
        except Exception as e:
            print(f"[ERRO] Inicialização: {e}")
            return False

    async def join_network(self, preferred_sink: Optional[str] = None):
        """Junta-se à rede com deteção de hops lazy"""
        if self.state not in [NodeState.DISCONNECTED, NodeState.RECOVERING]:
            return False
            
        self.state = NodeState.SCANNING
        self._log("A procurar rede...", "INFO")
        
        try:
            devices = await self.ble.scan_devices(timeout=5.0)
            
            if not devices:
                self.state = NodeState.DISCONNECTED
                return False
            
            # Estratégia: tenta conectar ao primeiro disponível (lazy)
            # Em cenário real, ordenaríamos por RSSI e tentaríamos obter hop count
            for dev in devices:
                if await self._try_connect(dev.address):
                    return True
            
            self.state = NodeState.DISCONNECTED
            return False
            
        except Exception as e:
            self._log(f"Erro no join: {e}", "ERROR")
            self.state = NodeState.DISCONNECTED
            return False

    async def _try_connect(self, address: str) -> bool:
        """Tenta estabelecer conexão com handshake E2E"""
        self.state = NodeState.CONNECTING
        
        if not await self.ble.connect_device(address):
            return False
        
        try:
            # Prepara E2E Session
            e2e = E2ESession()
            client_hello = e2e.initiate_handshake(self.crypto.private_key)
            
            # Prepara AUTH com certificado
            cert_pem = self.crypto.certificate.public_bytes(serialization.Encoding.PEM)
            auth_msg = struct.pack(">B", MessageType.AUTH_HANDSHAKE)
            auth_msg += struct.pack(">I", len(cert_pem))
            auth_msg += cert_pem
            auth_msg += client_hello
            
            await self.ble.send_data(address, auth_msg)
            self.state = NodeState.AUTHENTICATING
            
            # Aguarda resposta (timeout 10s)
            auth_future = asyncio.Future()
            self._pending_auth = auth_future
            
            try:
                await asyncio.wait_for(auth_future, timeout=10.0)
                
                # Configura link
                self.uplink = LinkInfo(
                    address=address,
                    nid=auth_future.result(),  # NID do Sink
                    hops=0,  # Direto
                    is_uplink=True,
                    last_heartbeat=time.time(),
                    e2e_session=e2e,
                    session_established=True,
                    state="ACTIVE"
                )
                
                self.state = NodeState.NETWORK_JOINED
                self.join_time = time.time()
                self.hb_manager = HeartbeatManager(self.crypto)  # Para verificar assinaturas
                
                self._log(f"Conectado ao Sink: {self.uplink.nid.hex()[:16]}...", "SUCCESS")
                
                # Inicia monitorização contínua (opcional)
                # asyncio.create_task(self.diagnostics.continuous_monitor(60))
                
                return True
                
            except asyncio.TimeoutError:
                self._log("Timeout na autenticação", "WARNING")
                await self.ble.disconnect_device(address)
                return False
                
        except Exception as e:
            self._log(f"Erro na conexão: {e}", "ERROR")
            await self.ble.disconnect_device(address)
            return False

    async def _on_data_received(self, sender_address: str, data: bytes):
        """Handler principal de mensagens"""
        if len(data) < 1:
            return
            
        msg_type = data[0]
        payload = data[1:]
        
        handlers = {
            MessageType.HEARTBEAT: self._handle_heartbeat,
            MessageType.AUTH_HANDSHAKE: self._handle_auth_response,
            MessageType.DATA: self._handle_data_message,
            MessageType.ROUTING_UPDATE: self._handle_routing_update,
            MessageType.NODE_MESSAGE: self._handle_node_message,
            MessageType.TOPOLOGY_RESPONSE: self._handle_topology_response,
            MessageType.DISCONNECT_NOTICE: self._handle_cascade_disconnect,
        }
        
        handler = handlers.get(msg_type)
        if handler:
            try:
                await handler(sender_address, payload)
            except Exception as e:
                self._log(f"Erro handler {msg_type}: {e}", "ERROR")

    async def _handle_auth_response(self, address: str, data: bytes):
        """Processa ServerHello e completa E2E handshake"""
        try:
            # Verifica se é resposta ao nosso pedido pendente
            if not hasattr(self, '_pending_auth') or self._pending_auth.done():
                return
            
            offset = 0
            cert_len = struct.unpack(">I", data[offset:offset+4])[0]
            offset += 4
            sink_cert_der = data[offset:offset+cert_len]
            offset += cert_len
            
            # Verifica certificado e extrai chave pública
            sink_nid, is_sink = self.crypto.verify_certificate(sink_cert_der)
            if not is_sink or not sink_nid:
                self._log("Certificado do Sink inválido!", "ERROR")
                return
            
            # Guarda chave pública para verificação de heartbeats
            sink_cert = x509.load_der_x509_certificate(sink_cert_der, default_backend())
            self.sink_public_key = sink_cert.public_key()
            
            # Completa handshake E2E
            if hasattr(self, '_current_e2e'):
                remaining_data = data[offset:]
                session_key = self._current_e2e.complete_handshake(
                    remaining_data, 
                    self.crypto.private_key,
                    lambda cert: self.sink_public_key  # Verificação já feita acima
                )
                
                self._pending_auth.set_result(sink_nid)
                
        except Exception as e:
            self._log(f"Erro na autenticação: {e}", "ERROR")
            if hasattr(self, '_pending_auth') and not self._pending_auth.done():
                self._pending_auth.set_exception(e)

    async def _handle_heartbeat(self, address: str, data: bytes):
        """Processa heartbeat assinado"""
        try:
            if not self.uplink or self.uplink.address != address:
                return
            
            if not self.sink_public_key:
                return
            
            if not self.hb_manager:
                return
            
            # Verifica assinatura
            valid, seq, ts = self.hb_manager.verify_heartbeat(data, self.sink_public_key)
            
            if not valid:
                self._log("Heartbeat com assinatura inválida rejeitado!", "WARNING")
                return
            
            # Atualiza estado
            self.uplink.last_heartbeat = time.time()
            self.uplink.missed_heartbeats = 0
            
            # Forward para downlinks (com reencriptação se necessário)
            if self.downlinks:
                forward_data = struct.pack(">B", MessageType.HEARTBEAT) + data
                await self._broadcast_to_downlinks(forward_data, exclude=address)
            
            # Atualiza GUI se necessário
            if self.gui:
                self.gui.update_known_nodes([self.uplink.nid.hex()])
                
        except Exception as e:
            self._log(f"Erro no heartbeat: {e}", "ERROR")

    async def _handle_data_message(self, address: str, data: bytes):
        """Processa mensagem de dados (E2E encriptada)"""
        try:
            link = None
            is_uplink = False
            
            if self.uplink and self.uplink.address == address:
                link = self.uplink
                is_uplink = True
            elif address in self.downlinks:
                link = self.downlinks[address]
            
            if not link or not link.e2e_session or not link.session_established:
                return
            
            # Desencripta E2E
            plaintext = link.e2e_session.decrypt_payload(data)
            if not plaintext:
                self._log("Falha na desencriptação E2E", "WARNING")
                return
            
            # Parse mensagem
            msg = NetworkMessage.deserialize(plaintext)
            if not msg:
                return
            
            self.messages_routed_uplink += 1
            
            # Atualiza tabela de encaminhamento (aprendizado)
            if is_uplink:
                # Vem do Sink, atualiza rota para source
                self.forwarding_table.add_entry(msg.source_nid, address, 0)
            else:
                # Vem de downlink, atualiza hops
                self.forwarding_table.add_entry(msg.source_nid, address, link.hops)
            
            # Verifica se é para nós
            if msg.dest_nid == self.nid:
                self._process_local_message(msg)
            else:
                # Encaminha (store-and-forward com reencriptação hop-by-hop se necessário)
                await self._forward_message(msg, incoming_link=link)
                
        except Exception as e:
            self._log(f"Erro no processamento de dados: {e}", "ERROR")

    async def _handle_cascade_disconnect(self, address: str, data: bytes):
        """Processa mensagem de desconexão em cascata"""
        try:
            parsed = CascadeProtocol.parse_disconnect_message(
                CascadeProtocol.DISCONNECT_MAGIC + data
            )
            
            if not parsed:
                return
            
            failing_nid, reason, timestamp = parsed
            
            self._log(f"Recebido cascade disconnect: {failing_nid.hex()[:16]}... ({reason})", "WARNING")
            
            # Se o nosso uplink falhou, entra em RECOVERY
            if self.uplink and self.uplink.nid == failing_nid:
                await self._enter_recovery_state("parent_lost")
            else:
                # Se é um downlink que falhou, remove e propaga
                if address in self.downlinks:
                    await self._remove_downlink(address)
                    # Propaga para outros downlinks
                    await self._broadcast_to_downlinks(
                        struct.pack(">B", MessageType.DISCONNECT_NOTICE) + data
                    )
                    
        except Exception as e:
            self._log(f"Erro no cascade: {e}", "ERROR")

    async def _enter_recovery_state(self, reason: str):
        """Entra em estado de recuperação"""
        if self.state == NodeState.RECOVERING:
            return
            
        self.state = NodeState.RECOVERING
        self.recovery_start_time = time.time()
        
        self._log(f"### ENTRANDO EM ESTADO DE RECUPERAÇÃO ### ({reason})", "ERROR")
        
        # Notifica todos os downlinks
        disconnect_msg = CascadeProtocol.create_disconnect_message(self.nid, reason)
        full_msg = struct.pack(">B", MessageType.DISCONNECT_NOTICE) + disconnect_msg
        
        for addr in list(self.downlinks.keys()):
            try:
                await self.ble.send_data(addr, full_msg)
            except:
                pass
        
        # Marca rotas como inválidas (hops = infinito)
        self.forwarding_table.mark_recovery(self.nid)
        
        # Limpa conexões
        for addr in list(self.downlinks.keys()):
            await self._remove_downlink(addr)
        
        old_uplink = self.uplink
        self.uplink = None
        
        if old_uplink:
            await self.ble.disconnect_device(old_uplink.address)
        
        # Tenta reconnect após delay
        await asyncio.sleep(3)
        if self.running:
            self.state = NodeState.DISCONNECTED
            await self.join_network()


    async def _heartbeat_monitor(self):
        """Monitor de heartbeats com deteção de falha"""
        while self.running:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            
            if self.uplink and self.state == NodeState.NETWORK_JOINED:
                elapsed = time.time() - self.uplink.last_heartbeat
                if elapsed > HEARTBEAT_INTERVAL:
                    self.uplink.missed_heartbeats += 1
                    self.lost_heartbeats_total += 1
                    
                if self.uplink.missed_heartbeats >= 3:
                    self._log(f"Uplink perdido! ({self.uplink.missed_heartbeats} falhas)", "ERROR")
                    await self._enter_recovery_state("heartbeat_timeout")

    async def _aging_cleanup_loop(self):
        """Loop de limpeza de rotas obsoletas"""
        while self.running:
            await asyncio.sleep(60)  # Verifica a cada minuto
            self.forwarding_table._cleanup_expired()
            
            # Estatísticas
            stats = self.forwarding_table.get_statistics()
            if stats['expired'] > 0:
                self._log(f"Aging: {stats['expired']} rotas expiradas removidas")

    async def _gui_update_loop(self):
        """Atualiza GUI periodicamente"""
        while self.running and self.gui:
            try:
                await asyncio.sleep(1)
                
                # Prepara dados para GUI
                nodes = []
                edges = []
                
                # Este nó
                nodes.append({
                    'nid': self.nid.hex(),
                    'hops': 0,
                    'is_self': True,
                    'state': self.state.name
                })
                
                # Uplink
                if self.uplink:
                    nodes.append({
                        'nid': self.uplink.nid.hex(),
                        'hops': -1,
                        'is_sink': True
                    })
                    edges.append((self.nid.hex(), self.uplink.nid.hex()))
                
                # Downlinks
                for addr, link in self.downlinks.items():
                    nodes.append({
                        'nid': link.nid.hex() if link.nid else addr,
                        'hops': link.hops,
                        'state': link.state
                    })
                    edges.append((link.nid.hex() if link.nid else addr, self.nid.hex()))
                
                # Atualiza GUI
                self.gui.update_status(
                    nid=self.nid.hex(),
                    state=self.state.name,
                    uplink=self.uplink.nid.hex() if self.uplink else None,
                    hops=self.uplink.hops if self.uplink else -1,
                    downlinks=len(self.downlinks),
                    stats={
                        'routed': self.messages_routed_uplink,
                        'lost_hb': self.lost_heartbeats_total,
                        'queue': len(self.pending_queue) if hasattr(self, 'pending_queue') else 0
                    }
                )
                
                self.gui.update_topology(nodes, edges)
                
            except Exception as e:
                print(f"Erro update GUI: {e}")

    def _gui_send_message(self, target: str, message: str):
        """Callback da GUI para envio"""
        asyncio.create_task(self._async_send_message(target, message))
        
    async def _async_send_message(self, target: str, message: str):
        if target == "Sink":
            await self.send_to_sink("Inbox", message.encode())
        else:
            # Assume que é hex
            try:
                target_nid = bytes.fromhex(target.replace("...", ""))
                await self.send_to_node(target_nid, message.encode())
            except:
                pass

    def _gui_command(self, cmd: str):
        """Callback de comandos da GUI"""
        if cmd == "join":
            asyncio.create_task(self.join_network())
        elif cmd == "leave":
            asyncio.create_task(self._enter_recovery_state("user_request"))
        elif cmd == "force_recover":
            asyncio.create_task(self._enter_recovery_state("forced"))
        elif cmd == "update_topology":
            if self.uplink:
                asyncio.create_task(self.request_topology())

    def _gui_scan(self):
        """Callback de scan da GUI"""
        async def do_scan():
            result = await self.diagnostics.run_diagnostic(DiagnosticCommand.SCAN_NEIGHBORS)
            self._log(f"Scan encontrou {result.data.get('devices_found', 0)} dispositivos")
        asyncio.create_task(do_scan())

    def _log(self, msg: str, level: str = "INFO"):
        """Log para GUI e console"""
        print(f"[{level}] {msg}")
        if self.gui:
            self.gui.log(msg, level)


async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--gui", action="store_true", help="Ativar GUI")
    parser.add_argument("--auto-join", action="store_true")
    
    args = parser.parse_args()
    
    node = IoTNode(args.name)
    if args.gui:
        node.enable_gui()
    
    if not await node.initialize(args.cert, args.key, args.ca):
        sys.exit(1)
    
    if args.auto_join:
        await node.join_network()
    
    # Mantém running
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())