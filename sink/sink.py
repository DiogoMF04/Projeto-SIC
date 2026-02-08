#!/usr/bin/env python3
"""
Sink Complete Implementation
Com GUI, Assinatura de Heartbeats, Filas de Mensagens, e Gestão de Topologia
"""

import sys
import os
import asyncio
import uuid
import struct
import time
import json
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from common.constants import MessageType, ControlCommand, HEARTBEAT_INTERVAL
from common.crypto_utils import CryptoManager
from common.bluez_interface import BlueZInterface
from common.gui import NetworkGUI
from common.protocol import ForwardingTableAging, HeartbeatManager
from common.e2e_security import E2ESession
from common.network_control import NetworkDiagnosticTool
from common.protocol import NetworkMessage

@dataclass
class ConnectedNode:
    nid: bytes
    address: str
    hops: int
    downlinks: List[bytes]
    last_seen: float
    e2e_session: E2ESession
    message_queue: List[Dict] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)

class SinkNode:
    def __init__(self, name: str = "Sink"):
        self.name = name
        self.nid = uuid.uuid4().bytes
        
        self.crypto = CryptoManager()
        self.heartbeat_mgr: Optional[HeartbeatManager] = None
        
        self.ble = BlueZInterface("Sink", is_sink=True)
        self.ble.data_callback = self._on_data_received
        
        self.connected_nodes: Dict[str, ConnectedNode] = {}  # address -> node
        self.nid_to_address: Dict[bytes, str] = {}
        self.message_queues: Dict[bytes, List[Dict]] = defaultdict(list)
        
        self.running = False
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.gui: Optional[NetworkGUI] = None
        self.diagnostics: Optional[NetworkDiagnosticTool] = None
        
    def enable_gui(self):
        self.gui = NetworkGUI("IoT Sink Gateway", is_sink=True)
        self.gui.on_send_message = self._gui_broadcast
        self.gui.on_command = self._gui_command
        
    async def initialize(self, cert_path: str, key_path: str, ca_path: str):
        """Inicialização do Sink"""
        with open(cert_path, "rb") as f:
            self.crypto.load_certificate(f.read())
        with open(key_path, "rb") as f:
            self.crypto.private_key = serialization.load_pem_private_key(
                f.read(), None, default_backend())
        with open(ca_path, "rb") as f:
            self.crypto.load_ca_certificate(f.read())
        
        self.heartbeat_mgr = HeartbeatManager(self.crypto)
        
        self.ble.start_mainloop()
        self.ble.register_gatt_server()
        self.ble.register_advertisement()
        
        self.running = True
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self.diagnostics = NetworkDiagnosticTool(self.ble, self)
        
        if self.gui:
            gui_thread = threading.Thread(target=self.gui.run)
            gui_thread.daemon = True
            gui_thread.start()
            asyncio.create_task(self._gui_update_loop())
        
        self._log(f"Sink inicializado: {self.nid.hex()}")
        
    async def _heartbeat_loop(self):
        """Envio periódico de heartbeats assinados"""
        while self.running:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            
            # Cria heartbeat assinado
            hb_data = self.heartbeat_mgr.create_heartbeat()
            full_msg = struct.pack(">B", MessageType.HEARTBEAT) + hb_data
            
            # Envia para todos os nós conectados
            for addr, node in list(self.connected_nodes.items()):
                try:
                    await self.ble.send_data(addr, full_msg)
                    node.last_seen = time.time()
                except Exception as e:
                    self._log(f"Erro ao enviar heartbeat para {addr}: {e}", "ERROR")
        
    async def _on_data_received(self, sender: str, data: bytes):
        """Handler de mensagens"""
        if len(data) < 1:
            return
            
        msg_type = data[0]
        payload = data[1:]
        
        if msg_type == MessageType.AUTH_HANDSHAKE:
            await self._handle_auth(sender, payload)
        elif msg_type == MessageType.DATA:
            await self._handle_data(sender, payload)
        elif msg_type == MessageType.NODE_MESSAGE:
            await self._handle_node_to_node(sender, payload)
        elif msg_type == MessageType.TOPOLOGY_REQUEST:
            await self._send_topology(sender)
        elif msg_type == MessageType.NETWORK_DISCOVERY:
            await self._send_node_list(sender)
            
    async def _handle_auth(self, address: str, data: bytes):
        """Handshake E2E com novo nó"""
        try:
            offset = 0
            cert_len = struct.unpack(">I", data[offset:offset+4])[0]
            offset += 4
            client_cert = data[offset:offset+cert_len]
            offset += 4
            
            client_hello = data[offset:]
            
            # Verifica certificado
            nid, is_sink = self.crypto.verify_certificate(client_cert)
            if not nid or is_sink:
                self._log(f"Auth falhou para {address}: cert inválido", "WARNING")
                return
            
            # Cria sessão E2E
            e2e = E2ESession()
            response, session_key = e2e.respond_handshake(
                client_hello, 
                self.crypto.private_key,
                self.crypto.certificate.public_bytes(serialization.Encoding.PEM)
            )
            
            # Registra nó
            node = ConnectedNode(
                nid=nid,
                address=address,
                hops=0,
                downlinks=[],
                last_seen=time.time(),
                e2e_session=e2e,
                statistics={"connected_at": time.time()}
            )
            self.connected_nodes[address] = node
            self.nid_to_address[nid] = address
            
            # Envia resposta
            await self.ble.send_data(address, 
                struct.pack(">B", MessageType.AUTH_HANDSHAKE) + response)
            
            self._log(f"Nó autenticado: {nid.hex()[:16]}...", "SUCCESS")
            
            # Atualiza GUI
            if self.gui:
                self.gui.log(f"Novo nó conectado: {nid.hex()[:16]}...", "SUCCESS")
                
        except Exception as e:
            self._log(f"Erro no auth: {e}", "ERROR")
            
    async def _handle_node_to_node(self, sender: str, data: bytes):
        """Processa mensagem para fila de outro nó"""
        try:
            dest_nid = data[:16]
            payload = data[16:]
            
            # Guarda na fila
            msg_entry = {
                "from": self.connected_nodes[sender].nid.hex() if sender in self.connected_nodes else "unknown",
                "timestamp": time.time(),
                "payload": payload.hex(),
                "size": len(payload)
            }
            
            self.message_queues[dest_nid].append(msg_entry)
            
            # Notifica destinatário se conectado
            if dest_nid in self.nid_to_address:
                dest_addr = self.nid_to_address[dest_nid]
                await self.ble.send_data(dest_addr,
                    struct.pack(">B", MessageType.NODE_MESSAGE) + data)
            
            self._log(f"Mensagem encaminhada para fila de {dest_nid.hex()[:16]}...")
            
        except Exception as e:
            self._log(f"Erro no encaminhamento: {e}", "ERROR")
            
    async def _send_topology(self, address: str):
        """Envia mapa completo da rede"""
        topology = {
            "sink": self.nid.hex(),
            "timestamp": time.time(),
            "nodes": []
        }
        
        for addr, node in self.connected_nodes.items():
            topology["nodes"].append({
                "nid": node.nid.hex(),
                "hops": node.hops,
                "address": addr,
                "queue_size": len(self.message_queues.get(node.nid, [])),
                "last_seen": node.last_seen
            })
            
        await self.ble.send_data(address,
            struct.pack(">B", MessageType.TOPOLOGY_RESPONSE) + 
            json.dumps(topology).encode())
            
    async def _send_node_list(self, address: str):
        """Envia lista de nós para discovery"""
        nodes = []
        for node in self.connected_nodes.values():
            nodes.append({
                "nid": node.nid.hex(),
                "hops": node.hops,
                "direct": True,
                "last_seen": node.last_seen
            })
            
        await self.ble.send_control(address,
            bytes([ControlCommand.GET_NETWORK_NODES]) + json.dumps(nodes).encode())
            
    def _log(self, msg: str, level: str = "INFO"):
        print(f"[Sink] [{level}] {msg}")
        if self.gui:
            self.gui.log(msg, level)
            
    def _gui_broadcast(self, target: str, msg: str):
        pass
        
    def _gui_command(self, cmd: str):
        pass
        
    async def _gui_update_loop(self):
        while self.running and self.gui:
            await asyncio.sleep(2)
            # Atualiza estatísticas na GUI
            
    async def stop(self):
        self.running = False
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
        for addr in list(self.connected_nodes.keys()):
            await self.ble.disconnect_device(addr)
        self.ble.stop_mainloop()

async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--gui", action="store_true")
    
    args = parser.parse_args()
    
    sink = SinkNode()
    if args.gui:
        sink.enable_gui()
    
    await sink.initialize(args.cert, args.key, args.ca)
    
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        await sink.stop()

if __name__ == "__main__":
    asyncio.run(main())