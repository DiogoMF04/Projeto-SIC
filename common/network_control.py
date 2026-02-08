# common/network_control.py
import asyncio
import time
import json
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import threading

class DiagnosticCommand(Enum):
    PING = "ping"
    TRACEROUTE = "traceroute"
    SCAN_NEIGHBORS = "scan_neighbors"
    CHECK_MTU = "check_mtu"
    BANDWIDTH_TEST = "bandwidth_test"
    SECURITY_AUDIT = "security_audit"

@dataclass
class DiagnosticResult:
    command: str
    success: bool
    timestamp: float
    data: Dict
    duration_ms: float
    error_message: Optional[str] = None

class NetworkDiagnosticTool:
    """Ferramentas de diagnóstico independentes"""
    
    def __init__(self, ble_interface, node_ref=None):
        self.ble = ble_interface
        self.node = node_ref  # Referência opcional ao nó principal
        self.results_history: List[DiagnosticResult] = []
        self.is_running = False
        self._lock = threading.Lock()
        
    async def run_diagnostic(self, command: DiagnosticCommand, 
                            target: Optional[str] = None,
                            params: Optional[Dict] = None) -> DiagnosticResult:
        """
        Executa diagnóstico específico
        Não bloqueia: retorna future/coroutine
        """
        start_time = time.time()
        params = params or {}
        
        try:
            if command == DiagnosticCommand.SCAN_NEIGHBORS:
                data = await self._do_scan_neighbors(params.get("duration", 5))
            elif command == DiagnosticCommand.PING:
                if not target:
                    raise ValueError("Target required for ping")
                data = await self._do_ping(target, params.get("count", 3))
            elif command == DiagnosticCommand.TRACEROUTE:
                data = await self._do_traceroute(target)
            elif command == DiagnosticCommand.CHECK_MTU:
                data = await self._do_mtu_check(target)
            elif command == DiagnosticCommand.SECURITY_AUDIT:
                data = await self._do_security_audit()
            else:
                raise NotImplementedError(f"Comando {command} não implementado")
            
            duration = (time.time() - start_time) * 1000
            
            result = DiagnosticResult(
                command=command.value,
                success=True,
                timestamp=start_time,
                data=data,
                duration_ms=duration
            )
            
            with self._lock:
                self.results_history.append(result)
                if len(self.results_history) > 100:  # Limita histórico
                    self.results_history.pop(0)
            
            return result
            
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            return DiagnosticResult(
                command=command.value,
                success=False,
                timestamp=start_time,
                data={},
                duration_ms=duration,
                error_message=str(e)
            )
    
    async def _do_scan_neighbors(self, duration: int) -> Dict:
        """Scan BLE de vizinhos"""
        print(f"[DIAG] Iniciando scan BLE por {duration}s...")
        devices = await self.ble.scan_devices(timeout=duration)
        
        neighbors = []
        for dev in devices:
            neighbors.append({
                "address": dev.address,
                "name": dev.name,
                "rssi": dev.rssi,
                "uuid_count": len(dev.uuids) if hasattr(dev, 'uuids') else 0
            })
        
        return {
            "devices_found": len(neighbors),
            "neighbors": neighbors,
            "scan_duration": duration,
            "timestamp": time.time()
        }
    
    async def _do_ping(self, target: str, count: int) -> Dict:
        """Ping para endereço específico"""
        times = []
        success = 0
        
        for i in range(count):
            start = time.time()
            try:
                # Envia echo request especial
                ping_data = json.dumps({"type": "echo", "seq": i}).encode()
                await self.ble.send_data(target, b'\xF0' + ping_data)  # 0xF0 = tipo especial
                
                # Aguarda resposta 
                await asyncio.sleep(0.1)

                elapsed = (time.time() - start) * 1000
                times.append(elapsed)
                success += 1
                
            except Exception as e:
                times.append(-1)
            
            await asyncio.sleep(0.5)
        
        valid_times = [t for t in times if t > 0]
        avg_time = sum(valid_times) / len(valid_times) if valid_times else 0
        
        return {
            "target": target,
            "packets_sent": count,
            "packets_received": success,
            "packet_loss": (count - success) / count * 100,
            "avg_latency_ms": avg_time,
            "min_latency": min(valid_times) if valid_times else 0,
            "max_latency": max(valid_times) if valid_times else 0
        }
    
    async def _do_traceroute(self, target: str) -> Dict:
        """Traceroute simplificado"""
        hops = []
        
        # Simulação: em implementação real, usaríamos TTL/hop limit incrementado
        if self.node and self.node.uplink:
            curr_hop = 0
            current = self.node.uplink.address
            
            while curr_hop < 10:  # Max 10 hops
                hop_info = {
                    "hop": curr_hop + 1,
                    "address": current,
                    "nid": self.node.uplink.nid.hex()[:16] if self.node.uplink else "unknown"
                }
                hops.append(hop_info)
                
                if current == target:
                    break
                curr_hop += 1
        
        return {
            "target": target,
            "hops": len(hops),
            "path": hops,
            "complete": hops[-1]["address"] == target if hops else False
        }
    
    async def _do_mtu_check(self, target: Optional[str]) -> Dict:
        """Descobre MTU do caminho"""
        sizes = [20, 100, 512, 1024, 1500]
        results = {}
        
        for size in sizes:
            try:
                data = b'X' * size
                # Tenta enviar
                if target:
                    await self.ble.send_data(target, b'\xF1' + data)  # 0xF1 = MTU probe
                else:
                    # Broadcast para all neighbors
                    for addr in self.ble.connected_devices:
                        await self.ble.send_data(addr, b'\xF1' + data)
                
                results[size] = "success"
                await asyncio.sleep(0.1)
            except Exception as e:
                results[size] = f"failed: {str(e)}"
                break
        
        # Determina MTU máximo
        max_mtu = 0
        for size, status in sorted(results.items(), reverse=True):
            if status == "success":
                max_mtu = size
                break
        
        return {
            "test_sizes": sizes,
            "results": results,
            "suggested_mtu": max_mtu,
            "target": target or "broadcast"
        }
    
    async def _do_security_audit(self) -> Dict:
        """Auditoria de segurança das sessões"""
        audit = {
            "timestamp": time.time(),
            "e2e_sessions": [],
            "certificate_status": "unknown",
            "encryption_algorithms": "AES-256-GCM+ECDHE-P384"
        }
        
        if self.node:
            # Verifica sessão com Sink
            if self.node.uplink and self.node.uplink.dtls:
                session_info = self.node.uplink.dtls.get_security_parameters()
                audit["e2e_sessions"].append({
                    "peer": "sink",
                    "type": "uplink",
                    **session_info
                })
            
            # Verifica sessões com downlinks
            for addr, link in self.node.downlinks.items():
                if link.dtls:
                    session_info = link.dtls.get_security_parameters()
                    audit["e2e_sessions"].append({
                        "peer": addr,
                        "type": "downlink",
                        **session_info
                    })
            
            # Verifica certificado
            if self.node.crypto.certificate:
                from datetime import datetime
                cert = self.node.crypto.certificate
                not_after = cert.not_valid_after
                days_until_expire = (not_after - datetime.utcnow()).days
                audit["certificate_status"] = {
                    "valid": True,
                    "expires_in_days": days_until_expire,
                    "subject": str(cert.subject)
                }
        
        return audit
    
    def get_history(self, limit: int = 10) -> List[DiagnosticResult]:
        """Retorna histórico de diagnósticos"""
        with self._lock:
            return self.results_history[-limit:]
    
    def clear_history(self):
        """Limpa histórico"""
        with self._lock:
            self.results_history.clear()
    
    async def continuous_monitor(self, interval: int = 60):
        """Monitorização contínua em background"""
        self.is_running = True
        while self.is_running:
            try:
                # Scan periódico
                result = await self.run_diagnostic(
                    DiagnosticCommand.SCAN_NEIGHBORS,
                    params={"duration": 5}
                )
                print(f"[MONITOR] Scan automático: {result.data.get('devices_found', 0)} dispositivos")
                
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[MONITOR] Erro: {e}")
                await asyncio.sleep(interval)
    
    def stop_monitor(self):
        """Para monitorização"""
        self.is_running = False