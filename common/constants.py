"""
Constantes do protocolo e configurações
"""
import uuid
from enum import IntEnum

# UUIDs do serviço BLE GATT
SINK_SERVICE_UUID = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-eff123456789")
CONTROL_CHAR_UUID = uuid.UUID("b2c3d4e5-f6a7-8901-bcde-ff1234567890")
DATA_CHAR_UUID = uuid.UUID("c3d4e5f6-a7b8-9012-cdef-123456789012")

# Configurações de rede
HEARTBEAT_INTERVAL = 5.0  # segundos
HEARTBEAT_TIMEOUT = 15.0   # 3 heartbeats perdidos
MAX_MESSAGE_SIZE = 1024
NETWORK_ID_SIZE = 16  # 128 bits = 16 bytes

# Curva elíptica usada
ELLIPTIC_CURVE = "secp521r1"
SIGNATURE_ALGORITHM = "ecdsa-with-SHA512"
KEY_EXCHANGE_CURVE = "secp521r1"

class MessageType(IntEnum):
    """Tipos de mensagens do protocolo"""
    HEARTBEAT = 0x01
    AUTH_HANDSHAKE = 0x02
    SESSION_KEY = 0x03
    DATA = 0x04
    ROUTING_UPDATE = 0x05
    NETWORK_DISCOVERY = 0x06
    NODE_MESSAGE = 0x07      # Mensagem node-to-node via Sink
    TOPOLOGY_REQUEST = 0x08
    TOPOLOGY_RESPONSE = 0x09
    DISCONNECT_NOTICE = 0x0A

class ControlCommand(IntEnum):
    """Comandos de controlo da interface"""
    SCAN_DEVICES = 0x01
    CONNECT_DEVICE = 0x02
    DISCONNECT_DEVICE = 0x03
    GET_STATUS = 0x04
    SEND_TEST_MESSAGE = 0x05
    GET_NETWORK_NODES = 0x06
    SEND_TO_NODE = 0x07
    GET_MY_MESSAGES = 0x08

class DeviceStatus(IntEnum):
    DISCONNECTED = 0
    CONNECTING = 1
    AUTHENTICATING = 2
    CONNECTED = 3
    UPLINK_ESTABLISHED = 4