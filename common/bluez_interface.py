# common/bluez_interface.py

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass
import struct

# Interfaces BlueZ
DBUS_OM_IFACE = 'org.freedesktop.DBus.ObjectManager'
DBUS_PROP_IFACE = 'org.freedesktop.DBus.Properties'
BLUEZ_SERVICE_NAME = 'org.bluez'
ADAPTER_IFACE = 'org.bluez.Adapter1'
DEVICE_IFACE = 'org.bluez.Device1'
CHARACTERISTIC_IFACE = 'org.bluez.GattCharacteristic1'
SERVICE_IFACE = 'org.bluez.GattService1'
AGENT_IFACE = 'org.bluez.Agent1'
AGENT_MANAGER_IFACE = 'org.bluez.AgentManager1'
LE_ADVERTISING_MANAGER_IFACE = 'org.bluez.LEAdvertisingManager1'
LE_ADVERTISEMENT_IFACE = 'org.bluez.LEAdvertisement1'

@dataclass
class BLEDevice:
    address: str
    name: str
    rssi: int
    path: str
    uuids: List[str]

class BlueZInterface:
    def __init__(self, device_name: str, is_sink: bool = False):
        self.device_name = device_name
        self.is_sink = is_sink
        
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        self.bus = dbus.SystemBus()
        self.mainloop = GLib.MainLoop()
        self.mainloop_thread = None
        
        # Callbacks
        self.data_callback: Optional[Callable] = None
        self.control_callback: Optional[Callable] = None
        self.connection_callback: Optional[Callable] = None
        
        self.adapter = None
        self.adapter_path = None
        self.find_adapter()
        
        self.connected_devices: Dict[str, dbus.ProxyObject] = {}  # address -> device proxy
        self.device_paths: Dict[str, str] = {}  # address -> object path
        
        # GATT Server (para Sink)
        self.app_path = '/org/iot/network'
        self.services = []
        self.advertisement = None
        
        # GATT Client
        self.characteristics: Dict[str, dbus.ProxyObject] = {}  # path -> char proxy
        
    def find_adapter(self):
        """Procura adaptador Bluetooth disponível"""
        remote_om = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, '/'), 
                                   DBUS_OM_IFACE)
        objects = remote_om.GetManagedObjects()
        
        for path, interfaces in objects.items():
            if ADAPTER_IFACE in interfaces:
                self.adapter_path = path
                self.adapter = dbus.Interface(
                    self.bus.get_object(BLUEZ_SERVICE_NAME, path),
                    ADAPTER_IFACE
                )
                print(f"Adaptador encontrado: {path}")
                return
                
        raise Exception("Nenhum adaptador Bluetooth encontrado")
    
    def start_mainloop(self):
        """Inicia mainloop D-Bus em thread separada"""
        if not self.mainloop_thread:
            self.mainloop_thread = threading.Thread(target=self.mainloop.run)
            self.mainloop_thread.daemon = True
            self.mainloop_thread.start()
    
    def stop_mainloop(self):
        """Para mainloop"""
        if self.mainloop:
            self.mainloop.quit()
            if self.mainloop_thread:
                self.mainloop_thread.join()
    
    async def scan_devices(self, timeout: float = 5.0, uuid_filter: str = None) -> List[BLEDevice]:
        """Procura dispositivos BLE próximos"""
        devices = []
        device_found = {}
        
        def on_interfaces_added(path, interfaces):
            if DEVICE_IFACE in interfaces:
                props = interfaces[DEVICE_IFACE]
                address = props.get('Address', '')
                name = props.get('Name', '')
                rssi = props.get('RSSI', -100)
                
                if uuid_filter:
                    uuids = props.get('UUIDs', [])
                    if uuid_filter not in uuids:
                        return
                
                if address and address not in device_found:
                    device = BLEDevice(
                        address=address,
                        name=name,
                        rssi=rssi,
                        path=path,
                        uuids=props.get('UUIDs', [])
                    )
                    devices.append(device)
                    device_found[address] = True
        
        bus = dbus.SystemBus()
        bus.add_signal_receiver(
            on_interfaces_added,
            dbus_interface=DBUS_OM_IFACE,
            signal_name='InterfacesAdded'
        )
        
        # Inicia discovery
        self.adapter.SetDiscoveryFilter({'Transport': 'le'})
        self.adapter.StartDiscovery()
        
        # Aguarda timeout
        time.sleep(timeout)
        
        self.adapter.StopDiscovery()
        bus.remove_signal_receiver(on_interfaces_added, 
                                   dbus_interface=DBUS_OM_IFACE,
                                   signal_name='InterfacesAdded')
        
        # Ordena por RSSI
        return sorted(devices, key=lambda x: x.rssi, reverse=True)
    
    async def connect_device(self, address: str) -> bool:
        """Conecta a dispositivo BLE"""
        try:
            # Procura path do dispositivo
            device_path = None
            remote_om = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, '/'), 
                                       DBUS_OM_IFACE)
            objects = remote_om.GetManagedObjects()
            
            for path, interfaces in objects.items():
                if DEVICE_IFACE in interfaces:
                    if interfaces[DEVICE_IFACE].get('Address') == address:
                        device_path = path
                        break
            
            if not device_path:
                # Cria device object se não existe
                device_path = f"{self.adapter_path}/dev_{address.replace(':', '_')}"
                self.adapter.CreateDevice(address)
                time.sleep(0.5)
            
            device = dbus.Interface(
                self.bus.get_object(BLUEZ_SERVICE_NAME, device_path),
                DEVICE_IFACE
            )
            
            # Connect
            device.Connect()
            time.sleep(1)  # Aguarda estabelecimento
            
            self.connected_devices[address] = device
            self.device_paths[address] = device_path
            
            # Descobre características
            await self._discover_characteristics(address, device_path)
            
            # Subscribe notificações
            await self._subscribe_notifications(address)
            
            return True
            
        except Exception as e:
            print(f"Erro ao conectar {address}: {e}")
            return False
    
    async def _discover_characteristics(self, address: str, device_path: str):
        """Descobre características GATT do dispositivo"""
        remote_om = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, '/'), 
                                   DBUS_OM_IFACE)
        objects = remote_om.GetManagedObjects()
        
        char_paths = []
        for path, interfaces in objects.items():
            if path.startswith(device_path):
                if CHARACTERISTIC_IFACE in interfaces:
                    char_paths.append(path)
                    char_proxy = dbus.Interface(
                        self.bus.get_object(BLUEZ_SERVICE_NAME, path),
                        CHARACTERISTIC_IFACE
                    )
                    self.characteristics[path] = char_proxy
    
    async def _subscribe_notifications(self, address: str):
        """Subscreve notificações de todas as características"""
        for path, char_proxy in self.characteristics.items():
            try:
                props = dbus.Interface(
                    self.bus.get_object(BLUEZ_SERVICE_NAME, path),
                    DBUS_PROP_IFACE
                )
                flags = props.Get(CHARACTERISTIC_IFACE, 'Flags')
                
                if 'notify' in flags:
                    # Regista handler de notificação
                    bus = dbus.SystemBus()
                    bus.add_signal_receiver(
                        lambda iface, changed, invalidated, path=path: 
                            self._on_characteristic_changed(path, changed),
                        dbus_interface=DBUS_PROP_IFACE,
                        signal_name='PropertiesChanged',
                        path=path
                    )
                    
                    char_proxy.StartNotify()
            except Exception as e:
                print(f"Erro ao subscrever {path}: {e}")
    
    def _on_characteristic_changed(self, char_path, changed):
        """Handler de notificação GATT"""
        if 'Value' in changed:
            value = bytes(changed['Value'])
            
            # Determina se é data ou control baseado no UUID
            props = dbus.Interface(
                self.bus.get_object(BLUEZ_SERVICE_NAME, char_path),
                DBUS_PROP_IFACE
            )
            uuid = props.Get(CHARACTERISTIC_IFACE, 'UUID')
            
            # Extrai address do path
            address = None
            for addr, path in self.device_paths.items():
                if char_path.startswith(path):
                    address = addr
                    break
            
            if uuid == "b2c3d4e5-f6a7-8901-bcde-ff1234567890" and self.control_callback:
                self.control_callback(address, value)
            elif uuid == "c3d4e5f6-a7b8-9012-cdef-123456789012" and self.data_callback:
                self.data_callback(address, value)
    
    async def disconnect_device(self, address: str):
        """Desconecta dispositivo"""
        if address in self.connected_devices:
            try:
                device = self.connected_devices[address]
                device.Disconnect()
                del self.connected_devices[address]
                if address in self.device_paths:
                    del self.device_paths[address]
            except Exception as e:
                print(f"Erro ao desconectar {address}: {e}")
    
    async def send_data(self, address: str, data: bytes):
        """Escreve dados em característica (Write Request)"""
        if address not in self.device_paths:
            return
            
        device_path = self.device_paths[address]
        
        # Encontra característica de data para este dispositivo
        for char_path, char_proxy in self.characteristics.items():
            if char_path.startswith(device_path):
                try:
                    props = dbus.Interface(
                        self.bus.get_object(BLUEZ_SERVICE_NAME, char_path),
                        DBUS_PROP_IFACE
                    )
                    uuid = props.Get(CHARACTERISTIC_IFACE, 'UUID')
                    
                    if uuid == "c3d4e5f6-a7b8-9012-cdef-123456789012":
                        # Write value with response
                        char_proxy.WriteValue(data, {'type': 'request'})
                        return
                except:
                    pass
    
    async def send_control(self, address: str, data: bytes):
        """Escreve comando de controlo"""
        if address not in self.device_paths:
            return
            
        device_path = self.device_paths[address]
        
        for char_path, char_proxy in self.characteristics.items():
            if char_path.startswith(device_path):
                try:
                    props = dbus.Interface(
                        self.bus.get_object(BLUEZ_SERVICE_NAME, char_path),
                        DBUS_PROP_IFACE
                    )
                    uuid = props.Get(CHARACTERISTIC_IFACE, 'UUID')
                    
                    if uuid == "b2c3d4e5-f6a7-8901-bcde-ff1234567890":
                        char_proxy.WriteValue(data, {'type': 'request'})
                        return
                except:
                    pass
    
    async def broadcast_to_downlinks(self, data: bytes):
        """Envia dados para todos os downlinks conectados"""
        for address in list(self.connected_devices.keys()):
            await self.send_data(address, data)

    # ========== GATT Server (para Sink) ==========
    
    def register_gatt_server(self):
        """Registra aplicação GATT no BlueZ"""
        if not self.is_sink:
            return
            
        gatt_manager = dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE_NAME, self.adapter_path),
            'org.bluez.GattManager1'
        )
        
        app = IOTApplication(self.bus, self.app_path, self._on_local_characteristic_read, 
                            self._on_local_characteristic_write)
        gatt_manager.RegisterApplication(
            app.get_path(),
            {},
            reply_handler=lambda: print("GATT registrado"),
            error_handler=lambda e: print(f"Erro GATT: {e}")
        )
        self.services = app.services
    
    def _on_local_characteristic_read(self, char_path):
        """Callback quando central lê característica local"""
        return dbus.Array([], signature='y')
    
    def _on_local_characteristic_write(self, char_path, value, options):
        """Callback quando central escreve na característica local"""
        address = options.get('device', 'unknown')
        data = bytes(value)
        
        # Determina tipo pela path/objeto
        char_obj = None
        for service in self.services:
            for char in service.characteristics:
                if char.get_path() == char_path:
                    char_obj = char
                    break
        
        if char_obj:
            if 'control' in char_obj.uuid:
                if self.control_callback:
                    self.control_callback(address, data)
            else:
                if self.data_callback:
                    self.data_callback(address, data)
        
        return dbus.Boolean(True)
    
    def register_advertisement(self):
        """Registra anúncio LE (Sink apenas)"""
        if not self.is_sink:
            return
            
        ad_manager = dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE_NAME, self.adapter_path),
            LE_ADVERTISING_MANAGER_IFACE
        )
        
        self.advertisement = IOTAdvertisement(self.bus, 0, self.device_name)
        ad_manager.RegisterAdvertisement(
            self.advertisement.get_path(),
            {},
            reply_handler=lambda: print("Anúncio ativo"),
            error_handler=lambda e: print(f"Erro anúncio: {e}")
        )

class IOTAdvertisement(dbus.service.Object):
    """Anúncio LE para o Sink"""
    def __init__(self, bus, index, name):
        self.path = f"/org/iot/advertisement{index}"
        self.bus = bus
        self.name = name
        dbus.service.Object.__init__(self, bus, self.path)
        
    def get_path(self):
        return dbus.ObjectPath(self.path)
        
    def get_properties(self):
        return {
            LE_ADVERTISEMENT_IFACE: {
                'Type': 'peripheral',
                'LocalName': self.name,
                'ServiceUUIDs': ['a1b2c3d4-e5f6-7890-abcd-eff123456789'],
                'Discoverable': True,
                'IncludeTxPower': True
            }
        }
    
    @dbus.service.method(DBUS_PROP_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface == LE_ADVERTISEMENT_IFACE:
            return self.get_properties()[LE_ADVERTISEMENT_IFACE]
        return {}
    
    @dbus.service.method(LE_ADVERTISEMENT_IFACE)
    def Release(self):
        print("Anúncio libertado")

class IOTApplication(dbus.service.Object):
    """Aplicação GATT contendo serviços"""
    def __init__(self, bus, path, read_cb, write_cb):
        self.path = path
        self.bus = bus
        self.services = []
        self.read_callback = read_cb
        self.write_callback = write_cb
        dbus.service.Object.__init__(self, bus, path)
        
        # Cria serviço IOT
        self.add_service(IOTService(bus, path, 0, read_cb, write_cb))
        
    def get_path(self):
        return dbus.ObjectPath(self.path)
    
    def add_service(self, service):
        self.services.append(service)
        
    @dbus.service.method(DBUS_OM_IFACE, out_signature='a{oa{sa{sv}}}')
    def GetManagedObjects(self):
        response = {}
        for service in self.services:
            response[service.get_path()] = service.get_properties()
            for char in service.characteristics:
                response[char.get_path()] = char.get_properties()
        return response

class IOTService(dbus.service.Object):
    """Serviço GATT IOT"""
    UUID = "a1b2c3d4-e5f6-7890-abcd-eff123456789"
    
    def __init__(self, bus, path, index, read_cb, write_cb):
        self.path = f"{path}/service{index}"
        self.bus = bus
        self.characteristics = []
        dbus.service.Object.__init__(self, bus, self.path)
        
        # Característica de Controlo
        self.add_characteristic(ControlCharacteristic(bus, self, 0, read_cb, write_cb))
        # Característica de Dados
        self.add_characteristic(DataCharacteristic(bus, self, 1, read_cb, write_cb))
        
    def get_path(self):
        return dbus.ObjectPath(self.path)
    
    def add_characteristic(self, char):
        self.characteristics.append(char)
        
    def get_properties(self):
        return {
            SERVICE_IFACE: {
                'UUID': self.UUID,
                'Primary': True,
                'Characteristics': dbus.Array(
                    [c.get_path() for c in self.characteristics],
                    signature='o'
                )
            }
        }

class IOTCharacteristic(dbus.service.Object):
    """Base para características"""
    def __init__(self, bus, path, uuid, flags, index, read_cb, write_cb):
        self.uuid = uuid
        self.flags = flags
        self.read_callback = read_cb
        self.write_callback = write_cb
        dbus.service.Object.__init__(self, bus, path)

    def get_properties(self):
        return {
            CHARACTERISTIC_IFACE: {
                'UUID': self.uuid,
                'Service': self.service.get_path(),
                'Flags': self.flags,
                'Descriptors': dbus.Array([], signature='o')
            }
        }
    
    @dbus.service.method(CHARACTERISTIC_IFACE, in_signature='a{sv}', out_signature='ay')
    def ReadValue(self, options):
        return self.read_callback(self.path)
    
    @dbus.service.method(CHARACTERISTIC_IFACE, in_signature='aya{sv}', out_signature='')
    def WriteValue(self, value, options):
        self.write_callback(self.path, value, options)
    
    @dbus.service.method(CHARACTERISTIC_IFACE)
    def StartNotify(self):
        pass
    
    @dbus.service.method(CHARACTERISTIC_IFACE)
    def StopNotify(self):
        pass

class ControlCharacteristic(IOTCharacteristic):
    """Característica para comandos de controlo"""
    UUID = "b2c3d4e5-f6a7-8901-bcde-ff1234567890"
    
    def __init__(self, bus, service, index, read_cb, write_cb):
        path = f"{service.path}/char{index}"
        super().__init__(bus, path, self.UUID, ['read', 'write', 'notify'], 
                        index, read_cb, write_cb)
        self.service = service

class DataCharacteristic(IOTCharacteristic):
    """Característica para dados"""
    UUID = "c3d4e5f6-a7b8-9012-cdef-123456789012"
    
    def __init__(self, bus, service, index, read_cb, write_cb):
        path = f"{service.path}/char{index}"
        super().__init__(bus, path, self.UUID, ['read', 'write', 'notify'],
                        index, read_cb, write_cb)
        self.service = service