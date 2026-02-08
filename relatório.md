# SIC Project - Bluetooth-based Secure Ad-hoc Network for IoT Devices


**Data:** 2026-02-03  
**Autor:** Diogo Ferreira 114002
ajuda de formatação e documentação por IA

---

## 1. Visão Geral da Arquitetura

O sistema implementa uma rede ad-hoc IoT baseada em Bluetooth Low Energy (BLE) com as seguintes características fundamentais:

- **Topologia em Árvore:** Estrutura hierárquica com Sink na raiz e nós IoT como sensores/routers
- **Segurança End-to-End:** Criptografia AES-256-GCM com troca de chaves ECDH P-384
- **Autenticação X.509:** Certificados EC P-521 emitidos por CA central
- **Roteamento Adaptativo:** Tabelas de encaminhamento com envelhecimento automático (aging)
- **Tolerância a Falhas:** Protocolo de desconexão em cascata com estado RECOVERING

---

## 2. Estrutura do Projeto
projrecurso/
├── common/
│   ├── constants.py              # Constantes do protocolo e tipos de mensagens
│   ├── crypto_utils.py           # Primitivas criptográficas base
│   ├── protocol.py               # Mensagens de rede e tabela de encaminhamento básica
│   ├── protocol_enhanced.py      # Tabela com aging, heartbeats assinados, cascade
│   ├── e2e_security.py           # Handshake DTLS-like e sessões seguras
│   ├── bluez_interface.py        # Interface nativa BlueZ via D-Bus
│   ├── gui.py                    # Interface gráfica Tkinter
│   └── network_controls.py       # Ferramentas de diagnóstico independentes
├── sync/
│   └── sink_complete.py          # Implementação completa do Sink
├── node/
│   └── iot_node_complete.py      # Implementação completa do nó IoT
├── support/
│   └── ca_manager.py             # Autoridade de Certificação
└── relatório.md

---

## 3. Funcionalidades Implementadas

### 3.1 Funcionalidades Obrigatórias Base

| Funcionalidade | Descrição | Estado |
|---------------|-----------|--------|
| Topologia em Árvore | Estrutura hierárquica lazy com minimização de hops | ✅ Completo |
| Autenticação X.509 | Certificados EC P-521 com identificação de Sink | ✅ Completo |
| DTLS End-to-End | Canal seguro com ECDH P-384 e AES-256-GCM | ✅ Completo |
| Heartbeat | Broadcast periódico com deteção de falhas (3 misses) | ✅ Completo |
| Tabelas de Encaminhamento | Aprendizado tipo switch com forwarding | ✅ Completo |
| MACs por Ligação | HMAC-SHA3-256 com contadores anti-replay | ✅ Completo |

### 3.2 Funcionalidades Adicionais Requeridas

| Funcionalidade | Descrição Técnica |
|---------------|-------------------|
| **Interface Gráfica (Tkinter)** | Visualização em tempo real da topologia, estado das conexões (uplink/downlink), e mensagens recebidas | 
| **Tabela com Aging** | Expiração automática de rotas após 5 minutos de inatividade; callback `on_entry_expire` para notificação | 
| **Estado RECOVERING** | Propagação de falhas: notificação em cascata aos downlinks, marcação de hops como infinito, rejoin automático | 
| **Handshake E2E Completo** | Protocolo DTLS-like com ECDHE, autenticação mútua via certificados, derivação HKDF-SHA384 | 
| **Assinatura de Heartbeats** | ECDSA-SHA256 no Sink; verificação obrigatória pelos nós; prevenção de spoofing | 
| **Ferramentas de Diagnóstico** | Módulo independente com: scan BLE, ping, traceroute, MTU check, security audit |
### 3.3 Funcionalidades Extra (Bónus)

| Funcionalidade | Descrição |
|---------------|-----------|
| Filas de Mensagens Node-to-Node | Sistema de mensagens indiretas via Sink com notificação push |
| Reconexão Automática | Tentativa automática de rejoin após perda de uplink |
| Visualização Gráfica de Topologia | Canvas Tkinter com rendering hierárquico do grafo de rede |
| Estatísticas Detalhadas | Contadores de mensagens, heartbeats perdidos, uptime |
| Monitorização Contínua | Modo de diagnóstico automático em background |

---

## 4. Design de Segurança

### 4.1 Pilha de Segurança em Camadas
Camada 1 - BLE Link Layer
└── Pairing "Just Works" + encriptação nativa BLE
└── Proteção contra sniffing local
Camada 2 - Ligação Ponto-a-Ponto
└── ECDH P-384 (ephemeral) + HKDF-SHA384
└── Chaves de sessão únicas por ligação
└── Perfect Forward Secrecy
Camada 3 - End-to-End (E2E)
└── AES-256-GCM com nonces baseados em contadores
└── Confidencialidade: nós intermediários não leem conteúdo
└── Integridade: MAC autenticado por mensagem
└── Anti-replay: contadores monotónicos de 64 bits
Camada 4 - Aplicação
└── X.509 v3 com ECDSA P-521
└── Autenticação mútua baseada em CA comum
└── Identificação de Sink via OID userID
└── Assinatura de heartbeats prevenindo spoofing de topologia

## 5. Protocolo de Recuperação (Cascade)
### 5.1 Estado RECOVERING
Quando um nó detecta perda de uplink (3 heartbeats perdidos ou desconexão BLE):
Transição de Estado: NETWORK_JOINED → RECOVERING
Propagação: Envia CASCADE_DISCONNECT para todos os downlinks
Invalidação: Marca próprias rotas como hops = ∞ na tabela local
Limpeza: Desconecta todos os downlinks BLE
Reconexão: Após timeout de 3s, tenta join_network() novo

## 6. Gestão de Encaminhamento com Aging
### 6.1 Política de Expiração
Timeout padrão: 300 segundos (5 minutos) sem atividade
Atualização: Cada pacote roteado atualiza last_seen
Remoção: Automática com callback opcional on_entry_expire
Soft-delete: Entradas expiradas marcadas como is_active=False antes da remoção

##  7. Interface Gráfica
### 7.1 Componentes da GUI
Painel de Estado: NID, estado de conexão, uplink, hops, downlinks, estatísticas
Visualização de Topologia: Canvas com grafo hierárquico (Sink=vermelho, Self=azul, Ativo=verde, Recovering=laranja)
Painel de Mensagens: Tabs para mensagens recebidas e logs do sistema
Controles: Join/Leave/Force Recover, Scan BLE, Update Topology, Envio de mensagens
### 7.2 Atualizações em Tempo Real
Thread separada para Tkinter (thread-safe via queues)
Atualização periódica (1-2s) de estado e topologia
Colorização dinâmica baseada no estado da conexão
## 8. Ferramentas de Diagnóstico
### 8.1 Comandos Disponíveis
| Comando          | Descrição                                 | Parâmetros    |
| ---------------- | ----------------------------------------- | ------------- |
| `SCAN_NEIGHBORS` | Procura dispositivos BLE próximos         | duration (s)  |
| `PING`           | Teste de latência para nó específico      | target, count |
| `TRACEROUTE`     | Traçado de rota até destino               | target        |
| `CHECK_MTU`      | Descoberta de MTU do caminho              | target (opt)  |
| `SECURITY_AUDIT` | Verificação de sessões E2E e certificados | -             |
### 8.2 Execução Independente
Não bloqueia ciclo principal do nó
Retorna DiagnosticResult com timestamp, duração e dados estruturados
Histórico mantido em memória (últimos 100 resultados)
## 9. Instruções de Utilização
### 9.1 Preparação da Infraestrutura de Chaves
cd support/
python ca_manager.py create-ca
python ca_manager.py issue <sink_nid_hex> sink
python ca_manager.py issue <node1_nid_hex>
python ca_manager.py issue <node2_nid_hex>
cd sync/
python sink.py \
    --cert ../support/ca_storage/device_<sink_nid>.pem \
    --key ../support/ca_storage/sink_key.pem \
    --ca ../support/ca_storage/ca_cert.pem \
    --gui

cd node/
python node.py "Node1" \
    --cert ../support/ca_storage/device_<node1_nid>.pem \
    --key ../support/ca_storage/node1_key.pem \
    --ca ../support/ca_storage/ca_cert.pem \
    --gui \
    --auto-join

## 10. Decisões de Design Justificadas
### 10.1 ECDH P-384 vs P-521 para E2E
P-384 oferece segurança adequada (≈192-bit symmetric equivalent) com melhor performance para sessões efémeras; P-521 mantido para identidades de longo prazo conforme especificação original.
### 10.2 Aging de 5 Minutos
 Equilíbrio entre reatividade a falhas de mobilidade e estabilidade em redes semi-estáticas. Ajustável via parâmetro aging_timeout.
### 10.3 Assinatura de Heartbeats vs HMAC
Prevenção de ataques onde nós comprometidos poderiam gerar heartbeats válidos; apenas o Sink com chave privada pode originar heartbeats aceites.