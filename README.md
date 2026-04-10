# Sentinel-RS 🛡️

Network Security Monitor com blocking integrado em Rust.

## Funcionalidades

### 🔍 Monitoramento de Rede
- **Sniffer de pacotes**: Captura de pacotes em tempo real usando pcap
- **Identificação de dispositivos**: Detecção de dispositivos na rede via MAC e OUI
- **Análise de tráfego**: Protocolos TCP, UDP, ICMP
- **Monitor DHCP**: Rastreamento de leases DHCP

### 🚨 Detecção de Anomalias
- **Port Scan Detection**: Identifica varreduras de portas suspeitas
- **Alertas em tempo real**: Notificações SSE para eventos de segurança

### 🛡️ Sistema de Blocking
- **DNS Sinkhole**: Bloqueio de domínios maliciosos via DNS
- **Firewall**: Integração com iptables (Linux) / pf (macOS)
- **Blocklists**: Suporte a múltiplas fontes:
  - fabriziosalmi/blacklists (60+ listas)
  - StevenBlack Hosts
  - Firebog lists
  - Malware domain lists
  - Listas personalizadas

### 🌐 Interface Web
- **Dashboard em tempo real**: HTMX + TailwindCSS
- **Streaming de eventos**: Atualizações ao vivo via Server-Sent Events
- **Gerenciamento de blocks**: Adicionar/remover domínios e IPs

### 💾 Persistência
- **SQLite**: Armazenamento de dados local
- **Backup/Restore**: Sistema de backup completo

## Requisitos

- Rust 1.70+
- macOS ou Linux
- Permissões de root para captura de pacotes e DNS

## Instalação

```bash
# Clone o projeto
cd sentinel-rs

# Compile
cargo build

# Execute (sem sniffer - para testes)
SNIFFER_ENABLED=false cargo run

# Execute com sudo (completo)
sudo cargo run
```

## Variáveis de Ambiente

| Variável | Padrão | Descrição |
|-----------|--------|-----------|
| `INTERFACE` | auto | Interface de rede |
| `DB_PATH` | data/sentinel.db | Caminho do banco SQLite |
| `OUI_PATH` | data/oui.txt | Banco de dados OUI |
| `SNIFFER_ENABLED` | true | Ativar sniffer de pacotes |
| `DNS_ENABLED` | false | Ativar DNS sinkhole |
| `DNS_PORT` | 53 | Porta do DNS sinkhole |
| `FIREWALL_ENABLED` | true | Ativar gerenciamento de firewall |
| `LISTEN_ADDR` | 0.0.0.0:8080 | Endereço do servidor web |

## Configuração de Rede

### Opção 1: DNS do Roteador (Recomendado)
1. Descubra o IP da máquina: `ifconfig` ou `ip addr`
2. Acesse as configurações do roteador
3. Configure o DNS primário para o IP da máquina do Sentinel-RS

### Opção 2: DNS nos Dispositivos
Configure manualmente o DNS para o IP da máquina do Sentinel-RS em cada dispositivo.

### Opção 3: DNS Sinkhole Nativo
```bash
sudo DNS_ENABLED=true DNS_PORT=53 cargo run
```

## Acesso

- **Dashboard**: http://localhost:8080
- **Blocking**: http://localhost:8080/blocking
- **API Events**: http://localhost:8080/events

## Estrutura do Projeto

```
sentinel-rs/
├── src/
│   ├── sniffer/      # Captura de pacotes
│   ├── devices/      # Gerenciamento de dispositivos
│   ├── anomaly/      # Detecção de anomalias
│   ├── blocking/     # Sistema de blocking (DNS, Firewall)
│   ├── db/           # Persistência SQLite
│   ├── web/          # Servidor Axum
│   └── network/      # Scanner, DHCP, VPN
├── templates/        # Templates HTML
└── data/             # Dados (banco, blocklists)
```

## Tecnologias

- **Backend**: Rust, Axum, Tokio
- **Database**: SQLite (rusqlite)
- **Frontend**: HTML, TailwindCSS, HTMX
- **Packet Capture**: pcap, etherparse

## Usuário Padrão

- **Usuário**: admin
- **Senha**: admin123

⚠️ Altere a senha em produção!

## Licença

MIT License