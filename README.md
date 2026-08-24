# proxy-router-manager-ui

Lightweight local management UI for a [mihomo](https://github.com/MetaCubeX/mihomo) transparent proxy gateway backed by SOCKS5 proxy pools on Proxmox VMs.

## Features

- Reads `/etc/mihomo/config.yaml` for proxy definitions and per-VM `SRC-IP-CIDR` assignments
- Reads `/etc/dnsmasq.conf` and dnsmasq lease file for DHCP / static lease state
- Parses recent mihomo logs for per-proxy and per-VM hit counts (1-hour window)
- Drag-and-drop VM reassignment board with diff preview and one-click apply
- Active proxy health checks: parallel HTTPS download via HTTP proxy, SOCKS5, or direct interface
- Domain/IP rule manager: add `DIRECT`, `REJECT`, `REJECT-DROP` rules for domains or CIDRs, with optional per-VM AND scoping
- pve1 VM provisioning panel: bridge switch, static DHCP, mihomo rule, and lease verification in one click
- Read-only by default; write mode requires `PROXY_MANAGER_ALLOW_WRITE=1`

## Requirements

- Python 3.10+
- `pyyaml` (`pip install pyyaml`)
- mihomo, dnsmasq running on the same host
- SSH access to Proxmox hosts (for VM provisioning)

## Configuration

Copy and edit the Proxmox host list in `server.py` or use environment variables:

| Variable | Default | Description |
|---|---|---|
| `PVE1_HOST` | `192.0.2.1` | pve1 management IP |
| `PVE1_ADDR` | `192.0.2.1` | pve1 display address |
| `PVE2_ADDR` | `192.0.2.2` | pve2 display address |
| `PVE3_ADDR` | `192.0.2.3` | pve3 display address |
| `PVE4_ADDR` | `192.0.2.4` | pve4 display address |
| `MIHOMO_CONFIG` | `/etc/mihomo/config.yaml` | mihomo config path |
| `DNSMASQ_CONFIG` | `/etc/dnsmasq.conf` | dnsmasq config path |
| `DNSMASQ_LEASES` | `/var/lib/misc/dnsmasq.leases` | dnsmasq leases file |
| `PROXY_MANAGER_ALLOW_WRITE` | `0` | Set to `1` to enable config writes |
| `PORT` | `8088` | HTTP listen port |

## Run

```bash
cd proxy-router-manager-ui
pip install -r requirements.txt

# Read-only preview
python3 server.py --host 0.0.0.0 --port 8088

# Write-enabled (backs up config before each change)
PROXY_MANAGER_ALLOW_WRITE=1 python3 server.py --host 0.0.0.0 --port 8088
```

Open `http://<your-router-ip>:8088/`

## Systemd

```ini
[Unit]
Description=Proxy Router Manager UI
After=network.target mihomo.service

[Service]
Type=simple
WorkingDirectory=/opt/proxy-manager-ui
Environment=PROXY_MANAGER_ALLOW_WRITE=1
ExecStart=/usr/bin/python3 server.py --host 0.0.0.0 --port 8088
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## License

MIT
