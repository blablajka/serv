import json
import os

def generate_singbox_config(servers, output_path="/etc/sing-box/config.json"):
    """
    Генерирует конфиг sing-box-extended в формате 1.13+.
    Endpoint-теги используются напрямую в selector (без detour-outbounds).
    Поле amnezia — на уровне endpoint, не peer.
    """
    
    endpoints = []
    outbounds = [
        {"type": "direct", "tag": "direct"}
    ]
    
    selector_outbounds = ["direct"]
    
    for server in servers:
        tag = server["name"]
        endpoint_tag = f"ep-{tag}"
        # endpoint_tag используется напрямую в selector — detour не нужен
        selector_outbounds.append(endpoint_tag)
        
        obfs_params = server.get("amnezia_obfs", {})
        
        # Peer config для endpoint
        peer = {
            "address": server["ip"],
            "port": server["port"],
            "public_key": server["peer_public_key"],
            "allowed_ips": ["0.0.0.0/0"],
            "persistent_keepalive_interval": 25
        }
        
        # AmneziaWG обфускация — поле "amnezia" в ENDPOINT (не в peer!)
        # Строчные буквы: jc, jmin, jmax, s1-s4, h1-h4
        amnezia = None
        if obfs_params:
            amnezia = {
                "jc": obfs_params.get("jc", 120),
                "jmin": obfs_params.get("jmin", 23),
                "jmax": obfs_params.get("jmax", 911),
                "s1": obfs_params.get("s1", 0),
                "s2": obfs_params.get("s2", 0),
                "s3": obfs_params.get("s3", 0),
                "s4": obfs_params.get("s4", 0),
                "h1": obfs_params.get("h1", 1),
                "h2": obfs_params.get("h2", 2),
                "h3": obfs_params.get("h3", 3),
                "h4": obfs_params.get("h4", 4)
            }

        # Endpoint (физическое WireGuard-соединение)
        endpoint = {
            "type": "wireguard",
            "tag": endpoint_tag,
            "mtu": 1400,
            "address": [server["local_address"]],
            "private_key": server["private_key"],
            "domain_resolver": "dns-local",
            "peers": [peer]
        }
        if amnezia:
            endpoint["amnezia"] = amnezia
        endpoints.append(endpoint)

    outbounds.append({
        "type": "selector",
        "tag": "Select-Outbound",
        "outbounds": selector_outbounds,
        "default": selector_outbounds[-1] if len(selector_outbounds) > 1 else "direct"
    })

    config = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "tag": "dns-google",
                    "type": "https",
                    "server": "8.8.8.8",
                    "server_port": 443,
                    "path": "/dns-query",
                    "tls": {
                        "enabled": True,
                        "server_name": "dns.google"
                    },
                    "detour": "Select-Outbound"
                },
                {"tag": "dns-local", "type": "local"}
            ],
            "rules": [],
            "final": "dns-google",
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "address": ["10.255.0.1/24"],
                "mtu": 1400,
                "udp_timeout": "1m",
                "auto_route": False,
                "strict_route": False
            }
        ],
        "endpoints": endpoints,
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"inbound": "tun-in", "action": "sniff"},
                {"port": 53, "action": "hijack-dns"},
                {
                    "domain_suffix": [
                        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
                        "discord.com", "discord.gg", "discordapp.net"
                    ],
                    "outbound": "direct"
                }
            ],
            "auto_detect_interface": True,
            "final": "Select-Outbound",
            "default_domain_resolver": "dns-local"
        },
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "",
                "secret": "",
                "default_mode": "rule"
            }
        }
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
