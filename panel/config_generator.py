import json
import os

def generate_singbox_config(servers, output_path="/etc/sing-box/config.json"):
    """
    Генерирует конфиг sing-box-extended в формате 1.13+.
    
    Ключевые изменения (миграция):
    - WireGuard теперь в секции "endpoints", а не "outbounds"
    - В outbounds используется type=wireguard с detour на endpoint
    - DNS серверы: новый формат с полем "type"
    - Нет "dns" outbound — вместо него action "hijack-dns" в route rules
    - Нет "sniff" в inbound — вместо него action "sniff" в route rules
    - Нет "outbound" в dns rules — вместо него "default_domain_resolver" в route
    """
    
    endpoints = []
    outbounds = [
        {"type": "direct", "tag": "direct"}
    ]
    
    selector_outbounds = ["direct"]
    
    for server in servers:
        tag = server["name"]
        endpoint_tag = f"ep-{tag}"
        selector_outbounds.append(tag)
        
        obfs_params = server.get("amnezia_obfs", {})
        
        # Peer config для endpoint
        peer = {
            "address": server["ip"],
            "port": server["port"],
            "public_key": server["peer_public_key"],
            "allowed_ips": ["0.0.0.0/0"],
            "persistent_keepalive_interval": 25
        }
        
        # AmneziaWG обфускация — поле "awg" в peer (формат sing-box-extended)
        if obfs_params:
            peer["awg"] = {
                "Jc": obfs_params.get("jc", 120),
                "Jmin": obfs_params.get("jmin", 23),
                "Jmax": obfs_params.get("jmax", 911),
                "S1": obfs_params.get("s1", 0),
                "S2": obfs_params.get("s2", 0),
                "H1": obfs_params.get("h1", 1),
                "H2": obfs_params.get("h2", 2),
                "H3": obfs_params.get("h3", 3),
                "H4": obfs_params.get("h4", 4)
            }

        # Endpoint (физическое WireGuard-соединение)
        endpoints.append({
            "type": "wireguard",
            "tag": endpoint_tag,
            "mtu": 1420,
            "address": [server["local_address"]],
            "private_key": server["private_key"],
            "domain_resolver": "dns-local",
            "peers": [peer]
        })
        
        # Outbound (ссылка на endpoint через detour)
        outbounds.append({
            "type": "wireguard",
            "tag": tag,
            "detour": endpoint_tag
        })

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
                {"tag": "dns-google", "type": "udp", "server": "8.8.8.8"},
                {"tag": "dns-local", "type": "local"}
            ],
            "final": "dns-google",
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "address": ["10.255.0.1/24"],
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
                {"ip_cidr": ["77.88.0.0/16", "5.255.0.0/16", "213.180.0.0/16"], "outbound": "direct"}
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
