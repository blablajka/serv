import json
import os

def generate_singbox_config(servers, output_path="/etc/sing-box/config.json"):
    outbounds = [
        {"type": "direct", "tag": "direct"}
    ]
    
    selector_outbounds = ["direct"]
    
    for server in servers:
        tag = server["name"]
        selector_outbounds.append(tag)
        
        obfs_params = server.get("amnezia_obfs", {})
        amnezia_config = {
            "jc": obfs_params.get("jc", 120),
            "jmin": obfs_params.get("jmin", 23),
            "jmax": obfs_params.get("jmax", 911),
            "s1": obfs_params.get("s1", 0),
            "s2": obfs_params.get("s2", 0),
            "h1": obfs_params.get("h1", 1),
            "h2": obfs_params.get("h2", 2),
            "h3": obfs_params.get("h3", 3),
            "h4": obfs_params.get("h4", 4)
        }

        outbounds.append({
            "type": "wireguard",
            "tag": tag,
            "server": server["ip"],
            "server_port": server["port"],
            "system_interface": False,
            "local_address": [server["local_address"]],
            "private_key": server["private_key"],
            "peer_public_key": server["peer_public_key"],
            "mtu": 1420,
            "domain_resolver": "dns-local",
            "amnezia": amnezia_config
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
                "strict_route": False,
                "sniff": True
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
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
