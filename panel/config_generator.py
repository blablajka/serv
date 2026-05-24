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

    if not os.path.exists("/etc/sing-box/hy2.crt"):
        os.system('openssl req -x509 -newkey rsa:4096 -keyout /etc/sing-box/hy2.key -out /etc/sing-box/hy2.crt -days 3650 -nodes -subj "/CN=bing.com" >/dev/null 2>&1')

    hy2_users = []
    clients_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "clients_db.json")
    try:
        if os.path.exists(clients_db_path):
            with open(clients_db_path, "r", encoding="utf-8") as f:
                clients_db = json.load(f)
                for cid, data in clients_db.items():
                    if "hy2_password" in data:
                        hy2_users.append({"password": data["hy2_password"]})
    except Exception as e:
        print("Error loading clients_db for hy2_users:", e)
        
    if not hy2_users:
        hy2_users.append({"password": "testpassword123"})

    masquerade_url = "https://www.bing.com"
    domains_txt_path = "/opt/smart_vpn/Reality-SNI-Finder/domains.txt"
    if os.path.exists(domains_txt_path):
        try:
            with open(domains_txt_path, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
                if first_line:
                    masquerade_url = f"https://{first_line}"
        except Exception:
            pass

    config = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "tag": "dns-cloudflare",
                    "type": "https",
                    "server": "1.1.1.1",
                    "server_port": 443,
                    "path": "/dns-query",
                    "tls": {
                        "enabled": True,
                        "server_name": "cloudflare-dns.com"
                    },
                    "detour": "Select-Outbound"
                },
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
                    "detour": "direct"
                },
                {"tag": "dns-local", "type": "local"}
            ],
            "rules": [
                {
                    "domain_suffix": [
                        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
                        "youtube.googleapis.com", "youtubei.googleapis.com",
                        "youtubeembeddedplayer.googleapis.com", "jnn-pa.googleapis.com",
                        "youtube-nocookie.com", "youtubekids.com",
                        "wide-youtube.l.google.com", "youtube-ui.l.google.com",
                        "yt-video-upload.l.google.com", "ytimg.l.google.com"
                    ],
                    "server": "dns-google"
                }
            ],
            "final": "dns-cloudflare",
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "inet4_address": "10.255.0.1/24",
                "auto_route": True,
                "strict_route": True,
                "endpoint_independent_nat": True,
                "stack": "system",
                "sniff": True
            },
            {
                "type": "hysteria2",
                "tag": "hy2-in",
                "listen": "::",
                "listen_port": 8443,
                "users": hy2_users,
                "up_mbps": 1000,
                "down_mbps": 1000,
                "masquerade": masquerade_url,
                "tls": {
                    "enabled": True,
                    "server_name": "blueorb.online",
                    "certificate_path": "/etc/letsencrypt/live/blueorb.online/fullchain.pem",
                    "key_path": "/etc/letsencrypt/live/blueorb.online/privkey.pem"
                }
            }
        ],
        "endpoints": endpoints,
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"inbound": "tun-in", "action": "sniff"},
                {"port": 53, "action": "hijack-dns"},
                {
                    "network": "udp",
                    "port": 443,
                    "domain_suffix": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com"],
                    "action": "reject"
                },
                {
                    "domain_suffix": [
                        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
                        "youtube.googleapis.com", "youtubei.googleapis.com",
                        "youtubeembeddedplayer.googleapis.com", "jnn-pa.googleapis.com",
                        "youtube-nocookie.com", "youtubekids.com",
                        "wide-youtube.l.google.com", "youtube-ui.l.google.com",
                        "yt-video-upload.l.google.com", "ytimg.l.google.com",
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
