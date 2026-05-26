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

    ws_path = "/secret-path"
    domain = "blueorb.online"
    clients_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "clients_db.json")
    try:
        if os.path.exists(clients_db_path):
            with open(clients_db_path, "r", encoding="utf-8") as f:
                db = json.load(f)
                if "__global__" in db:
                    ws_path = db["__global__"].get("ws_path", ws_path)
                    domain = db["__global__"].get("domain", domain)
    except Exception as e:
        print("Error loading clients_db:", e)

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
                    "detour": "Select-Outbound"
                },
                {"tag": "dns-local", "type": "local"}
            ],
            "rules": [
                {
                    "domain": [domain, "www.cloudflare.com"],
                    "server": "dns-local"
                },
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
                "address": ["10.255.0.1/24"],
                "auto_route": True,
                "strict_route": True,
                "endpoint_independent_nat": True,
                "stack": "system"
            },
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 1080
            }
        ],
        "endpoints": endpoints,
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"inbound": ["tun-in", "socks-in"], "action": "sniff"},
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


def generate_xray_config(db, output_path="/usr/local/etc/xray/config.json"):
    """
    Генерирует конфиг Xray-core (VLESS+Reality+XHTTP+Vision).
    Клиенты подтягиваются из db.
    """
    global_cfg = db.get("__global__", {})
    private_key = global_cfg.get("reality_private_key", "")
    short_ids = global_cfg.get("reality_short_ids", ["", "1a2b3c4d"])
    xhttp_path = global_cfg.get("xhttp_path", "/api/v1/stream/")
    server_names = global_cfg.get("reality_server_names", ["github.com", "objects.githubusercontent.com"])
    target = global_cfg.get("reality_target", "github.com:443")

    clients = []
    for cid, data in db.items():
        if cid == "__global__": continue
        if data.get("vless_uuid"):
            clients.append({
                "id": data["vless_uuid"],
                "email": cid,
                "flow": "xtls-rprx-vision",
                "level": 0
            })

    config = {
        "log": {
            "loglevel": "warning",
            "dnsLog": False,
            "access": "none"
        },
        "api": {
            "tag": "api",
            "listen": "127.0.0.1:10085",
            "services": ["HandlerService", "LoggerService", "StatsService"]
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "handshake": 4,
                    "connIdle": 300,
                    "uplinkOnly": 2,
                    "downlinkOnly": 5,
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                    "bufferSize": 0
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True
            }
        },
        "dns": {
            "servers": [
                "https+local://1.1.1.1/dns-query",
                "https+local://8.8.8.8/dns-query",
                {
                    "address": "127.0.0.1",
                    "port": 53,
                    "domains": ["geosite:private"]
                }
            ],
            "queryStrategy": "UseIP",
            "tag": "dns_inbound"
        },
        "inbounds": [
            {
                "tag": "vless-reality-xhttp",
                "listen": "0.0.0.0",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": clients,
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": target,
                        "xver": 0,
                        "serverNames": server_names,
                        "privateKey": private_key,
                        "minClientVer": "",
                        "maxClientVer": "",
                        "maxTimeDiff": 0,
                        "shortIds": short_ids
                    },
                    "xhttpSettings": {
                        "path": xhttp_path,
                        "mode": "auto",
                        "extra": {
                            "headers": {},
                            "xPaddingBytes": "100-1000",
                            "noSSEHeader": False,
                            "scMaxEachPostBytes": "500000-1000000",
                            "scMaxBufferedPosts": 30,
                            "scStreamUpServerSecs": "20-80"
                        }
                    }
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True
                }
            }
        ],
        "outbounds": [
            {
                "tag": "to-singbox",
                "protocol": "socks",
                "settings": {
                    "servers": [
                        {
                            "address": "127.0.0.1",
                            "port": 1080
                        }
                    ]
                },
                "streamSettings": {
                    "sockopt": {
                        "tcpFastOpen": True,
                        "tcpKeepAliveInterval": 30
                    }
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "UseIPv4"
                }
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {
                    "response": {"type": "http"}
                }
            },
            {
                "tag": "dns-out",
                "protocol": "dns"
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["vless-reality-xhttp"],
                    "port": 53,
                    "outboundTag": "dns-out"
                },
                {
                    "type": "field",
                    "protocol": ["bittorrent"],
                    "outboundTag": "block"
                },
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "block"
                },
                {
                    "type": "field",
                    "domain": [
                        "geosite:category-ads-all",
                        "geosite:category-porn"
                    ],
                    "outboundTag": "block"
                },
                {
                    "type": "field",
                    "outboundTag": "to-singbox",
                    "network": "tcp,udp"
                }
            ]
        }
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
