import json
import os
import subprocess
import asyncio
import re
import logging
import httpx
import aiofiles
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import Optional, List
import paramiko
import secrets

app = FastAPI()
security = HTTPBasic()
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

PANEL_DIR = os.path.dirname(os.path.abspath(__file__))
SERVERS_FILE = os.path.join(PANEL_DIR, "servers.json")
CONFIG_FILE = "/etc/sing-box/config.json"
ADMIN_USER = os.environ.get("PANEL_USER", "admin")
ADMIN_PASS = os.environ.get("PANEL_PASS", "admin")

app.mount("/static", StaticFiles(directory=os.path.join(PANEL_DIR, "static")), name="static")

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = secrets.compare_digest(credentials.username, ADMIN_USER)
    correct_pass = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (correct_user and correct_pass):
        raise HTTPException(status_code=401, detail="Неверные учётные данные",
                            headers={"WWW-Authenticate": "Basic"})
    return credentials.username

def load_servers():
    if os.path.exists(SERVERS_FILE):
        try:
            with open(SERVERS_FILE, "r") as f:
                return json.load(f)
        except:
            return []
    return []

def save_servers(servers):
    with open(SERVERS_FILE, "w") as f:
        json.dump(servers, f, indent=2, ensure_ascii=False)

def reload_singbox():
    try:
        subprocess.run(["systemctl", "restart", "sing-box"], timeout=10)
    except Exception as e:
        logger.error(f"Ошибка перезапуска sing-box: {e}")

class ServerModel(BaseModel):
    name: str
    ip: str
    port: int
    local_address: str
    private_key: str
    peer_public_key: str
    limit_gb: Optional[float] = 0
    limit_users: Optional[int] = 0
    ssh_port: Optional[int] = 22
    ssh_user: Optional[str] = "root"
    ssh_password: Optional[str] = ""
    amnezia_obfs: Optional[dict] = {}

class AutoInstallModel(BaseModel):
    name: str
    ip: str
    ssh_port: Optional[int] = 22
    ssh_user: Optional[str] = "root"
    ssh_password: str
    limit_gb: Optional[float] = 0
    limit_users: Optional[int] = 0

@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = os.path.join(PANEL_DIR, "static", "index.html")
    async with aiofiles.open(index_path, "r", encoding="utf-8") as f:
        return await f.read()

@app.get("/api/status")
async def get_status(username: str = Depends(verify_credentials)):
    servers = load_servers()
    sb_running = False
    try:
        result = subprocess.run(["systemctl", "is-active", "sing-box"], capture_output=True, text=True, timeout=5)
        sb_running = result.stdout.strip() == "active"
    except:
        pass
    return {
        "sing_box_running": sb_running,
        "servers_count": len(servers),
        "servers": [{
            "name": s["name"],
            "ip": s["ip"],
            "port": s["port"],
            "limit_gb": s.get("limit_gb", 0),
            "limit_users": s.get("limit_users", 0)
        } for s in servers]
    }

@app.get("/api/logs")
async def get_logs(username: str = Depends(verify_credentials), lines: int = 50):
    try:
        result = subprocess.run(
            ["journalctl", "-u", "sing-box", f"-n", str(lines), "--no-pager", "-o", "short"],
            capture_output=True, text=True, timeout=10
        )
        log_lines = result.stdout.strip().split("\n")
        panel_result = subprocess.run(
            ["journalctl", "-u", "smart-vpn-panel", "-n", "20", "--no-pager", "-o", "short"],
            capture_output=True, text=True, timeout=10
        )
        panel_lines = panel_result.stdout.strip().split("\n")
        return {"logs": log_lines + ["--- Panel ---"] + panel_lines}
    except Exception as e:
        return {"logs": [f"Ошибка получения логов: {e}"]}

@app.get("/api/servers")
async def get_servers(username: str = Depends(verify_credentials)):
    return load_servers()

@app.post("/api/servers")
async def add_server(server: ServerModel, username: str = Depends(verify_credentials)):
    servers = load_servers()
    server_dict = server.dict()
    servers.append(server_dict)
    save_servers(servers)
    from config_generator import generate_singbox_config
    generate_singbox_config(servers, CONFIG_FILE)
    reload_singbox()
    return {"status": "ok", "message": "Сервер добавлен"}

@app.delete("/api/servers/{server_name}")
async def delete_server(server_name: str, username: str = Depends(verify_credentials)):
    servers = load_servers()
    servers = [s for s in servers if s["name"] != server_name]
    save_servers(servers)
    from config_generator import generate_singbox_config
    generate_singbox_config(servers, CONFIG_FILE)
    reload_singbox()
    return {"status": "ok"}

@app.post("/api/servers/auto-install")
async def auto_install_server(data: AutoInstallModel, username: str = Depends(verify_credentials)):
    logger.info(f"Начинаем автоустановку на {data.ip}...")

    def run_ssh(ssh_client, cmd, timeout=300):
        """Выполнить команду и вернуть (stdout, stderr, exit_code)"""
        stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return out, err, exit_code

    try:
        import random

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=data.ip, port=data.ssh_port, username=data.ssh_user,
                    password=data.ssh_password, timeout=30)
        logger.info(f"SSH подключение к {data.ip} установлено")

        # Шаг 1: Установка AmneziaWG через PPA (Ubuntu 22.04)
        logger.info("Устанавливаем AmneziaWG на зарубежный сервер...")
        commands = [
            "DEBIAN_FRONTEND=noninteractive apt-get update -y",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common curl",
            "add-apt-repository ppa:amnezia/ppa -y",
            "DEBIAN_FRONTEND=noninteractive apt-get update -y",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y amneziawg-dkms amneziawg-tools",
            "mkdir -p /etc/amnezia/amneziawg",
        ]
        for cmd in commands:
            out, err, code = run_ssh(ssh, cmd, timeout=300)
            logger.info(f"[{code}] {cmd[:60]}")
            if code != 0 and "apt-get install" in cmd and "amneziawg" in cmd:
                raise Exception(f"Ошибка установки AmneziaWG: {err[:500]}")

        # Шаг 2: Генерация серверных ключей на зарубежном сервере
        logger.info("Генерируем серверные ключи...")
        out, err, code = run_ssh(ssh, "awg genkey | tee /etc/amnezia/amneziawg/server_private.key | awg pubkey | tee /etc/amnezia/amneziawg/server_public.key")
        if code != 0:
            raise Exception(f"Ошибка генерации серверных ключей: {err}")

        out, err, code = run_ssh(ssh, "cat /etc/amnezia/amneziawg/server_private.key")
        if not out:
            raise Exception("Серверный приватный ключ пустой!")
        server_private_key = out.strip()

        out, err, code = run_ssh(ssh, "cat /etc/amnezia/amneziawg/server_public.key")
        if not out:
            raise Exception("Серверный публичный ключ пустой!")
        server_public_key = out.strip()
        logger.info(f"Серверный pubkey: {server_public_key[:20]}...")

        # Шаг 3: Генерируем клиентские ключи тоже на зарубежном сервере
        logger.info("Генерируем клиентские ключи...")
        out, err, code = run_ssh(ssh, "awg genkey | tee /tmp/client_priv.key | awg pubkey | tee /tmp/client_pub.key")
        if code != 0:
            raise Exception(f"Ошибка генерации клиентских ключей: {err}")

        out, err, code = run_ssh(ssh, "cat /tmp/client_priv.key")
        if not out:
            raise Exception("Клиентский приватный ключ пустой!")
        client_private_key = out.strip()

        out, err, code = run_ssh(ssh, "cat /tmp/client_pub.key")
        if not out:
            raise Exception("Клиентский публичный ключ пустой!")
        client_public_key = out.strip()
        logger.info(f"Клиентский pubkey: {client_public_key[:20]}...")

        # Шаг 4: Параметры обфускации и порт
        obfs = {
            "jc": random.randint(3, 120),
            "jmin": random.randint(10, 50),
            "jmax": random.randint(500, 1000),
            "s1": random.randint(15, 150),
            "s2": random.randint(15, 150),
            "s3": 0, "s4": 0,
            "h1": 1, "h2": 2, "h3": 3, "h4": 4
        }
        wg_port = random.randint(20000, 60000)

        # Определяем сетевой интерфейс
        out, _, _ = run_ssh(ssh, "ip route | grep default | awk '{print $5}' | head -1")
        net_iface = out.strip() or "eth0"
        logger.info(f"Сетевой интерфейс: {net_iface}")

        # Шаг 5: Создаём конфиг AmneziaWG
        wg_conf = (
            "[Interface]\n"
            f"PrivateKey = {server_private_key}\n"
            f"Address = 10.66.66.1/24\n"
            f"ListenPort = {wg_port}\n"
            f"Jc = {obfs['jc']}\n"
            f"Jmin = {obfs['jmin']}\n"
            f"Jmax = {obfs['jmax']}\n"
            f"S1 = {obfs['s1']}\n"
            f"S2 = {obfs['s2']}\n"
            f"H1 = {obfs['h1']}\n"
            f"H2 = {obfs['h2']}\n"
            f"H3 = {obfs['h3']}\n"
            f"H4 = {obfs['h4']}\n"
            "SaveConfig = false\n"
            f"PostUp = iptables -A FORWARD -i awg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o {net_iface} -j MASQUERADE\n"
            f"PostDown = iptables -D FORWARD -i awg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o {net_iface} -j MASQUERADE\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {client_public_key}\n"
            f"AllowedIPs = 10.66.66.2/32\n"
        )

        # Записываем конфиг через SFTP
        logger.info("Записываем конфиг awg0...")
        sftp = ssh.open_sftp()
        with sftp.file('/etc/amnezia/amneziawg/awg0.conf', 'w') as f:
            f.write(wg_conf)
        sftp.close()

        # Шаг 6: Включаем IP-форвардинг и запускаем AWG
        run_ssh(ssh, "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-vpn.conf && sysctl -p /etc/sysctl.d/99-vpn.conf")
        run_ssh(ssh, "systemctl stop awg-quick@awg0 || true")
        run_ssh(ssh, "systemctl enable --now awg-quick@awg0")
        run_ssh(ssh, f"ufw allow {wg_port}/udp || true")

        # Удаляем временные ключевые файлы
        run_ssh(ssh, "rm -f /tmp/client_priv.key /tmp/client_pub.key")

        out, err, code = run_ssh(ssh, "systemctl is-active awg-quick@awg0")
        logger.info(f"Статус awg0: '{out}' (код {code})")
        ssh.close()

        if out != "active":
            raise Exception(f"awg-quick@awg0 не запустился. Проверьте логи: journalctl -u awg-quick@awg0")

        # Шаг 7: Сохраняем и перезапускаем sing-box
        server = {
            "name": data.name,
            "ip": data.ip,
            "port": wg_port,
            "local_address": "10.66.66.2/32",
            "private_key": client_private_key,
            "peer_public_key": server_public_key,
            "limit_gb": data.limit_gb,
            "limit_users": data.limit_users,
            "ssh_port": data.ssh_port,
            "ssh_user": data.ssh_user,
            "ssh_password": data.ssh_password,
            "wg_interface": "awg0",
            "amnezia_obfs": obfs
        }

        servers = load_servers()
        servers.append(server)
        save_servers(servers)

        from config_generator import generate_singbox_config
        generate_singbox_config(servers, CONFIG_FILE)
        reload_singbox()

        logger.info(f"Сервер {data.name} ({data.ip}:{wg_port}) успешно добавлен!")
        return {"status": "ok", "message": f"Сервер {data.name} установлен и подключён!"}

    except Exception as e:
        logger.error(f"Ошибка автоустановки на {data.ip}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/orchestrator/status")
async def orchestrator_status(username: str = Depends(verify_credentials)):
    servers = load_servers()
    results = []
    for server in servers:
        results.append({
            "name": server["name"],
            "ip": server["ip"],
            "status": "configured"
        })
    return {"servers": results}
