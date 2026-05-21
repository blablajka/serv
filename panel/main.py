from fastapi import FastAPI, HTTPException, Request, Depends, status, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import httpx
import json
import os
import subprocess
import asyncio
import secrets
import paramiko
import time
import logging
import random
import aiofiles
from collections import deque
import datetime

from config_generator import generate_singbox_config

# Настраиваем кастомный логгер — сохраняем логи оркестратора в память для веба
orchestrator_logs = deque(maxlen=100)

class MemoryHandler(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        orchestrator_logs.appendleft(log_entry)

logger = logging.getLogger("SmartVPN")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

mh = MemoryHandler()
mh.setFormatter(formatter)
logger.addHandler(mh)

app = FastAPI(title="Smart VPN Panel")
security = HTTPBasic()

PANEL_DIR = os.path.dirname(os.path.abspath(__file__))
SERVERS_FILE = os.path.join(PANEL_DIR, "servers.json")
CONFIG_FILE = "/etc/sing-box/config.json"
AWG_SERVER_API = "http://127.0.0.1:8080"
AWG_TOKEN = os.environ.get("AWG_TOKEN", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
CLASH_API_URL = "http://127.0.0.1:9090"
CLASH_SELECTOR = "Select-Outbound"

app.mount("/static", StaticFiles(directory=os.path.join(PANEL_DIR, "static")), name="static")

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USER)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def load_servers():
    if not os.path.exists(SERVERS_FILE):
        return []
    try:
        with open(SERVERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return []

def save_servers(servers):
    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        json.dump(servers, f, indent=2, ensure_ascii=False)
    generate_singbox_config(servers, CONFIG_FILE)
    try:
        subprocess.run(["systemctl", "restart", "sing-box"], check=True, timeout=15)
    except Exception as e:
        logger.error(f"Failed to restart sing-box: {e}")

class ServerModel(BaseModel):
    name: str
    ip: str
    port: int
    local_address: str
    private_key: str
    peer_public_key: str
    limit_gb: int = 30
    limit_users: int = 5
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_password: str = ""
    ssh_key_path: str = ""
    wg_interface: str = "awg0"
    amnezia_obfs: dict = {}

class AutoInstallModel(BaseModel):
    name: str
    ip: str
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_password: str
    limit_gb: int = 30
    limit_users: int = 5

# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def index(username: str = Depends(verify_credentials)):
    index_path = os.path.join(PANEL_DIR, "static", "index.html")
    async with aiofiles.open(index_path, "r", encoding="utf-8") as f:
        return await f.read()

@app.get("/api/servers")
async def get_servers(username: str = Depends(verify_credentials)):
    servers = load_servers()
    # Маскируем секретные данные
    result = []
    for s in servers:
        s2 = dict(s)
        s2["private_key"] = "***"
        if "ssh_password" in s2:
            s2["ssh_password"] = "***"
        result.append(s2)
    return result

@app.post("/api/servers")
async def add_server(server: ServerModel, username: str = Depends(verify_credentials)):
    servers = load_servers()
    srv_dict = server.dict()
    servers.append(srv_dict)
    save_servers(servers)
    return {"status": "ok"}

@app.delete("/api/servers/{name}")
async def delete_server(name: str, username: str = Depends(verify_credentials)):
    servers = load_servers()
    servers = [s for s in servers if s["name"] != name]
    save_servers(servers)
    return {"status": "ok"}

@app.post("/api/servers/auto-install")
async def auto_install_server(data: AutoInstallModel, username: str = Depends(verify_credentials)):
    logger.info(f"Начинаем автоустановку на {data.ip}...")

    def run_ssh(ssh_client, cmd, timeout=300):
        """Выполнить команду через SSH, вернуть (stdout, stderr, exit_code)"""
        stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return out, err, exit_code

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=data.ip, port=data.ssh_port, username=data.ssh_user,
                    password=data.ssh_password, timeout=30)
        logger.info(f"SSH подключение к {data.ip} установлено")

        # Шаг 1: Установка AmneziaWG через PPA (Ubuntu 22.04)
        logger.info("Устанавливаем AmneziaWG на зарубежный сервер...")
        install_cmds = [
            # Ждём пока отпустят dpkg-лок (авто-обновления и т.п.)
            "while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do echo 'Ждём dpkg...'; sleep 5; done",
            "sudo DEBIAN_FRONTEND=noninteractive apt-get update -y",
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common",
            "sudo add-apt-repository ppa:amnezia/ppa -y",
            "sudo DEBIAN_FRONTEND=noninteractive apt-get update -y",
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y amneziawg-dkms amneziawg-tools",
            "sudo mkdir -p /etc/amnezia/amneziawg",
        ]
        for cmd in install_cmds:
            out, err, code = run_ssh(ssh, cmd, timeout=600)
            logger.info(f"[{code}] {cmd[:70]}")
            if code != 0 and "amneziawg" in cmd and "install" in cmd:
                raise Exception(f"Ошибка установки AmneziaWG: {err[:500]}")


        # Шаг 2: Генерация серверных ключей на зарубежном сервере
        logger.info("Генерируем серверные ключи на зарубежном сервере...")
        out, err, code = run_ssh(ssh, "sudo awg genkey | sudo tee /etc/amnezia/amneziawg/server_private.key | sudo awg pubkey | sudo tee /etc/amnezia/amneziawg/server_public.key")
        if code != 0:
            raise Exception(f"Ошибка генерации серверных ключей: {err}")

        out, err, code = run_ssh(ssh, "sudo cat /etc/amnezia/amneziawg/server_private.key")
        if not out:
            raise Exception("Серверный приватный ключ пустой!")
        server_private_key = out.strip()

        out, err, code = run_ssh(ssh, "sudo cat /etc/amnezia/amneziawg/server_public.key")
        if not out:
            raise Exception("Серверный публичный ключ пустой!")
        server_public_key = out.strip()
        logger.info(f"Серверный pubkey: {server_public_key[:20]}...")

        # Шаг 3: Генерируем клиентские ключи на зарубежном сервере
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
        logger.info(f"Сетевой интерфейс: {net_iface}, порт: {wg_port}")

        # Шаг 5: Создаём конфиг AmneziaWG на зарубежном сервере
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

        # Записываем конфиг через /tmp (SFTP не требует root)
        sftp = ssh.open_sftp()
        with sftp.file('/tmp/awg0.conf', 'w') as f:
            f.write(wg_conf)
        sftp.close()
        run_ssh(ssh, "sudo mv /tmp/awg0.conf /etc/amnezia/amneziawg/awg0.conf")
        run_ssh(ssh, "sudo chmod 600 /etc/amnezia/amneziawg/awg0.conf")

        # Шаг 6: Включаем IP-форвардинг и запускаем AWG
        run_ssh(ssh, "echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-vpn.conf && sudo sysctl -p /etc/sysctl.d/99-vpn.conf")
        run_ssh(ssh, "sudo systemctl stop awg-quick@awg0 2>/dev/null || true")
        run_ssh(ssh, "sudo systemctl enable --now awg-quick@awg0")
        run_ssh(ssh, f"sudo ufw allow {wg_port}/udp 2>/dev/null || true")
        run_ssh(ssh, "rm -f /tmp/client_priv.key /tmp/client_pub.key")

        out, err, code = run_ssh(ssh, "sudo systemctl is-active awg-quick@awg0")
        logger.info(f"Статус awg0: '{out}' (код {code})")
        ssh.close()

        if out != "active":
            raise Exception(f"awg-quick@awg0 не запустился! Проверьте: journalctl -u awg-quick@awg0")

        # Шаг 7: Сохраняем сервер и перезапускаем sing-box
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
            "ssh_key_path": "",
            "wg_interface": "awg0",
            "amnezia_obfs": obfs
        }

        servers = load_servers()
        servers.append(server)
        save_servers(servers)

        logger.info(f"Сервер {data.name} ({data.ip}:{wg_port}) успешно добавлен!")
        return {"status": "ok", "message": f"Сервер {data.name} установлен и подключён!"}

    except Exception as e:
        logger.error(f"Ошибка автоустановки на {data.ip}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs")
async def get_logs(username: str = Depends(verify_credentials)):
    logs_data = []

    # 1. Логи sing-box из journalctl
    try:
        sb_logs = subprocess.check_output(
            ["journalctl", "-u", "sing-box", "-n", "30", "-o", "cat"],
            stderr=subprocess.STDOUT, text=True
        )
        for line in reversed(sb_logs.strip().split('\n')):
            if line:
                logs_data.append(f"[SING-BOX] {line}")
    except FileNotFoundError:
        logs_data.append("[SING-BOX] journalctl не найден")
    except Exception as e:
        logs_data.append(f"[SING-BOX] Ошибка чтения логов: {e}")

    # 2. Логи оркестратора из памяти
    logs_data.extend(list(orchestrator_logs))

    return {"logs": logs_data}

@app.get("/api/status")
async def get_status(username: str = Depends(verify_credentials)):
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{CLASH_API_URL}/proxies/{CLASH_SELECTOR}", timeout=2)
            if r.status_code == 200:
                data = r.json()
                return {"now": data.get("now"), "orchestrator_cache": last_orchestrator_stats}
    except:
        pass
    return {"error": "Clash API недоступен", "orchestrator_cache": last_orchestrator_stats}

async def proxy_awg(method: str, endpoint: str, data=None):
    headers = {"Authorization": f"Bearer {AWG_TOKEN}"} if AWG_TOKEN else {}
    url = f"{AWG_SERVER_API}{endpoint}"
    async with httpx.AsyncClient() as client:
        if method == "GET":
            r = await client.get(url, headers=headers)
        elif method == "POST":
            r = await client.post(url, json=data, headers=headers)
        elif method == "DELETE":
            r = await client.delete(url, headers=headers)
        return JSONResponse(content=r.json(), status_code=r.status_code)

@app.get("/api/clients")
async def get_clients(username: str = Depends(verify_credentials)):
    return await proxy_awg("GET", "/clients")

@app.post("/api/clients")
async def create_client(request: Request, username: str = Depends(verify_credentials)):
    data = await request.json()
    return await proxy_awg("POST", "/clients", data)

@app.delete("/api/clients/{client_id}")
async def delete_client(client_id: str, username: str = Depends(verify_credentials)):
    return await proxy_awg("DELETE", f"/clients/{client_id}")

@app.get("/api/clients/{client_id}/config")
async def get_client_config(client_id: str, username: str = Depends(verify_credentials)):
    headers = {"Authorization": f"Bearer {AWG_TOKEN}"} if AWG_TOKEN else {}
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{AWG_SERVER_API}/clients/{client_id}/config", headers=headers)
        return {"config": r.text}

# --- Orchestrator Logic ---
last_orchestrator_stats = {}

def get_server_stats(server):
    """SSH на зарубежный сервер, получаем трафик и кол-во активных пиров"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        key_path = server.get("ssh_key_path", "")
        if key_path and os.path.exists(key_path):
            ssh.connect(hostname=server["ip"], port=server.get("ssh_port", 22),
                        username=server.get("ssh_user", "root"), key_filename=key_path, timeout=5)
        else:
            ssh.connect(hostname=server["ip"], port=server.get("ssh_port", 22),
                        username=server.get("ssh_user", "root"),
                        password=server.get("ssh_password", ""), timeout=5)

        iface = server.get("wg_interface", "awg0")
        stdin, stdout, stderr = ssh.exec_command(f"awg show {iface} transfer")
        transfer_data = stdout.read().decode('utf-8').strip()

        stdin, stdout, stderr = ssh.exec_command(f"awg show {iface} latest-handshakes")
        handshake_data = stdout.read().decode('utf-8').strip()
        ssh.close()

        total_bytes = sum([int(p[1]) + int(p[2]) for line in transfer_data.split('\n')
                           if (p := line.split()) and len(p) >= 3])
        total_gb = total_bytes / (1024**3)

        active_users = sum([1 for line in handshake_data.split('\n')
                            if (p := line.split()) and len(p) >= 2
                            and int(p[1]) > 0 and (time.time() - int(p[1])) < 300])

        return total_gb, active_users, True
    except Exception as e:
        logger.error(f"Healthcheck failed for {server['name']}: {e}")
        return 0, 0, False

async def switch_outbound(target_name):
    """Переключить активный outbound через Clash API"""
    async with httpx.AsyncClient() as client:
        await client.put(f"{CLASH_API_URL}/proxies/{CLASH_SELECTOR}", json={"name": target_name})
        logger.info(f"SWITCH EVENT: Переключение на -> {target_name}")

async def orchestrator_loop():
    """Мониторинг серверов и автопереключение"""
    global last_orchestrator_stats
    while True:
        try:
            servers = load_servers()
            if not servers:
                await asyncio.sleep(60)
                continue

            available_servers = []

            for srv in servers:
                gb, users, is_alive = get_server_stats(srv)
                last_orchestrator_stats[srv["name"]] = {"gb": gb, "users": users, "alive": is_alive}

                if not is_alive:
                    continue
                if srv.get("limit_gb", 0) > 0 and gb >= srv["limit_gb"]:
                    continue
                if srv.get("limit_users", 0) > 0 and users >= srv["limit_users"]:
                    continue

                available_servers.append((srv, users, gb))

            # Узнаём текущий outbound
            current = None
            async with httpx.AsyncClient() as client:
                try:
                    r = await client.get(f"{CLASH_API_URL}/proxies/{CLASH_SELECTOR}", timeout=2)
                    if r.status_code == 200:
                        current = r.json().get("now")
                except:
                    pass

            if available_servers:
                available_servers.sort(key=lambda x: (x[1], x[2]))
                best = available_servers[0][0]
                best_tag = f"ep-{best['name']}"

                if current != best_tag:
                    current_stats = last_orchestrator_stats.get(current, {})
                    is_current_ok = (current_stats.get("alive") and
                                     current_stats.get("gb", 0) < next(
                                         (s["limit_gb"] for s in servers if f"ep-{s['name']}" == current), 9999))
                    if not is_current_ok:
                        await switch_outbound(best_tag)
            else:
                logger.warning("АХТУНГ: Все серверы недоступны или исчерпали лимиты! Fallback на direct.")
                if current != "direct":
                    await switch_outbound("direct")

        except Exception as e:
            logger.error(f"Orchestrator error: {e}")

        await asyncio.sleep(60)

# --- App Lifecycle ---
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(orchestrator_loop())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
