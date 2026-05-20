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
from collections import deque
import datetime

from config_generator import generate_singbox_config

# Настраиваем кастомный логгер, чтобы сохранять логи оркестратора в память для веба
orchestrator_logs = deque(maxlen=100)

class MemoryHandler(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        orchestrator_logs.appendleft(log_entry)

logger = logging.getLogger("SmartVPN")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Вывод в консоль
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

# Вывод в память для веб-морды
mh = MemoryHandler()
mh.setFormatter(formatter)
logger.addHandler(mh)

app = FastAPI(title="Smart VPN Panel")
security = HTTPBasic()

SERVERS_FILE = "servers.json"
AWG_SERVER_API = "http://127.0.0.1:8080"
AWG_TOKEN = os.environ.get("AWG_TOKEN", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
CLASH_API_URL = "http://127.0.0.1:9090"
CLASH_SELECTOR = "Select-Outbound"

app.mount("/static", StaticFiles(directory="static"), name="static")

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USER)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def load_servers():
    if not os.path.exists(SERVERS_FILE):
        return []
    with open(SERVERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_servers(servers):
    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        json.dump(servers, f, indent=2, ensure_ascii=False)
    
    generate_singbox_config(servers)
    try:
        subprocess.run(["systemctl", "restart", "sing-box"], check=True)
    except Exception as e:
        logging.error(f"Failed to restart sing-box: {e}")

class ServerModel(BaseModel):
    name: str
    ip: str
    port: int
    local_address: str
    private_key: str
    peer_public_key: str
    limit_gb: int
    limit_users: int
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_password: str = ""
    ssh_key_path: str = "/root/.ssh/id_rsa"
    wg_interface: str = "wg0"

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
    return FileResponse("static/index.html")

@app.get("/api/servers")
async def get_servers(username: str = Depends(verify_credentials)):
    servers = load_servers()
    # Mask private info
    for s in servers:
        s["private_key"] = "***"
        if "ssh_password" in s:
            s["ssh_password"] = "***"
    return servers

@app.post("/api/servers")
async def add_server(server: ServerModel, username: str = Depends(verify_credentials)):
    servers = load_servers()
    srv_dict = server.dict()
    # Don't save empty passwords if not needed
    if not srv_dict.get("ssh_password"):
        srv_dict.pop("ssh_password", None)
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
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=data.ip, port=data.ssh_port, username=data.ssh_user, password=data.ssh_password, timeout=15)
        
        # Генерируем случайные параметры обфускации
        import random
        obfs = {
            "jc": random.randint(3, 120),
            "jmin": random.randint(10, 50),
            "jmax": random.randint(500, 1000),
            "s1": random.randint(15, 150),
            "s2": random.randint(15, 150),
            "h1": 1, "h2": 2, "h3": 3, "h4": 4
        }
        
        # Универсальный скрипт установки AmneziaWG (Ubuntu/Debian)
        setup_script = """
        sudo apt update -y
        if grep -qi "ubuntu" /etc/os-release; then
            sudo add-apt-repository ppa:amnezia/ppa -y || true
            sudo apt update -y
            sudo apt install -y amneziawg-dkms amneziawg-tools
        else
            sudo apt install -y linux-headers-$(uname -r) build-essential dkms git
            rm -rf /tmp/awg-kernel /tmp/awg-tools
            git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git /tmp/awg-kernel
            cd /tmp/awg-kernel && sudo make module && sudo make install
            git clone https://github.com/amnezia-vpn/amneziawg-tools.git /tmp/awg-tools
            cd /tmp/awg-tools/src && sudo make && sudo make install
        fi
        sudo mkdir -p /etc/amnezia/amneziawg/
        sudo awg genkey | sudo tee /etc/amnezia/amneziawg/privatekey | sudo awg pubkey | sudo tee /etc/amnezia/amneziawg/publickey
        """
        stdin, stdout, stderr = ssh.exec_command(setup_script)
        stdout.channel.recv_exit_status()
            
        stdin, stdout, stderr = ssh.exec_command("sudo cat /etc/amnezia/amneziawg/privatekey")
        priv_key = stdout.read().decode().strip()
        stdin, stdout, stderr = ssh.exec_command("sudo cat /etc/amnezia/amneziawg/publickey")
        pub_key = stdout.read().decode().strip()
        
        wg_port = random.randint(20000, 60000)
        # Генерируем конфиг AmneziaWG
        wg_conf = f"""
[Interface]
PrivateKey = {priv_key}
Address = 10.0.0.1/24
ListenPort = {wg_port}
Jc = {obfs['jc']}
Jmin = {obfs['jmin']}
Jmax = {obfs['jmax']}
S1 = {obfs['s1']}
S2 = {obfs['s2']}
H1 = {obfs['h1']}
H2 = {obfs['h2']}
H3 = {obfs['h3']}
H4 = {obfs['h4']}
SaveConfig = false
PostUp = iptables -A FORWARD -i awg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i awg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
"""
        # Создаем временный файл и перемещаем через sudo
        sftp = ssh.open_sftp()
        with sftp.file('/tmp/awg0.conf', 'w') as f:
            f.write(wg_conf)
        sftp.close()
        
        ssh.exec_command("sudo mv /tmp/awg0.conf /etc/amnezia/amneziawg/awg0.conf")
        ssh.exec_command("sudo systemctl enable --now awg-quick@awg0")
        ssh.exec_command("echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-vpn.conf && sudo sysctl -p /etc/sysctl.d/99-vpn.conf")
        ssh.close()
        
        server = {
            "name": data.name,
            "ip": data.ip,
            "port": wg_port,
            "local_address": "10.0.0.2/32",
            "private_key": "",
            "peer_public_key": pub_key,
            "limit_gb": data.limit_gb,
            "limit_users": data.limit_users,
            "ssh_port": data.ssh_port,
            "ssh_user": data.ssh_user,
            "ssh_password": data.ssh_password,
            "ssh_key_path": "",
            "wg_interface": "awg0",
            "amnezia_obfs": obfs
        }
        
        # Генерация клиентских ключей ЛОКАЛЬНО
        priv = subprocess.check_output(["awg", "genkey"]).decode().strip()
        pub = subprocess.check_output(["awg", "pubkey"], input=priv.encode()).decode().strip()
        server["private_key"] = priv
        
        # Идем обратно на сервер и добавляем пира
        ssh.connect(hostname=data.ip, port=data.ssh_port, username=data.ssh_user, password=data.ssh_password)
        ssh.exec_command(f"sudo awg set awg0 peer {pub} allowed-ips 10.0.0.2/32")
        ssh.close()
        
        servers = load_servers()
        servers.append(server)
        save_servers(servers)
        
        return {"status": "ok", "message": "Успешно установлено и добавлено!"}
        
    except Exception as e:
        logger.error(f"Ошибка автоустановки: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка автоустановки: {str(e)}")

@app.get("/api/logs")
async def get_logs(username: str = Depends(verify_credentials)):
    logs_data = []
    
    # 1. Получаем логи sing-box
    try:
        sb_logs = subprocess.check_output(
            ["journalctl", "-u", "sing-box", "-n", "30", "-o", "cat"], 
            stderr=subprocess.STDOUT, text=True
        )
        for line in reversed(sb_logs.strip().split('\n')):
            if line:
                logs_data.append(f"[SING-BOX] {line}")
    except FileNotFoundError:
        logs_data.append("[SING-BOX] journalctl не найден (Windows/Test Env?)")
    except Exception as e:
        logs_data.append(f"[SING-BOX] Ошибка чтения логов: {e}")

    # 2. Добавляем логи оркестратора
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
        return {"error": "Clash API timeout or unavailable", "orchestrator_cache": last_orchestrator_stats}
    return {"now": "unknown", "orchestrator_cache": last_orchestrator_stats}

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
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        key_path = server.get("ssh_key_path", "")
        if key_path and os.path.exists(key_path):
            ssh.connect(hostname=server["ip"], port=server.get("ssh_port", 22), username=server.get("ssh_user", "root"), key_filename=key_path, timeout=5)
        else:
            ssh.connect(hostname=server["ip"], port=server.get("ssh_port", 22), username=server.get("ssh_user", "root"), password=server.get("ssh_password", ""), timeout=5)

        iface = server.get("wg_interface", "awg0")
        stdin, stdout, stderr = ssh.exec_command(f"sudo awg show {iface} transfer")
        transfer_data = stdout.read().decode('utf-8').strip()
        
        stdin, stdout, stderr = ssh.exec_command(f"sudo awg show {iface} latest-handshakes")
        handshake_data = stdout.read().decode('utf-8').strip()
        ssh.close()

        total_bytes = sum([int(p[1]) + int(p[2]) for line in transfer_data.split('\n') if (p := line.split()) and len(p) >= 3])
        total_gb = total_bytes / (1024**3)

        active_users = sum([1 for line in handshake_data.split('\n') if (p := line.split()) and len(p) >= 2 and int(p[1]) > 0 and (time.time() - int(p[1])) < 300])

        return total_gb, active_users, True
    except Exception as e:
        logger.error(f"Healthcheck failed for {server['name']}: {e}")
        return 0, 0, False

async def switch_outbound(target_name):
    async with httpx.AsyncClient() as client:
        await client.put(f"{CLASH_API_URL}/proxies/{CLASH_SELECTOR}", json={"name": target_name})
        logger.info(f"SWITCH EVENT: Переключение исходящего узла на -> {target_name}")

async def orchestrator_loop():
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
                status_str = "ALIVE" if is_alive else "DEAD"
                last_orchestrator_stats[srv["name"]] = {"gb": gb, "users": users, "alive": is_alive}
                
                if not is_alive:
                    continue
                
                if gb >= srv["limit_gb"] or users >= srv["limit_users"]:
                    continue
                
                available_servers.append((srv, users, gb))

            # Текущий
            current = None
            async with httpx.AsyncClient() as client:
                try:
                    r = await client.get(f"{CLASH_API_URL}/proxies/{CLASH_SELECTOR}")
                    if r.status_code == 200:
                        current = r.json().get("now")
                except: pass

            if available_servers:
                available_servers.sort(key=lambda x: (x[1], x[2]))
                best_name = available_servers[0][0]["name"]
                
                # Если текущий мертв или исчерпал лимиты, переключаем!
                if current != best_name:
                    current_stats = last_orchestrator_stats.get(current, {})
                    is_current_ok = current_stats.get("alive") and current_stats.get("gb", 0) < next((s["limit_gb"] for s in servers if s["name"] == current), 9999)
                    
                    if not is_current_ok:
                        await switch_outbound(best_name)
            else:
                logger.warning("АХТУНГ: Все зарубежные серверы недоступны или исчерпали лимиты! Fallback на direct.")
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
