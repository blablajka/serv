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
import collections
from collections import deque
import datetime

class SSHPool:
    def __init__(self):
        self.clients = {}

    def get_client(self, server):
        ip = server["ip"]
        if ip in self.clients:
            client = self.clients[ip]
            if client.get_transport() and client.get_transport().is_active():
                try:
                    client.exec_command("echo 1", timeout=2)
                    return client
                except:
                    pass
            client.close()
            del self.clients[ip]
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            key_path = server.get("ssh_key_path", "")
            if key_path and os.path.exists(key_path):
                ssh.connect(hostname=ip, port=server.get("ssh_port", 22),
                            username=server.get("ssh_user", "root"), key_filename=key_path, timeout=5)
            else:
                ssh.connect(hostname=ip, port=server.get("ssh_port", 22),
                            username=server.get("ssh_user", "root"),
                            password=server.get("ssh_password", ""), timeout=5)
            self.clients[ip] = ssh
            return ssh
        except Exception as e:
            logger.error(f"SSH pool connect failed to {ip}: {e}")
            return None

ssh_pool = SSHPool()


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
AWG_TOKEN = os.environ.get("AWG_API_TOKEN") or os.environ.get("AWG_TOKEN", "secret_token_123")
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
def add_server(server: ServerModel, username: str = Depends(verify_credentials)):
    servers = load_servers()
    srv_dict = server.dict()
    servers.append(srv_dict)
    save_servers(servers)
    return {"status": "ok"}

@app.delete("/api/servers/{name}")
def delete_server(name: str, username: str = Depends(verify_credentials)):
    servers = load_servers()
    servers = [s for s in servers if s["name"] != name]
    save_servers(servers)
    return {"status": "ok"}

@app.post("/api/servers/auto-install")
def auto_install_server(data: AutoInstallModel, username: str = Depends(verify_credentials)):
    logger.info(f"Начинаем автоустановку на {data.ip}...")

    def run_ssh(ssh_client, cmd, timeout=300, sudo_pass=None):
        """Выполнить SSH-команду.
        sudo_pass — пишем в stdin для 'sudo -S'. Sudo кэширует credentials,
        поэтому достаточно один раз. Если пользователь root — sudo не нужен.
        """
        stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=timeout)
        if sudo_pass is not None:
            try:
                stdin.write(sudo_pass + "\n")
                stdin.flush()
            except Exception:
                pass
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        # Убираем строки sudo-промпта из вывода
        err = "\n".join(l for l in err.splitlines()
                        if "[sudo]" not in l and "password for" not in l.lower())
        return out, err, exit_code

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=data.ip, port=data.ssh_port, username=data.ssh_user,
                    password=data.ssh_password, timeout=30)
        logger.info(f"SSH подключение к {data.ip} установлено")

        sp = data.ssh_password  # sudo_pass shorthand

        # Определяем: мы root или нет?
        out_uid, _, _ = run_ssh(ssh, "id -u")
        is_root = out_uid.strip() == "0"
        logger.info(f"Пользователь: {'root' if is_root else data.ssh_user + ' (non-root, используем sudo -S)'}")

        # Если не root — кэшируем sudo credentials сразу
        if not is_root:
            out_sv, err_sv, code_sv = run_ssh(ssh, "sudo -S -v 2>&1", sudo_pass=sp)
            if code_sv != 0 and "incorrect" in (out_sv + err_sv).lower():
                raise Exception(f"sudo: неверный пароль для {data.ssh_user}. Проверьте SSH-пароль.")
            if code_sv != 0 and "not allowed" in (out_sv + err_sv).lower():
                raise Exception(f"Пользователь {data.ssh_user} не имеет прав sudo. Подключитесь как root.")
            logger.info("sudo credentials кэшированы")

        def S(cmd):
            """Обернуть в sudo -S если не root"""
            return cmd if is_root else f"sudo -S {cmd}"

        # Шаг 1: Установка AmneziaWG через PPA (Ubuntu 22.04)
        logger.info("Устанавливаем AmneziaWG на зарубежный сервер...")

        # Определяем версию ядра для правильной установки linux-headers
        kver_out, _, _ = run_ssh(ssh, "uname -r")
        kver = kver_out.strip()
        logger.info(f"Ядро: {kver}")

        install_cmds = [
            # Ждём освобождения dpkg-лока (unattended-upgrades и т.п.)
            S("bash -c 'while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do echo Waiting dpkg...; sleep 5; done'"),
            S("DEBIAN_FRONTEND=noninteractive apt-get update -y"),
            S("DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common"),
            S("add-apt-repository ppa:amnezia/ppa -y"),
            S("DEBIAN_FRONTEND=noninteractive apt-get update -y"),
            # linux-headers нужны для компиляции DKMS модуля
            S(f"DEBIAN_FRONTEND=noninteractive apt-get install -y linux-headers-{kver} || "
              f"DEBIAN_FRONTEND=noninteractive apt-get install -y linux-headers-generic"),
            S("DEBIAN_FRONTEND=noninteractive apt-get install -y amneziawg-dkms amneziawg-tools"),
            S("mkdir -p /etc/amnezia/amneziawg"),
            # Загружаем кернельный модуль
            S("modprobe amneziawg || true"),
        ]
        for cmd in install_cmds:
            out, err, code = run_ssh(ssh, cmd, timeout=600, sudo_pass=sp)
            logger.info(f"[{code}] {cmd[:80]}")
            if code != 0 and "amneziawg" in cmd and "install" in cmd:
                raise Exception(f"Ошибка установки AmneziaWG: {err[:500]}")

        # Шаг 2: Генерация серверных ключей во /tmp (awg genkey НЕ требует root!)
        # Потом sudo mv в /etc/ — один простой sudo без pipeline
        logger.info("Генерируем серверные ключи...")
        out, err, code = run_ssh(ssh,
            "awg genkey > /tmp/srv_priv.key && awg pubkey < /tmp/srv_priv.key > /tmp/srv_pub.key")
        if code != 0:
            raise Exception(f"Ошибка генерации серверных ключей: {err}")

        # Перемещаем в /etc/ с sudo (простая команда — нет pipeline, sudo -S работает корректно)
        run_ssh(ssh, S("mv /tmp/srv_priv.key /etc/amnezia/amneziawg/server_private.key"), sudo_pass=sp)
        run_ssh(ssh, S("mv /tmp/srv_pub.key  /etc/amnezia/amneziawg/server_public.key"),  sudo_pass=sp)
        run_ssh(ssh, S("chmod 600 /etc/amnezia/amneziawg/server_private.key"), sudo_pass=sp)

        out, err, code = run_ssh(ssh, S("cat /etc/amnezia/amneziawg/server_private.key"), sudo_pass=sp)
        if not out:
            raise Exception("Серверный приватный ключ пустой!")
        server_private_key = out.strip()

        out, err, code = run_ssh(ssh, S("cat /etc/amnezia/amneziawg/server_public.key"), sudo_pass=sp)
        if not out:
            raise Exception("Серверный публичный ключ пустой!")
        server_public_key = out.strip()
        logger.info(f"Серверный pubkey: {server_public_key[:20]}...")

        # Шаг 3: Генерируем клиентские ключи в /tmp (без root)
        logger.info("Генерируем клиентские ключи...")
        out, err, code = run_ssh(ssh, "awg genkey > /tmp/client_priv.key && awg pubkey < /tmp/client_priv.key > /tmp/client_pub.key")
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
        run_ssh(ssh, S("mv /tmp/awg0.conf /etc/amnezia/amneziawg/awg0.conf"), sudo_pass=sp)
        run_ssh(ssh, S("chmod 600 /etc/amnezia/amneziawg/awg0.conf"), sudo_pass=sp)

        # Шаг 6: IP-форвардинг и запуск AWG
        run_ssh(ssh, S("bash -c \"echo net.ipv4.ip_forward=1 > /etc/sysctl.d/99-vpn.conf && sysctl -p /etc/sysctl.d/99-vpn.conf\""), sudo_pass=sp)
        run_ssh(ssh, S("systemctl stop awg-quick@awg0 2>/dev/null || true"), sudo_pass=sp)
        run_ssh(ssh, S("ip link delete awg0 2>/dev/null || true"), sudo_pass=sp) # Чистим старый интерфейс, если завис
        run_ssh(ssh, S("systemctl enable --now awg-quick@awg0"), sudo_pass=sp)
        run_ssh(ssh, S(f"bash -c \"ufw allow {wg_port}/udp 2>/dev/null || true\""), sudo_pass=sp)
        run_ssh(ssh, "rm -f /tmp/client_priv.key /tmp/client_pub.key")

        out, err, code = run_ssh(ssh, S("systemctl is-active awg-quick@awg0"), sudo_pass=sp)
        logger.info(f"Статус awg0: '{out}' (код {code})")

        if out.strip() != "active":
            # Автоматически читаем journalctl чтобы показать причину
            jlog, _, _ = run_ssh(ssh, S("journalctl -u awg-quick@awg0 -n 15 --no-pager -o cat 2>&1"), sudo_pass=sp)
            logger.error(f"journalctl awg-quick@awg0:\n{jlog}")
            # Также проверяем DKMS-модуль
            dkms_out, _, _ = run_ssh(ssh, "lsmod | grep amneziawg")
            logger.info(f"amneziawg lsmod: '{dkms_out}'")
            ssh.close()
            raise Exception(
                f"awg-quick@awg0 не запустился (статус: {out.strip()}).\n"
                f"journalctl: {jlog[:600]}"
            )
        ssh.close()

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
                # Конвертируем deque в list для JSON
                cache = {k: {**v, "history_cpu": list(v.get("history_cpu", [])), "history_ram": list(v.get("history_ram", [])), "history_gb": list(v.get("history_gb", []))} for k, v in last_orchestrator_stats.items()}
                return {"now": data.get("now"), "orchestrator_cache": cache}
    except:
        pass
    cache = {k: {**v, "history_cpu": list(v.get("history_cpu", [])), "history_ram": list(v.get("history_ram", [])), "history_gb": list(v.get("history_gb", []))} for k, v in last_orchestrator_stats.items()}
    return {"error": "Clash API недоступен", "orchestrator_cache": cache}

async def proxy_awg(method: str, endpoint: str, data=None):
    headers = {"Authorization": f"Bearer {AWG_TOKEN}"} if AWG_TOKEN else {}
    url = f"{AWG_SERVER_API}{endpoint}"
    logger.info(f"Запрос к локальному awg-server: {method} {endpoint} (data: {data})")
    try:
        async with httpx.AsyncClient() as client:
            if method == "GET":
                r = await client.get(url, headers=headers, timeout=5)
            elif method == "POST":
                r = await client.post(url, json=data, headers=headers, timeout=5)
            elif method == "DELETE":
                r = await client.delete(url, headers=headers, timeout=5)
            
            logger.info(f"Ответ от awg-server: [{r.status_code}] {r.text[:300]}")
            
            try:
                content = r.json()
            except Exception:
                content = {"detail": r.text}
                
            return JSONResponse(content=content, status_code=r.status_code)
    except httpx.ConnectError as ce:
        msg = f"Ошибка подключения к awg-server на {AWG_SERVER_API}: {ce}. Проверьте, запущен ли сервис awg-server (systemctl status awg-server)"
        logger.error(msg)
        return JSONResponse(content={"error": msg}, status_code=502)
    except Exception as e:
        msg = f"Ошибка вызова awg-server ({method} {endpoint}): {e}"
        logger.error(msg)
        return JSONResponse(content={"error": msg}, status_code=500)

@app.get("/api/clients")
async def get_clients(username: str = Depends(verify_credentials)):
    return await proxy_awg("GET", "/api/clients")

@app.post("/api/clients")
async def create_client(request: Request, username: str = Depends(verify_credentials)):
    import uuid, re
    data = await request.json()
    logger.info(f"Поступил запрос на создание клиента: {data}")

    # awg-server требует поле "id" (name он не поддерживает)
    # генерируем id из name (слаг) или случайный UUID
    if not data.get("id"):
        name = data.get("name", "")
        if name:
            slug = re.sub(r"[^a-zA-Z0-9_-]", "-", name).strip("-").lower()
            slug = slug[:40] or "client"
            data["id"] = f"{slug}-{uuid.uuid4().hex[:8]}"
        else:
            data["id"] = str(uuid.uuid4())

    # awg-server не имеет поля name — убираем чтобы не было лишних полей
    payload = {"id": data["id"]}
    if data.get("awg_params"):
        payload["awg_params"] = data["awg_params"]

    logger.info(f"Отправляем в awg-server: {payload}")
    return await proxy_awg("POST", "/api/clients", payload)

@app.delete("/api/clients/{client_id}")
async def delete_client(client_id: str, username: str = Depends(verify_credentials)):
    logger.info(f"Поступил запрос на удаление клиента: {client_id}")
    return await proxy_awg("DELETE", f"/api/clients/{client_id}")

@app.get("/api/clients/{client_id}/config")
async def get_client_config(client_id: str, username: str = Depends(verify_credentials)):
    headers = {"Authorization": f"Bearer {AWG_TOKEN}"} if AWG_TOKEN else {}
    url = f"{AWG_SERVER_API}/api/clients/{client_id}/configuration"
    logger.info(f"Запрос конфига для клиента {client_id} от awg-server")
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                logger.info(f"Конфиг для {client_id} успешно получен")
                return {"config": r.text}
            else:
                logger.error(f"Не удалось получить конфиг для {client_id}: [{r.status_code}] {r.text}")
                raise HTTPException(status_code=r.status_code, detail=f"awg-server error: {r.text}")
    except Exception as e:
        logger.error(f"Исключение при получении конфига {client_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# --- Orchestrator Logic ---
last_orchestrator_stats = {}

def get_server_stats(server):
    """SSH на зарубежный сервер: получаем CPU, RAM, трафик и пиров"""
    try:
        ssh = ssh_pool.get_client(server)
        if not ssh:
            return 0, 0, 0, 0, False

        iface = server.get("wg_interface", "awg0")
        cmd = f"""
        echo "CPU=$(top -bn1 | grep '%Cpu(s)' | awk '{{print $2 + $4}}')"
        echo "RAM=$(free -m | awk 'NR==2{{printf "%.1f", $3*100/$2}}')"
        awg show {iface} transfer
        echo "---"
        awg show {iface} latest-handshakes
        """
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=5)
        out = stdout.read().decode('utf-8').strip().split('\n')
        
        cpu = 0
        ram = 0
        transfer_data = []
        handshake_data = []
        parsing_handshakes = False
        
        for line in out:
            line = line.strip()
            if line.startswith("CPU="):
                try: cpu = float(line.split("=")[1])
                except: pass
            elif line.startswith("RAM="):
                try: ram = float(line.split("=")[1])
                except: pass
            elif line == "---":
                parsing_handshakes = True
            elif parsing_handshakes:
                handshake_data.append(line)
            else:
                transfer_data.append(line)

        total_bytes = sum([int(p[1]) + int(p[2]) for line in transfer_data
                           if (p := line.split()) and len(p) >= 3])
        total_gb = total_bytes / (1024**3)

        active_users = sum([1 for line in handshake_data
                            if (p := line.split()) and len(p) >= 2
                            and int(p[1]) > 0 and (time.time() - int(p[1])) < 300])

        return total_gb, active_users, cpu, ram, True
    except Exception as e:
        logger.error(f"Healthcheck failed for {server['name']}: {e}")
        return 0, 0, 0, 0, False

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
                await asyncio.sleep(10)
                continue

            # Асинхронно опрашиваем все серверы
            tasks = [asyncio.to_thread(get_server_stats, srv) for srv in servers]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            available_servers = []
            
            for srv, res in zip(servers, results):
                if isinstance(res, Exception):
                    logger.error(f"Error fetching stats for {srv['name']}: {res}")
                    gb, users, cpu, ram, is_alive = 0, 0, 0, 0, False
                else:
                    gb, users, cpu, ram, is_alive = res

                # Храним историю из последних 60 значений (10 минут)
                if srv["name"] not in last_orchestrator_stats:
                    last_orchestrator_stats[srv["name"]] = {
                        "gb": gb, "users": users, "alive": is_alive,
                        "history_cpu": collections.deque(maxlen=60),
                        "history_ram": collections.deque(maxlen=60),
                        "history_gb": collections.deque(maxlen=60)
                    }
                
                stats = last_orchestrator_stats[srv["name"]]
                stats["gb"] = gb
                stats["users"] = users
                stats["alive"] = is_alive
                if is_alive:
                    stats["history_cpu"].append(cpu)
                    stats["history_ram"].append(ram)
                    stats["history_gb"].append(gb)
                else:
                    stats["history_cpu"].append(0)
                    stats["history_ram"].append(0)
                    stats["history_gb"].append(0)

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

        await asyncio.sleep(10)

# --- App Lifecycle ---
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(orchestrator_loop())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
