#!/bin/bash
set -e

# Цвета для логов
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function handle_error() {
    log_error "Произошла ошибка во время установки (Строка $1). Проверьте логи выше."
    exit 1
}

trap 'handle_error $LINENO' ERR

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}     Установка Умной VPN-системы          ${NC}"
echo -e "${BLUE}==========================================${NC}"

# Проверка ОС
if ! grep -qiE "ubuntu|debian" /etc/os-release; then
    log_error "Эта система протестирована только на Ubuntu и Debian!"
    log_error "Обнаружена неизвестная ОС. Пожалуйста, используйте Ubuntu 22.04 или Debian 12."
    exit 1
fi

# Проверка, скачаны ли файлы. Если скрипт запущен через curl, скачиваем репо.
if [ ! -d "panel" ]; then
    log_info "Файлы панели не найдены локально. Клонируем репозиторий..."
    rm -rf /tmp/smart_vpn_install
    git clone https://github.com/blablajka/serv.git /tmp/smart_vpn_install
    cd /tmp/smart_vpn_install
fi

# 0. Настройка безопасности (SSH)
NEW_SSH_PORT=22
read -p "Хотите ли вы изменить стандартный SSH порт (22) на другой для безопасности? [y/N]: " change_ssh
if [[ "$change_ssh" =~ ^[Yy]$ ]]; then
    read -p "Введите новый порт (например, 2222): " NEW_SSH_PORT
    if [[ "$NEW_SSH_PORT" =~ ^[0-9]+$ ]] && [ "$NEW_SSH_PORT" -ge 1024 ] && [ "$NEW_SSH_PORT" -le 65535 ]; then
        log_info "Меняем порт SSH на $NEW_SSH_PORT..."
        sed -i "s/^#Port 22/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
        sed -i "s/^Port 22/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
        if ! grep -q "^Port $NEW_SSH_PORT" /etc/ssh/sshd_config; then
            echo "Port $NEW_SSH_PORT" >> /etc/ssh/sshd_config
        fi
        systemctl restart sshd || systemctl restart ssh
        log_success "Порт SSH изменен на $NEW_SSH_PORT."
    else
        log_error "Некорректный порт! Оставляем порт 22."
        NEW_SSH_PORT=22
    fi
fi

# Проверка авторизации по ключу
if grep -q "ssh-rsa" ~/.ssh/authorized_keys 2>/dev/null || grep -q "ssh-ed25519" ~/.ssh/authorized_keys 2>/dev/null; then
    read -p "У вас настроен вход по SSH-ключу. Отключить вход по паролю для максимальной защиты? [Y/n]: " disable_pass
    if [[ ! "$disable_pass" =~ ^[Nn]$ ]]; then
        sed -i "s/^#PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
        sed -i "s/^PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
        systemctl restart sshd || systemctl restart ssh
        log_success "Вход по паролю отключен."
    fi
fi

# 1. Создание Swap
log_info "Проверка Swap (важно для компиляции)..."
if [ $(swapon -s | wc -l) -eq 0 ]; then
    log_info "Создаем Swap 2GB..."
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
    log_success "Swap создан."
else
    log_success "Swap уже существует."
fi

# 1. Очистка Ubuntu от лишнего мусора (Экономия ~100MB ОЗУ)
if grep -qi "ubuntu" /etc/os-release; then
    log_info "Оптимизация Ubuntu: удаляем snapd для экономии ОЗУ..."
    systemctl stop snapd.service snapd.socket snapd.seeded.service || true
    apt autoremove --purge -y snapd || true
    rm -rf /var/cache/snapd/ || true
    systemctl disable --now multipathd || true
fi

# 3. Установка зависимостей
log_info "Обновление пакетов и установка зависимостей..."
apt update -y || handle_error $LINENO
apt install -y curl wget git iptables iptables-persistent iproute2 python3 python3-pip python3-venv build-essential wireguard-tools ufw rsyslog cron ipset dnsutils || handle_error $LINENO
log_success "Зависимости установлены."

# 3.1 Настройка UFW (Firewall)
log_info "Настройка Firewall (UFW)..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow $NEW_SSH_PORT/tcp
ufw allow 5000/tcp
ufw allow 51820/udp
ufw --force enable
log_success "UFW настроен и включен."

# 3.2 Блокировка сканеров РКН
log_info "Настройка блокировки сканеров РКН..."
mkdir -p /var/log/blacklist
if id "syslog" &>/dev/null; then
    chown syslog:adm /var/log/blacklist
else
    chown root:adm /var/log/blacklist
fi
chmod 0755 /var/log/blacklist

echo ':msg, contains, "Blocked IP attempt: " /var/log/blacklist/blacklist.log' > /etc/rsyslog.d/99-blacklist.conf
systemctl restart rsyslog

wget -qO /var/log/blacklist/blacklist_updater.sh https://raw.githubusercontent.com/blablajka/AS_Network_List_for-debian/main/blacklist_updater.sh
chmod +x /var/log/blacklist/blacklist_updater.sh
/var/log/blacklist/blacklist_updater.sh
(crontab -l 2>/dev/null; echo "0 9 * * * /var/log/blacklist/blacklist_updater.sh") | crontab -

wget -qO /usr/local/bin/domain_blocker.sh https://raw.githubusercontent.com/blablajka/AS_Network_List_for-debian/main/domain_blocker.sh
chmod +x /usr/local/bin/domain_blocker.sh
wget -qO /var/log/blacklist/domains.list https://raw.githubusercontent.com/blablajka/AS_Network_List_for-debian/main/domains.list
/usr/local/bin/domain_blocker.sh --install || true
log_success "Блокировка сканеров РКН активирована."

# 2. Установка AmneziaWG (инструменты + DKMS-модуль ядра)
# ВАЖНО: awg-server требует модуль ядра amneziawg на bridge-сервере!
log_info "Установка AmneziaWG (модуль ядра + инструменты)..."

if grep -qi "ubuntu" /etc/os-release; then
    log_info "Ubuntu: устанавливаем из PPA amnezia..."
    apt install -y software-properties-common || handle_error $LINENO
    add-apt-repository ppa:amnezia/ppa -y || true
    apt update -y || handle_error $LINENO
    # Нужны ОБА пакета хэдеров: linux-headers-X.X.X-generic И linux-headers-X.X.X
    # Иначе DKMS не находит заголовки и не компилирует модуль
    KVER=$(uname -r)
    KVER_BASE=$(echo "$KVER" | sed 's/-generic$//')
    apt install -y linux-headers-${KVER} linux-headers-${KVER_BASE} amneziawg-dkms amneziawg-tools || true
    # Если зависимости сломаны — принудительная переустановка
    apt install --reinstall -y linux-headers-${KVER} linux-headers-${KVER_BASE} 2>/dev/null || true
else
    log_info "Debian: компилируем AmneziaWG из исходников..."
    apt install -y linux-headers-$(uname -r) build-essential dkms git || handle_error $LINENO
    if ! command -v awg &> /dev/null; then
        git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git /tmp/awg-kernel
        cd /tmp/awg-kernel
        make module && make install || handle_error $LINENO
        git clone https://github.com/amnezia-vpn/amneziawg-tools.git /tmp/awg-tools
        cd /tmp/awg-tools/src
        make && make install || handle_error $LINENO
        cd /opt/smart_vpn || cd /tmp/smart_vpn_install
    fi
fi

# Загружаем модуль ядра и добавляем в автозагрузку
if ! modprobe amneziawg 2>/dev/null; then
    log_info "Первая попытка modprobe не удалась, пробуем пересобрать DKMS..."
    dkms install amneziawg/1.0.0 -k $(uname -r) 2>/dev/null || true
    modprobe amneziawg || log_error "Не удалось загрузить amneziawg — возможно нужна перезагрузка"
fi
echo "amneziawg" > /etc/modules-load.d/amneziawg.conf
log_success "AmneziaWG установлен, модуль ядра загружен."

# 3. Установка Go
log_info "Проверка и установка Go..."
if ! command -v go &> /dev/null; then
    wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.profile
    rm go1.22.4.linux-amd64.tar.gz
fi
export PATH=$PATH:/usr/local/go/bin
log_success "Go установлен ($(go version))."

# 4. Сборка awg-server
log_info "Сборка awg-server (это может занять время)..."
mkdir -p /opt/awg-server/data
if [ ! -f "/opt/awg-server/awg-server" ]; then
    git clone https://github.com/stealthsurf-vpn/awg-server.git /tmp/awg-server-src
    cd /tmp/awg-server-src
    go build -o /opt/awg-server/awg-server . || handle_error $LINENO
    cd - > /dev/null
    rm -rf /tmp/awg-server-src
fi

cat <<EOF > /etc/systemd/system/awg-server.service
[Unit]
Description=AmneziaWG Server API
After=network.target

[Service]
WorkingDirectory=/opt/awg-server
ExecStart=/bin/bash -c "AWG_ENDPOINT=\\\$(curl -s ifconfig.me || wget -qO- ifconfig.me) /opt/awg-server/awg-server"
Restart=always
RestartSec=5
Environment="AWG_API_TOKEN=secret_token_123"
Environment="AWG_HTTP_PORT=8080"
Environment="AWG_ADDRESS=10.255.0.1/24"
Environment="AWG_DATA_DIR=/opt/awg-server/data"

[Install]
WantedBy=multi-user.target
EOF
log_success "awg-server собран и настроен."

# 5. Установка sing-box-extended (Загрузка готового бинарника)
log_info "Установка sing-box-extended..."
mkdir -p /etc/sing-box
if [ ! -f "/usr/local/bin/sing-box" ]; then
    # Скачиваем последний релиз для amd64
    LATEST_URL=$(curl -s https://api.github.com/repos/shtorm-7/sing-box-extended/releases/latest | grep "browser_download_url" | grep "linux-amd64.tar.gz" | cut -d '"' -f 4)
    if [ -z "$LATEST_URL" ]; then
        log_error "Не удалось найти ссылку на релиз sing-box-extended!"
        exit 1
    fi
    wget -qO /tmp/sing-box.tar.gz "$LATEST_URL"
    tar -xzf /tmp/sing-box.tar.gz -C /tmp/
    # Архив содержит папку, например sing-box-1.9.0-linux-amd64
    mv /tmp/sing-box-*-linux-amd64/sing-box /usr/local/bin/sing-box
    chmod +x /usr/local/bin/sing-box
    rm -rf /tmp/sing-box.tar.gz /tmp/sing-box-*-linux-amd64
fi

cat <<EOF > /etc/systemd/system/sing-box.service
[Unit]
Description=sing-box service
After=network.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
log_success "sing-box собран и настроен."

# 6. Настройка маршрутизации
log_info "Настройка маршрутизации..."
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-vpn.conf
sysctl -p /etc/sysctl.d/99-vpn.conf > /dev/null 2>&1

cat <<EOF > /opt/setup_routing.sh
#!/bin/bash
# Ждем, пока sing-box создаст интерфейс tun0 (до 10 секунд)
for i in {1..10}; do
    ip link show tun0 >/dev/null 2>&1 && break
    sleep 1
done

iptables -t nat -A POSTROUTING -s 10.255.0.0/24 -o tun0 -j MASQUERADE || true
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o tun0 -j MASQUERADE || true
ip rule add from 10.255.0.0/24 lookup 100 || true
ip rule add from 10.99.0.0/24 lookup 100 || true
ip route add default dev tun0 table 100 || true
EOF
chmod +x /opt/setup_routing.sh

cat <<EOF > /etc/systemd/system/vpn-routing.service
[Unit]
Description=VPN Routing Setup
After=network.target sing-box.service awg-server.service
PartOf=sing-box.service

[Service]
Type=oneshot
ExecStart=/opt/setup_routing.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
log_success "Маршрутизация настроена."

# 7. Установка Zapret (Обход DPI)
log_info "Установка Zapret для обхода DPI (YouTube, Discord)..."
if [ ! -d "/opt/zapret-discord-youtube-linux" ]; then
    git clone https://github.com/Sergeydigl3/zapret-discord-youtube-linux.git /opt/zapret-discord-youtube-linux
    cd /opt/zapret-discord-youtube-linux
    ./service.sh download-deps --default
    
    MAIN_IFACE=$(ip route get 8.8.8.8 | awk '{print $5}' | head -n1)
    log_info "Автоматически выбран сетевой интерфейс для Zapret: $MAIN_IFACE"
    
    cat <<EOF > conf.env
interface=$MAIN_IFACE
gamefiltertcp=false
gamefilterudp=true
strategy=discord
EOF
    
    ./service.sh service install || true
    cd /opt/smart_vpn || cd /tmp/smart_vpn_install
fi
log_success "Zapret установлен."

# 8. Установка Python Панели
log_info "Развертывание веб-панели и оркестратора..."
mkdir -p /opt/smart_vpn
cp -r . /opt/smart_vpn/
cd /opt/smart_vpn

python3 -m venv venv
./venv/bin/pip install -r requirements.txt || handle_error $LINENO

cat <<EOF > /etc/systemd/system/smart-vpn-panel.service
[Unit]
Description=Smart VPN Panel & Orchestrator
After=network.target

[Service]
WorkingDirectory=/opt/smart_vpn/panel
ExecStart=/opt/smart_vpn/venv/bin/python main.py
Restart=always
Environment="AWG_TOKEN=secret_token_123"
Environment="ADMIN_USER=admin"
Environment="ADMIN_PASS=admin"

[Install]
WantedBy=multi-user.target
EOF

echo "[]" > /opt/smart_vpn/panel/servers.json
/opt/smart_vpn/venv/bin/python -c "
import sys
sys.path.append('/opt/smart_vpn/panel')
from config_generator import generate_singbox_config
generate_singbox_config([], '/etc/sing-box/config.json')
"
log_success "Веб-панель развернута."

# 8. Запуск сервисов
log_info "Запуск всех сервисов..."
systemctl daemon-reload
systemctl enable --now awg-server || handle_error $LINENO
systemctl enable --now sing-box || handle_error $LINENO
systemctl enable --now vpn-routing || handle_error $LINENO
systemctl enable --now smart-vpn-panel || handle_error $LINENO
log_success "Сервисы запущены!"

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}        УСТАНОВКА ЗАВЕРШЕНА!              ${NC}"
echo -e "${GREEN}==========================================${NC}"
echo -e "Панель доступна по адресу: ${YELLOW}http://$(curl -s ifconfig.me):5000${NC}"
echo -e "Логин: ${YELLOW}admin${NC} / Пароль: ${YELLOW}admin${NC}"
