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

# 0. Создание Swap
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

# 2. Установка зависимостей
log_info "Обновление пакетов и установка зависимостей..."
apt update -y || handle_error $LINENO
apt install -y curl wget git iptables iproute2 python3 python3-pip python3-venv build-essential wireguard-tools || handle_error $LINENO
log_success "Зависимости установлены."

# 2. Установка AmneziaWG
log_info "Установка AmneziaWG..."
if ! command -v awg &> /dev/null; then
    if grep -qi "ubuntu" /etc/os-release; then
        log_info "Обнаружена Ubuntu, используем официальный PPA..."
        apt install -y software-properties-common || handle_error $LINENO
        add-apt-repository ppa:amnezia/ppa -y || true
        apt update -y || handle_error $LINENO
        apt install -y amneziawg-dkms amneziawg-tools || handle_error $LINENO
    else
        log_info "Обнаружен Debian, компилируем AmneziaWG из исходников (это займет пару минут)..."
        apt install -y linux-headers-$(uname -r) build-essential dkms git || handle_error $LINENO
        
        # Компиляция модуля ядра
        git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git /tmp/awg-kernel
        cd /tmp/awg-kernel
        make module && make install || handle_error $LINENO
        
        # Компиляция утилит (awg)
        git clone https://github.com/amnezia-vpn/amneziawg-tools.git /tmp/awg-tools
        cd /tmp/awg-tools/src
        make && make install || handle_error $LINENO
        cd /opt/smart_vpn || cd /tmp/smart_vpn_install
    fi
fi
log_success "AmneziaWG установлен."

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
mkdir -p /opt/awg-server
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
ExecStart=/opt/awg-server/awg-server
WorkingDirectory=/opt/awg-server
Restart=always
Environment="AWG_SERVER_PORT=8080"
Environment="AWG_SERVER_TOKEN=secret_token_123"

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
iptables -t nat -A POSTROUTING -s 10.255.0.0/24 -o tun0 -j MASQUERADE || true
ip rule add from 10.255.0.0/24 lookup 100 || true
ip route add default dev tun0 table 100 || true
EOF
chmod +x /opt/setup_routing.sh

cat <<EOF > /etc/systemd/system/vpn-routing.service
[Unit]
Description=VPN Routing Setup
After=network.target sing-box.service awg-server.service

[Service]
Type=oneshot
ExecStart=/opt/setup_routing.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
log_success "Маршрутизация настроена."

# 7. Установка Python Панели
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
