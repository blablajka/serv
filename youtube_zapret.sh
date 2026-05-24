#!/bin/bash

echo "=== 1. Установка зависимостей ==="
sudo apt update
sudo apt install -y build-essential make git pkg-config \
    libmnl-dev libcap-dev zlib1g-dev libnetfilter-queue-dev \
    libnfnetlink-dev libsystemd-dev

echo "=== 2. Скачивание Zapret ==="
cd /opt
if [ ! -d "zapret" ]; then
    sudo git clone https://github.com/bol-van/zapret.git
fi
cd zapret

echo "=== 3. Отключение DNS хостинга ==="
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo rm -f /etc/resolv.conf
sudo tee /etc/resolv.conf > /dev/null <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
EOF

echo "=== 4. Создание списка только для YouTube ==="
sudo mkdir -p /opt/zapret/lists
sudo tee /opt/zapret/lists/hostlist.txt > /dev/null << 'EOF'
youtube.com
googlevideo.com
ytimg.com
youtu.be
youtube-nocookie.com
youtube.googleapis.com
EOF

echo "=== 5. Финальная рабочая конфигурация ==="
# Важно: NFQWS_OPT_DESYNC должен содержать параметры обхода,
# и мы применяем их ТОЛЬКО к доменам из hostlist.txt
sudo tee /opt/zapret/config > /dev/null << 'EOF'
# /opt/zapret/config
FWTYPE=iptables
MODE=nfqws
MODE_HTTP=0
MODE_HTTP_KEEPALIVE=0
MODE_HTTPS=1
MODE_QUIC=1
MODE_FILTER=none
DESYNC_MARK=0x40000000

# Параметры nfqws
NFQWS_OPT_DESYNC="--filter-tcp=80,443 --dpi-desync=fake,disorder --dpi-desync-fooling=md5sig,badseq --hostlist=/opt/zapret/lists/hostlist.txt --new --filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=8 --hostlist=/opt/zapret/lists/hostlist.txt"

# Применяем только для исходящего трафика самого сервера
# (так как sing-box создает подключения от лица локального хоста)
INIT_APPLY_FW=1
DISABLE_IPV6=1
EOF

echo "=== 6. Установка и запуск Zapret ==="
echo "ВНИМАНИЕ: Сейчас запустится install_prereq.sh и install_bin.sh."
sudo ./install_prereq.sh
sudo ./install_bin.sh
sudo ./init.d/sysv/zapret restart
sudo systemctl enable zapret
sudo systemctl restart zapret

echo "Готово! Убедитесь, что zapret запущен:"
sudo systemctl status zapret --no-pager
