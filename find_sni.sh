#!/bin/bash
# Скрипт для поиска и валидации SNI-доноров для Xray Reality
# Запускать на вашем VPN-сервере (RU или EU)

# Устанавливаем базовые утилиты
if ! command -v jq &> /dev/null || ! command -v curl &> /dev/null; then
    echo "Устанавливаем зависимости (curl, jq, openssl)..."
    apt update && apt install -y jq curl openssl coreutils
fi

# Получаем публичный IP сервера
IP=$(curl -s api.ipify.org)
echo "🌐 Ваш IP: $IP"

# Получаем ASN
ASN_INFO=$(curl -s "https://api.bgpview.io/ip/$IP" | jq -r '.data.prefixes[0] | "ASN: \(.asn.asn) (\(.asn.name)), Подсеть: \(.prefix)"')
echo "🏢 $ASN_INFO"
echo "----------------------------------------"

# Устанавливаем sni-tool, если его нет
if ! command -v snitool &> /dev/null; then
    echo "⚙️ Устанавливаю sni-tool (это потребует компиляции Rust, может занять несколько минут)..."
    apt install -y cargo git
    git clone https://github.com/Erifirin/sni-tool /tmp/sni-tool
    cd /tmp/sni-tool
    cargo build --release
    cp target/release/snitool /usr/local/bin/
    echo "📦 Собираю базу snitool..."
    snitool db build
    cd - > /dev/null
    rm -rf /tmp/sni-tool
fi

echo "🔍 Ищу и проверяю SNI-кандидатов для IP $IP..."
echo "----------------------------------------"

# snitool lookup wsni IP_МОЕГО_СЕРВЕРА выводит список подходящих доменов
# Мы читаем их построчно и сразу проверяем
snitool lookup wsni "$IP" | while read -r SNI; do
    [ -z "$SNI" ] && continue
    
    # 1. TLS 1.3 + X25519 — критически важно для Reality
    TLS13=$(echo | timeout 5 openssl s_client -connect "${SNI}:443" -tls1_3 -groups X25519 -servername "${SNI}" 2>&1 | grep -c "TLSv1.3")
    
    # 2. HTTP/2 ALPN
    H2=$(echo | timeout 5 openssl s_client -connect "${SNI}:443" -servername "${SNI}" -alpn h2 2>&1 | grep -c "ALPN protocol: h2")
    
    # 3. Нет редиректа на www/другой домен
    REDIR=$(curl -sI --max-time 5 "https://${SNI}/" 2>/dev/null | grep -c -i "^location:")
    
    if [ "$TLS13" -gt 0 ] && [ "$H2" -gt 0 ] && [ "$REDIR" -eq 0 ]; then
        echo -e "✅ \033[0;32mИДЕАЛЬНЫЙ SNI:\033[0m ${SNI}"
    else
        echo -e "❌ \033[0;31mНЕ ПОДХОДИТ:\033[0m ${SNI} (tls13=${TLS13}/1 h2=${H2}/1 redir=${REDIR}/0)"
    fi
done

echo "----------------------------------------"
echo "🎉 Проверка завершена!"
echo "Скопируйте один из ИДЕАЛЬНЫХ SNI."
echo "Затем зайдите в веб-панель (Settings -> Reality Server Names), замените github.com на этот SNI, и перезапустите VPN сервер в панели."
