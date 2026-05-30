#!/bin/bash
# Скрипт для строгой проверки списка доменов на ASN и Криптографию (TLS 1.3, HTTP2)
# Использование: ./check_domains_asn.sh [имя_файла.txt] [целевой_IP]

if ! command -v jq &> /dev/null || ! command -v curl &> /dev/null || ! command -v dig &> /dev/null || ! command -v whois &> /dev/null; then
    echo "Устанавливаем зависимости (curl, jq, dnsutils, whois)..."
    apt update && apt install -y jq curl dnsutils whois
fi

DOMAINS_FILE="${1:-domains.txt}"
TARGET_IP=${2:-}

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "❌ Файл $DOMAINS_FILE не найден!"
    exit 1
fi

echo "🌐 Определяем ASN целевого сервера..."
if [ -n "$TARGET_IP" ]; then
    MY_IP="$TARGET_IP"
else
    MY_IP=$(curl -s api.ipify.org)
fi

MY_ASN=$(whois -h whois.cymru.com " -v $MY_IP" | tail -1 | awk '{print $1}')

if [ -z "$MY_ASN" ] || [ "$MY_ASN" == "null" ]; then
    echo "❌ Не удалось определить ASN сервера."
    exit 1
fi

echo "✅ Ваш ASN: AS$MY_ASN"
echo "----------------------------------------"
echo "🔍 Проверяем домены из $DOMAINS_FILE (В 10 потоков)..."
echo "----------------------------------------"

# Экспортируем функцию для xargs
check_crypto() {
    local DOMAIN=$1
    local MY_ASN=$2
    local DOMAIN_IP=$(dig +short "$DOMAIN" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    
    if [ -z "$DOMAIN_IP" ]; then return; fi
    
    local ASN_INFO=$(whois -h whois.cymru.com " -v $DOMAIN_IP" | tail -1)
    local DOMAIN_ASN=$(echo "$ASN_INFO" | awk '{print $1}')
    
    if [ "$DOMAIN_ASN" != "$MY_ASN" ]; then
        echo -e "❌ \033[0;31mДРУГОЙ ASN:\033[0m $DOMAIN (IP: $DOMAIN_IP, AS$DOMAIN_ASN)"
        return
    fi
    
    local TLS13=$(echo | timeout 3 openssl s_client -connect "${DOMAIN}:443" -tls1_3 -groups X25519 -servername "${DOMAIN}" 2>&1 | grep -c "TLSv1.3")
    local H2=$(echo | timeout 3 openssl s_client -connect "${DOMAIN}:443" -servername "${DOMAIN}" -alpn h2 2>&1 | grep -c "ALPN protocol: h2")
    local REDIR=$(curl -sI --max-time 3 "https://${DOMAIN}/" 2>/dev/null | grep -c -i "^location:")
    
    if [ "$TLS13" -gt 0 ] && [ "$H2" -gt 0 ] && [ "$REDIR" -eq 0 ]; then
        echo -e "✅ \033[0;32mИДЕАЛЬНЫЙ ДОМЕН (ASN+TLS+H2):\033[0m $DOMAIN"
    else
        echo -e "⚠️  \033[0;33mПЛОХОЕ КРИПТО:\033[0m $DOMAIN (tls13=${TLS13} h2=${H2} redir=${REDIR})"
    fi
}
export -f check_crypto

cat "$DOMAINS_FILE" | xargs -n 1 -P 10 -I {} bash -c "check_crypto {} $MY_ASN"

echo "----------------------------------------"
echo "🎉 Проверка завершена!"
