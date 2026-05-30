#!/bin/bash
# Скрипт для фильтрации domains.txt по строгому совпадению ASN
# Запускать после отработки reality_sni_finder.sh

if ! command -v jq &> /dev/null || ! command -v curl &> /dev/null || ! command -v dig &> /dev/null; then
    echo "Устанавливаем зависимости (curl, jq, dnsutils)..."
    apt update && apt install -y jq curl dnsutils
fi

DOMAINS_FILE="./domains.txt"

if [ ! -f "$DOMAINS_FILE" ]; then
    echo "❌ Файл $DOMAINS_FILE не найден! Сначала запустите Reality-SNI-Finder."
    exit 1
fi

echo "🌐 Определяем ASN вашего сервера..."
MY_IP=$(curl -s api.ipify.org)
MY_ASN=$(curl -s "https://api.bgpview.io/ip/$MY_IP" | jq -r '.data.prefixes[0].asn.asn')

if [ -z "$MY_ASN" ] || [ "$MY_ASN" == "null" ]; then
    echo "❌ Не удалось определить ASN сервера."
    exit 1
fi

echo "✅ Ваш ASN: AS$MY_ASN"
echo "----------------------------------------"
echo "🔍 Проверяем домены из $DOMAINS_FILE на совпадение ASN..."
echo "----------------------------------------"

# Для ускорения запросов к whois/ASN API мы используем mass dns resolving
while read -r DOMAIN; do
    [ -z "$DOMAIN" ] && continue
    
    # 1. Получаем IP домена
    DOMAIN_IP=$(dig +short "$DOMAIN" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    
    if [ -z "$DOMAIN_IP" ]; then
        echo -e "⚠️  \033[0;33mПРОПУСК:\033[0m $DOMAIN (не резолвится IP)"
        continue
    fi
    
    # 2. Получаем ASN для этого IP через cymru (намного быстрее и без лимитов, чем bgpview)
    # Формат вывода: AS | IP | ASN Name
    ASN_INFO=$(whois -h whois.cymru.com " -v $DOMAIN_IP" | tail -1)
    DOMAIN_ASN=$(echo "$ASN_INFO" | awk '{print $1}')
    
    # 3. Сравниваем ASN
    if [ "$DOMAIN_ASN" == "$MY_ASN" ]; then
        echo -e "✅ \033[0;32mИДЕАЛЬНОЕ СОВПАДЕНИЕ ASN:\033[0m $DOMAIN (IP: $DOMAIN_IP, AS$DOMAIN_ASN)"
    else
        echo -e "❌ \033[0;31mДРУГОЙ ПРОВАЙДЕР:\033[0m $DOMAIN (IP: $DOMAIN_IP, AS$DOMAIN_ASN)"
    fi
    
    # Небольшая пауза, чтобы не забанили
    sleep 0.2
done < "$DOMAINS_FILE"

echo "----------------------------------------"
echo "🎉 Проверка завершена! Берите любой домен с зеленой галочкой."
