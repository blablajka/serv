#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Reality SNI Finder"
APP_PY="reality_sni_finder.py"
OUT_FILE="domains.txt"
CONF_FILE=".rsf.conf"

export RSF_PY_URL="https://raw.githubusercontent.com/ShatakVPN/Reality-SNI-Finder/main/reality_sni_finder.py"

# ---------- Colors & UI ----------
ESC=$(printf '\033')
BOLD="${ESC}[1m"; DIM="${ESC}[2m"; RESET="${ESC}[0m"
C0="${ESC}[38;5;39m"   # blue
C1="${ESC}[38;5;208m"  # orange
C2="${ESC}[38;5;82m"   # green
C3="${ESC}[38;5;197m"  # red
C4="${ESC}[38;5;244m"  # gray

line() { printf "${C4}────────────────────────────────────────────────────────────${RESET}\n"; }
title() {
  clear
  printf "${BOLD}${C0}┌──────────────────────────────────────────────────────────┐${RESET}\n"
  printf "${BOLD}${C0}│${RESET} ${BOLD}${C1}${APP_NAME}${RESET} ${C4}— simple SNI hunter for Reality      ${RESET} ${BOLD}${C0}│${RESET}\n"
  printf "${BOLD}${C0}└──────────────────────────────────────────────────────────┘${RESET}\n"
}

pause() { read -r -p "$(printf "${DIM}Press [Enter] to continue...${RESET} ")" _; }

spinner() {
  local pid=$1; local frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
  local i=0
  tput civis || true
  while kill -0 "$pid" >/dev/null 2>&1; do
    printf "\r${DIM}%s${RESET} " "${frames[i % ${#frames[@]}]}"
    i=$(( (i+1) % ${#frames[@]} ))
    sleep 0.1
  done
  printf "\r"
  tput cnorm || true
}

# ---------- Config handling ----------
load_conf() { [[ -f "$CONF_FILE" ]] && source "$CONF_FILE" || true; }
save_conf() {
  cat > "$CONF_FILE" <<EOF
# Reality SNI Finder config
export RSF_BLOCKS="${RSF_BLOCKS:-6}"
export RSF_RATE="${RSF_RATE:-4000}"
export RSF_TIMEOUT="${RSF_TIMEOUT:-8}"
export RSF_THREADS="${RSF_THREADS:-64}"
export RSF_VERIFY_H2="${RSF_VERIFY_H2:-1}"
export RSF_INCLUDE_GENERIC="${RSF_INCLUDE_GENERIC:-1}"
export RSF_REF_IP="${RSF_REF_IP:-}"
EOF
}

# ---------- Dependency management ----------
detect_pm() {
  for pm in apt-get apt dnf yum pacman zypper apk; do
    command -v "$pm" >/dev/null 2>&1 && { echo "$pm"; return; }
  done
  echo ""
}

install_pkgs() {
  local pm; pm=$(detect_pm)
  [[ -z "$pm" ]] && { printf "${C3}No supported package manager found. Install masscan curl openssl python3 whois dnsutils manually.${RESET}\n"; return 1; }
  printf "${C2}Installing dependencies with ${pm}...${RESET}\n"
  case "$pm" in
    apt|apt-get)
      sudo "$pm" update -y
      sudo "$pm" install -y masscan curl openssl python3 whois dnsutils
      ;;
    dnf|yum)
      sudo "$pm" install -y epel-release || true
      sudo "$pm" install -y masscan curl openssl python3 whois bind-utils
      ;;
    pacman)
      sudo "$pm" -Sy --noconfirm masscan curl openssl python whois bind
      ;;
    zypper)
      sudo "$pm" refresh
      sudo "$pm" install -y masscan curl openssl python3 whois bind-utils
      ;;
    apk)
      sudo "$pm" add --no-cache masscan curl openssl python3 whois bind-tools
      ;;
    *) return 1;;
  esac
}

check_deps() {
  local miss=()
  for b in python3 masscan curl openssl whois dig; do
    command -v "$b" >/dev/null 2>&1 || miss+=("$b")
  done
  if (( ${#miss[@]} )); then
    printf "${C3}Missing: %s${RESET}\n" "${miss[*]}"
    read -r -p "Install automatically? [Y/n] " ans; ans=${ans:-Y}
    [[ "$ans" =~ ^[Yy]$ ]] && install_pkgs || return 1
  fi
}

# ---------- Python writer (inline fallback) ----------
ensure_python() {
  if [[ -f "$APP_PY" ]]; then return 0; fi

  if [[ -n "${RSF_PY_URL:-}" ]]; then
    printf "${C2}Downloading ${APP_PY} from RSF_PY_URL...${RESET}\n"
    if curl -fsSL "$RSF_PY_URL" -o "$APP_PY"; then
      chmod +x "$APP_PY"; return 0
    else
      printf "${C3}Download failed. Using embedded fallback...${RESET}\n"
    fi
  fi

  # Embedded fallback (heredoc)
  cat > "$APP_PY" <<'PY'
# (the Python engine is embedded by the shell)
# If you are reading this inside the shell writer, something went wrong.
PY
  # Replace embedded stub with full engine via here-doc append
  cat >> "$APP_PY" <<'PY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# The full engine is injected here:
import ipaddress, math, os, re, shlex, socket, ssl, subprocess, sys, time, threading
import concurrent.futures
from typing import Dict, List, Tuple, Optional, Set
class Progress:
    def __init__(self, total: int, title: str, width: int = 46):
        self.total = max(1, total); self.title = title; self.width = width
        self.done = 0; self.lock = threading.Lock(); self.start = time.time(); self._render()
    def advance(self, n: int = 1):
        with self.lock:
            self.done = min(self.total, self.done + n); self._render()
    def finish(self):
        with self.lock:
            self.done = self.total; self._render(end=True)
    def _render(self, end: bool=False):
        ratio = self.done / self.total; filled = int(self.width * ratio)
        bar = "█"*filled + "░"*(self.width-filled); pct = f"{int(ratio*100):3d}%"; elapsed = time.time()-self.start
        msg = f"\r{self.title} [{bar}] {pct}  ({self.done}/{self.total}, {elapsed:0.1f}s)"; sys.stdout.write(msg); sys.stdout.flush()
        if end: sys.stdout.write("\n")
def die(msg: str, code: int = 1): sys.stderr.write(f"[!] {msg}\n"); sys.exit(code)
def check_tool(tool: str):
    from shutil import which
    if which(tool) is None: die(f"Required tool not found: {tool}")
def public_ipv4_autodetect(timeout: float = 4.0) -> Optional[str]:
    cmds=["curl -fsS --max-time 4 https://api.ipify.org","curl -fsS --max-time 4 https://ifconfig.me","dig +short myip.opendns.com @resolver1.opendns.com"]
    for c in cmds:
        try:
            ip=subprocess.check_output(["bash","-lc",c], text=True).strip()
            if ip:
                ipaddress.ip_address(ip)
                if ":" not in ip: return ip
        except Exception: pass
    return None
def base24(ip: str) -> ipaddress.IPv4Network:
    a=ipaddress.ip_address(ip)
    if a.version!=4: die("Only IPv4 is supported.")
    return ipaddress.ip_network(f"{ip}/24", strict=False)
def neighbor_24_cidrs(ref_ip: str, blocks_each_side: int) -> List[str]:
    ref_net=base24(ref_ip); ref_base=int(ipaddress.ip_address(str(ref_net.network_address)))
    out=[]
    for off in range(-blocks_each_side, blocks_each_side+1):
        b=ref_base+off*256
        if 0<=b<=0xFFFFFFFF: out.append(str(ipaddress.ip_network(f"{ipaddress.ip_address(b)}/24", strict=True)))
    seen=set(); ordered=[]
    for c in out:
        if c not in seen: seen.add(c); ordered.append(c)
    return ordered
def parse_masscan(text: str) -> List[str]:
    ips=[]
    for line in text.splitlines():
        parts=line.split()
        if len(parts)>=4 and parts[0]=="open" and parts[1]=="tcp": ips.append(parts[3])
    return sorted(set(ips))
def run_masscan_cidr(cidr: str, rate: int) -> List[str]:
    cmd=f"masscan {shlex.quote(cidr)} -p443 --rate {rate} --wait 0 --open-only -oL -"
    p=subprocess.run(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    return parse_masscan(p.stdout)
def probe_tls_no_sni(ip: str, timeout: float = 3.0) -> Dict:
    res={"ip":ip,"ok":False,"latency_ms":None,"alpn":None,"has_tls13":False,"cert_cn":None,"cert_sans":[]}
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try: ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    except Exception: pass
    try: ctx.set_alpn_protocols(["h2","http/1.1"])
    except Exception: pass
    t0=time.time()
    try:
        with socket.create_connection((ip,443),timeout=timeout) as sock:
            with ctx.wrap_socket(sock,server_hostname=None) as ssock:
                res["latency_ms"]=round((time.time()-t0)*1000,2); res["ok"]=True
                try: res["alpn"]=ssock.selected_alpn_protocol()
                except Exception: res["alpn"]=None
                res["has_tls13"]=(ssock.version()=="TLSv1_3" or ssock.version()=="TLSv1.3")
                cert=ssock.getpeercert()
                if cert:
                    for tup in cert.get("subject",[]):
                        for k,v in tup:
                            if getattr(k,"lower",lambda:k)().lower()=="commonname": res["cert_cn"]=v
                    res["cert_sans"]=[v for (t,v) in cert.get("subjectAltName",[]) if getattr(t,"lower",lambda:t)().lower()=="dns"]
    except Exception: pass
    if res["ok"] and not res["cert_sans"]:
        try:
            out=subprocess.getoutput(f"echo | openssl s_client -connect {ip}:443 -showcerts 2>/dev/null | openssl x509 -noout -text")
            if out.strip(): res["cert_sans"]=re.findall(r"DNS:([^,\s]+)", out)
        except Exception: pass
    return res
GENERIC_SAN=set(["sni.cloudflaressl.com","ssl.cloudflare.com","akamai.net","cloudfront.net","edgekey.net","edgesuite.net"])
def is_domain(d: str)->bool:
    d=d.strip().lower()
    return "." in d and not d.endswith(".local") and not d.endswith(".lan") and len(d)<253
def expand_wildcard(d: str)->list:
    if d.startswith("*.") and d.count(".")>=2:
        root=d[2:]; return [root,f"www.{root}"]
    return [d]
def domains_from_cert(cn,sans,include_generic=True)->list:
    items=[]
    if cn and is_domain(cn): items.extend(expand_wildcard(cn.lower()))
    for s in sans or []:
        s=s.strip().lower()
        if not is_domain(s): continue
        if (not include_generic) and (s in GENERIC_SAN): continue
        items.extend(expand_wildcard(s))
    seen=set(); out=[]
    for i in items:
        if i not in seen: seen.add(i); out.append(i)
    return out
def verify_http2(domain: str, ip: str, timeout: float=8.0)->bool:
    cmd=["curl","-sS","-m",str(int(timeout)),"--http2","-o","/dev/null","--resolve",f"{domain}:443:{ip}",f"https://{domain}/"]
    try:
        p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        return p.returncode==0
    except Exception: return False
def ipnum_dist_norm(a: str, b: str)->float:
    try:
        d=abs(int(ipaddress.ip_address(a))-int(ipaddress.ip_address(b))); return d/(2**32)*1000.0
    except Exception: return 1000.0
def main():
    blocks=int(os.environ.get("RSF_BLOCKS","6"))
    rate=int(os.environ.get("RSF_RATE","4000"))
    timeout=float(os.environ.get("RSF_TIMEOUT","8"))
    threads=int(os.environ.get("RSF_THREADS","64"))
    include_generic=os.environ.get("RSF_INCLUDE_GENERIC","1")=="1"
    verify_h2=os.environ.get("RSF_VERIFY_H2","1")=="1"
    ref_ip_env=os.environ.get("RSF_REF_IP","").strip()
    TOPN=30
    for tool in ("masscan","curl","openssl"): 
        from shutil import which
        if which(tool) is None: die(f"Required tool not found: {tool}")
    ref_ip=ref_ip_env or public_ipv4_autodetect()
    if not ref_ip: die("Cannot detect public IPv4 automatically. Set RSF_REF_IP or ensure outbound DNS/HTTP works.")
    cidrs=neighbor_24_cidrs(ref_ip, blocks)
    ips_all=[]; pb=Progress(len(cidrs),"Scanning blocks")
    for cidr in cidrs:
        ips_all.extend(run_masscan_cidr(cidr, rate)); pb.advance(); time.sleep(0.03)
    pb.finish()
    ips=sorted(set(ips_all))
    if not ips: die("No hosts with port 443 were found.")
    pb2=Progress(len(ips),"TLS probing"); probes=[]
    def _probe(ip):
        r=probe_tls_no_sni(ip, timeout=max(3.0,timeout-2)); pb2.advance(); return r
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for r in ex.map(_probe, ips):
            if r.get("ok"): probes.append(r)
    pb2.finish()
    if not probes: die("No TLS-capable hosts responded.")
    candidates=[]
    for p in probes:
        for d in domains_from_cert(p.get("cert_cn"), p.get("cert_sans"), include_generic=include_generic):
            candidates.append((p["ip"], p["latency_ms"], d))
    if not candidates: die("No domains extracted from certificates.")
    if verify_h2:
        pb3=Progress(len(candidates),"Verifying HTTP/2"); filtered=[]
        def _verify(t):
            ip,lat,dom=t; ok=verify_http2(dom, ip, timeout=timeout); pb3.advance(); return (ip,lat,dom,ok)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for ip,lat,dom,ok in ex.map(_verify, candidates):
                if ok: filtered.append((ip,lat,dom))
        pb3.finish(); candidates=filtered
        if not candidates: die("No domains passed real HTTP/2 verification.")
    scored=[]
    for ip,lat,dom in candidates:
        score=(lat if (lat is not None) else 5000.0) + 0.3*ipnum_dist_norm(ip, ref_ip)
        scored.append((score, dom))
    scored.sort(key=lambda x:x[0])
    seen=set(); top=[]
    for _,dom in scored:
        if dom not in seen:
            seen.add(dom); top.append(dom)
        if len(top)>=TOPN: break
    with open("domains.txt","w",encoding="utf-8") as f: f.write("\n".join(top))
    print(f"\n[✓] Wrote {len(top)} domains to domains.txt")
if __name__=="__main__": main()
PY
  chmod +x "$APP_PY"
}

# ---------- Run engine ----------
run_engine() {
  load_conf
  export RSF_BLOCKS="${RSF_BLOCKS:-6}"
  export RSF_RATE="${RSF_RATE:-4000}"
  export RSF_TIMEOUT="${RSF_TIMEOUT:-8}"
  export RSF_THREADS="${RSF_THREADS:-64}"
  export RSF_VERIFY_H2="${RSF_VERIFY_H2:-1}"
  export RSF_INCLUDE_GENERIC="${RSF_INCLUDE_GENERIC:-1}"
  export RSF_REF_IP="${RSF_REF_IP:-}"

  ensure_python
  check_deps || true

  printf "${C2}Starting scan...${RESET}\n"
  set +e
  python3 "$APP_PY"
  code=$?
  set -e
  if [[ $code -eq 0 ]]; then
    printf "${C2}Done.${RESET} "
    if [[ -f "$OUT_FILE" ]]; then
      printf "Output: ${BOLD}%s${RESET}  " "$(pwd)/$OUT_FILE"
      printf "(count: ${BOLD}%s${RESET})\n" "$(wc -l < "$OUT_FILE" 2>/dev/null || echo 0)"
    else
      printf "${C3}No output file found.${RESET}\n"
    fi
  else
    printf "${C3}Engine exited with code %s${RESET}\n" "$code"
  fi
  pause
}

# ---------- Settings menu ----------
edit_settings() {
  load_conf
  printf "\nCurrent settings:\n"
  line
  printf "Blocks each side      : ${BOLD}%s${RESET}\n" "${RSF_BLOCKS:-6}"
  printf "Masscan rate (pps)    : ${BOLD}%s${RESET}\n" "${RSF_RATE:-4000}"
  printf "Timeout (sec)         : ${BOLD}%s${RESET}\n" "${RSF_TIMEOUT:-8}"
  printf "Threads               : ${BOLD}%s${RESET}\n" "${RSF_THREADS:-64}"
  printf "Verify HTTP/2         : ${BOLD}%s${RESET}\n" "${RSF_VERIFY_H2:-1}"
  printf "Include generic SANs  : ${BOLD}%s${RESET}\n" "${RSF_INCLUDE_GENERIC:-1}"
  printf "Override ref IP       : ${BOLD}%s${RESET}\n" "${RSF_REF_IP:-}"
  line
  read -r -p "Blocks each side (blank=keep): " v; [[ -n "${v:-}" ]] && RSF_BLOCKS="$v"
  read -r -p "Masscan rate pps (blank=keep): " v; [[ -n "${v:-}" ]] && RSF_RATE="$v"
  read -r -p "Timeout seconds (blank=keep): " v; [[ -n "${v:-}" ]] && RSF_TIMEOUT="$v"
  read -r -p "Threads (blank=keep)         : " v; [[ -n "${v:-}" ]] && RSF_THREADS="$v"
  read -r -p "Verify HTTP/2 [1/0] (blank=keep): " v; [[ -n "${v:-}" ]] && RSF_VERIFY_H2="$v"
  read -r -p "Include generic [1/0] (blank=keep): " v; [[ -n "${v:-}" ]] && RSF_INCLUDE_GENERIC="$v"
  read -r -p "Override ref IP (blank=keep) : " v; [[ -n "${v:-}" ]] && RSF_REF_IP="$v"
  save_conf
  printf "${C2}Saved.${RESET}\n"; pause
}

view_output() {
  if [[ -f "$OUT_FILE" ]]; then
    printf "${C2}Output file:${RESET} %s\n" "$(pwd)/$OUT_FILE"
    printf "Count: %s\n" "$(wc -l < "$OUT_FILE" 2>/dev/null || echo 0)"
    printf "\nPreview:\n"; line; head -n 20 "$OUT_FILE" || true; line
  else
    printf "${C3}No output file found.${RESET}\n"
  fi
  pause
}

clean_output() {
  if [[ -f "$OUT_FILE" ]]; then
    rm -f "$OUT_FILE"; printf "${C2}Removed ${OUT_FILE}.${RESET}\n"
  else
    printf "${C4}Nothing to clean.${RESET}\n"
  fi
  pause
}

# Require root for fast masscan; escalate if needed
if [[ $EUID -ne 0 ]]; then
  printf "${C1}Elevating to root using sudo...${RESET}\n"
  exec sudo -E bash "$0" "$@"
fi

# Run engine automatically without menu
TARGET_IP=${1:-}

if [ -n "$TARGET_IP" ]; then
    export RSF_REF_IP="$TARGET_IP"
    echo "🎯 Используем целевой IP: $TARGET_IP"
fi

# Уменьшаем таймаут для TLS-пробинга, чтобы пропускать медленные сервера
export RSF_TIMEOUT=5

run_engine

# Отключаем strict mode (set -e), чтобы скрипт не падал при ошибках grep/dig/whois
set +e

echo "🌐 Определяем ASN целевого сервера..."
if [ -n "$TARGET_IP" ]; then
    MY_IP="$TARGET_IP"
else
    MY_IP=$(curl -s api.ipify.org)
fi

MY_ASN=$(whois -h whois.cymru.com " -v $MY_IP" | tail -1 | awk '{print $1}')

if [ -z "$MY_ASN" ]; then
    echo "❌ Не удалось определить ASN сервера. Пропускаем фильтрацию по ASN."
else
    echo "✅ Ваш ASN: AS$MY_ASN"
    echo "----------------------------------------"
    echo "🔍 Проверяем найденные домены на совпадение ASN (ускорено)..."
    
    if [ ! -f "domains.txt" ]; then
        echo "❌ Файл domains.txt не найден!"
        exit 1
    fi
    
    mv domains.txt domains_unfiltered.txt
    
    # Запускаем проверку ASN параллельно для максимальной скорости!
    check_domain() {
        local DOMAIN=$1
        local MY_ASN=$2
        local DOMAIN_IP=$(dig +short "$DOMAIN" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
        if [ -z "$DOMAIN_IP" ]; then return; fi
        
        local ASN_INFO=$(whois -h whois.cymru.com " -v $DOMAIN_IP" | tail -1)
        local DOMAIN_ASN=$(echo "$ASN_INFO" | awk '{print $1}')
        
        if [ "$DOMAIN_ASN" == "$MY_ASN" ]; then
            echo -e "✅ \033[0;32mИДЕАЛЬНОЕ СОВПАДЕНИЕ ASN:\033[0m $DOMAIN (IP: $DOMAIN_IP, AS$DOMAIN_ASN)"
            echo "$DOMAIN" >> domains.txt
        else
            echo -e "❌ \033[0;31mДРУГОЙ ПРОВАЙДЕР:\033[0m $DOMAIN (IP: $DOMAIN_IP, AS$DOMAIN_ASN)"
        fi
    }
    export -f check_domain
    
    # xargs запускает до 10 потоков проверки одновременно
    cat domains_unfiltered.txt | xargs -n 1 -P 10 -I {} bash -c "check_domain {} $MY_ASN"
    
    echo "----------------------------------------"
    echo "🎉 Итоговый список идеальных доменов сохранен в domains.txt"
    cat domains.txt || true
fi

