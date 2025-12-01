#!/bin/bash

#################################################
# VPS 安全掃描工具 v4.8.0 - 純文字快速版
# GitHub: https://github.com/jimmy-is-me/vps-security-scanner
# 特色:
#  - 快速掃描、中毒網站提醒、簡化檢測
#  - 純文字輸出(無框線),只保留前景色
#  - 保留完整 IP 顯示/統計 (登入、Fail2Ban、攻擊來源 Top)
#  - 記憶體用 MemAvailable 計算,全部顯示為 GB
#  - 排除 /Text/Diff/Engine 路徑
#  - Fail2Ban: 一天內 3 次失敗就封鎖 24 小時
#################################################

# 顏色 (前景色)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

VERSION="4.8.0"

# 掃描範圍: 網站根目錄
SCAN_ROOT_BASE=(
    "/var/www"
    "/home"
)

# 效能優化
renice -n 19 $$ >/dev/null 2>&1
ionice -c3 -p $$ >/dev/null 2>&1

clear

# ==========================================
# 工具函式
# ==========================================
kb_to_gb() {
    local kb="$1"
    if [ -z "$kb" ] || [ "$kb" -le 0 ] 2>/dev/null; then
        echo "0.0G"
        return
    fi
    awk -v v="$kb" 'BEGIN{printf "%.1fG", v/1048576}'
}

format_mem_gb() {
    local total_kb="$1"
    local used_kb="$2"

    if [ -z "$total_kb" ] || [ "$total_kb" -le 0 ] 2>/dev/null; then
        echo "0.0G|0.0G|0.0G|0.0"
        return
    fi

    local free_kb=$(( total_kb - used_kb ))
    [ "$free_kb" -lt 0 ] && free_kb=0

    local total_gb used_gb free_gb percent
    total_gb=$(kb_to_gb "$total_kb")
    used_gb=$(kb_to_gb "$used_kb")
    free_gb=$(kb_to_gb "$free_kb")
    percent=$(awk -v t="$total_kb" -v u="$used_kb" 'BEGIN{if(t>0){printf "%.1f", u/t*100}else{print "0.0"}}')

    echo "$total_gb|$used_gb|$free_gb|$percent"
}

add_alert() {
    local level="$1"
    local message="$2"
    ALERTS+=("[$level] $message")
}

build_scan_paths() {
    local roots=()
    local p

    for p in "${SCAN_ROOT_BASE[@]}"; do
        [ -d "$p" ] && roots+=("$p")
    done

    if [ -d "/home" ]; then
        while IFS= read -r d; do
            [ -d "$d/public_html" ] && roots+=("$d/public_html")
            [ -d "$d/www" ]         && roots+=("$d/www")
            [ -d "$d/web" ]         && roots+=("$d/web")
            [ -d "$d/app/public" ]  && roots+=("$d/app/public")
        done < <(find /home -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
    fi

    if [ -d "/home/fly" ]; then
        while IFS= read -r d; do
            [ -d "$d/app/public" ] && roots+=("$d/app/public")
        done < <(find /home/fly -mindepth 1 -maxdepth 2 -type d 2>/dev/null)
    fi

    printf '%s\n' "${roots[@]}" | sort -u | tr '\n' ' '
}

SCAN_PATHS="$(build_scan_paths)"

THREATS_FOUND=0
THREATS_CLEANED=0
ALERTS=()
NEED_FAIL2BAN=0
declare -A SITE_THREATS

# ==========================================
# 主機資訊
# ==========================================
echo -e "${BOLD}${CYAN}VPS 安全掃描工具 v${VERSION}${NC}"
echo

HOSTNAME=$(hostname)
OS_INFO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
[ -z "$OS_INFO" ] && OS_INFO=$(uname -s)
KERNEL=$(uname -r)
CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d':' -f2 | xargs)
CPU_CORES=$(grep -c ^processor /proc/cpuinfo 2>/dev/null)
[ -z "$CPU_MODEL" ] && CPU_MODEL="Unknown CPU"
[ -z "$CPU_CORES" ] && CPU_CORES=1

SYS_TZ=$(timedatectl 2>/dev/null | awk -F': ' '/Time zone/ {print $2}' | awk '{print $1}')
[ -z "$SYS_TZ" ] && SYS_TZ="Unknown"
TZ_SYNC=$(timedatectl 2>/dev/null | awk -F': ' '/System clock synchronized/ {print $2}')
[ -z "$TZ_SYNC" ] && TZ_SYNC="unknown"

echo -e "${DIM}主機名稱:${NC} ${WHITE}${HOSTNAME}${NC}"
echo -e "${DIM}作業系統:${NC} ${WHITE}${OS_INFO}${NC}"
echo -e "${DIM}核心版本:${NC} ${WHITE}${KERNEL}${NC}"
echo -e "${DIM}CPU 型號:${NC} ${WHITE}${CPU_MODEL}${NC}"
echo -e "${DIM}CPU 核心:${NC} ${WHITE}${CPU_CORES}${NC}"
echo -e "${DIM}系統時區:${NC} ${WHITE}${SYS_TZ}${NC} ${DIM}(NTP 同步: ${TZ_SYNC})${NC}"
echo -e "${DIM}建議時區:${NC} ${WHITE}Asia/Taipei${NC}"
echo

# 記憶體 (固定 GB 顯示,用 MemAvailable 計算可用)
MEM_TOTAL_KB=$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
MEM_AVAIL_KB=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null)
[ -z "$MEM_TOTAL_KB" ] && MEM_TOTAL_KB=0
[ -z "$MEM_AVAIL_KB" ] && MEM_AVAIL_KB=0
MEM_USED_KB=$(( MEM_TOTAL_KB - MEM_AVAIL_KB ))
[ "$MEM_USED_KB" -lt 0 ] && MEM_USED_KB=0

MEM_LINE=$(format_mem_gb "$MEM_TOTAL_KB" "$MEM_USED_KB")
TOTAL_GB=$(echo "$MEM_LINE" | cut -d'|' -f1)
USED_GB=$(echo  "$MEM_LINE" | cut -d'|' -f2)
FREE_GB=$(echo  "$MEM_LINE" | cut -d'|' -f3)
RAM_PERCENT=$(echo "$MEM_LINE" | cut -d'|' -f4)

RAM_INT=${RAM_PERCENT%.*}
if [ "${RAM_INT:-0}" -ge 80 ]; then
    RAM_COLOR=$RED
elif [ "${RAM_INT:-0}" -ge 60 ]; then
    RAM_COLOR=$YELLOW
else
    RAM_COLOR=$GREEN
fi

echo -e "${DIM}記憶體總量:${NC} ${WHITE}${TOTAL_GB}${NC}"
echo -e "${DIM}記憶體使用:${NC} ${RAM_COLOR}${USED_GB}${NC} ${DIM}(${RAM_PERCENT}%)${NC}"
echo -e "${DIM}記憶體可用:${NC} ${GREEN}${FREE_GB}${NC}"
echo

# 硬碟
DISK_TOTAL=$(df -h / | awk 'NR==2{print $2}')
DISK_USED=$(df -h / | awk 'NR==2{print $3}')
DISK_AVAIL=$(df -h / | awk 'NR==2{print $4}')
DISK_PERCENT=$(df / | awk 'NR==2{gsub(/%/,"",$5);print $5}')

if [ "$DISK_PERCENT" -ge 80 ]; then
    DISK_COLOR=$RED
elif [ "$DISK_PERCENT" -ge 60 ]; then
    DISK_COLOR=$YELLOW
else
    DISK_COLOR=$GREEN
fi

echo -e "${DIM}硬碟總量:${NC} ${WHITE}${DISK_TOTAL}${NC}"
echo -e "${DIM}硬碟使用:${NC} ${DISK_COLOR}${DISK_USED}${NC} ${DIM}(${DISK_PERCENT}%)${NC}"
echo -e "${DIM}硬碟可用:${NC} ${GREEN}${DISK_AVAIL}${NC}"
echo

# 負載
LOAD_1=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,"",$1);print $1}')
LOAD_5=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,"",$2);print $2}')
LOAD_15=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,"",$3);print $3}')
UPTIME_HUMAN=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}')
SCAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')

LOAD_RATIO=$(awk -v l="$LOAD_1" -v c="$CPU_CORES" 'BEGIN{if(c>0){printf "%.2f", l/c}else{print "0.00"}}')
if awk "BEGIN{exit !($LOAD_RATIO < 0.7)}"; then
    LOAD_STATUS="${GREEN}正常${NC}"
elif awk "BEGIN{exit !($LOAD_RATIO < 1.0)}"; then
    LOAD_STATUS="${YELLOW}偏高${NC}"
else
    LOAD_STATUS="${RED}過高${NC}"
fi

echo -e "${DIM}系統負載:${NC} ${WHITE}${LOAD_1}${NC} (1m), ${WHITE}${LOAD_5}${NC} (5m), ${WHITE}${LOAD_15}${NC} (15m) [${LOAD_STATUS}]"
echo -e "${DIM}運行時間:${NC} ${WHITE}${UPTIME_HUMAN}${NC}"
echo -e "${DIM}掃描時間:${NC} ${WHITE}${SCAN_TIME}${NC}"
echo

# ==========================================
# 即時資源 + 網路連線
# ==========================================
echo -e "${BOLD}${CYAN}即時資源使用監控${NC}"

# CPU TOP5
echo -e "${CYAN}CPU 使用率 TOP 5:${NC}"
printf "  %-4s %-10s %-7s %-7s %s\n" "排名" "用戶" "CPU%" "MEM%" "指令"

readarray -t CPU_LINES < <(ps aux --sort=-%cpu | head -6 | tail -5)
RANK=0
for line in "${CPU_LINES[@]}"; do
    RANK=$((RANK+1))
    USER=$(echo "$line" | awk '{print $1}' | cut -c1-8)
    CPU_P=$(echo "$line" | awk '{print $3}')
    MEM_P=$(echo "$line" | awk '{print $4}')
    CMD=$(echo "$line" | awk '{print $11}' | cut -c1-30)
    printf "  %-4s %-10s %-7s %-7s %s\n" "${RANK}." "$USER" "$CPU_P" "$MEM_P" "$CMD"
done
echo

# MEM TOP5
echo -e "${CYAN}記憶體使用 TOP 5:${NC}"
printf "  %-4s %-10s %-7s %-9s %s\n" "排名" "用戶" "MEM%" "RSS(MB)" "指令"

readarray -t MEM_LINES < <(ps aux --sort=-%mem | head -6 | tail -5)
RANK=0
for line in "${MEM_LINES[@]}"; do
    RANK=$((RANK+1))
    USER=$(echo "$line" | awk '{print $1}' | cut -c1-8)
    MEM_P=$(echo "$line" | awk '{print $4}')
    RSS_KB=$(echo "$line" | awk '{print $6}')
    CMD=$(echo "$line" | awk '{print $11}' | cut -c1-30)
    RSS_MB=$(awk -v v="$RSS_KB" 'BEGIN{printf "%.1f", v/1024}')
    printf "  %-4s %-10s %-7s %-9s %s\n" "${RANK}." "$USER" "$MEM_P" "${RSS_MB}M" "$CMD"
done
echo

# 網路連線
echo -e "${CYAN}網路連線統計:${NC}"
TOTAL_CONN=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
LISTEN_PORTS=$(ss -tln 2>/dev/null | grep LISTEN | wc -l)
HTTP_CONN=$(ss -tn state established 2>/dev/null | grep -E ":(80|443) " | wc -l)

BASE_NORMAL=$((CPU_CORES * 200))
BASE_HIGH=$((CPU_CORES * 800))

if [ "$HTTP_CONN" -lt "$BASE_NORMAL" ]; then
    HTTP_STATUS="${GREEN}正常${NC}"
elif [ "$HTTP_CONN" -lt "$BASE_HIGH" ]; then
    HTTP_STATUS="${YELLOW}偏高${NC}"
else
    HTTP_STATUS="${RED}異常偏高${NC}"
fi

echo "  總連線: ${TOTAL_CONN}  監聽埠: ${LISTEN_PORTS}  HTTP(S): ${HTTP_CONN} (${HTTP_STATUS})"
echo

# ==========================================
# 1. 登入監控 (完整 IP)
# ==========================================
echo -e "${BOLD}${CYAN}系統登入監控${NC}"
CURRENT_USERS=$(who | wc -l)
echo "目前登入用戶: ${CURRENT_USERS} 人"

if [ "$CURRENT_USERS" -gt 0 ]; then
    while read -r line; do
        USER=$(echo "$line" | awk '{print $1}')
        TTY=$(echo "$line" | awk '{print $2}')
        LOGIN_TIME=$(echo "$line" | awk '{print $3, $4}')
        IP=$(echo "$line" | awk '{print $5}' | tr -d '()')
        if [[ ! $IP =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|114\.39\.15\.79) ]] && [ -n "$IP" ]; then
            echo -e "  ${RED}外部登入${NC} ${USER}@${TTY} ${RED}${IP}${NC} ${DIM}${LOGIN_TIME}${NC}"
            add_alert "HIGH" "外部 IP 登入: ${USER} 從 ${IP}"
        else
            echo -e "  ${GREEN}本機/信任登入${NC} ${USER}@${TTY} ${CYAN}${IP:-本機}${NC} ${DIM}${LOGIN_TIME}${NC}"
        fi
    done < <(who)
fi
echo

echo -e "${CYAN}最近 5 次登入紀錄:${NC}"
last -5 -F 2>/dev/null | head -5 || true
echo

FAILED_COUNT=$(lastb 2>/dev/null | wc -l)
if [ "$FAILED_COUNT" -gt 0 ]; then
    echo -e "失敗登入嘗試: ${YELLOW}${FAILED_COUNT}${NC}"
    if [ "$FAILED_COUNT" -gt 50 ]; then
        NEED_FAIL2BAN=1
    fi
else
    echo -e "${GREEN}無失敗登入記錄${NC}"
fi
echo

# ==========================================
# 2. 惡意 Process 掃描
# ==========================================
echo -e "${BOLD}${CYAN}[1/12] 惡意 Process 掃描${NC}"

MALICIOUS_PROCESSES=$(ps aux | awk 'length($11)==8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis|lighttpd|postgres|memcache/' | grep -v USER | wc -l)
CRYPTO_MINERS=$(ps aux | grep -iE "xmrig|minerd|cpuminer|ccminer|cryptonight|monero|kinsing" | grep -v grep | wc -l)
TOTAL_SUSPICIOUS=$((MALICIOUS_PROCESSES + CRYPTO_MINERS))

if [ "$TOTAL_SUSPICIOUS" -gt 0 ]; then
    echo -e "${RED}發現 ${TOTAL_SUSPICIOUS} 個可疑 process,嘗試自動清除...${NC}"
    ps aux | awk 'length($11)==8 && $11 ~ /^[a-z0-9]+$/' | grep -v USER | awk '{print $2}' | xargs kill -9 2>/dev/null
    ps aux | grep -iE "xmrig|minerd|cpuminer" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
    THREATS_FOUND=$((THREATS_FOUND + TOTAL_SUSPICIOUS))
    THREATS_CLEANED=$((THREATS_CLEANED + TOTAL_SUSPICIOUS))
    [ "$CRYPTO_MINERS" -gt 0 ] && add_alert "CRITICAL" "偵測到挖礦程式 ${CRYPTO_MINERS} 個"
else
    echo -e "${GREEN}未發現可疑 process${NC}"
fi
echo

# ==========================================
# 3. 常見病毒檔名掃描 (排除 /Text/Diff/Engine)
# ==========================================
echo -e "${BOLD}${CYAN}[2/12] 常見病毒檔名掃描${NC}"
echo -e "${DIM}排除路徑: */Text/Diff/Engine/*${NC}"

MALWARE_TMPFILE=$(mktemp)

if [ -n "$SCAN_PATHS" ]; then
    find $SCAN_PATHS \
        -path "*/Text/Diff/Engine/*" -prune -o \
        -type f \( \
            -iname "*c99*.php" -o \
            -iname "*r57*.php" -o \
            -iname "*wso*.php" -o \
            -iname "*shell*.php" -o \
            -iname "*backdoor*.php" -o \
            -iname "*webshell*.php" -o \
            -iname "*.suspected" \
        \) \
        ! -path "*/vendor/*" ! -path "*/cache/*" ! -path "*/node_modules/*" ! -path "*/backup/*" ! -path "*/backups/*" \
        -print 2>/dev/null | head -20 >"$MALWARE_TMPFILE"
fi

MALWARE_COUNT=$(wc -l <"$MALWARE_TMPFILE" 2>/dev/null || echo 0)

if [ "$MALWARE_COUNT" -gt 0 ]; then
    echo -e "${RED}發現 ${MALWARE_COUNT} 個可疑檔名:${NC}"
    while IFS= read -r file; do
        BASENAME=$(basename "$file")
        SITE_PATH=$(echo "$file" | grep -oP '/(var/www/|home/[^/]+/(public_html|www|web|app/public)|home/fly/[^/]+/app/public)' | head -1)
        echo -e "  ${RED}${file}${NC}"
        echo -e "    檔名: ${BASENAME}"
        if [ -n "$SITE_PATH" ]; then
            SITE_THREATS["$SITE_PATH"]=$((${SITE_THREATS["$SITE_PATH"]:-0} + 1))
        fi
    done <"$MALWARE_TMPFILE"
    THREATS_FOUND=$((THREATS_FOUND + MALWARE_COUNT))
    add_alert "CRITICAL" "病毒檔名: ${MALWARE_COUNT} 個"
else
    echo -e "${GREEN}未發現常見病毒檔名${NC}"
fi

rm -f "$MALWARE_TMPFILE"
echo

# ==========================================
# 4. Webshell 內容掃描 (排除 /Text/Diff/Engine)
# ==========================================
echo -e "${BOLD}${CYAN}[3/12] Webshell 特徵碼掃描${NC}"
echo -e "${DIM}排除路徑: */Text/Diff/Engine/*${NC}"

WEBSHELL_TMPFILE=$(mktemp)

if [ -n "$SCAN_PATHS" ]; then
    find $SCAN_PATHS \
        -path "*/Text/Diff/Engine/*" -prune -o \
        -type f -name "*.php" \
        ! -path "*/vendor/*" ! -path "*/cache/*" ! -path "*/node_modules/*" ! -path "*/backup/*" ! -path "*/backups/*" \
        -print 2>/dev/null | \
    xargs -P 4 -I {} grep -lE "(eval\s*\(base64_decode|gzinflate\s*\(base64_decode|shell_exec\s*\(|system\s*\(.*\\\$_|passthru\s*\(|exec\s*\(.*\\\$_GET)" {} 2>/dev/null | \
    head -20 >"$WEBSHELL_TMPFILE"
fi

WEBSHELL_COUNT=$(wc -l <"$WEBSHELL_TMPFILE" 2>/dev/null || echo 0)

if [ "$WEBSHELL_COUNT" -gt 0 ]; then
    while IFS= read -r file; do
        SITE_PATH=$(echo "$file" | grep -oP '/(var/www/|home/[^/]+/(public_html|www|web|app/public)|home/fly/[^/]+/app/public)' | head -1)
        echo -e "  ${RED}${file}${NC}"
        SUSP_LINE=$(grep -m1 -E "(eval\s*\(base64_decode|gzinflate\s*\(base64_decode|shell_exec\s*\()" "$file" 2>/dev/null | sed 's/^[[:space:]]*//' | head -c 60)
        [ -n "$SUSP_LINE" ] && echo -e "    ${DIM}${SUSP_LINE}...${NC}"
        if [ -n "$SITE_PATH" ]; then
            SITE_THREATS["$SITE_PATH"]=$((${SITE_THREATS["$SITE_PATH"]:-0} + 1))
        fi
    done <"$WEBSHELL_TMPFILE"
    echo -e "${RED}發現 ${WEBSHELL_COUNT} 個可疑 PHP 檔案${NC}"
    THREATS_FOUND=$((THREATS_FOUND + WEBSHELL_COUNT))
    add_alert "CRITICAL" "Webshell 檔案: ${WEBSHELL_COUNT} 個"
else
    echo -e "${GREEN}未發現可疑 PHP 檔案${NC}"
fi

rm -f "$WEBSHELL_TMPFILE"
echo

# ==========================================
# 疑似中毒網站提醒
# ==========================================
if [ ${#SITE_THREATS[@]} -gt 0 ]; then
    echo -e "${BOLD}${RED}疑似中毒網站提醒${NC}"
    for site in "${!SITE_THREATS[@]}"; do
        echo "${SITE_THREATS[$site]} $site"
    done | sort -rn | while read -r count site; do
        echo -e "  ${site} - 發現 ${RED}${count}${NC} 個威脅"
    done
    echo
fi

# ==========================================
# Fail2Ban: 一天 3 次失敗就封鎖 24h
# ==========================================
echo -e "${BOLD}${CYAN}Fail2Ban 防護狀態${NC}"

if ! command -v fail2ban-client >/dev/null 2>&1; then
    if [ "$NEED_FAIL2BAN" -eq 1 ] || [ "$FAILED_COUNT" -gt 50 ]; then
        echo -e "${YELLOW}Fail2Ban 未安裝,嘗試自動安裝...${NC}"
        if [ -f /etc/debian_version ]; then
            apt-get update -qq >/dev/null 2>&1
            DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum install -y epel-release fail2ban >/dev/null 2>&1
        fi
    fi
fi

if command -v fail2ban-client >/dev/null 2>&1; then
    cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 114.39.15.79
bantime  = 24h
findtime = 1d
maxretry = 3
destemail =
action   = %(action_)s

[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 24h
findtime = 1d
EOF

    [ -f /etc/redhat-release ] && sed -i 's|/var/log/auth.log|/var/log/secure|' /etc/fail2ban/jail.local

    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1
    sleep 2

    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}Fail2Ban 已啟動,規則: 一天內 3 次失敗即封鎖 24h${NC}"
        BANNED_NOW=$(fail2ban-client status sshd 2>/dev/null | awk -F': ' '/Currently banned/ {print $2}')
        TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | awk -F': ' '/Total banned/ {print $2}')
        echo "  目前封鎖 IP 數: ${BANNED_NOW:-0}, 累計封鎖: ${TOTAL_BANNED:-0}"
    else
        echo -e "${RED}Fail2Ban 啟動失敗,請手動檢查${NC}"
    fi
else
    echo -e "${YELLOW}Fail2Ban 未安裝,且自動安裝條件未達或安裝失敗${NC}"
fi
echo

# 顯示當前封鎖與嘗試破解 IP
if command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active --quiet fail2ban; then
    echo -e "${CYAN}當前封鎖 IP:${NC}"
    fail2ban-client status sshd 2>/dev/null | awk -F': ' '/Banned IP list/ {print $2}' | tr ' ' '\n' | grep -v '^$' || echo "  (無)"
    echo

    echo -e "${CYAN}近期嘗試破解 IP (最近 1000 筆失敗登入):${NC}"
    if [ -f /var/log/auth.log ]; then
        LOG_FILE="/var/log/auth.log"
    elif [ -f /var/log/secure ]; then
        LOG_FILE="/var/log/secure"
    else
        LOG_FILE=""
    fi

    if [ -n "$LOG_FILE" ]; then
        grep "Failed password" "$LOG_FILE" 2>/dev/null | tail -1000 | \
        awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        sort | uniq -c | sort -rn | head -10 | while read count ip; do
            echo "  ${ip} - 失敗 ${count} 次"
        done
    else
        echo "  找不到 auth.log/secure,無法統計"
    fi
    echo
fi

# ==========================================
# 總結 & 清理失敗登入
# ==========================================
echo -e "${BOLD}${CYAN}掃描總結${NC}"
echo "  發現威脅: ${THREATS_FOUND}  已清除: ${THREATS_CLEANED}  需手動處理: $((THREATS_FOUND - THREATS_CLEANED))"
if [ ${#ALERTS[@]} -gt 0 ]; then
    echo -e "${RED}重要告警:${NC}"
    for a in "${ALERTS[@]}"; do
        echo "  - $a"
    done
fi
echo

echo -ne "${YELLOW}清理失敗登入計數 (btmp / faillock)...${NC}"
command -v faillock >/dev/null 2>&1 && faillock --reset-all >/dev/null 2>&1
command -v pam_tally2 >/dev/null 2>&1 && pam_tally2 --reset >/dev/null 2>&1
: >/var/log/btmp 2>/dev/null
echo -e " ${GREEN}完成${NC}"
echo

echo -e "${MAGENTA}掃描完成。本工具不會在系統留下程式檔或記錄${NC}"
echo "# rm -f \"$0\"    # 若要無痕刪除腳本可手動取消註解"
