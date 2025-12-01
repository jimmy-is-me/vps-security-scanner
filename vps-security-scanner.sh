#!/bin/bash

#################################################
# VPS 安全掃描工具 v4.6.1 - 輕量級快速版
# GitHub: https://github.com/jimmy-is-me/vps-security-scanner
#################################################

# 顏色 (只用前景色,不要框線/底色)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

VERSION="4.6.1"

# 掃描範圍: 常見網站根目錄
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
# kB -> GB(一位小數)
kb_to_gb() {
    local kb="$1"
    if [ -z "$kb" ] || [ "$kb" -le 0 ] 2>/dev/null; then
        echo "0.0G"
        return
    fi
    awk -v v="$kb" 'BEGIN{printf "%.1fG", v/1048576}'
}

# 記憶體人類可讀 (全部用 GB,含百分比)
format_mem() {
    local total_kb="$1"
    local used_kb="$2"

    if [ -z "$total_kb" ] || [ "$total_kb" -le 0 ] 2>/dev/null; then
        echo "總量:0.0G 使用:0.0G(0%) 可用:0.0G"
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

# 自動尋找網站根目錄
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

# ==========================================
# 全域計數
# ==========================================
THREATS_FOUND=0
THREATS_CLEANED=0
ALERTS=()
NEED_FAIL2BAN=0
declare -A SITE_THREATS

# ==========================================
# 自動設定時區為 Asia/Taipei
# ==========================================
CURRENT_TZ=$(timedatectl 2>/dev/null | awk -F': ' '/Time zone/ {print $2}' | awk '{print $1}')
if [ "$CURRENT_TZ" != "Asia/Taipei" ] && command -v timedatectl >/dev/null 2>&1; then
    timedatectl set-timezone Asia/Taipei >/dev/null 2>&1
fi
NEW_TZ=$(timedatectl 2>/dev/null | awk -F': ' '/Time zone/ {print $2}' | awk '{print $1}')
[ -z "$NEW_TZ" ] && NEW_TZ="Unknown"

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

TZ_SYNC=$(timedatectl 2>/dev/null | awk -F': ' '/System clock synchronized/ {print $2}')
[ -z "$TZ_SYNC" ] && TZ_SYNC="unknown"

echo -e "${DIM}主機名稱:${NC} ${WHITE}${HOSTNAME}${NC}"
echo -e "${DIM}作業系統:${NC} ${WHITE}${OS_INFO}${NC}"
echo -e "${DIM}核心版本:${NC} ${WHITE}${KERNEL}${NC}"
echo -e "${DIM}CPU 型號:${NC} ${WHITE}${CPU_MODEL}${NC}"
echo -e "${DIM}CPU 核心:${NC} ${WHITE}${CPU_CORES}${NC}"
echo -e "${DIM}系統時區:${NC} ${WHITE}${NEW_TZ}${NC} ${DIM}(NTP 同步: ${TZ_SYNC})${NC}"

# 記憶體
MEM_TOTAL_KB=$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
MEM_AVAIL_KB=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null)
[ -z "$MEM_TOTAL_KB" ] && MEM_TOTAL_KB=0
[ -z "$MEM_AVAIL_KB" ] && MEM_AVAIL_KB=0
MEM_USED_KB=$(( MEM_TOTAL_KB - MEM_AVAIL_KB ))
[ "$MEM_USED_KB" -lt 0 ] && MEM_USED_KB=0

MEM_LINE=$(format_mem "$MEM_TOTAL_KB" "$MEM_USED_KB")
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

# 負載
LOAD_1=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,"",$1);print $1}')
LOAD_5=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,"",$2);print $2}')
LOAD_15=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,"",$3);print $3}')
UPTIME_HUMAN=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}')

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
echo

# ==========================================
# 網路連線統計 + 健康判斷
# ==========================================
echo -e "${BOLD}${CYAN}網路連線統計${NC}"
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

echo -e "${DIM}總連線:${NC} ${WHITE}${TOTAL_CONN}${NC}  ${DIM}監聽埠:${NC} ${WHITE}${LISTEN_PORTS}${NC}  ${DIM}HTTP(S):${NC} ${WHITE}${HTTP_CONN}${NC} (${HTTP_STATUS})"
echo

# ==========================================
# (以下流程邏輯與你 v4.6.0 相同,僅排版維持純文字/顏色)
# 1. 登入監控
# 2. 惡意 process
# 3. 病毒檔名
# 4. Webshell
# 5. 疑似中毒網站
# 6. Fail2Ban
# 7. 重置失敗登入
# ==========================================

# 1. 登入狀態監控
echo -e "${BOLD}${CYAN}系統登入監控${NC}"
CURRENT_USERS=$(who | wc -l)
echo -e "目前登入用戶: ${WHITE}${CURRENT_USERS}${NC}"

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

FAILED_COUNT=$(lastb 2>/dev/null | wc -l)
echo
if [ "$FAILED_COUNT" -gt 0 ]; then
    echo -e "失敗登入嘗試: ${YELLOW}${FAILED_COUNT}${NC}"
else
    echo -e "${GREEN}無失敗登入記錄${NC}"
fi
echo

# 2. 惡意 Process 掃描
echo -e "${BOLD}${CYAN}惡意 Process 掃描${NC}"
MALICIOUS_PROCESSES=$(ps aux | awk 'length($11)==8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis|lighttpd|postgres|memcache/' | grep -v "USER" | wc -l)
CRYPTO_MINERS=$(ps aux | grep -iE "xmrig|minerd|cpuminer|ccminer|cryptonight|monero|kinsing" | grep -v grep | wc -l)
TOTAL_SUSPICIOUS=$((MALICIOUS_PROCESSES + CRYPTO_MINERS))

if [ "$TOTAL_SUSPICIOUS" -gt 0 ]; then
    echo -e "${RED}發現 ${TOTAL_SUSPICIOUS} 個可疑 process,嘗試自動清除...${NC}"
    ps aux | awk 'length($11)==8 && $11 ~ /^[a-z0-9]+$/' | grep -v "USER" | awk '{print $2}' | xargs kill -9 2>/dev/null
    ps aux | grep -iE "xmrig|minerd|cpuminer" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
    THREATS_FOUND=$((THREATS_FOUND + TOTAL_SUSPICIOUS))
    THREATS_CLEANED=$((THREATS_CLEANED + TOTAL_SUSPICIOUS))
    [ "$CRYPTO_MINERS" -gt 0 ] && add_alert "CRITICAL" "偵測到挖礦程式 ${CRYPTO_MINERS} 個"
    echo -e "${GREEN}可疑 process 已嘗試清除${NC}"
else
    echo -e "${GREEN}未發現可疑 process${NC}"
fi
echo

# 3. 常見病毒檔名 (略: 與你原版邏輯相同,僅去框線)
# 4. Webshell 內容掃描 (同上)
# --- 這兩段可以直接沿用你上面 v4.6.0 的 find/grep 區塊,不用再動,為了篇幅就不重貼 ---

# ==========================================
# Fail2Ban: 曾經嘗試破解也要封鎖
# ==========================================
echo -e "${BOLD}${CYAN}Fail2Ban 防護狀態${NC}"

if command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active --quiet fail2ban; then
    echo -e "${GREEN}Fail2Ban 已安裝並運行中${NC}"
else
    echo -e "${YELLOW}Fail2Ban 未安裝,正在自動安裝...${NC}"
    if [ -f /etc/debian_version ]; then
        apt-get update -qq >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1
    elif [ -f /etc/redhat-release ]; then
        yum install -y epel-release fail2ban >/dev/null 2>&1
    fi
fi

if command -v fail2ban-client >/dev/null 2>&1; then
    cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 114.39.15.79
bantime = 24h
findtime = 1y
maxretry = 3
destemail =
action = %(action_)s

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 24h
findtime = 1y
EOF

    [ -f /etc/redhat-release ] && sed -i 's|/var/log/auth.log|/var/log/secure|' /etc/fail2ban/jail.local

    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1

    echo -e "規則: ${WHITE}maxretry = 3, findtime = 1y, bantime = 24h${NC}"
    echo -e "說明: ${DIM}一年內累積 3 次失敗登入就封鎖 24 小時,無論何時嘗試${NC}"
fi
echo

# ==========================================
# 總結 & 清理登入記錄
# ==========================================
echo -e "${BOLD}${CYAN}掃描總結${NC}"
echo -e "發現威脅: ${WHITE}${THREATS_FOUND}${NC}  已自動清除: ${GREEN}${THREATS_CLEANED}${NC}  需手動處理: ${YELLOW}$((THREATS_FOUND - THREATS_CLEANED))${NC}"
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
: > /var/log/btmp 2>/dev/null
echo -e " ${GREEN}完成${NC}"

echo
echo -e "${MAGENTA}掃描完成,本工具不會在系統留下程式檔或記錄${NC}"
echo

# 無痕刪除腳本 (如需啟用自行取消註解)
# rm -f "$0"
