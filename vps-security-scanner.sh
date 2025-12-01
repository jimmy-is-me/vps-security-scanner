#!/bin/bash

#################################################
# VPS 安全掃描工具 v4.5.2 - 輕量級快速版
# GitHub: https://github.com/jimmy-is-me/vps-security-scanner
# 特色:快速掃描、中毒網站提醒、簡化檢測
# 更新:
#  - 只掃描網站根目錄 (PHP 掃毒)
#  - Fail2Ban 規則: 5 次失敗 / 不限時間 = 封鎖 24 小時
#  - 封鎖 IP 區塊顯示: 當前嘗試破解 IP 與嘗試次數
#################################################

# 顏色與圖示
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BLUE='\033[0;34m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_CYAN='\033[46m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

VERSION="4.5.2"

# 掃描範圍: 網站根目錄 (PHP 掃描只針對這些)
SCAN_ROOTS=(
    "/var/www"
    "/home"
)

# 效能優化
renice -n 19 $$ > /dev/null 2>&1
ionice -c3 -p $$ > /dev/null 2>&1

clear

# ==========================================
# 標題
# ==========================================
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}                                                                    ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}         🛡️  VPS 安全掃描工具 v${VERSION} - 快速版              ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}                                                                    ${NC}${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 計數器
THREATS_FOUND=0
THREATS_CLEANED=0
ALERTS=()
NEED_FAIL2BAN=0
declare -A SITE_THREATS  # 記錄每個網站的威脅數量

add_alert() {
    local level=$1
    local message=$2
    ALERTS+=("[$level] $message")
}

# 將 SCAN_ROOTS 組成 find 用的 path
build_scan_paths() {
    local args=()
    for p in "${SCAN_ROOTS[@]}"; do
        [ -d "$p" ] && args+=("$p")
    done
    echo "${args[@]}"
}

SCAN_PATHS="$(build_scan_paths)"

# ==========================================
# 主機基本資訊
# ==========================================
echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${YELLOW} 🖥️  主機資訊${NC}                                                     ${CYAN}│${NC}"
echo -e "${CYAN}├────────────────────────────────────────────────────────────────┤${NC}"

HOSTNAME=$(hostname)
OS_INFO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
[ -z "$OS_INFO" ] && OS_INFO=$(uname -s)
KERNEL=$(uname -r)
CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d':' -f2 | xargs)
CPU_CORES=$(grep -c ^processor /proc/cpuinfo 2>/dev/null)
[ -z "$CPU_MODEL" ] && CPU_MODEL="Unknown CPU"

echo -e "${CYAN}│${NC} ${DIM}主機名稱:${NC} ${WHITE}${HOSTNAME}${NC}"
echo -e "${CYAN}│${NC} ${DIM}作業系統:${NC} ${WHITE}${OS_INFO}${NC}"
echo -e "${CYAN}│${NC} ${DIM}核心版本:${NC} ${WHITE}${KERNEL}${NC}"
echo -e "${CYAN}│${NC} ${DIM}CPU 型號:${NC} ${WHITE}${CPU_MODEL}${NC}"
echo -e "${CYAN}│${NC} ${DIM}CPU 核心:${NC} ${WHITE}${CPU_CORES} 核心${NC}"

# 記憶體資訊
TOTAL_RAM=$(free -h | awk '/^Mem:/ {print $2}')
USED_RAM=$(free -h | awk '/^Mem:/ {print $3}')
FREE_RAM=$(free -h | awk '/^Mem:/ {print $4}')
RAM_PERCENT=$(free | awk '/^Mem:/ {printf "%.1f", $3/$2 * 100}')

RAM_INT=${RAM_PERCENT%.*}
if [ "${RAM_INT:-0}" -gt 80 ]; then
    RAM_COLOR="${RED}"
elif [ "${RAM_INT:-0}" -gt 60 ]; then
    RAM_COLOR="${YELLOW}"
else
    RAM_COLOR="${GREEN}"
fi

echo -e "${CYAN}│${NC} ${DIM}記憶體總量:${NC} ${WHITE}${TOTAL_RAM}${NC}"
echo -e "${CYAN}│${NC} ${DIM}記憶體使用:${NC} ${RAM_COLOR}${USED_RAM}${NC} ${DIM}(${RAM_PERCENT}%)${NC}"
echo -e "${CYAN}│${NC} ${DIM}記憶體可用:${NC} ${GREEN}${FREE_RAM}${NC}"

# 硬碟空間
DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
DISK_PERCENT=$(df / | awk 'NR==2 {print $5}' | tr -d '%')

if [ "$DISK_PERCENT" -gt 80 ]; then
    DISK_COLOR="${RED}"
elif [ "$DISK_PERCENT" -gt 60 ]; then
    DISK_COLOR="${YELLOW}"
else
    DISK_COLOR="${GREEN}"
fi

echo -e "${CYAN}│${NC} ${DIM}硬碟總量:${NC} ${WHITE}${DISK_TOTAL}${NC}"
echo -e "${CYAN}│${NC} ${DIM}硬碟使用:${NC} ${DISK_COLOR}${DISK_USED}${NC} ${DIM}(${DISK_PERCENT}%)${NC}"
echo -e "${CYAN}│${NC} ${DIM}硬碟可用:${NC} ${GREEN}${DISK_AVAIL}${NC}"

# 系統負載
LOAD_1=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)
LOAD_5=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $2}' | xargs)
LOAD_15=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $3}' | xargs)
UPTIME=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}')
SCAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')

echo -e "${CYAN}│${NC} ${DIM}系統負載:${NC} ${WHITE}${LOAD_1}${NC} ${DIM}(1分) ${WHITE}${LOAD_5}${NC} ${DIM}(5分) ${WHITE}${LOAD_15}${NC} ${DIM}(15分)${NC}"
echo -e "${CYAN}│${NC} ${DIM}運行時間:${NC} ${WHITE}${UPTIME}${NC}"
echo -e "${CYAN}│${NC} ${DIM}掃描時間:${NC} ${WHITE}${SCAN_TIME}${NC}"

echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
echo ""

# ==========================================
# 即時資源使用監控
# ==========================================
echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${YELLOW} 💻 即時資源使用監控${NC}                                           ${CYAN}│${NC}"
echo -e "${CYAN}├────────────────────────────────────────────────────────────────┤${NC}"

# CPU 使用率 TOP 5
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ CPU 使用率 TOP 5${NC}"
echo -e "${CYAN}│${NC}   ${DIM}排名  用戶       CPU%   記憶體%  指令${NC}"

readarray -t CPU_LINES < <(ps aux --sort=-%cpu | head -6 | tail -5)
RANK=0
for line in "${CPU_LINES[@]}"; do
    RANK=$((RANK + 1))
    USER=$(echo "$line" | awk '{print $1}' | cut -c1-8)
    CPU=$(echo "$line" | awk '{print $3}')
    MEM=$(echo "$line" | awk '{print $4}')
    CMD=$(echo "$line" | awk '{print $11}' | cut -c1-25)
    
    CPU_INT=${CPU%.*}
    if [ "${CPU_INT:-0}" -gt 50 ]; then
        CPU_COLOR="${RED}"
    elif [ "${CPU_INT:-0}" -gt 20 ]; then
        CPU_COLOR="${YELLOW}"
    else
        CPU_COLOR="${WHITE}"
    fi
    
    printf "${CYAN}│${NC}   ${DIM}%-4s ${YELLOW}%-10s ${NC}${CPU_COLOR}%6s%% ${DIM}%6s%%  ${NC}%s\n" \
           "${RANK}." "$USER" "$CPU" "$MEM" "$CMD"
done

# 記憶體使用 TOP 5
echo -e "${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ 記憶體使用 TOP 5${NC}"
echo -e "${CYAN}│${NC}   ${DIM}排名  用戶       記憶體%  RSS      指令${NC}"

readarray -t MEM_LINES < <(ps aux --sort=-%mem | head -6 | tail -5)
RANK=0
for line in "${MEM_LINES[@]}"; do
    RANK=$((RANK + 1))
    USER=$(echo "$line" | awk '{print $1}' | cut -c1-8)
    MEM=$(echo "$line" | awk '{print $4}')
    RSS=$(echo "$line" | awk '{print $6}')
    CMD=$(echo "$line" | awk '{print $11}' | cut -c1-25)
    
    RSS_MB=$(awk "BEGIN {printf \"%.1f\", $RSS/1024}")
    
    MEM_INT=${MEM%.*}
    if [ "${MEM_INT:-0}" -gt 20 ]; then
        MEM_COLOR="${RED}"
    elif [ "${MEM_INT:-0}" -gt 10 ]; then
        MEM_COLOR="${YELLOW}"
    else
        MEM_COLOR="${WHITE}"
    fi
    
    printf "${CYAN}│${NC}   ${DIM}%-4s ${YELLOW}%-10s ${NC}${MEM_COLOR}%7s%% ${DIM}%6sM  ${NC}%s\n" \
           "${RANK}." "$USER" "$MEM" "$RSS_MB" "$CMD"
done

# 網站服務資源使用
echo -e "${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ 網站服務資源使用${NC}"

WEB_SERVICES=0

# Nginx
if pgrep -x nginx > /dev/null 2>&1; then
    PROCS=$(pgrep -x nginx | wc -l)
    CPU=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
    
    echo -e "${CYAN}│${NC}   ${GREEN}✓${NC} ${WHITE}Nginx${NC}"
    echo -e "${CYAN}│${NC}      ${DIM}進程: ${WHITE}${PROCS}${DIM} | CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"
    
    if [ -d /etc/nginx/sites-enabled ]; then
        SITES=$(ls -1 /etc/nginx/sites-enabled 2>/dev/null | grep -v default | wc -l)
        [ $SITES -gt 0 ] && echo -e "${CYAN}│${NC}      ${DIM}管理網站: ${WHITE}${SITES}${DIM} 個${NC}"
    fi
    WEB_SERVICES=1
fi

# PHP-FPM
if pgrep -f "php-fpm" > /dev/null 2>&1; then
    PROCS=$(pgrep -f "php-fpm" | wc -l)
    CPU=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
    PHP_VER=$(php -v 2>/dev/null | head -1 | awk '{print $2}' | cut -d. -f1,2 || echo "?")
    
    echo -e "${CYAN}│${NC}   ${GREEN}✓${NC} ${WHITE}PHP-FPM ${DIM}(v${PHP_VER})${NC}"
    echo -e "${CYAN}│${NC}      ${DIM}進程: ${WHITE}${PROCS}${DIM} | CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"
    
    WP_COUNT=$(find /var/www /home -maxdepth 5 -name "wp-config.php" -type f 2>/dev/null | wc -l)
    [ $WP_COUNT -gt 0 ] && echo -e "${CYAN}│${NC}      ${DIM}WordPress 網站: ${WHITE}${WP_COUNT}${DIM} 個${NC}"
    WEB_SERVICES=1
fi

# MySQL/MariaDB
if pgrep -x "mysqld\|mariadbd" > /dev/null 2>&1; then
    PROC_NAME=$(pgrep -x mysqld > /dev/null && echo "mysqld" || echo "mariadbd")
    CPU=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
    
    echo -e "${CYAN}│${NC}   ${GREEN}✓${NC} ${WHITE}MySQL/MariaDB${NC}"
    echo -e "${CYAN}│${NC}      ${DIM}CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"
    WEB_SERVICES=1
fi

[ $WEB_SERVICES -eq 0 ] && echo -e "${CYAN}│${NC}   ${DIM}未偵測到網站服務運行${NC}"

# 網路連線統計
echo -e "${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ 網路連線統計${NC}"

TOTAL_CONN=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
LISTEN_PORTS=$(ss -tln 2>/dev/null | grep LISTEN | wc -l)
HTTP_CONN=$(ss -tn state established 2>/dev/null | grep -E ":(80|443) " | wc -l)

echo -e "${CYAN}│${NC}   ${DIM}總連線: ${WHITE}${TOTAL_CONN}${DIM} | 監聽埠: ${WHITE}${LISTEN_PORTS}${DIM} | HTTP(S): ${WHITE}${HTTP_CONN}${NC}"

echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
echo ""

# ==========================================
# 1. 登入狀態監控
# ==========================================
echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${YELLOW} 👤 系統登入監控${NC}                                              ${CYAN}│${NC}"
echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
echo ""

CURRENT_USERS=$(who | wc -l)
echo -e "${BOLD}${CYAN}▶ 目前登入用戶: ${WHITE}${CURRENT_USERS} 人${NC}"

if [ $CURRENT_USERS -gt 0 ]; then
    echo ""
    echo -e "${DIM}  ┌─────────────────────────────────────────────────────────┐${NC}"
    while read line; do
        USER=$(echo $line | awk '{print $1}')
        TTY=$(echo $line | awk '{print $2}')
        LOGIN_TIME=$(echo $line | awk '{print $3, $4}')
        IP=$(echo $line | awk '{print $5}' | tr -d '()')
        
        if [[ ! $IP =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|114\.39\.15\.79) ]] && [ ! -z "$IP" ]; then
            echo -e "${DIM}  │${NC} ${RED}⚠${NC} ${USER}${NC} @ ${TTY} | ${RED}${IP}${NC} | ${LOGIN_TIME}"
            add_alert "HIGH" "外部 IP 登入: ${USER} 從 ${IP}"
        else
            echo -e "${DIM}  │${NC} ${GREEN}✓${NC} ${USER}${NC} @ ${TTY} | ${CYAN}${IP:-本機}${NC} | ${LOGIN_TIME}"
        fi
    done < <(who)
    echo -e "${DIM}  └─────────────────────────────────────────────────────────┘${NC}"
fi

echo ""
echo -e "${BOLD}${CYAN}▶ 最近 5 次登入記錄${NC}"
last -5 -F 2>/dev/null | head -5 | while read line; do
    echo -e "  ${DIM}${line}${NC}"
done

echo ""
FAILED_COUNT=$(lastb 2>/dev/null | wc -l)
if [ $FAILED_COUNT -gt 0 ]; then
    echo -e "${YELLOW}⚡ 失敗登入嘗試: ${WHITE}${FAILED_COUNT} 次${NC}"
    
    if [ $FAILED_COUNT -gt 100 ]; then
        echo -e "${RED}⚠ ${BOLD}偵測到大量暴力破解嘗試！${NC}"
        NEED_FAIL2BAN=1
        
        if command -v fail2ban-client &> /dev/null && systemctl is-active --quiet fail2ban; then
            BANNED_COUNT=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
            echo -e "${GREEN}✓ Fail2Ban 已封鎖 ${BANNED_COUNT:-0} 個 IP${NC}"
        else
            add_alert "CRITICAL" "SSH 暴力破解攻擊: ${FAILED_COUNT} 次失敗登入（建議安裝 Fail2Ban）"
        fi
        
        echo -e "${RED}前 5 名攻擊來源:${NC}"
        lastb 2>/dev/null | awk '{print $3}' | grep -v "^$" | sort | uniq -c | sort -rn | head -5 | while read count ip; do
            echo -e "  ${RED}├─${NC} ${ip} ${DIM}(${count} 次)${NC}"
        done
    fi
else
    echo -e "${GREEN}✓ 無失敗登入記錄${NC}"
fi

echo ""

# ==========================================
# 2. 惡意 Process 掃描
# ==========================================
echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${YELLOW} [1/12] 🔍 惡意 Process 掃描${NC}                                 ${CYAN}│${NC}"
echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
echo ""

MALICIOUS_PROCESSES=$(ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis|lighttpd|postgres|memcache/' | grep -v "USER" | wc -l)
CRYPTO_MINERS=$(ps aux | grep -iE "xmrig|minerd|cpuminer|ccminer|cryptonight|monero|kinsing" | grep -v grep | wc -l)
TOTAL_SUSPICIOUS=$((MALICIOUS_PROCESSES + CRYPTO_MINERS))

if [ $TOTAL_SUSPICIOUS -gt 0 ]; then
    echo -e "${RED}⚠ ${BOLD}發現 ${TOTAL_SUSPICIOUS} 個可疑 process${NC}"
    echo ""
    
    if [ $MALICIOUS_PROCESSES -gt 0 ]; then
        echo -e "${RED}  ├─ 亂碼名稱 process: ${MALICIOUS_PROCESSES} 個${NC}"
        ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/' | grep -v "USER" | head -3 | while read line; do
            PROC=$(echo $line | awk '{print $11}')
            PID=$(echo $line | awk '{print $2}')
            CPU=$(echo $line | awk '{print $3}')
            echo -e "${RED}  │  • ${PROC} ${DIM}(PID: ${PID}, CPU: ${CPU}%)${NC}"
        done
    fi
    
    if [ $CRYPTO_MINERS -gt 0 ]; then
        echo -e "${RED}  ├─ 挖礦程式: ${CRYPTO_MINERS} 個${NC}"
        ps aux | grep -iE "xmrig|minerd|cpuminer" | grep -v grep | head -3 | while read line; do
            PROC=$(echo $line | awk '{print $11}')
            PID=$(echo $line | awk '{print $2}')
            CPU=$(echo $line | awk '{print $3}')
            echo -e "${RED}  │  • ${PROC} ${DIM}(PID: ${PID}, CPU: ${CPU}%)${NC}"
        done
        add_alert "CRITICAL" "偵測到挖礦程式: ${CRYPTO_MINERS} 個"
    fi
    
    THREATS_FOUND=$((THREATS_FOUND + TOTAL_SUSPICIOUS))
    
    echo ""
    echo -ne "${YELLOW}🧹 自動清除中...${NC}"
    ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/' | grep -v "USER" | awk '{print $2}' | xargs kill -9 2>/dev/null
    ps aux | grep -iE "xmrig|minerd|cpuminer" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
    THREATS_CLEANED=$((THREATS_CLEANED + TOTAL_SUSPICIOUS))
    echo -e " ${GREEN}✓ 完成！${NC}"
else
    echo -e "${GREEN}✓ 未發現可疑 process${NC}"
fi

echo ""

# ==========================================
# 3. 常見病毒檔名快速掃描 (網站根目錄)
# ==========================================
echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${YELLOW} [2/12] 🦠 常見病毒檔名掃描${NC}                                   ${CYAN}│${NC}"
echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
echo ""

echo -e "${DIM}檢查項目: 常見病毒檔名 (c99, r57, wso, shell, backdoor) - 僅網站根目錄${NC}"
echo ""

MALWARE_TMPFILE=$(mktemp)

if [ -n "$SCAN_PATHS" ]; then
    # 僅掃描網站根目錄樹狀 (不掃全系統)
    find $SCAN_PATHS -type f \( \
        -iname "*c99*.php" -o \
        -iname "*r57*.php" -o \
        -iname "*wso*.php" -o \
        -iname "*shell*.php" -o \
        -iname "*backdoor*.php" -o \
        -iname "*webshell*.php" -o \
        -iname "*.suspected" \
        \) ! -path "*/vendor/*" ! -path "*/cache/*" ! -path "*/node_modules/*" ! -path "*/backup/*" ! -path "*/backups/*" \
        2>/dev/null | head -20 > "$MALWARE_TMPFILE"
fi

MALWARE_COUNT=$(wc -l < "$MALWARE_TMPFILE" 2>/dev/null || echo 0)

if [ $MALWARE_COUNT -gt 0 ]; then
    echo -e "${RED}⚠ ${BOLD}發現 ${MALWARE_COUNT} 個可疑檔名:${NC}"
    echo ""
    while IFS= read -r file; do
        BASENAME=$(basename "$file")
        SITE_PATH=$(echo "$file" | grep -oP '/(var/www/|home/)[^/]+' | head -1)
        
        echo -e "${RED}  ├─ ${file}${NC}"
        echo -e "${DIM}  │  └─ 檔名: ${BASENAME}${NC}"
        
        # 記錄網站威脅
        if [ ! -z "$SITE_PATH" ]; then
            SITE_THREATS["$SITE_PATH"]=$((${SITE_THREATS["$SITE_PATH"]:-0} + 1))
        fi
    done < "$MALWARE_TMPFILE"
    
    THREATS_FOUND=$((THREATS_FOUND + MALWARE_COUNT))
    add_alert "CRITICAL" "病毒檔名: ${MALWARE_COUNT} 個"
    
    echo ""
    echo -e "${YELLOW}建議動作:${NC}"
    echo -e "  ${DIM}1. 檢查這些檔案是否為惡意程式${NC}"
    echo -e "  ${DIM}2. 確認後手動刪除: ${WHITE}rm -f /path/to/suspicious.php${NC}"
else
    echo -e "${GREEN}✓ 未發現常見病毒檔名${NC}"
fi

rm -f "$MALWARE_TMPFILE"
echo ""

# ==========================================
# 4. Webshell 內容掃描 (網站根目錄)
# ==========================================
echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${YELLOW} [3/12] 🔍 Webshell 特徵碼掃描 (內容檢測)${NC}                    ${CYAN}│${NC}"
echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
echo ""

echo -e "${DIM}掃描範圍: 網站根目錄下的 PHP 檔案 (排除 vendor/cache/node_modules/backup)${NC}"
echo -e "${DIM}偵測特徵: eval(), base64_decode(), shell_exec(), system()${NC}"
echo -e "${DIM}顯示數量: 最多 20 筆可疑檔案${NC}"
echo ""

WEBSHELL_COUNT=0
WEBSHELL_TMPFILE=$(mktemp)

if [ -n "$SCAN_PATHS" ]; then
    find $SCAN_PATHS -type f -name "*.php" \
        ! -path "*/vendor/*" ! -path "*/cache/*" ! -path "*/node_modules/*" ! -path "*/backup/*" ! -path "*/backups/*" \
        2>/dev/null | \
    xargs -P 4 -I {} grep -lE "(eval\s*\(|base64_decode\s*\(.*eval|shell_exec\s*\(|system\s*\(.*\\\$_|passthru\s*\(|exec\s*\(.*\\\$_GET)" {} 2>/dev/null | \
    head -20 > "$WEBSHELL_TMPFILE"
fi

WEBSHELL_COUNT=$(wc -l < "$WEBSHELL_TMPFILE" 2>/dev/null || echo 0)

if [ $WEBSHELL_COUNT -gt 0 ]; then
    while IFS= read -r file; do
        SITE_PATH=$(echo "$file" | grep -oP '/(var/www/|home/)[^/]+' | head -1)
        
        echo -e "${RED}  ├─ ${file}${NC}"
        
        SUSPICIOUS_LINE=$(grep -m1 -E "(eval\s*\(|base64_decode\s*\(.*eval|shell_exec)" "$file" 2>/dev/null | sed 's/^[[:space:]]*//' | head -c 60)
        [ ! -z "$SUSPICIOUS_LINE" ] && echo -e "${DIM}  │  └─ ${SUSPICIOUS_LINE}...${NC}"
        
        if [ ! -z "$SITE_PATH" ]; then
            SITE_THREATS["$SITE_PATH"]=$((${SITE_THREATS["$SITE_PATH"]:-0} + 1))
        fi
    done < "$WEBSHELL_TMPFILE"
    
    echo ""
    echo -e "${RED}⚠ ${BOLD}發現 ${WEBSHELL_COUNT} 個可疑 PHP 檔案${NC}"
    [ $WEBSHELL_COUNT -eq 20 ] && echo -e "${DIM}  (顯示前 20 筆,可能還有更多)${NC}"
    
    THREATS_FOUND=$((THREATS_FOUND + WEBSHELL_COUNT))
    add_alert "CRITICAL" "Webshell 檔案: ${WEBSHELL_COUNT} 個"
    
    echo ""
    echo -e "${YELLOW}建議動作:${NC}"
    echo -e "  ${DIM}1. 檢查上方列出的檔案是否為惡意程式${NC}"
    echo -e "  ${DIM}2. 使用編輯器檢視檔案完整內容${NC}"
    echo -e "  ${DIM}3. 確認後手動刪除: ${WHITE}rm -f /path/to/suspicious.php${NC}"
else
    echo -e "${GREEN}✓ 未發現可疑 PHP 檔案${NC}"
fi

rm -f "$WEBSHELL_TMPFILE"
echo ""

# ==========================================
# 疑似中毒網站提醒
# ==========================================
if [ ${#SITE_THREATS[@]} -gt 0 ]; then
    echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${RED} 🚨 疑似中毒網站提醒${NC}                                          ${CYAN}│${NC}"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -e "${RED}${BOLD}以下網站發現多個可疑檔案,建議優先檢查:${NC}"
    echo ""
    
    for site in "${!SITE_THREATS[@]}"; do
        echo "${SITE_THREATS[$site]} $site"
    done | sort -rn | while read count site; do
        if [ "$count" -ge 5 ]; then
            RISK_LEVEL="${BG_RED}${WHITE} 高風險 ${NC}"
        elif [ "$count" -ge 3 ]; then
            RISK_LEVEL="${BG_YELLOW}${WHITE} 中風險 ${NC}"
        else
            RISK_LEVEL="${YELLOW}低風險${NC}"
        fi
        
        echo -e "  ${RISK_LEVEL} ${WHITE}${site}${NC} - ${RED}發現 ${count} 個威脅${NC}"
    done
    
    echo ""
    echo -e "${YELLOW}建議處理步驟:${NC}"
    echo -e "  ${DIM}1. 立即備份網站資料${NC}"
    echo -e "  ${DIM}2. 檢查上方列出的可疑檔案${NC}"
    echo -e "  ${DIM}3. 更新 WordPress 核心、佈景主題、外掛${NC}"
    echo -e "  ${DIM}4. 更改所有管理員密碼${NC}"
    echo -e "  ${DIM}5. 考慮安裝 Wordfence 或 Sucuri 防護外掛${NC}"
    echo ""
fi

# ==========================================
# 總結報告
# ==========================================
echo -e "\n"
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}                   🛡️  掃描結果總結                             ${NC}${CYAN}║${NC}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"

if [ $THREATS_FOUND -eq 0 ] && [ ${#ALERTS[@]} -eq 0 ]; then
    THREAT_LEVEL="${BG_GREEN}${WHITE} ✓ 系統安全 ${NC}"
elif [ $THREATS_FOUND -lt 5 ]; then
    THREAT_LEVEL="${BG_YELLOW}${WHITE} ⚡ 低風險 ${NC}"
elif [ $THREATS_FOUND -lt 20 ]; then
    THREAT_LEVEL="${BG_YELLOW}${WHITE} ⚠ 中風險 ${NC}"
else
    THREAT_LEVEL="${BG_RED}${WHITE} 🔥 高風險 - 主機可能已被入侵 ${NC}"
fi

echo -e "${CYAN}║${NC} ${BOLD}威脅等級:${NC} ${THREAT_LEVEL}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  發現威脅: ${WHITE}${THREATS_FOUND}${NC} | 已清除: ${GREEN}${THREATS_CLEANED}${NC} | 需手動: ${YELLOW}$((THREATS_FOUND - THREATS_CLEANED))${NC}"

if [ ${#ALERTS[@]} -gt 0 ]; then
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} ${RED}${BOLD}🔥 重要告警:${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
    
    for alert in "${ALERTS[@]}"; do
        if [[ $alert == *"CRITICAL"* ]]; then
            MSG=$(echo "$alert" | cut -d']' -f2-)
            echo -e "${CYAN}║${NC}  ${BG_RED}${WHITE} CRITICAL ${NC}${MSG}"
        elif [[ $alert == *"HIGH"* ]]; then
            MSG=$(echo "$alert" | cut -d']' -f2-)
            echo -e "${CYAN}║${NC}  ${RED}HIGH${NC}    ${MSG}"
        fi
    done
fi

# Fail2Ban 區塊 (含封鎖規則 + 封鎖 IP + 當前嘗試破解 IP 統計)
if command -v fail2ban-client &> /dev/null && systemctl is-active --quiet fail2ban; then
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} ${GREEN}🛡️  Fail2Ban 防護統計:${NC}"
    
    BANNED_NOW=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
    TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $NF}')
    
    echo -e "${CYAN}║${NC}    當前封鎖: ${WHITE}${BANNED_NOW:-0}${NC} 個 | 累計封鎖: ${WHITE}${TOTAL_BANNED:-0}${NC} 次"
    echo -e "${CYAN}║${NC}    ${DIM}封鎖規則: 5 次失敗 / 不限時間 = 封鎖 24 小時${NC}"
    
    if [ "${BANNED_NOW:-0}" -gt 0 ]; then
        echo -e "${CYAN}║${NC}"
        echo -e "${CYAN}║${NC} ${YELLOW}封鎖 IP 列表:${NC}"
        
        fail2ban-client status sshd 2>/dev/null | grep "Banned IP list" | awk -F: '{print $2}' | tr ' ' '\n' | grep -v "^$" | while read ip; do
            LAST_ATTEMPT=$(grep "$ip" /var/log/auth.log 2>/dev/null | grep "Failed password" | tail -1 | awk '{print $1" "$2" "$3}')
            [ -z "$LAST_ATTEMPT" ] && LAST_ATTEMPT="Unknown"
            echo -e "${CYAN}║${NC}    ${RED}${ip}${NC} ${DIM}| 最後嘗試: ${LAST_ATTEMPT} | 封鎖: 24h | 狀態: 封鎖中${NC}"
        done
    fi

    # 新增: 當前嘗試破解 IP 與次數 (從 auth.log / secure 抓最新失敗紀錄)
    echo -e "${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}當前嘗試破解 IP (近 1,000 筆失敗登入):${NC}"

    if [ -f /var/log/auth.log ]; then
        LOG_FILE="/var/log/auth.log"
    elif [ -f /var/log/secure ]; then
        LOG_FILE="/var/log/secure"
    else
        LOG_FILE=""
    fi

    if [ -n "$LOG_FILE" ]; then
        # 抓最近 1000 筆 Failed password,統計 IP 次數,顯示前 10 名
        grep "Failed password" "$LOG_FILE" 2>/dev/null | tail -1000 | \
        awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
        sort | uniq -c | sort -rn | head -10 | while read count ip; do
            echo -e "${CYAN}║${NC}    ${WHITE}${ip}${NC} ${DIM}- 失敗嘗試 ${count} 次${NC}"
        done
    else
        echo -e "${CYAN}║${NC}    ${DIM}找不到 auth.log/secure,無法顯示嘗試 IP${NC}"
    fi
else
    if [ $NEED_FAIL2BAN -eq 1 ] || [ $FAILED_COUNT -gt 50 ]; then
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║${NC} ${YELLOW}🛡️  Fail2Ban 防護系統:${NC} ${RED}未安裝${NC}"
        echo -e "${CYAN}║${NC} ${CYAN}正在自動安裝 Fail2Ban...${NC}"
        
        if [ -f /etc/debian_version ]; then
            apt-get update -qq > /dev/null 2>&1
            DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban > /dev/null 2>&1
        elif [ -f /etc/redhat-release ]; then
            yum install -y epel-release > /dev/null 2>&1
            yum install -y fail2ban > /dev/null 2>&1
        fi
        
        if [ $? -eq 0 ]; then
            cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 114.39.15.79
bantime = 24h
findtime = 0
maxretry = 5
destemail = 
action = %(action_)s

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
bantime = 24h
findtime = 0
EOF

            [ -f /etc/redhat-release ] && sed -i 's|logpath = /var/log/auth.log|logpath = /var/log/secure|' /etc/fail2ban/jail.local
            
            systemctl enable fail2ban > /dev/null 2>&1
            systemctl restart fail2ban > /dev/null 2>&1
            sleep 2
            
            if systemctl is-active --quiet fail2ban; then
                echo -e "${CYAN}║${NC} ${GREEN}✓ Fail2Ban 安裝成功並已啟動${NC}"
                echo -e "${CYAN}║${NC}    • 白名單: ${WHITE}114.39.15.79${NC}"
                echo -e "${CYAN}║${NC}    • 封鎖規則: ${WHITE}5 次失敗 / 不限時間 = 封鎖 24 小時${NC}"
            else
                echo -e "${CYAN}║${NC} ${RED}⚠ Fail2Ban 安裝失敗，請手動安裝${NC}"
            fi
        else
            echo -e "${CYAN}║${NC} ${RED}⚠ Fail2Ban 安裝失敗，請手動安裝${NC}"
        fi
    fi
fi

echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC} ${DIM}掃描完成: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"

echo ""
echo -e "${MAGENTA}🛡️  掃描工具不會在系統留下任何記錄或工具${NC}"
echo -e "${DIM}   GitHub: https://github.com/jimmy-is-me/vps-security-scanner${NC}"
echo ""

# ==========================================
# 掃描完成後重置失敗登入記錄
# ==========================================
echo -ne "${YELLOW}🧹 清理失敗登入記錄...${NC}"

if command -v faillock &> /dev/null; then
    faillock --reset-all > /dev/null 2>&1
fi

if command -v pam_tally2 &> /dev/null; then
    pam_tally2 --reset > /dev/null 2>&1
fi

echo -n > /var/log/btmp 2>/dev/null
echo -n > /var/log/wtmp.1 2>/dev/null

echo -e " ${GREEN}✓ 完成${NC}"
echo ""

# 無痕跡模式
# rm -f "$0"
