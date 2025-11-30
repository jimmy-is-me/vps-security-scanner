#!/bin/bash

#################################################
# VPS 安全掃描工具 v4.3 - 無痕跡高效能版
# GitHub: https://github.com/jimmy-is-me/vps-security-scanner
# 特色：完全無痕跡、智慧告警、自動清除、Fail2Ban 自動防護
# 更新：修正資源監控顯示、新增網站資訊
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

VERSION="4.3.1"

# 效能優化
renice -n 19 $$ > /dev/null 2>&1
ionice -c3 -p $$ > /dev/null 2>&1

clear

# ==========================================
# 標題
# ==========================================
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}                                                                    ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}         🛡️  VPS 安全掃描工具 v${VERSION} - 無痕跡版               ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}                                                                    ${NC}${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 計數器
THREATS_FOUND=0
THREATS_CLEANED=0
ALERTS=()
NEED_FAIL2BAN=0

add_alert() {
    local level=$1
    local message=$2
    ALERTS+=("[$level] $message")
}

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

if (( $(echo "$RAM_PERCENT > 80" | bc -l 2>/dev/null || echo 0) )); then
    RAM_COLOR="${RED}"
elif (( $(echo "$RAM_PERCENT > 60" | bc -l 2>/dev/null || echo 0) )); then
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
# 即時資源使用監控（修正+強化版）
# ==========================================
echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${YELLOW} 💻 即時資源使用監控${NC}                                           ${CYAN}│${NC}"
echo -e "${CYAN}├────────────────────────────────────────────────────────────────┤${NC}"

# CPU 使用率 TOP 5（修正 AWK 語法）
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ CPU 使用率 TOP 5${NC}"
echo -e "${CYAN}│${NC}   ${DIM}排名  用戶       CPU%   記憶體%  指令${NC}"
echo -e "${CYAN}│${NC}"

ps aux --sort=-%cpu | head -6 | tail -5 | while read line; do
    USER=$(echo $line | awk '{print $1}')
    CPU=$(echo $line | awk '{print $3}')
    MEM=$(echo $line | awk '{print $4}')
    CMD=$(echo $line | awk '{print $11}')
    
    # 截斷過長的用戶名和指令
    [ ${#USER} -gt 8 ] && USER="${USER:0:8}"
    [ ${#CMD} -gt 25 ] && CMD="${CMD:0:22}..."
    
    # CPU 顏色判斷
    if (( $(echo "$CPU > 50" | bc -l 2>/dev/null || echo 0) )); then
        CPU_COLOR="${RED}"
    elif (( $(echo "$CPU > 20" | bc -l 2>/dev/null || echo 0) )); then
        CPU_COLOR="${YELLOW}"
    else
        CPU_COLOR="${WHITE}"
    fi
    
    # 輸出格式化
    printf "${CYAN}│${NC}   ${DIM}%-4s ${YELLOW}%-10s ${NC}${CPU_COLOR}%6s%% ${DIM}%7s%%  ${NC}%s\n" \
           "$(($(ps aux --sort=-%cpu | head -6 | tail -5 | grep -n "$line" | cut -d: -f1)))." \
           "$USER" "$CPU" "$MEM" "$CMD"
done

# 記憶體使用 TOP 5
echo -e "${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ 記憶體使用 TOP 5${NC}"
echo -e "${CYAN}│${NC}   ${DIM}排名  用戶       記憶體%  RSS      指令${NC}"
echo -e "${CYAN}│${NC}"

ps aux --sort=-%mem | head -6 | tail -5 | while read line; do
    USER=$(echo $line | awk '{print $1}')
    MEM=$(echo $line | awk '{print $4}')
    RSS=$(echo $line | awk '{print $6}')
    CMD=$(echo $line | awk '{print $11}')
    
    [ ${#USER} -gt 8 ] && USER="${USER:0:8}"
    [ ${#CMD} -gt 25 ] && CMD="${CMD:0:22}..."
    
    # 轉換 RSS 為 MB
    RSS_MB=$(awk "BEGIN {printf \"%.1f\", $RSS/1024}")
    
    # 記憶體顏色判斷
    if (( $(echo "$MEM > 20" | bc -l 2>/dev/null || echo 0) )); then
        MEM_COLOR="${RED}"
    elif (( $(echo "$MEM > 10" | bc -l 2>/dev/null || echo 0) )); then
        MEM_COLOR="${YELLOW}"
    else
        MEM_COLOR="${WHITE}"
    fi
    
    printf "${CYAN}│${NC}   ${DIM}%-4s ${YELLOW}%-10s ${NC}${MEM_COLOR}%7s%% ${DIM}%6sM  ${NC}%s\n" \
           "$(($(ps aux --sort=-%mem | head -6 | tail -5 | grep -n "$line" | cut -d: -f1)))." \
           "$USER" "$MEM" "$RSS_MB" "$CMD"
done

# 網站服務資源使用（強化版：顯示網站名稱）
echo -e "${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ 網站服務資源使用${NC}"
echo -e "${CYAN}│${NC}"

WEB_SERVICES=0

# 檢測 Nginx
if pgrep -x "nginx" > /dev/null 2>&1; then
    SERVICE_PROCS=$(pgrep -x "nginx" | wc -l)
    SERVICE_CPU=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$3} END {printf "%.1f", sum}')
    SERVICE_MEM=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$4} END {printf "%.1f", sum}')
    SERVICE_RSS=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
    
    echo -e "${CYAN}│${NC}   ${GREEN}✓${NC} ${WHITE}Nginx${NC}"
    echo -e "${CYAN}│${NC}      ${DIM}進程數: ${WHITE}${SERVICE_PROCS}${DIM} | CPU: ${WHITE}${SERVICE_CPU}%${DIM} | 記憶體: ${WHITE}${SERVICE_MEM}% (${SERVICE_RSS}M)${NC}"
    
    # 顯示 Nginx 管理的網站數量
    if [ -d /etc/nginx/sites-enabled ]; then
        SITE_COUNT=$(ls -1 /etc/nginx/sites-enabled 2>/dev/null | grep -v default | wc -l)
        echo -e "${CYAN}│${NC}      ${DIM}管理網站: ${WHITE}${SITE_COUNT}${DIM} 個${NC}"
    fi
    WEB_SERVICES=1
fi

# 檢測 Apache
if pgrep -x "apache2\|httpd" > /dev/null 2>&1; then
    SERVICE_NAME=$(pgrep -x "apache2" > /dev/null && echo "apache2" || echo "httpd")
    SERVICE_PROCS=$(pgrep -x "$SERVICE_NAME" | wc -l)
    SERVICE_CPU=$(ps aux | grep -E "[$SERVICE_NAME]" | awk '{sum+=$3} END {printf "%.1f", sum}')
    SERVICE_MEM=$(ps aux | grep -E "[$SERVICE_NAME]" | awk '{sum+=$4} END {printf "%.1f", sum}')
    SERVICE_RSS=$(ps aux | grep -E "[$SERVICE_NAME]" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
    
    echo -e "${CYAN}│${NC}   ${GREEN}✓${NC} ${WHITE}Apache${NC}"
    echo -e "${CYAN}│${NC}      ${DIM}進程數: ${WHITE}${SERVICE_PROCS}${DIM} | CPU: ${WHITE}${SERVICE_CPU}%${DIM} | 記憶體: ${WHITE}${SERVICE_MEM}% (${SERVICE_RSS}M)${NC}"
    
    if [ -d /etc/apache2/sites-enabled ]; then
        SITE_COUNT=$(ls -1 /etc/apache2/sites-enabled 2>/dev/null | grep -v 000-default | wc -l)
        echo -e "${CYAN}│${NC}      ${DIM}管理網站: ${WHITE}${SITE_COUNT}${DIM} 個${NC}"
    fi
    WEB_SERVICES=1
fi

# 檢測 LiteSpeed
if pgrep -x "litespeed" > /dev/null 2>&1; then
    SERVICE_PROCS=$(pgrep -x "litespeed" | wc -l)
    SERVICE_CPU=$(ps aux | grep -E "[l]itespeed" | awk '{sum+=$3} END {printf "%.1f", sum}')
    SERVICE_MEM=$(ps aux | grep -E "[l]itespeed" | awk '{sum+=$4} END {printf "%.1f", sum}')
    SERVICE_RSS=$(ps aux | grep -E "[l]itespeed" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
    
    echo -e "${CYAN}│${NC}   ${GREEN}✓${NC} ${WHITE}LiteSpeed${NC}"
    echo -e "${CYAN}│${NC}      ${DIM}進程數: ${WHITE}${SERVICE_PROCS}${DIM} | CPU: ${WHITE}${SERVICE_CPU}%${DIM} | 記憶體: ${WHITE}${SERVICE_MEM}% (${SERVICE_RSS}M)${NC}"
    WEB_SERVICES=1
fi

# 檢測 PHP-FPM（並顯示版本和網站）
if pgrep -x "php-fpm" > /dev/null 2>&1; then
    SERVICE_PROCS=$(pgrep -x "php-fpm" | wc -l)
    SERVICE_CPU=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$3} END {printf "%.1f", sum}')
    SERVICE_MEM=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$4} END {printf "%.1f", sum}')
    SERVICE_RSS=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
    
    # 偵測 PHP 版本
    PHP_VERSION=$(php-fpm -v 2>/dev/null | head -1 | awk '{print $2}' || echo "未知")
    
    echo -e "${CYAN}│${NC}   ${GREEN}✓${NC} ${WHITE}PHP-FPM ${DIM}(v${PHP_VERSION})${NC}"
    echo -e "${CYAN}│${NC}      ${DIM}進程數: ${WHITE}${SERVICE_PROCS}${DIM} | CPU: ${WHITE}${SERVICE_CPU}%${DIM} | 記憶體: ${WHITE}${SERVICE_MEM}% (${SERVICE_RSS}M)${NC}"
    
    # 統計 PHP 網站數量
    WP_COUNT=$(find /var/www /home -name "wp-config.php" -type f 2>/dev/null | wc -l)
    if [ $WP_COUNT -gt 0 ]; then
        echo -e "${CYAN}│${NC}      ${DIM}WordPress 網站: ${WHITE}${WP_COUNT}${DIM} 個${NC}"
    fi
    WEB_SERVICES=1
fi

# 檢測 LSPHP（CloudPanel/XCloud）
if pgrep -f "lsphp" > /dev/null 2>&1; then
    SERVICE_PROCS=$(pgrep -f "lsphp" | wc -l)
    SERVICE_CPU=$(ps aux | grep -E "[l]sphp" | awk '{sum+=$3} END {printf "%.1f", sum}')
    SERVICE_MEM=$(ps aux | grep -E "[l]sphp" | awk '{sum+=$4} END {printf "%.1f", sum}')
    SERVICE_RSS=$(ps aux | grep -E "[l]sphp" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
    
    echo -e "${CYAN}│${NC}   ${GREEN}✓${NC} ${WHITE}LSPHP${NC}"
    echo -e "${CYAN}│${NC}      ${DIM}進程數: ${WHITE}${SERVICE_PROCS}${DIM} | CPU: ${WHITE}${SERVICE_CPU}%${DIM} | 記憶體: ${WHITE}${SERVICE_MEM}% (${SERVICE_RSS}M)${NC}"
    WEB_SERVICES=1
fi

if [ $WEB_SERVICES -eq 0 ]; then
    echo -e "${CYAN}│${NC}   ${DIM}未偵測到網站服務運行${NC}"
fi

# 網路連線統計
echo -e "${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ 網路連線統計${NC}"
echo -e "${CYAN}│${NC}"

TOTAL_CONN=$(ss -tn state established 2>/dev/null | wc -l)
LISTEN_PORTS=$(ss -tln 2>/dev/null | grep LISTEN | wc -l)
HTTP_CONN=$(ss -tn state established 2>/dev/null | grep -E ":(80|443)" | wc -l)

echo -e "${CYAN}│${NC}   ${DIM}總連線數: ${WHITE}${TOTAL_CONN}${DIM} | 監聽埠號: ${WHITE}${LISTEN_PORTS}${DIM} | HTTP(S): ${WHITE}${HTTP_CONN}${NC}"

# I/O 統計
if command -v iostat &> /dev/null; then
    IO_WAIT=$(iostat -c 1 2 2>/dev/null | awk '/^avg/ {print $4}' | tail -1)
    if [ ! -z "$IO_WAIT" ]; then
        echo -e "${CYAN}│${NC}   ${DIM}I/O 等待: ${WHITE}${IO_WAIT}%${NC}"
    fi
fi

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
    who | while read line; do
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
    done
    echo -e "${DIM}  └─────────────────────────────────────────────────────────┘${NC}"
fi

echo ""
echo -e "${BOLD}${CYAN}▶ 最近 5 次登入記錄${NC}"
last -5 -F 2>/dev/null | head -5 | awk '{if(NR>0) printf "  '"${DIM}"'%s'"${NC}"'\n", $0}'

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
        lastb 2>/dev/null | awk '{print $3}' | grep -v "^$" | sort | uniq -c | sort -rn | head -5 | while read line; do
            echo -e "  ${RED}├─${NC} ${line}"
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

# [繼續 3-12 掃描項目...]

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

# Fail2Ban 自動安裝
if command -v fail2ban-client &> /dev/null && systemctl is-active --quiet fail2ban; then
    BANNED_NOW=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
    TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $NF}')
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} ${GREEN}🛡️  Fail2Ban 防護統計:${NC}"
    echo -e "${CYAN}║${NC}    當前封鎖: ${WHITE}${BANNED_NOW:-0}${NC} 個 | 累計封鎖: ${WHITE}${TOTAL_BANNED:-0}${NC} 次"
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
bantime = 3600
findtime = 600
maxretry = 5
destemail = 
action = %(action_)s

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

            [ -f /etc/redhat-release ] && sed -i 's|logpath = /var/log/auth.log|logpath = /var/log/secure|' /etc/fail2ban/jail.local
            
            systemctl enable fail2ban > /dev/null 2>&1
            systemctl restart fail2ban > /dev/null 2>&1
            sleep 2
            
            if systemctl is-active --quiet fail2ban; then
                echo -e "${CYAN}║${NC} ${GREEN}✓ Fail2Ban 安裝成功並已啟動${NC}"
                echo -e "${CYAN}║${NC}    • 白名單: ${WHITE}114.39.15.79${NC}"
                echo -e "${CYAN}║${NC}    • 封鎖規則: ${WHITE}5 次失敗 / 10 分鐘 = 封鎖 1 小時${NC}"
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

# 無痕跡模式
# rm -f "$0"
