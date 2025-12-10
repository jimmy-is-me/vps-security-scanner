#!/bin/bash

#################################################
# VPS 安全掃描工具 v5.0.0 - 智慧威脅判斷版
# GitHub: https://github.com/jimmy-is-me/vps-security-scanner
# 新增功能:
#  - 智慧威脅等級判斷(只警告真正危險的狀況)
#  - 成功登入監控
#  - SSH Key 安全檢查
#  - 攻擊模式分析
#  - SSH 安全配置建議
#  - 優化 Fail2Ban 規則
#################################################

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

VERSION="5.0.0"

# 白名單 IP 定義
WHITELIST_IPS=(
    "127.0.0.1/8"
    "::1"
    "114.39.15.79"
    "114.39.15.120"
    "49.13.31.45"
    "91.107.195.115"
    "168.119.100.163"
    "188.34.177.5"
)

# 白名單 IP 註解
declare -A WHITELIST_NOTES
WHITELIST_NOTES["114.39.15.79"]="管理員"
WHITELIST_NOTES["114.39.15.120"]="管理員"
WHITELIST_NOTES["49.13.31.45"]="FLYWP"
WHITELIST_NOTES["91.107.195.115"]="FLYWP"
WHITELIST_NOTES["168.119.100.163"]="FLYWP"
WHITELIST_NOTES["188.34.177.5"]="FLYWP"

# 掃描範圍
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
    [ -z "$kb" ] && kb=0
    awk -v k="$kb" 'BEGIN {printf "%.1fG", k/1048576}'
}

add_alert() {
    local level="$1"
    local message="$2"
    ALERTS+=("[$level] $message")
}

build_scan_paths() {
    local roots=()
    for p in "${SCAN_ROOT_BASE[@]}"; do
        [ -d "$p" ] && roots+=("$p")
    done

    if [ -d "/home" ]; then
        while IFS= read -r d; do
            [ -d "$d/public_html" ] && roots+=("$d/public_html")
            [ -d "$d/www" ] && roots+=("$d/www")
            [ -d "$d/web" ] && roots+=("$d/web")
            [ -d "$d/app/public" ] && roots+=("$d/app/public")
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

# 計數器
THREATS_FOUND=0
THREATS_CLEANED=0
ALERTS=()
CRITICAL_THREATS=0
declare -A SITE_THREATS

# ==========================================
# 標題
# ==========================================
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}   🛡️  VPS 安全掃描工具 v${VERSION}${NC}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

# ==========================================
# 主機資訊
# ==========================================
echo -e "${YELLOW}🖥️  主機資訊${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

HOSTNAME=$(hostname)
OS_INFO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
[ -z "$OS_INFO" ] && OS_INFO=$(uname -s)
KERNEL=$(uname -r)
CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d':' -f2 | xargs)
CPU_CORES=$(grep -c ^processor /proc/cpuinfo 2>/dev/null)
[ -z "$CPU_MODEL" ] && CPU_MODEL="Unknown CPU"
[ -z "$CPU_CORES" ] && CPU_CORES=1

SYS_TZ=$(timedatectl 2>/dev/null | awk '/Time zone/ {print $3}')
[ -z "$SYS_TZ" ] && SYS_TZ="Unknown"
TZ_SYNC=$(timedatectl 2>/dev/null | awk '/System clock synchronized/ {print $4}')
[ -z "$TZ_SYNC" ] && TZ_SYNC="unknown"

echo -e "${DIM}主機名稱:${NC} ${WHITE}${HOSTNAME}${NC}"
echo -e "${DIM}作業系統:${NC} ${WHITE}${OS_INFO}${NC}"
echo -e "${DIM}核心版本:${NC} ${WHITE}${KERNEL}${NC}"
echo -e "${DIM}CPU 型號:${NC} ${WHITE}${CPU_MODEL}${NC}"
echo -e "${DIM}CPU 核心:${NC} ${WHITE}${CPU_CORES} 核心${NC}"
echo -e "${DIM}系統時區:${NC} ${WHITE}${SYS_TZ}${NC} ${DIM}(NTP: ${TZ_SYNC})${NC}"
echo -e "${DIM}建議時區:${NC} ${WHITE}Asia/Taipei${NC}"
echo ""

# 記憶體資訊
MEM_TOTAL_KB=$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
MEM_AVAIL_KB=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null)
[ -z "$MEM_TOTAL_KB" ] && MEM_TOTAL_KB=0
[ -z "$MEM_AVAIL_KB" ] && MEM_AVAIL_KB=0
MEM_USED_KB=$((MEM_TOTAL_KB - MEM_AVAIL_KB))
[ "$MEM_USED_KB" -lt 0 ] && MEM_USED_KB=0

TOTAL_GB=$(kb_to_gb "$MEM_TOTAL_KB")
USED_GB=$(kb_to_gb "$MEM_USED_KB")
AVAIL_GB=$(kb_to_gb "$MEM_AVAIL_KB")
RAM_PERCENT=$(awk -v t="$MEM_TOTAL_KB" -v u="$MEM_USED_KB" 'BEGIN {if(t>0){printf "%.1f", u/t*100}else{print "0.0"}}')

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
echo -e "${DIM}記憶體可用:${NC} ${GREEN}${AVAIL_GB}${NC}"
echo ""

# 硬碟資訊
DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
DISK_PERCENT=$(df / | awk 'NR==2 {print $5}' | tr -d '%')

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
echo ""

# 系統負載
LOAD_1=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,""); print $1}')
LOAD_5=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,""); print $2}')
LOAD_15=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,""); print $3}')
UPTIME_HUMAN=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}')
SCAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')

LOAD_RATIO=$(awk -v l="$LOAD_1" -v c="$CPU_CORES" 'BEGIN {if(c>0){printf "%.2f", l/c}else{print "0"}}')
LOAD_CMP=$(awk -v r="$LOAD_RATIO" 'BEGIN {if(r<0.7){print "正常"}else if(r<1.0){print "偏高"}else{print "過高"}}')

if [[ "$LOAD_CMP" == "正常" ]]; then
    LOAD_STATUS="${GREEN}${LOAD_CMP}${NC}"
elif [[ "$LOAD_CMP" == "偏高" ]]; then
    LOAD_STATUS="${YELLOW}${LOAD_CMP}${NC}"
else
    LOAD_STATUS="${RED}${LOAD_CMP}${NC}"
fi

echo -e "${DIM}系統負載:${NC} ${WHITE}${LOAD_1}${NC} ${DIM}(1分) ${WHITE}${LOAD_5}${NC} ${DIM}(5分) ${WHITE}${LOAD_15}${NC} ${DIM}(15分) [${LOAD_STATUS}]${NC}"
echo -e "${DIM}運行時間:${NC} ${WHITE}${UPTIME_HUMAN}${NC}"
echo -e "${DIM}掃描時間:${NC} ${WHITE}${SCAN_TIME}${NC}"
echo ""

# ==========================================
# 即時資源監控
# ==========================================
echo -e "${YELLOW}💻 即時資源使用監控${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

# CPU TOP 5
echo -e "${BOLD}${CYAN}▶ CPU 使用率 TOP 5${NC}"
echo -e "${DIM}排名  用戶       CPU%   記憶體%  指令${NC}"

readarray -t CPU_LINES < <(ps aux --sort=-%cpu | head -6 | tail -5)
RANK=0
for line in "${CPU_LINES[@]}"; do
    RANK=$((RANK + 1))
    USER=$(echo "$line" | awk '{print $1}' | cut -c1-8)
    CPU_P=$(echo "$line" | awk '{print $3}')
    MEM_P=$(echo "$line" | awk '{print $4}')
    CMD=$(echo "$line" | awk '{print $11}' | cut -c1-25)

    CPU_INT=${CPU_P%.*}
    if [ "${CPU_INT:-0}" -gt 50 ]; then
        CPU_COLOR=$RED
    elif [ "${CPU_INT:-0}" -gt 20 ]; then
        CPU_COLOR=$YELLOW
    else
        CPU_COLOR=$WHITE
    fi

    printf "${DIM}%-4s ${YELLOW}%-10s ${NC}${CPU_COLOR}%6s%% ${DIM}%6s%%  ${NC}%s\n" \
           "${RANK}." "$USER" "$CPU_P" "$MEM_P" "$CMD"
done
echo ""

# 記憶體 TOP 5
echo -e "${BOLD}${CYAN}▶ 記憶體使用 TOP 5${NC}"
echo -e "${DIM}排名  用戶       記憶體%  RSS(MB)  指令${NC}"

readarray -t MEM_LINES < <(ps aux --sort=-%mem | head -6 | tail -5)
RANK=0
for line in "${MEM_LINES[@]}"; do
    RANK=$((RANK + 1))
    USER=$(echo "$line" | awk '{print $1}' | cut -c1-8)
    MEM_P=$(echo "$line" | awk '{print $4}')
    RSS_KB=$(echo "$line" | awk '{print $6}')
    CMD=$(echo "$line" | awk '{print $11}' | cut -c1-25)

    RSS_MB=$(awk -v r="$RSS_KB" 'BEGIN {printf "%.1f", r/1024}')

    MEM_INT=${MEM_P%.*}
    if [ "${MEM_INT:-0}" -gt 20 ]; then
        MEM_COLOR=$RED
    elif [ "${MEM_INT:-0}" -gt 10 ]; then
        MEM_COLOR=$YELLOW
    else
        MEM_COLOR=$WHITE
    fi

    printf "${DIM}%-4s ${YELLOW}%-10s ${NC}${MEM_COLOR}%7s%% ${DIM}%6s  ${NC}%s\n" \
           "${RANK}." "$USER" "$MEM_P" "${RSS_MB}M" "$CMD"
done
echo ""

# 網站服務
echo -e "${BOLD}${CYAN}▶ 網站服務資源使用${NC}"
WEB_SERVICES=0

if pgrep -x nginx >/dev/null 2>&1; then
    PROCS=$(pgrep -x nginx | wc -l)
    CPU=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')

    echo -e "${GREEN}✓${NC} ${WHITE}Nginx${NC}"
    echo -e "   ${DIM}進程: ${WHITE}${PROCS}${DIM} | CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"

    if [ -d /etc/nginx/sites-enabled ]; then
        SITES=$(ls -1 /etc/nginx/sites-enabled 2>/dev/null | grep -v default | wc -l)
        [ "$SITES" -gt 0 ] && echo -e "   ${DIM}管理網站: ${WHITE}${SITES}${DIM} 個${NC}"
    fi
    WEB_SERVICES=1
fi

if pgrep -f "php-fpm" >/dev/null 2>&1; then
    PROCS=$(pgrep -f "php-fpm" | wc -l)
    CPU=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
    PHP_VER=$(php -v 2>/dev/null | head -1 | awk '{print $2}' | cut -d. -f1,2 || echo "?")

    echo -e "${GREEN}✓${NC} ${WHITE}PHP-FPM ${DIM}(v${PHP_VER})${NC}"
    echo -e "   ${DIM}進程: ${WHITE}${PROCS}${DIM} | CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"

    WP_COUNT=$(find /var/www /home -maxdepth 5 -name "wp-config.php" -type f 2>/dev/null | wc -l)
    [ "$WP_COUNT" -gt 0 ] && echo -e "   ${DIM}WordPress 網站: ${WHITE}${WP_COUNT}${DIM} 個${NC}"
    WEB_SERVICES=1
fi

if pgrep -x "mysqld\|mariadbd" >/dev/null 2>&1; then
    PROC_NAME=$(pgrep -x mysqld >/dev/null && echo "mysqld" || echo "mariadbd")
    CPU=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')

    echo -e "${GREEN}✓${NC} ${WHITE}MySQL/MariaDB${NC}"
    echo -e "   ${DIM}CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"
    WEB_SERVICES=1
fi

[ "$WEB_SERVICES" -eq 0 ] && echo -e "${DIM}未偵測到網站服務運行${NC}"
echo ""

# 網路連線
echo -e "${BOLD}${CYAN}▶ 網路連線統計${NC}"

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

echo -e "${DIM}總連線: ${WHITE}${TOTAL_CONN}${DIM} | 監聽埠: ${WHITE}${LISTEN_PORTS}${DIM} | HTTP(S): ${WHITE}${HTTP_CONN}${DIM} (${HTTP_STATUS})${NC}"
echo ""

# ==========================================
# SSH 安全配置檢查 (新增)
# ==========================================
echo -e "${YELLOW}🔐 SSH 安全配置檢查${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

SSH_CONFIG="/etc/ssh/sshd_config"
SSH_ISSUES=0

# 檢查 Root 登入
ROOT_LOGIN=$(grep -E "^PermitRootLogin" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}')
if [[ "$ROOT_LOGIN" == "yes" ]]; then
    echo -e "${RED}⚠ Root 登入已啟用${NC} ${DIM}(不安全)${NC}"
    echo -e "   ${CYAN}建議修改: ${WHITE}PermitRootLogin no${NC}"
    SSH_ISSUES=$((SSH_ISSUES + 1))
    add_alert "HIGH" "SSH Root 登入未關閉"
else
    echo -e "${GREEN}✓ Root 登入已停用${NC}"
fi

# 檢查 SSH Port
SSH_PORT=$(grep -E "^Port" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}')
if [[ -z "$SSH_PORT" ]] || [[ "$SSH_PORT" == "22" ]]; then
    echo -e "${YELLOW}⚡ SSH 使用預設埠 22${NC} ${DIM}(容易被掃描)${NC}"
    echo -e "   ${CYAN}建議修改為非標準埠: ${WHITE}Port 5248${NC}"
    SSH_ISSUES=$((SSH_ISSUES + 1))
else
    echo -e "${GREEN}✓ SSH 埠已變更為: ${WHITE}${SSH_PORT}${NC}"
fi

# 檢查密碼認證
PWD_AUTH=$(grep -E "^PasswordAuthentication" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}')
if [[ "$PWD_AUTH" == "yes" ]] || [[ -z "$PWD_AUTH" ]]; then
    echo -e "${YELLOW}⚡ 密碼認證已啟用${NC} ${DIM}(建議改用金鑰)${NC}"
    SSH_ISSUES=$((SSH_ISSUES + 1))
else
    echo -e "${GREEN}✓ 密碼認證已停用${NC}"
fi

# 檢查 SSH Key 安全性
echo ""
echo -e "${BOLD}${CYAN}▶ SSH 金鑰檢查${NC}"
if [ -f /root/.ssh/authorized_keys ]; then
    KEY_COUNT=$(grep -v "^#" /root/.ssh/authorized_keys 2>/dev/null | grep -c "ssh-")
    echo -e "${GREEN}✓ Root 已配置 ${KEY_COUNT} 把公鑰${NC}"
    
    # 檢查可疑的金鑰(包含可疑註解或來源)
    SUSPICIOUS_KEYS=0
    while IFS= read -r line; do
        if [[ $line =~ (malware|backdoor|hack|shell|exploit) ]]; then
            echo -e "${RED}⚠ 發現可疑金鑰註解: ${line:0:60}...${NC}"
            SUSPICIOUS_KEYS=$((SUSPICIOUS_KEYS + 1))
            CRITICAL_THREATS=$((CRITICAL_THREATS + 1))
        fi
    done < /root/.ssh/authorized_keys
    
    [ "$SUSPICIOUS_KEYS" -eq 0 ] && echo -e "   ${DIM}所有金鑰看起來正常${NC}"
else
    echo -e "${YELLOW}⚡ Root 未配置 SSH 金鑰${NC}"
fi

if [ "$SSH_ISSUES" -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ SSH 配置安全${NC}"
else
    echo ""
    echo -e "${YELLOW}建議執行以下命令強化 SSH 安全:${NC}"
    echo -e "${DIM}sudo nano /etc/ssh/sshd_config${NC}"
    echo -e "${DIM}修改後重啟: sudo systemctl restart sshd${NC}"
fi
echo ""

# ==========================================
# 登入監控(優化 - 加入成功登入檢查)
# ==========================================
echo -e "${YELLOW}👤 系統登入監控${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

CURRENT_USERS=$(who | wc -l)
echo -e "${BOLD}${CYAN}▶ 目前登入用戶: ${WHITE}${CURRENT_USERS} 人${NC}"

if [ "$CURRENT_USERS" -gt 0 ]; then
    echo ""
    while read line; do
        USER=$(echo "$line" | awk '{print $1}')
        TTY=$(echo "$line" | awk '{print $2}')
        LOGIN_TIME=$(echo "$line" | awk '{print $3, $4}')
        IP=$(echo "$line" | awk '{print $5}' | tr -d '()')

        # 檢查是否為白名單 IP
        IS_WHITELIST=0
        for whitelisted in "${WHITELIST_IPS[@]}"; do
            if [[ $IP == $whitelisted* ]] || [[ -z "$IP" ]]; then
                IS_WHITELIST=1
                break
            fi
        done

        if [[ "$IS_WHITELIST" -eq 0 ]] && [ -n "$IP" ]; then
            echo -e "${RED}⚠${NC} ${USER}${NC} @ ${TTY} | ${RED}${IP}${NC} | ${LOGIN_TIME}"
            add_alert "CRITICAL" "可疑外部 IP 登入: ${USER} 從 ${IP}"
            CRITICAL_THREATS=$((CRITICAL_THREATS + 1))
        else
            NOTE=""
            [[ $IP == "114.39.15.79" || $IP == "114.39.15.120" ]] && NOTE=" ${DIM}(管理員)${NC}"
            [[ $IP == "49.13.31.45" || $IP == "91.107.195.115" || $IP == "168.119.100.163" || $IP == "188.34.177.5" ]] && NOTE=" ${DIM}(FLYWP)${NC}"
            echo -e "${GREEN}✓${NC} ${USER}${NC} @ ${TTY} | ${CYAN}${IP:-本機}${NC}${NOTE} | ${LOGIN_TIME}"
        fi
    done < <(who)
fi

echo ""
echo -e "${BOLD}${CYAN}▶ 最近 10 次成功登入記錄${NC}"
RECENT_LOGINS=$(last -10 -F 2>/dev/null | grep -v "^$" | grep -v "^wtmp" | grep -v "^reboot")
if [ -n "$RECENT_LOGINS" ]; then
    echo "$RECENT_LOGINS" | while read line; do
        LOGIN_IP=$(echo "$line" | awk '{print $(NF-2)}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
        
        # 檢查是否為已知 IP
        IS_KNOWN=0
        for whitelisted in "114.39.15.79" "114.39.15.120" "49.13.31.45" "91.107.195.115" "168.119.100.163" "188.34.177.5"; do
            if [[ $LOGIN_IP == $whitelisted ]]; then
                IS_KNOWN=1
                break
            fi
        done
        
        if [[ "$IS_KNOWN" -eq 0 ]] && [ -n "$LOGIN_IP" ]; then
            echo -e "${RED}⚠ ${line}${NC}"
            add_alert "CRITICAL" "不明 IP 成功登入: ${LOGIN_IP}"
            CRITICAL_THREATS=$((CRITICAL_THREATS + 1))
        else
            echo -e "${DIM}${line}${NC}"
        fi
    done
else
    echo -e "${DIM}無最近登入記錄${NC}"
fi

echo ""

# ==========================================
# 智慧失敗登入分析(優化)
# ==========================================
echo -e "${BOLD}${CYAN}▶ 失敗登入分析(智慧威脅判斷)${NC}"

# 判斷日誌檔案位置
if [ -f /var/log/auth.log ]; then
    LOG_FILE="/var/log/auth.log"
elif [ -f /var/log/secure ]; then
    LOG_FILE="/var/log/secure"
else
    LOG_FILE=""
fi

if [ -n "$LOG_FILE" ]; then
    FAILED_COUNT=$(grep "Failed password" "$LOG_FILE" 2>/dev/null | wc -l)
    
    if [ "$FAILED_COUNT" -eq 0 ]; then
        echo -e "${GREEN}✓ 無失敗登入記錄${NC}"
    else
        echo -e "${DIM}總失敗嘗試: ${WHITE}${FAILED_COUNT}${NC} 次"
        
        # 分析攻擊模式
        echo ""
        echo -e "${CYAN}攻擊模式分析:${NC}"
        
        # 計算高集中度攻擊 (單一 IP > 500 次)
        HIGH_RISK_IPS=$(grep "Failed password" "$LOG_FILE" 2>/dev/null | \
            awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | \
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
            sort | uniq -c | sort -rn | awk '$1 > 500 {print $2}')
        
        HIGH_RISK_COUNT=$(echo "$HIGH_RISK_IPS" | grep -v "^$" | wc -l)
        
        if [ "$HIGH_RISK_COUNT" -gt 0 ]; then
            echo -e "${RED}🔴 高集中度攻擊: ${HIGH_RISK_COUNT} 個 IP 超過 500 次失敗${NC}"
            echo "$HIGH_RISK_IPS" | while read ip; do
                ATTEMPTS=$(grep "Failed password" "$LOG_FILE" 2>/dev/null | grep -c "$ip")
                echo -e "   ${RED}├─ ${ip} (${ATTEMPTS} 次)${NC}"
            done
            add_alert "CRITICAL" "高集中度爆破攻擊: ${HIGH_RISK_COUNT} 個 IP"
            CRITICAL_THREATS=$((CRITICAL_THREATS + HIGH_RISK_COUNT))
        else
            echo -e "${GREEN}✓ 無高集中度攻擊 (所有 IP < 500 次)${NC}"
        fi
        
        # 顯示前 10 名攻擊來源
        echo ""
        echo -e "${CYAN}失敗次數 TOP 10:${NC}"
        echo -e "${DIM}次數    IP 位址              威脅等級${NC}"
        
        grep "Failed password" "$LOG_FILE" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
        sort | uniq -c | sort -rn | head -10 | \
        while read count ip; do
            if [ "$count" -ge 500 ]; then
                LEVEL="${RED}極高風險${NC}"
            elif [ "$count" -ge 100 ]; then
                LEVEL="${YELLOW}中等風險${NC}"
            elif [ "$count" -ge 20 ]; then
                LEVEL="${GREEN}低風險${NC}"
            else
                LEVEL="${GREEN}背景噪音${NC}"
            fi
            printf "${WHITE}%-7d ${CYAN}%-20s ${NC}%b\n" "$count" "$ip" "$LEVEL"
        done
        
        echo ""
        echo -e "${DIM}💡 判斷說明:${NC}"
        echo -e "${DIM}• ${GREEN}背景噪音${NC}${DIM}: 1-20 次 (正常網路掃描)${NC}"
        echo -e "${DIM}• ${GREEN}低風險${NC}${DIM}: 20-100 次 (隨機掃描)${NC}"
        echo -e "${DIM}• ${YELLOW}中等風險${NC}${DIM}: 100-500 次 (持續嘗試)${NC}"
        echo -e "${DIM}• ${RED}極高風險${NC}${DIM}: >500 次 (集中攻擊,需立即處理)${NC}"
    fi
else
    echo -e "${YELLOW}⚡ 找不到日誌檔案,無法分析${NC}"
fi
echo ""

# ==========================================
# Fail2Ban 規則管理(優化)
# ==========================================
if command -v fail2ban-client &>/dev/null && systemctl is-active --quiet fail2ban; then
    echo -e "${YELLOW}🛡️  Fail2Ban 防護狀態${NC}"
    echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
    
    # 顯示當前白名單
    echo -e "${BOLD}${CYAN}▶ 白名單配置:${NC}"
    for ip in "${WHITELIST_IPS[@]}"; do
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            NOTE="${WHITELIST_NOTES[$ip]}"
            if [ -n "$NOTE" ]; then
                echo -e "  ${GREEN}•${NC} ${WHITE}${ip}${NC} ${DIM}(${NOTE})${NC}"
            else
                echo -e "  ${GREEN}•${NC} ${WHITE}${ip}${NC}"
            fi
        fi
    done
    echo ""
    
    # 獲取當前規則
    CURRENT_MAXRETRY=$(fail2ban-client get sshd maxretry 2>/dev/null || echo "5")
    CURRENT_FINDTIME=$(fail2ban-client get sshd findtime 2>/dev/null || echo "600")
    CURRENT_BANTIME=$(fail2ban-client get sshd bantime 2>/dev/null || echo "3600")
    
    echo -e "${BOLD}${CYAN}▶ 目前規則:${NC}"
    echo -e "${DIM}失敗次數: ${WHITE}${CURRENT_MAXRETRY}${NC} 次"
    echo -e "${DIM}時間窗口: ${WHITE}${CURRENT_FINDTIME}${NC} 秒 ${DIM}($(awk -v t="$CURRENT_FINDTIME" 'BEGIN{if(t>=86400){printf "%.0f天", t/86400}else if(t>=3600){printf "%.1f小時", t/3600}else{printf "%.0f分", t/60}}'))${NC}"
    echo -e "${DIM}封鎖時間: ${WHITE}${CURRENT_BANTIME}${NC} 秒 ${DIM}($(awk -v t="$CURRENT_BANTIME" 'BEGIN{if(t>=86400){printf "%.0f天", t/86400}else if(t>=3600){printf "%.1f小時", t/3600}else{printf "%.0f分", t/60}}'))${NC}"
    echo ""
    
    # 檢查是否需要更新規則
    NEED_UPDATE=0
    if [ "$CURRENT_MAXRETRY" -ne 3 ] || [ "$CURRENT_FINDTIME" -ne 86400 ] || [ "$CURRENT_BANTIME" -ne 86400 ]; then
        NEED_UPDATE=1
    fi
    
    if [ "$NEED_UPDATE" -eq 1 ]; then
        echo -e "${YELLOW}⚠ 建議更新規則為: 一天內 3 次失敗 = 封鎖 24h${NC}"
        echo -ne "${CYAN}是否立即更新? (y/N): ${NC}"
        read -t 10 -n 1 UPDATE_CHOICE
        echo ""
        
        if [[ "$UPDATE_CHOICE" =~ ^[Yy]$ ]]; then
            echo -ne "${CYAN}正在更新 Fail2Ban 規則...${NC}"
            
            # 備份
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak.$(date +%Y%m%d) 2>/dev/null
            
            # 獲取當前登入 IP
            CURRENT_IP=$(who am i | awk '{print $5}' | tr -d '()')
            
            # 建立白名單字串
            IGNORE_IP_STRING="${WHITELIST_IPS[*]}"
            [ -n "$CURRENT_IP" ] && IGNORE_IP_STRING="${IGNORE_IP_STRING} ${CURRENT_IP}"
            
            # 更新配置
            cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = ${IGNORE_IP_STRING}
bantime = 24h
findtime = 1d
maxretry = 3
destemail = 
action = %(action_)s

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 24h
findtime = 1d
EOF
            
            [ -f /etc/redhat-release ] && sed -i 's|logpath = /var/log/auth.log|logpath = /var/log/secure|' /etc/fail2ban/jail.local
            
            systemctl restart fail2ban >/dev/null 2>&1
            sleep 2
            
            if systemctl is-active --quiet fail2ban; then
                echo -e " ${GREEN}✓ 完成${NC}"
            else
                echo -e " ${RED}✗ 失敗${NC}"
            fi
        else
            echo -e "${DIM}跳過更新${NC}"
        fi
    else
        echo -e "${GREEN}✓ 規則已是最佳配置${NC}"
    fi
    echo ""
    
    # 處理高風險 IP
    if [ "$HIGH_RISK_COUNT" -gt 0 ] && [ -n "$HIGH_RISK_IPS" ]; then
        echo -e "${YELLOW}🎯 處理高風險 IP (>500 次失敗)${NC}"
        
        BANNED_IPS=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP list" | awk -F: '{print $2}')
        
        NEWLY_BANNED=0
        echo "$HIGH_RISK_IPS" | while read ip; do
            if ! echo "$BANNED_IPS" | grep -q "$ip"; then
                fail2ban-client set sshd banip "$ip" >/dev/null 2>&1
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✓ 已封鎖: ${ip}${NC}"
                    NEWLY_BANNED=$((NEWLY_BANNED + 1))
                fi
            else
                echo -e "${DIM}• 已封鎖: ${ip}${NC}"
            fi
        done
        echo ""
    fi
    
    # 最終統計
    BANNED_NOW=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
    TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $NF}')
    
    echo -e "${BOLD}${CYAN}▶ 封鎖統計:${NC}"
    echo -e "${DIM}當前封鎖: ${WHITE}${BANNED_NOW:-0}${NC} 個 IP"
    echo -e "${DIM}累計封鎖: ${WHITE}${TOTAL_BANNED:-0}${NC} 次"
    echo ""
    
else
    # 自動安裝 Fail2Ban
    if [ "$CRITICAL_THREATS" -gt 0 ] || [ "$HIGH_RISK_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}🛡️  Fail2Ban 未安裝${NC}"
        echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
        echo -e "${RED}⚠ 偵測到安全威脅,強烈建議安裝 Fail2Ban${NC}"
        echo -ne "${CYAN}是否立即安裝? (y/N): ${NC}"
        read -t 10 -n 1 INSTALL_CHOICE
        echo ""
        
        if [[ "$INSTALL_CHOICE" =~ ^[Yy]$ ]]; then
            echo -e "${CYAN}正在安裝 Fail2Ban...${NC}"
            
            if [ -f /etc/debian_version ]; then
                apt-get update -qq >/dev/null 2>&1
                DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1
            elif [ -f /etc/redhat-release ]; then
                yum install -y epel-release >/dev/null 2>&1
                yum install -y fail2ban >/dev/null 2>&1
            fi
            
            if [ $? -eq 0 ]; then
                CURRENT_IP=$(who am i | awk '{print $5}' | tr -d '()')
                IGNORE_IP_STRING="${WHITELIST_IPS[*]}"
                [ -n "$CURRENT_IP" ] && IGNORE_IP_STRING="${IGNORE_IP_STRING} ${CURRENT_IP}"
                
                cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = ${IGNORE_IP_STRING}
bantime = 24h
findtime = 1d
maxretry = 3
destemail = 
action = %(action_)s

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 24h
findtime = 1d
EOF
                
                [ -f /etc/redhat-release ] && sed -i 's|logpath = /var/log/auth.log|logpath = /var/log/secure|' /etc/fail2ban/jail.local
                
                systemctl enable fail2ban >/dev/null 2>&1
                systemctl restart fail2ban >/dev/null 2>&1
                sleep 2
                
                if systemctl is-active --quiet fail2ban; then
                    echo -e "${GREEN}✓ Fail2Ban 安裝成功${NC}"
                else
                    echo -e "${RED}⚠ Fail2Ban 啟動失敗${NC}"
                fi
            else
                echo -e "${RED}⚠ Fail2Ban 安裝失敗${NC}"
            fi
        else
            echo -e "${YELLOW}⚠ 已跳過安裝,建議手動安裝 Fail2Ban${NC}"
        fi
        echo ""
    fi
fi

# ==========================================
# 惡意 Process 掃描
# ==========================================
echo -e "${YELLOW}[1/4] 🔍 惡意 Process 掃描${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

MALICIOUS_PROCESSES=$(ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis|lighttpd|postgres|memcache/' | grep -v "USER" | wc -l)
CRYPTO_MINERS=$(ps aux | grep -iE "xmrig|minerd|cpuminer|ccminer|cryptonight|monero|kinsing" | grep -v grep | wc -l)
TOTAL_SUSPICIOUS=$((MALICIOUS_PROCESSES + CRYPTO_MINERS))

if [ "$TOTAL_SUSPICIOUS" -gt 0 ]; then
    echo -e "${RED}⚠ ${BOLD}發現 ${TOTAL_SUSPICIOUS} 個可疑 process${NC}"
    echo ""

    if [ "$MALICIOUS_PROCESSES" -gt 0 ]; then
        echo -e "${RED}├─ 亂碼名稱 process: ${MALICIOUS_PROCESSES} 個${NC}"
        ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/' | grep -v "USER" | head -3 | while read line; do
            PROC=$(echo "$line" | awk '{print $11}')
            PID=$(echo "$line" | awk '{print $2}')
            CPU_P=$(echo "$line" | awk '{print $3}')
            echo -e "${RED}│  • ${PROC} ${DIM}(PID: ${PID}, CPU: ${CPU_P}%)${NC}"
        done
    fi

    if [ "$CRYPTO_MINERS" -gt 0 ]; then
        echo -e "${RED}├─ 挖礦程式: ${CRYPTO_MINERS} 個${NC}"
        ps aux | grep -iE "xmrig|minerd|cpuminer" | grep -v grep | head -3 | while read line; do
            PROC=$(echo "$line" | awk '{print $11}')
            PID=$(echo "$line" | awk '{print $2}')
            CPU_P=$(echo "$line" | awk '{print $3}')
            echo -e "${RED}│  • ${PROC} ${DIM}(PID: ${PID}, CPU: ${CPU_P}%)${NC}"
        done
        add_alert "CRITICAL" "偵測到挖礦程式: ${CRYPTO_MINERS} 個"
        CRITICAL_THREATS=$((CRITICAL_THREATS + CRYPTO_MINERS))
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
# 病毒檔名掃描
# ==========================================
echo -e "${YELLOW}[2/4] 🦠 常見病毒檔名掃描${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
echo -e "${DIM}檢查項目: 常見病毒檔名(c99, r57, wso, shell, backdoor)${NC}"
echo -e "${DIM}排除路徑: vendor, cache, node_modules, backup${NC}"
echo ""

MALWARE_TMPFILE=$(mktemp)

if [ -n "$SCAN_PATHS" ]; then
    find $SCAN_PATHS -type f \( \
        -iname "*c99*.php" -o \
        -iname "*r57*.php" -o \
        -iname "*wso*.php" -o \
        -iname "*shell*.php" -o \
        -iname "*backdoor*.php" -o \
        -iname "*webshell*.php" -o \
        -iname "*.suspected" \
        \) ! -path "*/vendor/*" \
           ! -path "*/cache/*" \
           ! -path "*/node_modules/*" \
           ! -path "*/backup/*" \
           ! -path "*/backups/*" \
           ! -path "*/Text/Diff/Engine/*" \
        2>/dev/null | head -20 >"$MALWARE_TMPFILE"
fi

MALWARE_COUNT=$(wc -l <"$MALWARE_TMPFILE" 2>/dev/null || echo 0)

if [ "$MALWARE_COUNT" -gt 0 ]; then
    echo -e "${RED}⚠ ${BOLD}發現 ${MALWARE_COUNT} 個可疑檔名:${NC}"
    echo ""
    while IFS= read -r file; do
        BASENAME=$(basename "$file")
        SITE_PATH=$(echo "$file" | grep -oP '/(var/www/|home/[^/]+/(public_html|www|web|app/public)|home/fly/[^/]+/app/public)' | head -1)

        echo -e "${RED}├─ ${file}${NC}"
        echo -e "${DIM}│  └─ 檔名: ${BASENAME}${NC}"

        if [ -n "$SITE_PATH" ]; then
            SITE_THREATS["$SITE_PATH"]=$((${SITE_THREATS["$SITE_PATH"]:-0} + 1))
        fi
    done <"$MALWARE_TMPFILE"

    THREATS_FOUND=$((THREATS_FOUND + MALWARE_COUNT))
    CRITICAL_THREATS=$((CRITICAL_THREATS + MALWARE_COUNT))
    add_alert "CRITICAL" "病毒檔名: ${MALWARE_COUNT} 個"
else
    echo -e "${GREEN}✓ 未發現常見病毒檔名${NC}"
fi

rm -f "$MALWARE_TMPFILE"
echo ""

# ==========================================
# Webshell 內容掃描
# ==========================================
echo -e "${YELLOW}[3/4] 🔍 Webshell 特徵碼掃描${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
echo -e "${DIM}掃描範圍: 網站根目錄的 PHP 檔案${NC}"
echo -e "${DIM}偵測特徵: eval(base64_decode), shell_exec, system${NC}"
echo ""

WEBSHELL_TMPFILE=$(mktemp)

if [ -n "$SCAN_PATHS" ]; then
    find $SCAN_PATHS -type f -name "*.php" \
        ! -path "*/vendor/*" \
        ! -path "*/cache/*" \
        ! -path "*/node_modules/*" \
        ! -path "*/backup/*" \
        ! -path "*/Text/Diff/Engine/*" \
        2>/dev/null | \
    xargs -P 4 -I {} grep -lE "(eval\s*\(base64_decode|gzinflate\s*\(base64_decode|shell_exec\s*\(|system\s*\(.*\\\$_)" {} 2>/dev/null | \
    head -20 >"$WEBSHELL_TMPFILE"
fi

WEBSHELL_COUNT=$(wc -l <"$WEBSHELL_TMPFILE" 2>/dev/null || echo 0)

if [ "$WEBSHELL_COUNT" -gt 0 ]; then
    echo -e "${RED}⚠ ${BOLD}發現 ${WEBSHELL_COUNT} 個可疑 PHP 檔案${NC}"
    echo ""

    while IFS= read -r file; do
        SITE_PATH=$(echo "$file" | grep -oP '/(var/www/|home/[^/]+/(public_html|www|web|app/public)|home/fly/[^/]+/app/public)' | head -1)

        echo -e "${RED}├─ ${file}${NC}"

        if [ -n "$SITE_PATH" ]; then
            SITE_THREATS["$SITE_PATH"]=$((${SITE_THREATS["$SITE_PATH"]:-0} + 1))
        fi
    done <"$WEBSHELL_TMPFILE"

    THREATS_FOUND=$((THREATS_FOUND + WEBSHELL_COUNT))
    CRITICAL_THREATS=$((CRITICAL_THREATS + WEBSHELL_COUNT))
    add_alert "CRITICAL" "Webshell 檔案: ${WEBSHELL_COUNT} 個"
else
    echo -e "${GREEN}✓ 未發現可疑 PHP 檔案${NC}"
fi

rm -f "$WEBSHELL_TMPFILE"
echo ""

# ==========================================
# 疑似中毒網站提醒
# ==========================================
if [ ${#SITE_THREATS[@]} -gt 0 ]; then
    echo -e "${YELLOW}[4/4] 🚨 疑似中毒網站提醒${NC}"
    echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${RED}${BOLD}以下網站發現威脅:${NC}"
    echo ""

    for site in "${!SITE_THREATS[@]}"; do
        echo "${SITE_THREATS[$site]} $site"
    done | sort -rn | while read count site; do
        if [ "$count" -ge 5 ]; then
            RISK_LEVEL="${RED}【高風險】${NC}"
        elif [ "$count" -ge 3 ]; then
            RISK_LEVEL="${YELLOW}【中風險】${NC}"
        else
            RISK_LEVEL="${YELLOW}【低風險】${NC}"
        fi

        echo -e "${RISK_LEVEL} ${WHITE}${site}${NC} - ${RED}${count} 個威脅${NC}"
    done
    echo ""
fi

# ==========================================
# 總結報告(優化)
# ==========================================
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}   🛡️  掃描結果總結${NC}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"

# 智慧威脅等級判斷
if [ "$CRITICAL_THREATS" -gt 0 ]; then
    THREAT_LEVEL="${RED}🔥 嚴重威脅 - 發現 ${CRITICAL_THREATS} 個重大安全問題${NC}"
elif [ "$THREATS_FOUND" -gt 10 ]; then
    THREAT_LEVEL="${YELLOW}⚡ 中等風險 - 建議立即處理${NC}"
elif [ "$THREATS_FOUND" -gt 0 ]; then
    THREAT_LEVEL="${YELLOW}⚡ 低風險 - 建議檢查${NC}"
else
    THREAT_LEVEL="${GREEN}✓ 系統安全${NC}"
fi

echo -e "${BOLD}威脅等級:${NC} ${THREAT_LEVEL}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
echo -e "發現威脅: ${WHITE}${THREATS_FOUND}${NC} | 關鍵威脅: ${RED}${CRITICAL_THREATS}${NC} | 已清除: ${GREEN}${THREATS_CLEANED}${NC}"

if [ ${#ALERTS[@]} -gt 0 ]; then
    echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${RED}${BOLD}🚨 重要告警:${NC}"
    echo ""

    for alert in "${ALERTS[@]}"; do
        if [[ $alert == *"CRITICAL"* ]]; then
            MSG=$(echo "$alert" | cut -d']' -f2-)
            echo -e "${RED}[CRITICAL]${NC}${MSG}"
        elif [[ $alert == *"HIGH"* ]]; then
            MSG=$(echo "$alert" | cut -d']' -f2-)
            echo -e "${YELLOW}[HIGH]${NC}${MSG}"
        fi
    done
fi

echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
echo -e "${DIM}掃描完成: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"

echo ""
echo -e "${MAGENTA}💡 安全建議:${NC}"
if [ "$CRITICAL_THREATS" -eq 0 ] && [ "$THREATS_FOUND" -lt 5 ]; then
    echo -e "${GREEN}✓ 主機安全狀況良好${NC}"
    echo -e "${DIM}  • 持續監控登入記錄${NC}"
    echo -e "${DIM}  • 定期更新系統與軟體${NC}"
    echo -e "${DIM}  • Fail2Ban 持續運作中${NC}"
else
    echo -e "${YELLOW}⚠ 建議立即處理發現的威脅${NC}"
    echo -e "${DIM}  • 檢查並刪除可疑檔案${NC}"
    echo -e "${DIM}  • 更改所有管理員密碼${NC}"
    echo -e "${DIM}  • 更新 WordPress 與外掛${NC}"
fi

echo ""
echo -e "${MAGENTA}🛡️  掃描工具不會在系統留下任何記錄${NC}"
echo -e "${DIM}   GitHub: https://github.com/jimmy-is-me/vps-security-scanner${NC}"
echo ""

# 清理失敗登入記錄(可選)
if [ "$CRITICAL_THREATS" -eq 0 ]; then
    echo -ne "${YELLOW}🧹 是否清理失敗登入記錄? (y/N): ${NC}"
    read -t 5 -n 1 CLEAN_CHOICE
    echo ""
    
    if [[ "$CLEAN_CHOICE" =~ ^[Yy]$ ]]; then
        echo -ne "${CYAN}清理中...${NC}"
        
        if command -v faillock &>/dev/null; then
            faillock --reset-all >/dev/null 2>&1
        fi
        
        if command -v pam_tally2 &>/dev/null; then
            pam_tally2 --reset >/dev/null 2>&1
        fi
        
        echo -n >/var/log/btmp 2>/dev/null
        
        echo -e " ${GREEN}✓ 完成${NC}"
    else
        echo -e "${DIM}已跳過清理${NC}"
    fi
fi

echo ""
