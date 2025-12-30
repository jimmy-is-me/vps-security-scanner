#!/bin/bash

#################################################
# VPS 系統資源與安全掃描工具 v6.0.0
# 修正項目:
#  1. 移除白名單 IP 功能
#  2. Fail2Ban 直接覆蓋設定(不備份)
#  3. 強化系統資源監控(CPU/RAM/Swap/磁碟/I/O/資料庫/Cron)
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

VERSION="6.0.0"

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

kb_to_mb() {
    local kb="$1"
    [ -z "$kb" ] && kb=0
    awk -v k="$kb" 'BEGIN {printf "%.0fM", k/1024}'
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

get_threat_level() {
    local count=$1
    if [ "$count" -ge 500 ]; then
        echo "CRITICAL"
    elif [ "$count" -ge 100 ]; then
        echo "MEDIUM"
    elif [ "$count" -ge 20 ]; then
        echo "LOW"
    else
        echo "NOISE"
    fi
}

get_threat_display() {
    local level=$1
    case $level in
        CRITICAL) echo "${RED}極高風險${NC}" ;;
        MEDIUM) echo "${YELLOW}中等風險${NC}" ;;
        LOW) echo "${GREEN}低風險${NC}" ;;
        NOISE) echo "${GREEN}背景噪音${NC}" ;;
        *) echo "${DIM}未知${NC}" ;;
    esac
}

SCAN_PATHS="$(build_scan_paths)"

# 計數器
THREATS_FOUND=0
THREATS_CLEANED=0
ALERTS=()
CRITICAL_THREATS=0
HIGH_RISK_IPS_COUNT=0
declare -A SITE_THREATS

# ==========================================
# 標題
# ==========================================
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}   🛡️  VPS 系統資源與安全掃描工具 v${VERSION}${NC}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

# ==========================================
# 系統資訊與資源使用
# ==========================================
echo -e "${YELLOW}📊 系統資訊與資源使用${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

HOSTNAME=$(hostname)
OS_INFO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
[ -z "$OS_INFO" ] && OS_INFO=$(uname -s)
KERNEL=$(uname -r)
CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d':' -f2 | xargs)
CPU_CORES=$(grep -c ^processor /proc/cpuinfo 2>/dev/null)
[ -z "$CPU_MODEL" ] && CPU_MODEL="Unknown CPU"
[ -z "$CPU_CORES" ] && CPU_CORES=1

echo -e "${DIM}主機名稱:${NC} ${WHITE}${HOSTNAME}${NC}"
echo -e "${DIM}作業系統:${NC} ${WHITE}${OS_INFO}${NC}"
echo -e "${DIM}核心版本:${NC} ${WHITE}${KERNEL}${NC}"
echo -e "${DIM}CPU 型號:${NC} ${WHITE}${CPU_MODEL}${NC}"
echo -e "${DIM}CPU 核心:${NC} ${WHITE}${CPU_CORES} 核心${NC}"
UPTIME_HUMAN=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}')
echo -e "${DIM}運行時間:${NC} ${WHITE}${UPTIME_HUMAN}${NC}"
echo ""

# ==========================================
# CPU 使用率監控
# ==========================================
echo -e "${BOLD}${CYAN}▶ CPU 使用率${NC}"

# 系統負載
LOAD_1=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,""); print $1}')
LOAD_5=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,""); print $2}')
LOAD_15=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{gsub(/ /,""); print $3}')

LOAD_RATIO=$(awk -v l="$LOAD_1" -v c="$CPU_CORES" 'BEGIN {if(c>0){printf "%.2f", l/c}else{print "0"}}')
LOAD_CMP=$(awk -v r="$LOAD_RATIO" 'BEGIN {if(r<0.7){print "正常"}else if(r<1.0){print "偏高"}else{print "過高"}}')

if [[ "$LOAD_CMP" == "正常" ]]; then
    LOAD_STATUS="${GREEN}${LOAD_CMP}${NC}"
elif [[ "$LOAD_CMP" == "偏高" ]]; then
    LOAD_STATUS="${YELLOW}${LOAD_CMP}${NC}"
    add_alert "MEDIUM" "系統負載偏高"
else
    LOAD_STATUS="${RED}${LOAD_CMP}${NC}"
    add_alert "HIGH" "系統負載過高"
fi

echo -e "${DIM}系統負載:${NC} ${WHITE}${LOAD_1}${NC} ${DIM}(1分) ${WHITE}${LOAD_5}${NC} ${DIM}(5分) ${WHITE}${LOAD_15}${NC} ${DIM}(15分)${NC}"
echo -e "${DIM}負載狀態:${NC} ${LOAD_STATUS} ${DIM}(每核心負載: ${LOAD_RATIO})${NC}"

# CPU 使用率 TOP 5
echo ""
echo -e "${DIM}CPU 使用率 TOP 5:${NC}"
echo -e "${DIM}用戶       PID      CPU%   記憶體%  指令${NC}"

readarray -t CPU_LINES < <(ps aux --sort=-%cpu | head -6 | tail -5)
for line in "${CPU_LINES[@]}"; do
    USER=$(echo "$line" | awk '{print $1}' | cut -c1-10)
    PID=$(echo "$line" | awk '{print $2}')
    CPU_P=$(echo "$line" | awk '{print $3}')
    MEM_P=$(echo "$line" | awk '{print $4}')
    CMD=$(echo "$line" | awk '{print $11}' | cut -c1-30)

    CPU_INT=${CPU_P%.*}
    if [ "${CPU_INT:-0}" -gt 50 ]; then
        CPU_COLOR=$RED
        add_alert "HIGH" "進程 ${CMD} CPU 使用過高: ${CPU_P}%"
    elif [ "${CPU_INT:-0}" -gt 20 ]; then
        CPU_COLOR=$YELLOW
    else
        CPU_COLOR=$WHITE
    fi

    printf "${YELLOW}%-10s ${DIM}%-8s ${NC}${CPU_COLOR}%6s%% ${DIM}%7s%%${NC}  %s\n" \
           "$USER" "$PID" "$CPU_P" "$MEM_P" "$CMD"
done
echo ""

# ==========================================
# 記憶體 RAM 使用監控
# ==========================================
echo -e "${BOLD}${CYAN}▶ 記憶體 RAM 使用${NC}"

MEM_TOTAL_KB=$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
MEM_AVAIL_KB=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null)
MEM_FREE_KB=$(awk '/MemFree:/ {print $2}' /proc/meminfo 2>/dev/null)
MEM_BUFFERS_KB=$(awk '/^Buffers:/ {print $2}' /proc/meminfo 2>/dev/null)
MEM_CACHED_KB=$(awk '/^Cached:/ {print $2}' /proc/meminfo 2>/dev/null)

[ -z "$MEM_TOTAL_KB" ] && MEM_TOTAL_KB=0
[ -z "$MEM_AVAIL_KB" ] && MEM_AVAIL_KB=0
MEM_USED_KB=$((MEM_TOTAL_KB - MEM_AVAIL_KB))
[ "$MEM_USED_KB" -lt 0 ] && MEM_USED_KB=0

TOTAL_GB=$(kb_to_gb "$MEM_TOTAL_KB")
USED_GB=$(kb_to_gb "$MEM_USED_KB")
AVAIL_GB=$(kb_to_gb "$MEM_AVAIL_KB")
FREE_MB=$(kb_to_mb "$MEM_FREE_KB")
BUFFERS_MB=$(kb_to_mb "$MEM_BUFFERS_KB")
CACHED_MB=$(kb_to_mb "$MEM_CACHED_KB")

RAM_PERCENT=$(awk -v t="$MEM_TOTAL_KB" -v u="$MEM_USED_KB" 'BEGIN {if(t>0){printf "%.1f", u/t*100}else{print "0.0"}}')

RAM_INT=${RAM_PERCENT%.*}
if [ "${RAM_INT:-0}" -ge 90 ]; then
    RAM_COLOR=$RED
    RAM_STATUS="${RED}嚴重不足${NC}"
    add_alert "CRITICAL" "記憶體使用率嚴重: ${RAM_PERCENT}%"
elif [ "${RAM_INT:-0}" -ge 80 ]; then
    RAM_COLOR=$RED
    RAM_STATUS="${RED}偏高${NC}"
    add_alert "HIGH" "記憶體使用率過高: ${RAM_PERCENT}%"
elif [ "${RAM_INT:-0}" -ge 60 ]; then
    RAM_COLOR=$YELLOW
    RAM_STATUS="${YELLOW}中等${NC}"
else
    RAM_COLOR=$GREEN
    RAM_STATUS="${GREEN}正常${NC}"
fi

echo -e "${DIM}總量:${NC} ${WHITE}${TOTAL_GB}${NC} | ${DIM}使用:${NC} ${RAM_COLOR}${USED_GB} (${RAM_PERCENT}%)${NC} | ${DIM}可用:${NC} ${GREEN}${AVAIL_GB}${NC}"
echo -e "${DIM}空閒:${NC} ${WHITE}${FREE_MB}${NC} | ${DIM}緩衝:${NC} ${WHITE}${BUFFERS_MB}${NC} | ${DIM}快取:${NC} ${WHITE}${CACHED_MB}${NC}"
echo -e "${DIM}狀態:${NC} ${RAM_STATUS}"

# 記憶體使用 TOP 5
echo ""
echo -e "${DIM}記憶體使用 TOP 5:${NC}"
echo -e "${DIM}用戶       PID      記憶體%  RSS(MB)  指令${NC}"

readarray -t MEM_LINES < <(ps aux --sort=-%mem | head -6 | tail -5)
for line in "${MEM_LINES[@]}"; do
    USER=$(echo "$line" | awk '{print $1}' | cut -c1-10)
    PID=$(echo "$line" | awk '{print $2}')
    MEM_P=$(echo "$line" | awk '{print $4}')
    RSS_KB=$(echo "$line" | awk '{print $6}')
    CMD=$(echo "$line" | awk '{print $11}' | cut -c1-30)

    RSS_MB=$(awk -v r="$RSS_KB" 'BEGIN {printf "%.1f", r/1024}')

    MEM_INT=${MEM_P%.*}
    if [ "${MEM_INT:-0}" -gt 20 ]; then
        MEM_COLOR=$RED
        add_alert "MEDIUM" "進程 ${CMD} 記憶體使用過高: ${MEM_P}%"
    elif [ "${MEM_INT:-0}" -gt 10 ]; then
        MEM_COLOR=$YELLOW
    else
        MEM_COLOR=$WHITE
    fi

    printf "${YELLOW}%-10s ${DIM}%-8s ${NC}${MEM_COLOR}%7s%% ${DIM}%7s${NC}  %s\n" \
           "$USER" "$PID" "$MEM_P" "${RSS_MB}M" "$CMD"
done
echo ""

# ==========================================
# Swap 使用監控
# ==========================================
echo -e "${BOLD}${CYAN}▶ Swap 使用${NC}"

SWAP_TOTAL_KB=$(awk '/SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
SWAP_FREE_KB=$(awk '/SwapFree:/ {print $2}' /proc/meminfo 2>/dev/null)
[ -z "$SWAP_TOTAL_KB" ] && SWAP_TOTAL_KB=0
[ -z "$SWAP_FREE_KB" ] && SWAP_FREE_KB=0
SWAP_USED_KB=$((SWAP_TOTAL_KB - SWAP_FREE_KB))

if [ "$SWAP_TOTAL_KB" -eq 0 ]; then
    echo -e "${YELLOW}⚠ 系統未配置 Swap${NC}"
    echo -e "${DIM}建議: 為低記憶體 VPS 配置適量 Swap (建議 1-2G)${NC}"
else
    SWAP_TOTAL_GB=$(kb_to_gb "$SWAP_TOTAL_KB")
    SWAP_USED_MB=$(kb_to_mb "$SWAP_USED_KB")
    SWAP_FREE_MB=$(kb_to_mb "$SWAP_FREE_KB")
    
    SWAP_PERCENT=$(awk -v t="$SWAP_TOTAL_KB" -v u="$SWAP_USED_KB" 'BEGIN {if(t>0){printf "%.1f", u/t*100}else{print "0.0"}}')
    SWAP_INT=${SWAP_PERCENT%.*}
    
    if [ "${SWAP_INT:-0}" -ge 80 ]; then
        SWAP_COLOR=$RED
        SWAP_STATUS="${RED}過度使用${NC}"
        add_alert "HIGH" "Swap 使用率過高: ${SWAP_PERCENT}% (可能導致系統變慢)"
    elif [ "${SWAP_INT:-0}" -ge 50 ]; then
        SWAP_COLOR=$YELLOW
        SWAP_STATUS="${YELLOW}使用中${NC}"
        add_alert "MEDIUM" "Swap 使用率偏高: ${SWAP_PERCENT}%"
    else
        SWAP_COLOR=$GREEN
        SWAP_STATUS="${GREEN}正常${NC}"
    fi
    
    echo -e "${DIM}總量:${NC} ${WHITE}${SWAP_TOTAL_GB}${NC} | ${DIM}使用:${NC} ${SWAP_COLOR}${SWAP_USED_MB} (${SWAP_PERCENT}%)${NC} | ${DIM}空閒:${NC} ${GREEN}${SWAP_FREE_MB}${NC}"
    echo -e "${DIM}狀態:${NC} ${SWAP_STATUS}"
    
    if [ "${SWAP_INT:-0}" -ge 50 ]; then
        echo -e "${YELLOW}⚠ Swap 使用過多可能導致效能下降,建議:${NC}"
        echo -e "${DIM}  • 增加實體記憶體${NC}"
        echo -e "${DIM}  • 優化 PHP-FPM / MySQL 配置${NC}"
        echo -e "${DIM}  • 關閉不必要的服務${NC}"
    fi
fi
echo ""

# ==========================================
# 磁碟空間監控
# ==========================================
echo -e "${BOLD}${CYAN}▶ 磁碟空間${NC}"

DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
DISK_PERCENT=$(df / | awk 'NR==2 {print $5}' | tr -d '%')

if [ "$DISK_PERCENT" -ge 90 ]; then
    DISK_COLOR=$RED
    DISK_STATUS="${RED}嚴重不足${NC}"
    add_alert "CRITICAL" "硬碟空間嚴重不足: ${DISK_PERCENT}%"
elif [ "$DISK_PERCENT" -ge 80 ]; then
    DISK_COLOR=$RED
    DISK_STATUS="${RED}偏高${NC}"
    add_alert "HIGH" "硬碟使用率過高: ${DISK_PERCENT}%"
elif [ "$DISK_PERCENT" -ge 60 ]; then
    DISK_COLOR=$YELLOW
    DISK_STATUS="${YELLOW}中等${NC}"
else
    DISK_COLOR=$GREEN
    DISK_STATUS="${GREEN}正常${NC}"
fi

echo -e "${DIM}根目錄 (/):${NC}"
echo -e "  ${DIM}總量:${NC} ${WHITE}${DISK_TOTAL}${NC} | ${DIM}使用:${NC} ${DISK_COLOR}${DISK_USED} (${DISK_PERCENT}%)${NC} | ${DIM}可用:${NC} ${GREEN}${DISK_AVAIL}${NC}"
echo -e "  ${DIM}狀態:${NC} ${DISK_STATUS}"

# 大目錄檢查
echo ""
echo -e "${DIM}大目錄占用 TOP 5:${NC}"
if [ -d /var/www ] || [ -d /home ]; then
    du -sh /var/www /home /var/log /tmp /var/cache 2>/dev/null | sort -rh | head -5 | while read size dir; do
        echo -e "  ${WHITE}${size}${NC} ${DIM}${dir}${NC}"
    done
else
    echo -e "  ${DIM}無法檢測${NC}"
fi
echo ""

# ==========================================
# 磁碟 I/O 監控
# ==========================================
echo -e "${BOLD}${CYAN}▶ 磁碟 I/O 使用率${NC}"

if command -v iostat &>/dev/null; then
    DISK_UTIL=$(iostat -x 1 2 | tail -n +4 | awk 'NR>1 && $NF!="" {sum+=$NF; count++} END {if(count>0) printf "%.1f", sum/count; else print "0"}')
    DISK_UTIL_INT=${DISK_UTIL%.*}
    
    if [ "${DISK_UTIL_INT:-0}" -gt 80 ]; then
        IO_STATUS="${RED}瓶頸${NC}"
        add_alert "HIGH" "磁碟 I/O 使用率過高: ${DISK_UTIL}%"
    elif [ "${DISK_UTIL_INT:-0}" -gt 50 ]; then
        IO_STATUS="${YELLOW}偏高${NC}"
    else
        IO_STATUS="${GREEN}正常${NC}"
    fi
    
    echo -e "${DIM}平均使用率:${NC} ${WHITE}${DISK_UTIL}%${NC} - ${IO_STATUS}"
else
    echo -e "${YELLOW}⚠ 未安裝 iostat 工具${NC}"
    echo -e "${DIM}安裝: apt install sysstat / yum install sysstat${NC}"
fi
echo ""

# ==========================================
# 資料庫服務檢查
# ==========================================
echo -e "${BOLD}${CYAN}▶ 資料庫服務檢查${NC}"

DB_FOUND=0

# MySQL/MariaDB 檢查
if pgrep -x "mysqld\|mariadbd" >/dev/null 2>&1; then
    PROC_NAME=$(pgrep -x mysqld >/dev/null && echo "mysqld" || echo "mariadbd")
    CPU=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')

    echo -e "${GREEN}✓ MySQL/MariaDB 運行中${NC}"
    echo -e "  ${DIM}CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"
    
    # 檢查連線數
    if command -v mysql &>/dev/null; then
        MAX_CONN=$(mysql -e "SHOW VARIABLES LIKE 'max_connections';" 2>/dev/null | awk 'NR==2 {print $2}')
        CURRENT_CONN=$(mysql -e "SHOW STATUS LIKE 'Threads_connected';" 2>/dev/null | awk 'NR==2 {print $2}')
        
        if [ -n "$MAX_CONN" ] && [ -n "$CURRENT_CONN" ]; then
            CONN_PERCENT=$(awk -v c="$CURRENT_CONN" -v m="$MAX_CONN" 'BEGIN {if(m>0){printf "%.0f", c/m*100}else{print "0"}}')
            
            if [ "$CONN_PERCENT" -ge 80 ]; then
                CONN_STATUS="${RED}接近上限${NC}"
                add_alert "HIGH" "MySQL 連線數接近上限: ${CURRENT_CONN}/${MAX_CONN}"
            elif [ "$CONN_PERCENT" -ge 60 ]; then
                CONN_STATUS="${YELLOW}偏高${NC}"
            else
                CONN_STATUS="${GREEN}正常${NC}"
            fi
            
            echo -e "  ${DIM}連線數: ${WHITE}${CURRENT_CONN}${DIM}/${WHITE}${MAX_CONN}${DIM} (${CONN_PERCENT}%) - ${CONN_STATUS}${NC}"
        fi
    fi
    
    DB_FOUND=1
fi

# PostgreSQL 檢查
if pgrep -x "postgres" >/dev/null 2>&1; then
    CPU=$(ps aux | grep -E "[p]ostgres" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[p]ostgres" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[p]ostgres" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')

    echo -e "${GREEN}✓ PostgreSQL 運行中${NC}"
    echo -e "  ${DIM}CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"
    
    DB_FOUND=1
fi

# Redis 檢查
if pgrep -x "redis-server" >/dev/null 2>&1; then
    CPU=$(ps aux | grep -E "[r]edis-server" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[r]edis-server" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[r]edis-server" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')

    echo -e "${GREEN}✓ Redis 運行中${NC}"
    echo -e "  ${DIM}CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"
    
    DB_FOUND=1
fi

[ "$DB_FOUND" -eq 0 ] && echo -e "${DIM}未偵測到資料庫服務${NC}"
echo ""

# ==========================================
# 定時任務 Cron 檢查
# ==========================================
echo -e "${BOLD}${CYAN}▶ 定時任務 Cron 檢查${NC}"

CRON_FOUND=0

# 檢查 root crontab
if crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" >/dev/null; then
    ROOT_CRON_COUNT=$(crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | wc -l)
    echo -e "${GREEN}✓ Root 定時任務: ${WHITE}${ROOT_CRON_COUNT}${NC} 個"
    
    # 顯示高頻率任務
    HIGH_FREQ=$(crontab -l 2>/dev/null | grep -E "^\*.*\*.*\*.*\*.*\*" | wc -l)
    if [ "$HIGH_FREQ" -gt 0 ]; then
        echo -e "  ${YELLOW}⚠ 高頻率任務 (每分鐘): ${HIGH_FREQ} 個${NC}"
        add_alert "MEDIUM" "發現 ${HIGH_FREQ} 個高頻率 Cron 任務"
    fi
    
    # 檢查可疑腳本
    SUSPICIOUS_CRON=$(crontab -l 2>/dev/null | grep -iE "(curl|wget|/tmp/|/dev/shm/)" | grep -v "^#" | wc -l)
    if [ "$SUSPICIOUS_CRON" -gt 0 ]; then
        echo -e "  ${RED}⚠ 可疑任務: ${SUSPICIOUS_CRON} 個${NC}"
        add_alert "HIGH" "發現 ${SUSPICIOUS_CRON} 個可疑 Cron 任務"
        crontab -l 2>/dev/null | grep -iE "(curl|wget|/tmp/|/dev/shm/)" | grep -v "^#" | head -3 | while read line; do
            echo -e "    ${RED}${line:0:60}...${NC}"
        done
    fi
    
    CRON_FOUND=1
fi

# 檢查系統 cron 目錄
SYSTEM_CRON_FILES=$(find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -type f 2>/dev/null | wc -l)
if [ "$SYSTEM_CRON_FILES" -gt 0 ]; then
    echo -e "${GREEN}✓ 系統定時任務: ${WHITE}${SYSTEM_CRON_FILES}${NC} 個檔案"
    CRON_FOUND=1
fi

[ "$CRON_FOUND" -eq 0 ] && echo -e "${DIM}未設定定時任務${NC}"
echo ""

# ==========================================
# Fail2Ban 規則管理(直接覆蓋)
# ==========================================
if command -v fail2ban-client &>/dev/null && systemctl is-active --quiet fail2ban; then
    echo -e "${YELLOW}🛡️  Fail2Ban 防護狀態${NC}"
    echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
    
    # 獲取當前規則
    CURRENT_MAXRETRY=$(fail2ban-client get sshd maxretry 2>/dev/null || echo "5")
    CURRENT_FINDTIME=$(fail2ban-client get sshd findtime 2>/dev/null || echo "600")
    CURRENT_BANTIME=$(fail2ban-client get sshd bantime 2>/dev/null || echo "3600")
    
    echo -e "${BOLD}${CYAN}▶ 目前規則:${NC}"
    echo -e "${DIM}失敗次數: ${WHITE}${CURRENT_MAXRETRY}${NC} 次"
    echo -e "${DIM}時間窗口: ${WHITE}${CURRENT_FINDTIME}${NC} 秒"
    echo -e "${DIM}封鎖時間: ${WHITE}${CURRENT_BANTIME}${NC} 秒"
    echo ""
    
    # 檢查是否需要更新規則
    NEED_UPDATE=0
    if [ "$CURRENT_MAXRETRY" -ne 10 ] || [ "$CURRENT_FINDTIME" -ne 3600 ] || [ "$CURRENT_BANTIME" -ne 3600 ]; then
        NEED_UPDATE=1
    fi
    
    if [ "$NEED_UPDATE" -eq 1 ]; then
        echo -e "${YELLOW}⚠ 建議更新規則為: 1小時內 10 次失敗 = 封鎖 1 小時${NC}"
        echo -ne "${CYAN}是否立即更新? (y/N): ${NC}"
        read -t 10 -n 1 UPDATE_CHOICE
        echo ""
        
        if [[ "$UPDATE_CHOICE" =~ ^[Yy]$ ]]; then
            echo -ne "${CYAN}正在更新 Fail2Ban 規則...${NC}"
            
            # 獲取當前登入 IP
            CURRENT_IP=$(who am i | awk '{print $5}' | tr -d '()')
            
            # 直接覆蓋配置(不備份)
            cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 ${CURRENT_IP}
bantime = 1h
findtime = 1h
maxretry = 10
destemail = 
action = %(action_)s

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 10
bantime = 1h
findtime = 1h
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
    
    # 封鎖統計
    BANNED_NOW=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
    TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $NF}')
    
    echo -e "${BOLD}${CYAN}▶ 封鎖統計:${NC}"
    echo -e "${DIM}當前封鎖: ${WHITE}${BANNED_NOW:-0}${NC} 個 IP"
    echo -e "${DIM}累計封鎖: ${WHITE}${TOTAL_BANNED:-0}${NC} 次"
    echo ""
fi

# ==========================================
# 威脅掃描(精簡版)
# ==========================================
echo -e "${YELLOW}🔍 安全威脅掃描${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

# 惡意進程
MALICIOUS_PROCESSES=$(ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis/' | grep -v "USER" | wc -l)
CRYPTO_MINERS=$(ps aux | grep -iE "xmrig|minerd|cpuminer|ccminer|cryptonight|monero|kinsing" | grep -v grep | wc -l)
TOTAL_SUSPICIOUS=$((MALICIOUS_PROCESSES + CRYPTO_MINERS))

if [ "$TOTAL_SUSPICIOUS" -gt 0 ]; then
    echo -e "${RED}⚠ 發現 ${TOTAL_SUSPICIOUS} 個可疑進程${NC}"
    THREATS_FOUND=$((THREATS_FOUND + TOTAL_SUSPICIOUS))
    add_alert "CRITICAL" "發現可疑進程: ${TOTAL_SUSPICIOUS} 個"
else
    echo -e "${GREEN}✓ 未發現可疑進程${NC}"
fi

SCAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')
echo -e "${DIM}掃描完成: ${SCAN_TIME}${NC}"
echo ""

# ==========================================
# 總結報告
# ==========================================
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}   📊 系統健康度總結${NC}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"

HEALTH_SCORE=100

# 扣分機制
[ "${RAM_INT:-0}" -ge 90 ] && HEALTH_SCORE=$((HEALTH_SCORE - 20))
[ "${RAM_INT:-0}" -ge 80 ] && HEALTH_SCORE=$((HEALTH_SCORE - 10))
[ "$DISK_PERCENT" -ge 90 ] && HEALTH_SCORE=$((HEALTH_SCORE - 20))
[ "$DISK_PERCENT" -ge 80 ] && HEALTH_SCORE=$((HEALTH_SCORE - 10))
[ "$SWAP_INT" -ge 80 ] && HEALTH_SCORE=$((HEALTH_SCORE - 15))
[ "$LOAD_CMP" == "過高" ] && HEALTH_SCORE=$((HEALTH_SCORE - 15))
[ "$TOTAL_SUSPICIOUS" -gt 0 ] && HEALTH_SCORE=$((HEALTH_SCORE - 30))

if [ "$HEALTH_SCORE" -ge 80 ]; then
    HEALTH_COLOR=$GREEN
    HEALTH_STATUS="優良"
elif [ "$HEALTH_SCORE" -ge 60 ]; then
    HEALTH_COLOR=$YELLOW
    HEALTH_STATUS="中等"
else
    HEALTH_COLOR=$RED
    HEALTH_STATUS="需注意"
fi

echo -e "${BOLD}系統健康度:${NC} ${HEALTH_COLOR}${HEALTH_SCORE}/100${NC} ${DIM}(${HEALTH_STATUS})${NC}"

if [ ${#ALERTS[@]} -gt 0 ]; then
    echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${RED}${BOLD}⚠ 警告事項:${NC}"
    echo ""
    
    for alert in "${ALERTS[@]}"; do
        if [[ $alert == *"CRITICAL"* ]]; then
            MSG=$(echo "$alert" | cut -d']' -f2-)
            echo -e "${RED}[嚴重]${NC}${MSG}"
        elif [[ $alert == *"HIGH"* ]]; then
            MSG=$(echo "$alert" | cut -d']' -f2-)
            echo -e "${YELLOW}[高]${NC}${MSG}"
        elif [[ $alert == *"MEDIUM"* ]]; then
            MSG=$(echo "$alert" | cut -d']' -f2-)
            echo -e "${YELLOW}[中]${NC}${MSG}"
        fi
    done
fi

echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
echo -e "${DIM}掃描完成: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
