#!/bin/bash

#################################################
# VPS 系統資源與安全掃描工具 v6.5.0 - 完整版
# 修正項目:
#  1. 檢查與顯示進程
#  2. Fail2Ban: 1小時/10次/封1小時(無白名單,直接覆蓋)
#  3. 記憶體/Swap/CPU/磁碟/I/O/資料庫/Cron 完整監控
#  4. 保留所有安全掃描功能(惡意進程/病毒檔名/Webshell/登入監控)
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

VERSION="6.5.0"

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
SCAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')
echo -e "${DIM}運行時間:${NC} ${WHITE}${UPTIME_HUMAN}${NC}"
echo -e "${DIM}掃描時間:${NC} ${WHITE}${SCAN_TIME}${NC}"
echo ""

# ==========================================
# CPU 使用率監控
# ==========================================
echo -e "${BOLD}${CYAN}▶ CPU 使用率${NC}"

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
echo -e "${DIM}負載狀態:${NC} ${LOAD_STATUS} ${DIM}(每核心: ${LOAD_RATIO})${NC}"

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
        add_alert "HIGH" "進程 ${CMD} CPU 過高: ${CPU_P}%"
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
    add_alert "CRITICAL" "記憶體嚴重不足: ${RAM_PERCENT}%"
elif [ "${RAM_INT:-0}" -ge 80 ]; then
    RAM_COLOR=$RED
    RAM_STATUS="${RED}偏高${NC}"
    add_alert "HIGH" "記憶體使用過高: ${RAM_PERCENT}%"
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
        add_alert "MEDIUM" "進程 ${CMD} 記憶體過高: ${MEM_P}%"
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
    echo -e "${DIM}建議: 低記憶體 VPS 配置 1-2G Swap${NC}"
else
    SWAP_TOTAL_GB=$(kb_to_gb "$SWAP_TOTAL_KB")
    SWAP_USED_MB=$(kb_to_mb "$SWAP_USED_KB")
    SWAP_FREE_MB=$(kb_to_mb "$SWAP_FREE_KB")
    
    SWAP_PERCENT=$(awk -v t="$SWAP_TOTAL_KB" -v u="$SWAP_USED_KB" 'BEGIN {if(t>0){printf "%.1f", u/t*100}else{print "0.0"}}')
    SWAP_INT=${SWAP_PERCENT%.*}
    
    if [ "${SWAP_INT:-0}" -ge 80 ]; then
        SWAP_COLOR=$RED
        SWAP_STATUS="${RED}過度使用${NC}"
        add_alert "HIGH" "Swap 過度使用: ${SWAP_PERCENT}% (系統可能變慢)"
    elif [ "${SWAP_INT:-0}" -ge 50 ]; then
        SWAP_COLOR=$YELLOW
        SWAP_STATUS="${YELLOW}使用中${NC}"
    else
        SWAP_COLOR=$GREEN
        SWAP_STATUS="${GREEN}正常${NC}"
    fi
    
    echo -e "${DIM}總量:${NC} ${WHITE}${SWAP_TOTAL_GB}${NC} | ${DIM}使用:${NC} ${SWAP_COLOR}${SWAP_USED_MB} (${SWAP_PERCENT}%)${NC} | ${DIM}空閒:${NC} ${GREEN}${SWAP_FREE_MB}${NC}"
    echo -e "${DIM}狀態:${NC} ${SWAP_STATUS}"
    
    if [ "${SWAP_INT:-0}" -ge 50 ]; then
        echo -e "${YELLOW}⚠ 建議: 增加 RAM 或優化 PHP-FPM/MySQL 配置${NC}"
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
    add_alert "HIGH" "硬碟使用過高: ${DISK_PERCENT}%"
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

echo ""
echo -e "${DIM}大目錄占用 TOP 5:${NC}"
du -sh /var/www /home /var/log /tmp /var/cache 2>/dev/null | sort -rh | head -5 | while read size dir; do
    echo -e "  ${WHITE}${size}${NC} ${DIM}${dir}${NC}"
done
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
        add_alert "HIGH" "磁碟 I/O 過高: ${DISK_UTIL}%"
    elif [ "${DISK_UTIL_INT:-0}" -gt 50 ]; then
        IO_STATUS="${YELLOW}偏高${NC}"
    else
        IO_STATUS="${GREEN}正常${NC}"
    fi
    
    echo -e "${DIM}平均使用率:${NC} ${WHITE}${DISK_UTIL}%${NC} - ${IO_STATUS}"
else
    echo -e "${YELLOW}⚠ 未安裝 iostat${NC} ${DIM}(apt install sysstat)${NC}"
fi
echo ""

# ==========================================
# 資料庫服務檢查
# ==========================================
echo -e "${BOLD}${CYAN}▶ 資料庫服務檢查${NC}"

DB_FOUND=0

if pgrep -x "mysqld\|mariadbd" >/dev/null 2>&1; then
    PROC_NAME=$(pgrep -x mysqld >/dev/null && echo "mysqld" || echo "mariadbd")
    CPU=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[$PROC_NAME]" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')

    echo -e "${GREEN}✓ MySQL/MariaDB 運行中${NC}"
    echo -e "  ${DIM}CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"
    
    if command -v mysql &>/dev/null; then
        MAX_CONN=$(mysql -e "SHOW VARIABLES LIKE 'max_connections';" 2>/dev/null | awk 'NR==2 {print $2}')
        CURRENT_CONN=$(mysql -e "SHOW STATUS LIKE 'Threads_connected';" 2>/dev/null | awk 'NR==2 {print $2}')
        
        if [ -n "$MAX_CONN" ] && [ -n "$CURRENT_CONN" ]; then
            CONN_PERCENT=$(awk -v c="$CURRENT_CONN" -v m="$MAX_CONN" 'BEGIN {if(m>0){printf "%.0f", c/m*100}else{print "0"}}')
            
            if [ "$CONN_PERCENT" -ge 80 ]; then
                CONN_STATUS="${RED}接近上限${NC}"
                add_alert "HIGH" "MySQL 連線接近上限: ${CURRENT_CONN}/${MAX_CONN}"
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

if crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" >/dev/null; then
    ROOT_CRON_COUNT=$(crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | wc -l)
    echo -e "${GREEN}✓ Root 定時任務: ${WHITE}${ROOT_CRON_COUNT}${NC} 個"
    
    HIGH_FREQ=$(crontab -l 2>/dev/null | grep -E "^\*.*\*.*\*.*\*.*\*" | wc -l)
    if [ "$HIGH_FREQ" -gt 0 ]; then
        echo -e "  ${YELLOW}⚠ 高頻率任務 (每分鐘): ${HIGH_FREQ} 個${NC}"
        add_alert "MEDIUM" "發現 ${HIGH_FREQ} 個高頻率 Cron"
    fi
    
    SUSPICIOUS_CRON=$(crontab -l 2>/dev/null | grep -iE "(curl|wget|/tmp/|/dev/shm/)" | grep -v "^#" | wc -l)
    if [ "$SUSPICIOUS_CRON" -gt 0 ]; then
        echo -e "  ${RED}⚠ 可疑任務: ${SUSPICIOUS_CRON} 個${NC}"
        add_alert "HIGH" "發現 ${SUSPICIOUS_CRON} 個可疑 Cron"
        crontab -l 2>/dev/null | grep -iE "(curl|wget|/tmp/|/dev/shm/)" | grep -v "^#" | head -3 | while read line; do
            echo -e "    ${RED}${line:0:60}...${NC}"
        done
    fi
    
    CRON_FOUND=1
fi

SYSTEM_CRON_FILES=$(find /etc/cron.d /etc/cron.daily /etc/cron.hourly -type f 2>/dev/null | wc -l)
if [ "$SYSTEM_CRON_FILES" -gt 0 ]; then
    echo -e "${GREEN}✓ 系統定時任務: ${WHITE}${SYSTEM_CRON_FILES}${NC} 個檔案"
    CRON_FOUND=1
fi

[ "$CRON_FOUND" -eq 0 ] && echo -e "${DIM}未設定定時任務${NC}"
echo ""

# ==========================================
# 網站服務
# ==========================================
echo -e "${BOLD}${CYAN}▶ 網站服務資源使用${NC}"
WEB_SERVICES=0

if pgrep -x nginx >/dev/null 2>&1; then
    PROCS=$(pgrep -x nginx | wc -l)
    CPU=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[n]ginx" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')

    echo -e "${GREEN}✓ Nginx${NC}"
    echo -e "   ${DIM}進程: ${WHITE}${PROCS}${DIM} | CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"
    WEB_SERVICES=1
fi

if pgrep -f "php-fpm" >/dev/null 2>&1; then
    PROCS=$(pgrep -f "php-fpm" | wc -l)
    CPU=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$3} END {printf "%.1f", sum}')
    MEM=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$4} END {printf "%.1f", sum}')
    RSS=$(ps aux | grep -E "[p]hp-fpm" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')

    echo -e "${GREEN}✓ PHP-FPM${NC}"
    echo -e "   ${DIM}進程: ${WHITE}${PROCS}${DIM} | CPU: ${WHITE}${CPU}%${DIM} | 記憶體: ${WHITE}${MEM}% (${RSS}M)${NC}"
    WEB_SERVICES=1
fi

[ "$WEB_SERVICES" -eq 0 ] && echo -e "${DIM}未偵測到網站服務${NC}"
echo ""

# ==========================================
# Fail2Ban 規則管理(直接覆蓋,無白名單)
# ==========================================
if command -v fail2ban-client &>/dev/null && systemctl is-active --quiet fail2ban; then
    echo -e "${YELLOW}🛡️  Fail2Ban 防護狀態${NC}"
    echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
    
    CURRENT_MAXRETRY=$(fail2ban-client get sshd maxretry 2>/dev/null || echo "5")
    CURRENT_FINDTIME=$(fail2ban-client get sshd findtime 2>/dev/null || echo "600")
    CURRENT_BANTIME=$(fail2ban-client get sshd bantime 2>/dev/null || echo "3600")
    
    echo -e "${BOLD}${CYAN}▶ 目前規則:${NC}"
    echo -e "${DIM}失敗次數: ${WHITE}${CURRENT_MAXRETRY}${NC} 次"
    echo -e "${DIM}時間窗口: ${WHITE}${CURRENT_FINDTIME}${NC} 秒"
    echo -e "${DIM}封鎖時間: ${WHITE}${CURRENT_BANTIME}${NC} 秒"
    echo ""
    
    NEED_UPDATE=0
    if [ "$CURRENT_MAXRETRY" -ne 10 ] || [ "$CURRENT_FINDTIME" -ne 3600 ] || [ "$CURRENT_BANTIME" -ne 3600 ]; then
        NEED_UPDATE=1
    fi
    
    if [ "$NEED_UPDATE" -eq 1 ]; then
        echo -e "${YELLOW}⚠ 建議更新規則: 1小時/10次/封1小時${NC}"
        echo -ne "${CYAN}是否立即更新? (y/N): ${NC}"
        read -t 10 -n 1 UPDATE_CHOICE
        echo ""
        
        if [[ "$UPDATE_CHOICE" =~ ^[Yy]$ ]]; then
            echo -ne "${CYAN}正在更新 Fail2Ban 規則...${NC}"
            
            CURRENT_IP=$(who am i | awk '{print $5}' | tr -d '()')
            
            # 直接覆蓋(不備份,無白名單)
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
    
    BANNED_NOW=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
    TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $NF}')
    
    echo -e "${BOLD}${CYAN}▶ 封鎖統計:${NC}"
    echo -e "${DIM}當前封鎖: ${WHITE}${BANNED_NOW:-0}${NC} 個 IP"
    echo -e "${DIM}累計封鎖: ${WHITE}${TOTAL_BANNED:-0}${NC} 次"
    echo ""
fi

# ==========================================
# 登入監控
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

        if [ -n "$IP" ] && [ "$IP" != "127.0.0.1" ]; then
            echo -e "${YELLOW}⚠${NC} ${USER} @ ${TTY} | ${CYAN}${IP}${NC} | ${LOGIN_TIME}"
        else
            echo -e "${GREEN}✓${NC} ${USER} @ ${TTY} | ${DIM}本機${NC} | ${LOGIN_TIME}"
        fi
    done < <(who)
fi

echo ""
echo -e "${BOLD}${CYAN}▶ 最近 10 次成功登入${NC}"
RECENT_LOGINS=$(last -10 -F 2>/dev/null | grep -v "^$" | grep -v "^wtmp" | grep -v "^reboot")
if [ -n "$RECENT_LOGINS" ]; then
    echo "$RECENT_LOGINS" | head -10 | while read line; do
        echo -e "${DIM}${line}${NC}"
    done
else
    echo -e "${DIM}無最近登入記錄${NC}"
fi
echo ""

# ==========================================
# 失敗登入分析
# ==========================================
echo -e "${BOLD}${CYAN}▶ 失敗登入分析${NC}"

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
        
        ANALYSIS_TMP=$(mktemp)
        
        grep "Failed password" "$LOG_FILE" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
        sort | uniq -c | sort -rn > "$ANALYSIS_TMP"
        
        CRITICAL_COUNT=0
        MEDIUM_COUNT=0
        LOW_COUNT=0
        NOISE_COUNT=0
        
        while read count ip; do
            LEVEL=$(get_threat_level "$count")
            case $LEVEL in
                CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
                MEDIUM) MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
                LOW) LOW_COUNT=$((LOW_COUNT + 1)) ;;
                NOISE) NOISE_COUNT=$((NOISE_COUNT + 1)) ;;
            esac
        done < "$ANALYSIS_TMP"
        
        echo ""
        echo -e "${CYAN}威脅統計:${NC}"
        [ "$CRITICAL_COUNT" -gt 0 ] && echo -e "  ${RED}• 極高風險 (>500次): ${CRITICAL_COUNT} 個 IP${NC}"
        [ "$MEDIUM_COUNT" -gt 0 ] && echo -e "  ${YELLOW}• 中等風險 (100-500次): ${MEDIUM_COUNT} 個 IP${NC}"
        [ "$LOW_COUNT" -gt 0 ] && echo -e "  ${GREEN}• 低風險 (20-100次): ${LOW_COUNT} 個 IP${NC}"
        [ "$NOISE_COUNT" -gt 0 ] && echo -e "  ${GREEN}• 背景噪音 (<20次): ${NOISE_COUNT} 個 IP${NC}"
        
        if [ "$CRITICAL_COUNT" -gt 0 ]; then
            echo ""
            echo -e "${RED}🔴 極高風險 IP (>500次):${NC}"
            
            HIGH_RISK_IPS=""
            while read count ip; do
                if [ "$count" -ge 500 ]; then
                    echo -e "   ${RED}├─ ${ip} (${count} 次)${NC}"
                    HIGH_RISK_IPS="${HIGH_RISK_IPS} ${ip}"
                    HIGH_RISK_IPS_COUNT=$((HIGH_RISK_IPS_COUNT + 1))
                fi
            done < "$ANALYSIS_TMP"
            
            add_alert "CRITICAL" "極高風險爆破: ${CRITICAL_COUNT} 個 IP"
            CRITICAL_THREATS=$((CRITICAL_THREATS + CRITICAL_COUNT))
        else
            echo ""
            echo -e "${GREEN}✓ 無極高風險攻擊${NC}"
        fi
        
        echo ""
        echo -e "${CYAN}失敗次數 TOP 15:${NC}"
        echo -e "${DIM}次數    IP 位址              威脅等級${NC}"
        
        head -15 "$ANALYSIS_TMP" | while read count ip; do
            LEVEL=$(get_threat_level "$count")
            DISPLAY=$(get_threat_display "$LEVEL")
            printf "${WHITE}%-7d ${CYAN}%-20s ${NC}%b\n" "$count" "$ip" "$DISPLAY"
        done
        
        rm -f "$ANALYSIS_TMP"
    fi
else
    echo -e "${YELLOW}⚡ 找不到日誌檔案${NC}"
fi
echo ""

# ==========================================
# 惡意 Process 掃描
# ==========================================
echo -e "${YELLOW}[1/4] 🔍 惡意 Process 掃描${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

MALICIOUS_PROCESSES=$(ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis|lighttpd|postgres|memcache/' | grep -v "USER" | wc -l)
CRYPTO_MINERS=$(ps aux | grep -iE "xmrig|minerd|cpuminer|ccminer|cryptonight|monero|kinsing" | grep -v grep | wc -l)
TOTAL_SUSPICIOUS=$((MALICIOUS_PROCESSES + CRYPTO_MINERS))

if [ "$TOTAL_SUSPICIOUS" -gt 0 ]; then
    echo -e "${RED}⚠ 發現 ${TOTAL_SUSPICIOUS} 個可疑 process${NC}"
    echo ""

    if [ "$MALICIOUS_PROCESSES" -gt 0 ]; then
        echo -e "${RED}├─ 亂碼名稱: ${MALICIOUS_PROCESSES} 個${NC}"
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
        add_alert "CRITICAL" "挖礦程式: ${CRYPTO_MINERS} 個"
        CRITICAL_THREATS=$((CRITICAL_THREATS + CRYPTO_MINERS))
    fi

    THREATS_FOUND=$((THREATS_FOUND + TOTAL_SUSPICIOUS))

    echo ""
    echo -ne "${YELLOW}🧹 自動清除中...${NC}"
    ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/' | grep -v "USER" | awk '{print $2}' | xargs kill -9 2>/dev/null
    ps aux | grep -iE "xmrig|minerd|cpuminer" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
    THREATS_CLEANED=$((THREATS_CLEANED + TOTAL_SUSPICIOUS))
    echo -e " ${GREEN}✓ 完成${NC}"
else
    echo -e "${GREEN}✓ 未發現可疑 process${NC}"
fi
echo ""

# ==========================================
# 病毒檔名掃描
# ==========================================
echo -e "${YELLOW}[2/4] 🦠 病毒檔名掃描${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

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
        2>/dev/null | head -20 >"$MALWARE_TMPFILE"
fi

MALWARE_COUNT=$(wc -l <"$MALWARE_TMPFILE" 2>/dev/null || echo 0)

if [ "$MALWARE_COUNT" -gt 0 ]; then
    echo -e "${RED}⚠ 發現 ${MALWARE_COUNT} 個可疑檔名${NC}"
    echo ""
    while IFS= read -r file; do
        SITE_PATH=$(echo "$file" | grep -oP '/(var/www/|home/[^/]+/(public_html|www|web|app/public))' | head -1)
        echo -e "${RED}├─ ${file}${NC}"
        
        if [ -n "$SITE_PATH" ]; then
            SITE_THREATS["$SITE_PATH"]=$((${SITE_THREATS["$SITE_PATH"]:-0} + 1))
        fi
    done <"$MALWARE_TMPFILE"

    THREATS_FOUND=$((THREATS_FOUND + MALWARE_COUNT))
    CRITICAL_THREATS=$((CRITICAL_THREATS + MALWARE_COUNT))
    add_alert "CRITICAL" "病毒檔名: ${MALWARE_COUNT} 個"
else
    echo -e "${GREEN}✓ 未發現病毒檔名${NC}"
fi

rm -f "$MALWARE_TMPFILE"
echo ""

# ==========================================
# Webshell 掃描
# ==========================================
echo -e "${YELLOW}[3/4] 🔍 Webshell 特徵碼掃描${NC}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"

WEBSHELL_TMPFILE=$(mktemp)

if [ -n "$SCAN_PATHS" ]; then
    find $SCAN_PATHS -type f -name "*.php" \
        ! -path "*/vendor/*" \
        ! -path "*/cache/*" \
        ! -path "*/node_modules/*" \
        ! -path "*/backup/*" \
        2>/dev/null | \
    xargs -P 4 -I {} grep -lE "(eval\s*\(base64_decode|gzinflate\s*\(base64_decode|shell_exec\s*\(|system\s*\(.*\\\$_)" {} 2>/dev/null | \
    head -20 >"$WEBSHELL_TMPFILE"
fi

WEBSHELL_COUNT=$(wc -l <"$WEBSHELL_TMPFILE" 2>/dev/null || echo 0)

if [ "$WEBSHELL_COUNT" -gt 0 ]; then
    echo -e "${RED}⚠ 發現 ${WEBSHELL_COUNT} 個可疑 PHP${NC}"
    echo ""

    while IFS= read -r file; do
        SITE_PATH=$(echo "$file" | grep -oP '/(var/www/|home/[^/]+/(public_html|www|web|app/public))' | head -1)
        echo -e "${RED}├─ ${file}${NC}"
        
        if [ -n "$SITE_PATH" ]; then
            SITE_THREATS["$SITE_PATH"]=$((${SITE_THREATS["$SITE_PATH"]:-0} + 1))
        fi
    done <"$WEBSHELL_TMPFILE"

    THREATS_FOUND=$((THREATS_FOUND + WEBSHELL_COUNT))
    CRITICAL_THREATS=$((CRITICAL_THREATS + WEBSHELL_COUNT))
    add_alert "CRITICAL" "Webshell: ${WEBSHELL_COUNT} 個"
else
    echo -e "${GREEN}✓ 未發現可疑 PHP${NC}"
fi

rm -f "$WEBSHELL_TMPFILE"
echo ""

# ==========================================
# 疑似中毒網站
# ==========================================
if [ ${#SITE_THREATS[@]} -gt 0 ]; then
    echo -e "${YELLOW}[4/4] 🚨 疑似中毒網站${NC}"
    echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
    
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
# 總結報告
# ==========================================
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}   📊 掃描結果總結${NC}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════════${NC}"

if [ "$CRITICAL_THREATS" -gt 0 ]; then
    THREAT_LEVEL="${RED}🔥 嚴重威脅 - ${CRITICAL_THREATS} 個重大問題${NC}"
elif [ "$THREATS_FOUND" -gt 10 ]; then
    THREAT_LEVEL="${YELLOW}⚡ 中等風險${NC}"
elif [ "$THREATS_FOUND" -gt 0 ]; then
    THREAT_LEVEL="${YELLOW}⚡ 低風險${NC}"
else
    THREAT_LEVEL="${GREEN}✓ 系統安全${NC}"
fi

echo -e "${BOLD}威脅等級:${NC} ${THREAT_LEVEL}"
echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
echo -e "發現威脅: ${WHITE}${THREATS_FOUND}${NC} | 關鍵威脅: ${RED}${CRITICAL_THREATS}${NC} | 已清除: ${GREEN}${THREATS_CLEANED}${NC}"

if [ ${#ALERTS[@]} -gt 0 ]; then
    echo -e "${DIM}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${RED}${BOLD}⚠ 重要告警:${NC}"
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

echo -e "${MAGENTA}💡 安全建議:${NC}"
if [ "$CRITICAL_THREATS" -eq 0 ] && [ "$THREATS_FOUND" -lt 5 ]; then
    echo -e "${GREEN}✓ 系統安全狀況良好${NC}"
    echo -e "${DIM}  • 持續監控系統資源${NC}"
    echo -e "${DIM}  • 定期更新系統與軟體${NC}"
else
    echo -e "${YELLOW}⚠ 建議立即處理發現的威脅${NC}"
    echo -e "${DIM}  • 檢查並刪除可疑檔案${NC}"
    echo -e "${DIM}  • 更改所有管理員密碼${NC}"
    echo -e "${DIM}  • 更新 WordPress 與外掛${NC}"
fi
echo ""
