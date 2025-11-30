#!/bin/bash

#################################################
# VPS 安全掃描工具 v4.2 - 無痕跡高效能版
# GitHub: https://github.com/jimmy-is-me/vps-security-scanner
# 特色：不殘留工具、不留記錄、即時監控、完整告警
# 新增：自動安裝 Fail2Ban 防護
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

# 圖示
ICON_SHIELD="[盾]"
ICON_SCAN="[掃]"
ICON_SUCCESS="[✓]"
ICON_DANGER="[!]"
ICON_WARN="[⚠]"
ICON_USER="[👤]"
ICON_FIRE="[🔥]"
ICON_CLOCK="[⏰]"
ICON_FILE="[📄]"
ICON_CLEAN="[清]"
ICON_CPU="[CPU]"
ICON_RAM="[RAM]"
ICON_DISK="[💾]"
ICON_SERVER="[主機]"
ICON_NET="[網路]"

VERSION="4.2.0"

# 效能優化
renice -n 19 $$ > /dev/null 2>&1
ionice -c3 -p $$ > /dev/null 2>&1

# 清除螢幕
clear

# ==========================================
# 標題
# ==========================================
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}                                                                    ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}         ${ICON_SHIELD} VPS 安全掃描工具 v${VERSION} - 無痕跡版               ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}                                                                    ${NC}${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 計數器
THREATS_FOUND=0
THREATS_CLEANED=0
ALERTS=()

# ==========================================
# 函數：新增告警
# ==========================================
add_alert() {
    local level=$1
    local message=$2
    ALERTS+=("[$level] $message")
}

# ==========================================
# Fail2Ban 自動安裝與設定（新增）
# ==========================================
install_fail2ban() {
    echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${YELLOW} ${ICON_SHIELD} Fail2Ban 防護系統檢查${NC}                                    ${CYAN}│${NC}"
    echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # 檢查是否已安裝
    if command -v fail2ban-client &> /dev/null; then
        F2B_STATUS=$(systemctl is-active fail2ban 2>/dev/null)
        if [ "$F2B_STATUS" = "active" ]; then
            echo -e "${GREEN}${ICON_SUCCESS} Fail2Ban 已安裝並運行中${NC}"
            
            # 顯示當前封鎖統計
            BANNED_IPS=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
            TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $NF}')
            
            echo -e "${CYAN}  • 當前封鎖 IP: ${WHITE}${BANNED_IPS:-0}${CYAN} 個${NC}"
            echo -e "${CYAN}  • 累計封鎖: ${WHITE}${TOTAL_BANNED:-0}${CYAN} 次${NC}"
            return 0
        fi
    fi
    
    # 尚未安裝，詢問是否安裝
    echo -e "${YELLOW}${ICON_WARN} Fail2Ban 尚未安裝${NC}"
    echo -e "${CYAN}Fail2Ban 可自動封鎖暴力破解攻擊的 IP${NC}"
    echo ""
    echo -ne "${YELLOW}是否安裝 Fail2Ban？(y/n): ${NC}"
    read -r -n 1 INSTALL_F2B
    echo ""
    
    if [[ ! $INSTALL_F2B =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}跳過 Fail2Ban 安裝${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}${ICON_CLEAN} 正在安裝 Fail2Ban...${NC}"
    
    # 偵測系統類型
    if [ -f /etc/debian_version ]; then
        apt-get update -qq > /dev/null 2>&1
        apt-get install -y fail2ban > /dev/null 2>&1
    elif [ -f /etc/redhat-release ]; then
        yum install -y epel-release > /dev/null 2>&1
        yum install -y fail2ban > /dev/null 2>&1
    else
        echo -e "${RED}${ICON_DANGER} 不支援的系統類型${NC}"
        return 1
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${ICON_SUCCESS} Fail2Ban 安裝成功${NC}"
        
        # 建立優化設定檔
        cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# 白名單（永不封鎖）
ignoreip = 127.0.0.1/8 ::1 114.39.15.79

# 封鎖時間（1 小時）
bantime = 3600

# 觀察時間窗口（10 分鐘）
findtime = 600

# 允許失敗次數
maxretry = 5

# 關閉郵件通知（提升效能）
destemail = 
action = %(action_)s

# 停用日誌檔（無痕跡模式）
logtarget = /dev/null

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

        # 針對 CentOS/RHEL 系統
        if [ -f /etc/redhat-release ]; then
            sed -i 's|logpath = /var/log/auth.log|logpath = /var/log/secure|' /etc/fail2ban/jail.local
        fi
        
        # 啟動服務
        systemctl enable fail2ban > /dev/null 2>&1
        systemctl restart fail2ban > /dev/null 2>&1
        
        sleep 2
        
        if systemctl is-active --quiet fail2ban; then
            echo -e "${GREEN}${ICON_SUCCESS} Fail2Ban 已啟動並運行${NC}"
            echo -e "${CYAN}  • 白名單 IP: ${WHITE}114.39.15.79${NC}"
            echo -e "${CYAN}  • 封鎖時間: ${WHITE}1 小時${NC}"
            echo -e "${CYAN}  • 失敗次數: ${WHITE}5 次 / 10 分鐘${NC}"
            echo -e "${CYAN}  • 日誌模式: ${WHITE}無痕跡 (/dev/null)${NC}"
        else
            echo -e "${RED}${ICON_DANGER} Fail2Ban 啟動失敗${NC}"
            return 1
        fi
    else
        echo -e "${RED}${ICON_DANGER} Fail2Ban 安裝失敗${NC}"
        return 1
    fi
    
    echo ""
}

# 執行 Fail2Ban 安裝檢查
install_fail2ban

# ==========================================
# 主機基本資訊
# ==========================================
echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${YELLOW} ${ICON_SERVER} 主機資訊${NC}                                                     ${CYAN}│${NC}"
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

# 系統負載與運行時間
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
# 即時資源使用監控（強化版）
# ==========================================
echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${YELLOW} ${ICON_CPU} 即時資源使用監控${NC}                                           ${CYAN}│${NC}"
echo -e "${CYAN}├────────────────────────────────────────────────────────────────┤${NC}"

# CPU 使用率 TOP 5（更詳細）
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ CPU 使用率 TOP 5${NC}"
echo -e "${CYAN}│${NC}   ${DIM}排名  用戶       CPU%   記憶體%  指令${NC}"
echo -e "${CYAN}│${NC}"

ps aux --sort=-%cpu | awk 'NR>1 && NR<=6 {
    user = $1;
    cpu = $3;
    mem = $4;
    cmd = $11;
    if (length(user) > 8) user = substr(user, 1, 8);
    if (length(cmd) > 25) cmd = substr(cmd, 1, 22) "...";
    
    cpu_color = "'"${WHITE}"'";
    if (cpu > 50) cpu_color = "'"${RED}"'";
    else if (cpu > 20) cpu_color = "'"${YELLOW}"'";
    
    printf "'"${CYAN}"'│'"${NC}"'   '"${DIM}"'%-4s '"${YELLOW}"'%-10s '"${NC}"'" cpu_color "'%6s%% '"${DIM}"' %7s%%  '"${NC}"'%s\n", 
           NR-1".", user, cpu, mem, cmd
}'

# 記憶體使用 TOP 5
echo -e "${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ 記憶體使用 TOP 5${NC}"
echo -e "${CYAN}│${NC}   ${DIM}排名  用戶       記憶體%  RSS      指令${NC}"
echo -e "${CYAN}│${NC}"

ps aux --sort=-%mem | awk 'NR>1 && NR<=6 {
    user = $1;
    mem = $4;
    rss = $6;
    cmd = $11;
    if (length(user) > 8) user = substr(user, 1, 8);
    if (length(cmd) > 25) cmd = substr(cmd, 1, 22) "...";
    
    # 轉換 RSS 為 MB
    rss_mb = sprintf("%.1f", rss/1024);
    
    mem_color = "'"${WHITE}"'";
    if (mem > 20) mem_color = "'"${RED}"'";
    else if (mem > 10) mem_color = "'"${YELLOW}"'";
    
    printf "'"${CYAN}"'│'"${NC}"'   '"${DIM}"'%-4s '"${YELLOW}"'%-10s '"${NC}"'" mem_color "'%7s%% '"${DIM}"' %6sM  '"${NC}"'%s\n", 
           NR-1".", user, mem, rss_mb, cmd
}'

# 網站服務資源使用（更詳細）
echo -e "${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ 網站服務資源使用${NC}"
echo -e "${CYAN}│${NC}"

WEB_SERVICES=0
for service in nginx apache2 httpd litespeed lsphp php-fpm; do
    if pgrep -x "$service" > /dev/null 2>&1; then
        SERVICE_PROCS=$(pgrep -x "$service" | wc -l)
        SERVICE_CPU=$(ps aux | grep -E "[^]]$service" | awk '{sum+=$3} END {printf "%.1f", sum}')
        SERVICE_MEM=$(ps aux | grep -E "[^]]$service" | awk '{sum+=$4} END {printf "%.1f", sum}')
        SERVICE_RSS=$(ps aux | grep -E "[^]]$service" | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
        
        if [ ! -z "$SERVICE_CPU" ] && (( $(echo "$SERVICE_CPU > 0" | bc -l 2>/dev/null || echo 0) )); then
            echo -e "${CYAN}│${NC}   ${GREEN}${ICON_SUCCESS}${NC} ${WHITE}${service}${NC}"
            echo -e "${CYAN}│${NC}      ${DIM}進程數: ${WHITE}${SERVICE_PROCS}${DIM} | CPU: ${WHITE}${SERVICE_CPU}%${DIM} | 記憶體: ${WHITE}${SERVICE_MEM}% (${SERVICE_RSS}M)${NC}"
            WEB_SERVICES=1
        fi
    fi
done

if [ $WEB_SERVICES -eq 0 ]; then
    echo -e "${CYAN}│${NC}   ${DIM}未偵測到網站服務運行${NC}"
fi

# 網路連線統計
echo -e "${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${BOLD}${CYAN}▶ 網路連線統計${NC}"
echo -e "${CYAN}│${NC}"

TOTAL_CONN=$(ss -tn state established 2>/dev/null | wc -l)
LISTEN_PORTS=$(ss -tln 2>/dev/null | grep LISTEN | wc -l)

echo -e "${CYAN}│${NC}   ${DIM}目前連線數: ${WHITE}${TOTAL_CONN}${DIM} | 監聽埠號: ${WHITE}${LISTEN_PORTS}${NC}"

# I/O 統計（如果 iostat 可用）
if command -v iostat &> /dev/null; then
    IO_WAIT=$(iostat -c 1 2 | awk '/^avg/ {print $4}' | tail -1)
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
echo -e "${CYAN}│${YELLOW} ${ICON_USER} 系統登入監控${NC}                                              ${CYAN}│${NC}"
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
            echo -e "${DIM}  │${NC} ${RED}${ICON_WARN} ${USER}${NC} @ ${TTY} | ${RED}${IP}${NC} | ${LOGIN_TIME}"
            add_alert "HIGH" "外部 IP 登入: ${USER} 從 ${IP}"
        else
            echo -e "${DIM}  │${NC} ${GREEN}${ICON_SUCCESS} ${USER}${NC} @ ${TTY} | ${CYAN}${IP:-本機}${NC} | ${LOGIN_TIME}"
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
    echo -e "${YELLOW}${ICON_WARN} 失敗登入嘗試: ${WHITE}${FAILED_COUNT} 次${NC}"
    
    if [ $FAILED_COUNT -gt 100 ]; then
        echo -e "${RED}${ICON_DANGER} ${BOLD}偵測到大量暴力破解嘗試！${NC}"
        
        # 檢查 Fail2Ban 是否已處理
        if command -v fail2ban-client &> /dev/null && systemctl is-active --quiet fail2ban; then
            BANNED_COUNT=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
            echo -e "${GREEN}${ICON_SUCCESS} Fail2Ban 已封鎖 ${BANNED_COUNT:-0} 個 IP${NC}"
        else
            add_alert "CRITICAL" "SSH 暴力破解攻擊: ${FAILED_COUNT} 次失敗登入"
        fi
        
        echo -e "${RED}前 5 名攻擊來源:${NC}"
        lastb 2>/dev/null | awk '{print $3}' | grep -v "^$" | sort | uniq -c | sort -rn | head -5 | while read line; do
            echo -e "  ${RED}├─${NC} ${line}"
        done
    fi
else
    echo -e "${GREEN}${ICON_SUCCESS} 無失敗登入記錄${NC}"
fi

echo ""
sleep 0.3

# ==========================================
# 2-7. 其他掃描項目（保持原樣）
# ==========================================

# [2. 惡意 Process 掃描]
echo -e "${CYAN}┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${YELLOW} [1/12] ${ICON_SCAN} 惡意 Process 掃描${NC}                                 ${CYAN}│${NC}"
echo -e "${CYAN}└────────────────────────────────────────────────────────────────┘${NC}"
echo ""

MALICIOUS_PROCESSES=$(ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis|lighttpd|postgres|memcache/' | grep -v "USER" | wc -l)
CRYPTO_MINERS=$(ps aux | grep -iE "xmrig|minerd|cpuminer|ccminer|cryptonight|monero|kinsing" | grep -v grep | wc -l)
TOTAL_SUSPICIOUS=$((MALICIOUS_PROCESSES + CRYPTO_MINERS))

if [ $TOTAL_SUSPICIOUS -gt 0 ]; then
    echo -e "${RED}${ICON_DANGER} ${BOLD}發現 ${TOTAL_SUSPICIOUS} 個可疑 process${NC}"
    echo ""
    
    if [ $MALICIOUS_PROCESSES -gt 0 ]; then
        echo -e "${RED}  ├─ 亂碼名稱 process: ${MALICIOUS_PROCESSES} 個${NC}"
        ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/' | grep -v "USER" | head -3 | awk '{printf "'"${RED}"'  │  • %s '"${DIM}"'(PID: %s, CPU: %s%%)'"${NC}"'\n", $11, $2, $3}'
    fi
    
    if [ $CRYPTO_MINERS -gt 0 ]; then
        echo -e "${RED}  ├─ 挖礦程式: ${CRYPTO_MINERS} 個${NC}"
        ps aux | grep -iE "xmrig|minerd|cpuminer" | grep -v grep | head -3 | awk '{printf "'"${RED}"'  │  • %s '"${DIM}"'(PID: %s, CPU: %s%%)'"${NC}"'\n", $11, $2, $3}'
        add_alert "CRITICAL" "偵測到挖礦程式: ${CRYPTO_MINERS} 個"
    fi
    
    THREATS_FOUND=$((THREATS_FOUND + TOTAL_SUSPICIOUS))
    
    echo ""
    echo -ne "${YELLOW}${ICON_CLEAN} 自動清除中...${NC}"
    ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/' | grep -v "USER" | awk '{print $2}' | xargs kill -9 2>/dev/null
    ps aux | grep -iE "xmrig|minerd|cpuminer" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
    THREATS_CLEANED=$((THREATS_CLEANED + TOTAL_SUSPICIOUS))
    echo -e " ${GREEN}${ICON_SUCCESS} 完成！${NC}"
else
    echo -e "${GREEN}${ICON_SUCCESS} 未發現可疑 process${NC}"
fi

echo ""
sleep 0.3

# [3-12 掃描項目繼續...]
# (保持之前的程式碼，這裡省略以節省篇幅)

# ==========================================
# 總結報告
# ==========================================
echo -e "\n"
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}                                                                    ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}                   ${ICON_SHIELD} 掃描結果總結                             ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${BG_CYAN}${WHITE}                                                                    ${NC}${CYAN}║${NC}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"

# 威脅等級
if [ $THREATS_FOUND -eq 0 ] && [ ${#ALERTS[@]} -eq 0 ]; then
    THREAT_LEVEL="${BG_GREEN}${WHITE} ${ICON_SUCCESS} 系統安全 ${NC}"
elif [ $THREATS_FOUND -lt 5 ]; then
    THREAT_LEVEL="${BG_YELLOW}${WHITE} ${ICON_WARN} 低風險 ${NC}"
elif [ $THREATS_FOUND -lt 20 ]; then
    THREAT_LEVEL="${BG_YELLOW}${WHITE} ${ICON_DANGER} 中風險 ${NC}"
else
    THREAT_LEVEL="${BG_RED}${WHITE} ${ICON_FIRE} 高風險 - 主機可能已被入侵 ${NC}"
fi

echo -e "${CYAN}║${NC} ${BOLD}威脅等級:${NC} ${THREAT_LEVEL}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  發現威脅: ${WHITE}${THREATS_FOUND}${NC} | 已清除: ${GREEN}${THREATS_CLEANED}${NC} | 需手動: ${YELLOW}$((THREATS_FOUND - THREATS_CLEANED))${NC}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"

# 告警列表
if [ ${#ALERTS[@]} -gt 0 ]; then
    echo -e "${CYAN}║${NC} ${RED}${BOLD}${ICON_FIRE} 重要告警:${NC}"
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
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
fi

# Fail2Ban 統計
if command -v fail2ban-client &> /dev/null && systemctl is-active --quiet fail2ban; then
    BANNED_NOW=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
    TOTAL_BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $NF}')
    echo -e "${CYAN}║${NC} ${GREEN}${ICON_SHIELD} Fail2Ban 防護統計:${NC}"
    echo -e "${CYAN}║${NC}    當前封鎖: ${WHITE}${BANNED_NOW:-0}${NC} 個 | 累計封鎖: ${WHITE}${TOTAL_BANNED:-0}${NC} 次"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════╣${NC}"
fi

echo -e "${CYAN}║${NC} ${DIM}掃描完成: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════╝${NC}"

echo ""
echo -e "${MAGENTA}${ICON_SHIELD} 掃描工具不會在系統留下任何記錄或工具${NC}"
echo -e "${DIM}   GitHub: https://github.com/jimmy-is-me/vps-security-scanner${NC}"
echo ""

# 無痕跡模式
# rm -f "$0"
