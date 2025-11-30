#!/bin/bash

#################################################
# VPS 安全掃描工具 v4.0 - 無痕跡高效能版
# GitHub: https://github.com/jimmy-is-me/vps-security-scanner
# 特色：不殘留工具、不留記錄、即時監控、完整告警
#################################################

# 顏色與圖示
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BG_RED='\033[41m'
NC='\033[0m'

ICON_SHIELD="🛡️"
ICON_SCAN="🔍"
ICON_SUCCESS="✅"
ICON_DANGER="🚨"
ICON_WARN="⚠️"
ICON_USER="👤"
ICON_FIRE="🔥"
ICON_CLOCK="⏰"

VERSION="4.0.0"

# 效能優化
renice -n 19 $$ > /dev/null 2>&1
ionice -c3 -p $$ > /dev/null 2>&1

# 清除螢幕
clear

# ==========================================
# 標題
# ==========================================
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${WHITE} ${ICON_SHIELD} VPS 安全掃描工具 v${VERSION} - 無痕跡版               ${CYAN}║${NC}"
echo -e "${CYAN}║${CYAN} 掃描時間: $(date '+%Y-%m-%d %H:%M:%S')                        ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 計數器
THREATS_FOUND=0
THREATS_CLEANED=0
ALERTS=()

# ==========================================
# 函數：新增告警
# ==========================================
add_alert() {
    local level=$1  # CRITICAL, HIGH, MEDIUM, LOW
    local message=$2
    ALERTS+=("[$level] $message")
}

# ==========================================
# 0. 即時登入狀態監控（新增）
# ==========================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[系統狀態] ${ICON_USER} 登入監控${NC}"
echo ""

# 當前登入用戶
CURRENT_USERS=$(who | wc -l)
echo -e "${CYAN}${ICON_USER} 目前登入用戶數: ${WHITE}${CURRENT_USERS}${NC}"

if [ $CURRENT_USERS -gt 0 ]; then
    echo -e "${CYAN}┌─ 當前登入列表 ─────────────────────────────────────┐${NC}"
    who | while read line; do
        USER=$(echo $line | awk '{print $1}')
        TTY=$(echo $line | awk '{print $2}')
        LOGIN_TIME=$(echo $line | awk '{print $3, $4}')
        IP=$(echo $line | awk '{print $5}' | tr -d '()')
        
        # 檢查是否為可疑 IP
        if [[ ! $IP =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.) ]] && [ ! -z "$IP" ]; then
            echo -e "${RED}│ ${ICON_WARN} ${USER} @ ${TTY} | ${IP} | ${LOGIN_TIME}${NC}"
            add_alert "HIGH" "外部 IP 登入: ${USER} 從 ${IP}"
        else
            echo -e "${GREEN}│ ${ICON_SUCCESS} ${USER} @ ${TTY} | ${IP:-本機} | ${LOGIN_TIME}${NC}"
        fi
    done
    echo -e "${CYAN}└────────────────────────────────────────────────────┘${NC}"
fi

# 最近 5 次登入（成功）
echo ""
echo -e "${CYAN}${ICON_CLOCK} 最近 5 次成功登入:${NC}"
last -5 -F | head -5 | awk '{if(NR>0) printf "  %s\n", $0}'

# 失敗登入嘗試
echo ""
FAILED_COUNT=$(lastb 2>/dev/null | wc -l)
if [ $FAILED_COUNT -gt 0 ]; then
    echo -e "${YELLOW}${ICON_WARN} 失敗登入嘗試: ${FAILED_COUNT} 次${NC}"
    
    if [ $FAILED_COUNT -gt 100 ]; then
        echo -e "${RED}${ICON_DANGER} 偵測到大量暴力破解嘗試！${NC}"
        add_alert "CRITICAL" "SSH 暴力破解攻擊: ${FAILED_COUNT} 次失敗登入"
        
        # 顯示前 5 名攻擊 IP
        echo -e "${RED}前 5 名攻擊來源:${NC}"
        lastb 2>/dev/null | awk '{print $3}' | grep -v "^$" | sort | uniq -c | sort -rn | head -5 | while read line; do
            echo -e "${RED}  └─ ${line}${NC}"
        done
    fi
else
    echo -e "${GREEN}${ICON_SUCCESS} 無失敗登入記錄${NC}"
fi

sleep 0.5

# ==========================================
# 1. 惡意 Process 掃描（強化版）
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[1/12] ${ICON_SCAN} 惡意 Process 掃描${NC}"

# 掃描亂碼名稱 process
MALICIOUS_PROCESSES=$(ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis|lighttpd|postgres|memcache/' | grep -v "USER" | wc -l)

# 掃描挖礦程式
CRYPTO_MINERS=$(ps aux | grep -iE "xmrig|minerd|cpuminer|ccminer|cryptonight|monero|kinsing" | grep -v grep | wc -l)

TOTAL_SUSPICIOUS=$((MALICIOUS_PROCESSES + CRYPTO_MINERS))

if [ $TOTAL_SUSPICIOUS -gt 0 ]; then
    echo -e "${RED}${ICON_DANGER} 發現 ${TOTAL_SUSPICIOUS} 個可疑 process${NC}"
    
    if [ $MALICIOUS_PROCESSES -gt 0 ]; then
        echo -e "${RED}  └─ 亂碼名稱: ${MALICIOUS_PROCESSES} 個${NC}"
        ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/' | grep -v "USER" | head -3 | awk '{printf "     %s (PID: %s, CPU: %s%%)\n", $11, $2, $3}'
    fi
    
    if [ $CRYPTO_MINERS -gt 0 ]; then
        echo -e "${RED}  └─ 挖礦程式: ${CRYPTO_MINERS} 個${NC}"
        ps aux | grep -iE "xmrig|minerd|cpuminer" | grep -v grep | head -3 | awk '{printf "     %s (PID: %s, CPU: %s%%)\n", $11, $2, $3}'
        add_alert "CRITICAL" "偵測到挖礦程式: ${CRYPTO_MINERS} 個"
    fi
    
    THREATS_FOUND=$((THREATS_FOUND + TOTAL_SUSPICIOUS))
    
    # 自動清除
    echo -ne "${YELLOW}${ICON_FIRE} 正在清除...${NC}"
    ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/' | grep -v "USER" | awk '{print $2}' | xargs kill -9 2>/dev/null
    ps aux | grep -iE "xmrig|minerd|cpuminer" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
    THREATS_CLEANED=$((THREATS_CLEANED + TOTAL_SUSPICIOUS))
    echo -e " ${GREEN}完成！${NC}"
else
    echo -e "${GREEN}${ICON_SUCCESS} 正常${NC}"
fi

# ==========================================
# 2. 對外連線監控（強化版）
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[2/12] ${ICON_SCAN} 網路連線分析${NC}"

TOTAL_CONN=$(ss -tnp state established 2>/dev/null | wc -l)
SUSPICIOUS_CONN=$(ss -tnp state established 2>/dev/null | grep -E ":(80|443|8080|3306|6379)" | grep -v "litespeed\|lsphp\|nginx\|apache\|mysql\|redis" | wc -l)

echo -e "${CYAN}總連線數: ${WHITE}${TOTAL_CONN}${NC} | ${YELLOW}可疑連線: ${WHITE}${SUSPICIOUS_CONN}${NC}"

if [ $SUSPICIOUS_CONN -gt 15 ]; then
    echo -e "${RED}${ICON_DANGER} 可疑連線過多！${NC}"
    add_alert "HIGH" "偵測到 ${SUSPICIOUS_CONN} 個可疑對外連線"
    
    # 顯示前 5 個可疑連線
    ss -tnp state established 2>/dev/null | grep -E ":(80|443)" | head -5 | while read line; do
        echo -e "${RED}  └─ ${line}${NC}"
    done
    THREATS_FOUND=$((THREATS_FOUND + 1))
else
    echo -e "${GREEN}${ICON_SUCCESS} 連線狀況正常${NC}"
fi

# ==========================================
# 3. WordPress Uploads 掃描
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[3/12] ${ICON_SCAN} WordPress Uploads 木馬掃描${NC}"

UPLOADS_PHP=$(find /var/www /home -path "*/wp-content/uploads/*" -name "*.php" 2>/dev/null | wc -l)

if [ $UPLOADS_PHP -gt 0 ]; then
    echo -e "${RED}${ICON_DANGER} 發現 ${UPLOADS_PHP} 個可疑 PHP 檔案${NC}"
    find /var/www /home -path "*/wp-content/uploads/*" -name "*.php" 2>/dev/null | head -3 | while read file; do
        echo -e "${RED}  └─ ${file}${NC}"
    done
    
    add_alert "CRITICAL" "WordPress uploads 目錄發現 ${UPLOADS_PHP} 個 PHP 木馬"
    THREATS_FOUND=$((THREATS_FOUND + UPLOADS_PHP))
    
    echo -ne "${YELLOW}${ICON_FIRE} 正在清除...${NC}"
    find /var/www /home -path "*/wp-content/uploads/*" -name "*.php" -delete 2>/dev/null
    THREATS_CLEANED=$((THREATS_CLEANED + UPLOADS_PHP))
    echo -e " ${GREEN}完成！${NC}"
else
    echo -e "${GREEN}${ICON_SUCCESS} 正常${NC}"
fi

# ==========================================
# 4. Migration 目錄掃描
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[4/12] ${ICON_SCAN} Migration 暫存目錄掃描${NC}"

MIGRATION_FILES=$(find /home -path "*/.xcloud/migration-uploads/*" -o -path "*/.flywp/migration/*" -type f 2>/dev/null | wc -l)

if [ $MIGRATION_FILES -gt 0 ]; then
    echo -e "${RED}${ICON_DANGER} 發現 ${MIGRATION_FILES} 個殘留檔案${NC}"
    THREATS_FOUND=$((THREATS_FOUND + MIGRATION_FILES))
    
    echo -ne "${YELLOW}${ICON_FIRE} 正在清除...${NC}"
    find /home -type d -path "*/.xcloud/migration-uploads" -exec rm -rf {} + 2>/dev/null
    find /home -type d -path "*/.flywp/migration" -exec rm -rf {} + 2>/dev/null
    THREATS_CLEANED=$((THREATS_CLEANED + MIGRATION_FILES))
    echo -e " ${GREEN}完成！${NC}"
else
    echo -e "${GREEN}${ICON_SUCCESS} 正常${NC}"
fi

# ==========================================
# 5. Cron 惡意排程掃描
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[5/12] ${ICON_SCAN} Cron 排程安全檢查${NC}"

SUSPICIOUS_CRON=0

# 檢查 root crontab
ROOT_CRON=$(crontab -l 2>/dev/null | grep -v "^#" | grep -E "curl.*http|wget.*http|/tmp/|/dev/shm/|base64|eval" | wc -l)
if [ $ROOT_CRON -gt 0 ]; then
    echo -e "${RED}${ICON_DANGER} Root crontab: ${ROOT_CRON} 個可疑項目${NC}"
    crontab -l 2>/dev/null | grep -v "^#" | grep -E "curl.*http|wget.*http" | head -2 | while read line; do
        echo -e "${RED}  └─ ${line}${NC}"
    done
    SUSPICIOUS_CRON=$((SUSPICIOUS_CRON + ROOT_CRON))
    add_alert "CRITICAL" "Root crontab 發現惡意排程"
fi

# 檢查所有用戶 crontab
for user in $(cut -f1 -d: /etc/passwd); do
    USER_CRON=$(crontab -l -u $user 2>/dev/null | grep -v "^#" | grep -E "curl.*http|wget.*http|/tmp/" | wc -l)
    if [ $USER_CRON -gt 0 ]; then
        echo -e "${RED}${ICON_DANGER} 用戶 ${user}: ${USER_CRON} 個可疑項目${NC}"
        SUSPICIOUS_CRON=$((SUSPICIOUS_CRON + USER_CRON))
    fi
done

if [ $SUSPICIOUS_CRON -gt 0 ]; then
    THREATS_FOUND=$((THREATS_FOUND + SUSPICIOUS_CRON))
    echo -e "${YELLOW}${ICON_WARN} 請手動檢查並刪除惡意 cron${NC}"
else
    echo -e "${GREEN}${ICON_SUCCESS} 正常${NC}"
fi

# ==========================================
# 6. Webshell 特徵碼掃描（快速版）
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[6/12] ${ICON_SCAN} Webshell 快速掃描（最近 7 天）${NC}"

echo -ne "${CYAN}掃描中...${NC}"

WEBSHELLS=$(timeout 45 nice -n 19 find /var/www /home \
    -path "*/node_modules" -prune -o \
    -path "*/vendor" -prune -o \
    -path "*/.git" -prune -o \
    -name "*.php" -type f -mtime -7 \
    -exec grep -l "eval(base64\|gzinflate(base64\|eval(gzuncompress\|assert.*base64\|preg_replace.*\/e\|system(\$_\|passthru(\$_" {} + 2>/dev/null | wc -l)

echo -e "\r${CYAN}掃描完成          ${NC}"

if [ $? -eq 124 ]; then
    echo -e "${YELLOW}${ICON_WARN} 掃描超時（檔案過多）${NC}"
elif [ $WEBSHELLS -gt 0 ]; then
    echo -e "${RED}${ICON_DANGER} 發現 ${WEBSHELLS} 個可能的 webshell${NC}"
    add_alert "CRITICAL" "偵測到 ${WEBSHELLS} 個 webshell"
    THREATS_FOUND=$((THREATS_FOUND + WEBSHELLS))
    
    timeout 15 find /var/www /home -name "*.php" -mtime -7 \
        -exec grep -l "eval(base64" {} + 2>/dev/null | head -3 | while read file; do
        echo -e "${RED}  └─ ${file}${NC}"
    done
    
    echo -e "${YELLOW}${ICON_WARN} 請手動確認後刪除${NC}"
else
    echo -e "${GREEN}${ICON_SUCCESS} 正常${NC}"
fi

# ==========================================
# 7. WordPress 核心完整性
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[7/12] ${ICON_SCAN} WordPress 核心驗證${NC}"

WP_SITES=$(find /var/www /home -name "wp-config.php" -type f 2>/dev/null | wc -l)

if [ $WP_SITES -gt 0 ]; then
    echo -e "${CYAN}發現 ${WP_SITES} 個 WordPress 網站${NC}"
    
    if command -v wp &> /dev/null; then
        CORRUPTED=0
        find /var/www /home -name "wp-config.php" -type f 2>/dev/null | head -5 | while read config; do
            WP_DIR=$(dirname "$config")
            SITE_NAME=$(basename "$WP_DIR")
            cd "$WP_DIR"
            
            if ! wp core verify-checksums --allow-root 2>&1 | grep -q "Success"; then
                echo -e "${RED}  ✗ ${SITE_NAME}${NC}"
                ((CORRUPTED++))
            fi
        done
        
        if [ $CORRUPTED -gt 0 ]; then
            add_alert "HIGH" "${CORRUPTED} 個 WordPress 網站核心檔案異常"
        fi
    else
        echo -e "${CYAN}  未安裝 WP-CLI，跳過檢查${NC}"
    fi
else
    echo -e "${CYAN}  無 WordPress 網站${NC}"
fi

# ==========================================
# 8. 系統資源異常檢查
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[8/12] ${ICON_SCAN} 系統資源異常檢查${NC}"

# CPU 使用率
HIGH_CPU=$(ps -eo pid,user,%cpu,cmd --sort=-%cpu | awk 'NR>1 && $3>50 {print $0}' | wc -l)
if [ $HIGH_CPU -gt 0 ]; then
    echo -e "${RED}${ICON_DANGER} ${HIGH_CPU} 個程式 CPU 使用率 > 50%${NC}"
    ps -eo pid,user,%cpu,cmd --sort=-%cpu | awk 'NR>1 && $3>50' | head -3 | while read line; do
        echo -e "${RED}  └─ ${line}${NC}"
    done
    add_alert "MEDIUM" "偵測到異常高 CPU 使用率"
fi

# 記憶體使用率
MEM_USAGE=$(free | awk '/Mem:/ {printf "%.0f", $3/$2 * 100}')
if [ $MEM_USAGE -gt 90 ]; then
    echo -e "${RED}${ICON_DANGER} 記憶體使用率: ${MEM_USAGE}%${NC}"
    add_alert "MEDIUM" "記憶體使用率過高: ${MEM_USAGE}%"
else
    echo -e "${GREEN}${ICON_SUCCESS} 系統資源正常 (CPU/記憶體)${NC}"
fi

# ==========================================
# 9. 隱藏檔案掃描
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[9/12] ${ICON_SCAN} 隱藏惡意檔案掃描${NC}"

HIDDEN_EXEC=$(find /tmp /var/tmp /dev/shm /home -type f -name ".*" -executable 2>/dev/null | grep -v ".bashrc\|.profile\|.ssh\|.cache" | wc -l)

if [ $HIDDEN_EXEC -gt 0 ]; then
    echo -e "${RED}${ICON_DANGER} 發現 ${HIDDEN_EXEC} 個可疑隱藏檔案${NC}"
    find /tmp /var/tmp /dev/shm -type f -name ".*" -executable 2>/dev/null | head -3 | while read file; do
        echo -e "${RED}  └─ ${file}${NC}"
    done
    add_alert "HIGH" "發現 ${HIDDEN_EXEC} 個可疑隱藏執行檔"
    THREATS_FOUND=$((THREATS_FOUND + HIDDEN_EXEC))
else
    echo -e "${GREEN}${ICON_SUCCESS} 正常${NC}"
fi

# ==========================================
# 10. SSH 安全設定檢查
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[10/12] ${ICON_SCAN} SSH 安全設定檢查${NC}"

# 檢查 root 登入
if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
    echo -e "${YELLOW}${ICON_WARN} Root 可直接登入（建議停用）${NC}"
    add_alert "MEDIUM" "SSH 允許 Root 直接登入"
fi

# 檢查密碼登入
if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
    echo -e "${YELLOW}${ICON_WARN} 允許密碼登入（建議改用金鑰）${NC}"
fi

# 檢查 Fail2Ban
if ! command -v fail2ban-client &> /dev/null; then
    echo -e "${YELLOW}${ICON_WARN} 未安裝 Fail2Ban${NC}"
    add_alert "LOW" "未安裝 Fail2Ban 防護"
else
    echo -e "${GREEN}${ICON_SUCCESS} 已安裝 Fail2Ban${NC}"
fi

# ==========================================
# 11. 最近修改的系統檔案
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[11/12] ${ICON_SCAN} 系統檔案變動檢查（最近 24 小時）${NC}"

SYSTEM_CHANGES=$(find /etc /usr/bin /usr/sbin -type f -mtime -1 2>/dev/null | wc -l)

if [ $SYSTEM_CHANGES -gt 0 ]; then
    echo -e "${YELLOW}${ICON_WARN} ${SYSTEM_CHANGES} 個系統檔案被修改${NC}"
    find /etc -type f -mtime -1 2>/dev/null | head -3 | while read file; do
        echo -e "${YELLOW}  └─ ${file}${NC}"
    done
    add_alert "MEDIUM" "最近 24 小時有 ${SYSTEM_CHANGES} 個系統檔案被修改"
else
    echo -e "${GREEN}${ICON_SUCCESS} 正常${NC}"
fi

# ==========================================
# 12. 開放埠號檢查
# ==========================================
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}[12/12] ${ICON_SCAN} 開放埠號安全檢查${NC}"

LISTENING_PORTS=$(ss -tlnp | grep LISTEN | wc -l)
echo -e "${CYAN}監聽中的埠號: ${WHITE}${LISTENING_PORTS}${NC}"

# 檢查危險埠號
DANGEROUS_PORTS=$(ss -tlnp | grep -E ":3389|:5900|:23|:21[^0-9]" | wc -l)
if [ $DANGEROUS_PORTS -gt 0 ]; then
    echo -e "${RED}${ICON_DANGER} 偵測到危險埠號開放${NC}"
    ss -tlnp | grep -E ":3389|:5900|:23|:21[^0-9]" | while read line; do
        echo -e "${RED}  └─ ${line}${NC}"
    done
    add_alert "HIGH" "偵測到不安全的埠號開放 (RDP/VNC/Telnet/FTP)"
else
    echo -e "${GREEN}${ICON_SUCCESS} 正常${NC}"
fi

# ==========================================
# 告警總結（如果中毒顯示詳細資訊）
# ==========================================
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                ${ICON_SHIELD} 掃描結果總結                        ║${NC}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"

# 威脅等級
if [ $THREATS_FOUND -eq 0 ] && [ ${#ALERTS[@]} -eq 0 ]; then
    echo -e "${CYAN}║${NC} 威脅等級: ${GREEN}${ICON_SUCCESS} 安全${NC}                                    ${CYAN}║${NC}"
elif [ $THREATS_FOUND -lt 5 ]; then
    echo -e "${CYAN}║${NC} 威脅等級: ${YELLOW}${ICON_WARN} 低風險${NC}                                  ${CYAN}║${NC}"
elif [ $THREATS_FOUND -lt 20 ]; then
    echo -e "${CYAN}║${NC} 威脅等級: ${YELLOW}${ICON_DANGER} 中風險${NC}                                 ${CYAN}║${NC}"
else
    echo -e "${CYAN}║${NC} 威脅等級: ${BG_RED}${WHITE} ${ICON_FIRE} 高風險 - 主機可能已被入侵 ${NC}            ${CYAN}║${NC}"
fi

echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC} ${RED}發現威脅: ${THREATS_FOUND}${NC}   ${GREEN}已清除: ${THREATS_CLEANED}${NC}   ${YELLOW}需手動: $((THREATS_FOUND - THREATS_CLEANED))${NC}     ${CYAN}║${NC}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"

# 如果有告警，顯示詳細資訊
if [ ${#ALERTS[@]} -gt 0 ]; then
    echo -e "${CYAN}║${NC} ${RED}${ICON_FIRE} 重要告警:${NC}                                             ${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    
    for alert in "${ALERTS[@]}"; do
        if [[ $alert == *"CRITICAL"* ]]; then
            echo -e "${CYAN}║${NC} ${BG_RED}${WHITE} CRITICAL ${NC} ${alert#*] }${NC}"
        elif [[ $alert == *"HIGH"* ]]; then
            echo -e "${CYAN}║${NC} ${RED}HIGH${NC}     ${alert#*] }${NC}"
        elif [[ $alert == *"MEDIUM"* ]]; then
            echo -e "${CYAN}║${NC} ${YELLOW}MEDIUM${NC}   ${alert#*] }${NC}"
        fi
    done
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
fi

echo -e "${CYAN}║${NC} ${CYAN}${ICON_CLOCK} 掃描完成: $(date '+%Y-%m-%d %H:%M:%S')${NC}                  ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"

# ==========================================
# 中毒緊急處置建議
# ==========================================
if [ $THREATS_FOUND -gt 10 ] || [ ${#ALERTS[@]} -gt 3 ]; then
    echo ""
    echo -e "${BG_RED}${WHITE}                                                                  ${NC}"
    echo -e "${BG_RED}${WHITE}  ⚠️  警告：主機疑似已被入侵，建議立即執行以下動作：  ${NC}"
    echo -e "${BG_RED}${WHITE}                                                                  ${NC}"
    echo ""
    echo -e "${RED}【立即處置】${NC}"
    echo -e "  1. ${YELLOW}斷開所有可疑連線${NC}"
    echo -e "     killall -u <可疑用戶名>"
    echo -e "  2. ${YELLOW}更換所有密碼${NC}"
    echo -e "     passwd root"
    echo -e "     passwd <其他用戶>"
    echo -e "  3. ${YELLOW}停用可疑用戶${NC}"
    echo -e "     usermod -L <用戶名>"
    echo -e "  4. ${YELLOW}檢查並清除惡意 cron${NC}"
    echo -e "     crontab -e"
    echo -e "  5. ${YELLOW}重啟所有 Web 服務${NC}"
    echo -e "     systemctl restart apache2/nginx/litespeed"
    echo ""
    echo -e "${RED}【後續強化】${NC}"
    echo -e "  1. 安裝 Fail2Ban: apt install fail2ban -y"
    echo -e "  2. 停用 Root SSH: PermitRootLogin no"
    echo -e "  3. 改用金鑰登入: PasswordAuthentication no"
    echo -e "  4. 更新所有軟體: apt update && apt upgrade -y"
    echo -e "  5. 安裝 Wordfence (WordPress)"
    echo ""
else
    echo ""
    echo -e "${CYAN}【建議後續動作】${NC}"
    echo "  1. 定期執行此掃描（建議每日）"
    echo "  2. 安裝 Fail2Ban 防止暴力破解"
    echo "  3. 定期更新 WordPress 與外掛"
    echo "  4. 啟用 WordPress 自動更新"
    echo "  5. 使用強密碼 (20+ 字元)"
    echo ""
fi

echo -e "${MAGENTA}掃描工具不會在系統留下任何記錄或工具${NC}"
echo ""

# ==========================================
# 自動清除腳本本身（無痕跡模式）
# ==========================================
# 如果要完全無痕跡，取消下面的註解
# rm -f "$0"
