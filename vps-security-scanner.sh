#!/bin/bash

#################################################
# VPS 安全掃描與清除工具
# 適用於所有類型的 VPS (XCloud, FlyWP, cPanel, Plesk 等)
# GitHub: https://github.com/YOUR_USERNAME/vps-security-scanner
# License: MIT
#################################################

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 版本資訊
VERSION="1.0.0"

echo "========================================"
echo "  VPS 安全掃描與清除工具 v${VERSION}"
echo "  時間: $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"
echo ""

# 計數器
THREATS_FOUND=0
THREATS_CLEANED=0

# ==========================================
# 1. 掃描惡意 Process
# ==========================================
echo -e "${YELLOW}[1/10] 掃描惡意 Process...${NC}"
MALICIOUS_PROCESSES=$(ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis|lighttpd|postgres|memcache/' | grep -v "USER" | wc -l)

if [ $MALICIOUS_PROCESSES -gt 0 ]; then
    echo -e "${RED}✗ 發現 $MALICIOUS_PROCESSES 個可疑 process${NC}"
    ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis/' | grep -v "USER" | head -20
    THREATS_FOUND=$((THREATS_FOUND + MALICIOUS_PROCESSES))
    
    # 清除惡意 process
    echo "正在清除惡意 process..."
    ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis/' | grep -v "USER" | awk '{print $2}' | xargs kill -9 2>/dev/null
    THREATS_CLEANED=$((THREATS_CLEANED + MALICIOUS_PROCESSES))
    echo -e "${GREEN}✓ 已清除${NC}"
else
    echo -e "${GREEN}✓ 沒有發現可疑 process${NC}"
fi
echo ""

# ==========================================
# 2. 檢查對外可疑連線
# ==========================================
echo -e "${YELLOW}[2/10] 檢查對外連線...${NC}"
TOTAL_CONNECTIONS=$(ss -tnp state established 2>/dev/null | grep -E ":(80|443)" | wc -l)
SUSPICIOUS_CONNECTIONS=$(ss -tnp state established 2>/dev/null | grep -E ":(80|443)" | grep -v "litespeed\|lsphp\|nginx\|apache\|curl\|wget\|php-fpm" | wc -l)

echo "總對外連線數: $TOTAL_CONNECTIONS"
if [ $SUSPICIOUS_CONNECTIONS -gt 10 ]; then
    echo -e "${RED}✗ 發現 $SUSPICIOUS_CONNECTIONS 個可疑連線${NC}"
    ss -tnp state established 2>/dev/null | grep -E ":(80|443)" | grep -v "litespeed\|lsphp\|nginx\|apache\|curl\|wget\|php-fpm" | head -10
    THREATS_FOUND=$((THREATS_FOUND + 1))
else
    echo -e "${GREEN}✓ 連線狀況正常${NC}"
fi
echo ""

# ==========================================
# 3. 掃描 WordPress uploads 目錄的 PHP 木馬
# ==========================================
echo -e "${YELLOW}[3/10] 掃描 WordPress uploads 目錄...${NC}"
UPLOADS_PHP_COUNT=$(find /var/www /home -path "*/wp-content/uploads/*" -name "*.php" 2>/dev/null | wc -l)

if [ $UPLOADS_PHP_COUNT -gt 0 ]; then
    echo -e "${RED}✗ 發現 $UPLOADS_PHP_COUNT 個可疑 PHP 檔案${NC}"
    find /var/www /home -path "*/wp-content/uploads/*" -name "*.php" 2>/dev/null | head -10
    THREATS_FOUND=$((THREATS_FOUND + UPLOADS_PHP_COUNT))
    
    # 清除
    echo "正在刪除 uploads 目錄裡的 PHP 檔案..."
    find /var/www /home -path "*/wp-content/uploads/*" -name "*.php" -delete 2>/dev/null
    THREATS_CLEANED=$((THREATS_CLEANED + UPLOADS_PHP_COUNT))
    echo -e "${GREEN}✓ 已清除${NC}"
else
    echo -e "${GREEN}✓ 沒有發現可疑檔案${NC}"
fi
echo ""

# ==========================================
# 4. 掃描 XCloud/FlyWP migration 目錄
# ==========================================
echo -e "${YELLOW}[4/10] 掃描 XCloud/FlyWP migration 目錄...${NC}"
MIGRATION_MALWARE=$(find /home -path "*/.xcloud/migration-uploads/*" -o -path "*/.flywp/migration/*" -type f -executable 2>/dev/null | wc -l)

if [ $MIGRATION_MALWARE -gt 0 ]; then
    echo -e "${RED}✗ 發現 $MIGRATION_MALWARE 個可疑檔案${NC}"
    find /home -path "*/.xcloud/migration-uploads/*" -o -path "*/.flywp/migration/*" -type f -executable 2>/dev/null | head -10
    THREATS_FOUND=$((THREATS_FOUND + MIGRATION_MALWARE))
    
    # 清除
    echo "正在刪除 migration 目錄..."
    find /home -type d -path "*/.xcloud/migration-uploads" -exec rm -rf {} + 2>/dev/null
    find /home -type d -path "*/.flywp/migration" -exec rm -rf {} + 2>/dev/null
    THREATS_CLEANED=$((THREATS_CLEANED + MIGRATION_MALWARE))
    echo -e "${GREEN}✓ 已清除${NC}"
else
    echo -e "${GREEN}✓ 沒有發現可疑檔案${NC}"
fi
echo ""

# ==========================================
# 5. 掃描臨時目錄的惡意檔案
# ==========================================
echo -e "${YELLOW}[5/10] 掃描臨時目錄...${NC}"
TMP_MALWARE=$(find /tmp /dev/shm /var/tmp -type f -executable -mtime -7 2>/dev/null | wc -l)

if [ $TMP_MALWARE -gt 5 ]; then
    echo -e "${RED}✗ 發現 $TMP_MALWARE 個可疑可執行檔${NC}"
    find /tmp /dev/shm /var/tmp -type f -executable -mtime -7 -ls 2>/dev/null | head -10
    THREATS_FOUND=$((THREATS_FOUND + TMP_MALWARE))
    echo -e "${YELLOW}⚠ 請手動檢查後刪除${NC}"
else
    echo -e "${GREEN}✓ 臨時目錄正常${NC}"
fi
echo ""

# ==========================================
# 6. 掃描 cron 裡的可疑排程
# ==========================================
echo -e "${YELLOW}[6/10] 掃描 cron 排程...${NC}"
SUSPICIOUS_CRON=$(crontab -l 2>/dev/null | grep -v "^#" | grep -E "curl.*http|wget.*http|/tmp/|/dev/shm/|base64" | wc -l)

if [ $SUSPICIOUS_CRON -gt 0 ]; then
    echo -e "${RED}✗ Root crontab 發現 $SUSPICIOUS_CRON 個可疑項目${NC}"
    crontab -l 2>/dev/null | grep -v "^#" | grep -E "curl.*http|wget.*http|/tmp/|/dev/shm/|base64"
    THREATS_FOUND=$((THREATS_FOUND + SUSPICIOUS_CRON))
    echo -e "${YELLOW}⚠ 請手動檢查並刪除可疑的 cron 項目${NC}"
else
    echo -e "${GREEN}✓ Cron 排程正常${NC}"
fi
echo ""

# ==========================================
# 7. 掃描隱藏的惡意檔案
# ==========================================
echo -e "${YELLOW}[7/10] 掃描隱藏檔案...${NC}"
HIDDEN_MALWARE=$(find /home /tmp /var/tmp -type f -name ".*" -executable 2>/dev/null | grep -v ".bashrc\|.profile\|.ssh\|.cache" | wc -l)

if [ $HIDDEN_MALWARE -gt 0 ]; then
    echo -e "${RED}✗ 發現 $HIDDEN_MALWARE 個可疑隱藏檔案${NC}"
    find /home /tmp /var/tmp -type f -name ".*" -executable 2>/dev/null | grep -v ".bashrc\|.profile\|.ssh\|.cache" | head -10
    THREATS_FOUND=$((THREATS_FOUND + HIDDEN_MALWARE))
    echo -e "${YELLOW}⚠ 請手動檢查後刪除${NC}"
else
    echo -e "${GREEN}✓ 沒有發現可疑隱藏檔案${NC}"
fi
echo ""

# ==========================================
# 8. 掃描常見 webshell 特徵
# ==========================================
echo -e "${YELLOW}[8/10] 掃描 webshell 特徵碼...${NC}"
WEBSHELL_COUNT=$(find /var/www /home -name "*.php" -exec grep -l "eval(base64_decode\|gzinflate(base64_decode\|eval(gzuncompress\|@preg_replace.*\/e" {} \; 2>/dev/null | wc -l)

if [ $WEBSHELL_COUNT -gt 0 ]; then
    echo -e "${RED}✗ 發現 $WEBSHELL_COUNT 個可能的 webshell${NC}"
    find /var/www /home -name "*.php" -exec grep -l "eval(base64_decode\|gzinflate(base64_decode" {} \; 2>/dev/null | head -10
    THREATS_FOUND=$((THREATS_FOUND + WEBSHELL_COUNT))
    echo -e "${YELLOW}⚠ 請手動檢查後刪除（或用 Wordfence 掃描）${NC}"
else
    echo -e "${GREEN}✓ 沒有發現明顯的 webshell${NC}"
fi
echo ""

# ==========================================
# 9. 檢查 SSH 登入記錄
# ==========================================
echo -e "${YELLOW}[9/10] 檢查最近登入記錄...${NC}"
echo "最近 5 次登入:"
last -5 | head -5
echo ""

# ==========================================
# 10. 系統資源檢查
# ==========================================
echo -e "${YELLOW}[10/10] 系統資源檢查...${NC}"
echo "CPU 使用率前 5 名:"
ps -eo pid,user,%cpu,%mem,cmd --sort=-%cpu | head -6
echo ""

# ==========================================
# 總結報告
# ==========================================
echo "========================================"
echo "  掃描結果總結"
echo "========================================"
echo -e "發現威脅: ${RED}$THREATS_FOUND${NC}"
echo -e "已清除威脅: ${GREEN}$THREATS_CLEANED${NC}"
echo -e "需手動處理: ${YELLOW}$((THREATS_FOUND - THREATS_CLEANED))${NC}"
echo ""

if [ $THREATS_FOUND -eq 0 ]; then
    echo -e "${GREEN}✓ 恭喜！系統目前安全${NC}"
elif [ $THREATS_CLEANED -eq $THREATS_FOUND ]; then
    echo -e "${GREEN}✓ 所有威脅已自動清除！${NC}"
    echo "建議重啟受影響的服務以確保生效"
else
    echo -e "${YELLOW}⚠ 還有一些項目需要手動處理${NC}"
    echo "請檢查上面標記為「請手動檢查」的項目"
fi

echo ""
echo "建議後續動作:"
echo "1. 在所有 WordPress 網站安裝 Wordfence 並執行完整掃描"
echo "2. 更新所有 WordPress 核心、外掛、佈景主題"
echo "3. 更換所有密碼（WP admin、資料庫、SSH、FTP）"
echo "4. 安裝 Fail2Ban 保護 SSH"
echo "5. 停用 WordPress XML-RPC（如果不需要）"
echo "========================================"
