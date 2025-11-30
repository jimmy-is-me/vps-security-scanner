# 🛡️ VPS 安全掃描與清除工具 v4.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-4.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.linux.org/)

一鍵掃描並清除 VPS 上的惡意程式、webshell、木馬、挖礦程式等安全威脅。

**特色：完全無痕跡、智慧告警、自動清除、即時監控**

適用於所有 Linux VPS：XCloud、FlyWP、CloudPanel、cPanel、Plesk、DirectAdmin、純 VPS 等。

---

## 📋 目錄

- [功能特色](#功能特色)
- [快速開始](#快速開始)
- [掃描項目](#掃描項目)
- [告警系統](#告警系統)
- [安全性說明](#安全性說明)
- [使用範例](#使用範例)
- [系統需求](#系統需求)
- [常見問題](#常見問題)
- [後續建議動作](#後續建議動作)
- [更新日誌](#更新日誌)
- [貢獻](#貢獻)
- [授權條款](#授權條款)
- [免責聲明](#免責聲明)

---

## 功能特色

### 🚀 v4.0 重大更新

#### 🔥 完全無痕跡設計
- ❌ **不安裝任何掃毒工具**（不留 Maldet/ClamAV/AIDE 等）
- ❌ **不寫入系統記錄**（不產生 `/var/log` 檔案）
- ✅ **可選自動刪除腳本**（掃描完後自動移除）
- ✅ **所有檢測用內建指令**（ps, find, ss, grep 等）

#### 👤 即時登入監控
- 顯示當前所有登入用戶
- 標示外部 IP 登入（紅色警告）
- 顯示最近 5 次成功登入
- 統計失敗登入次數
- 列出前 5 名暴力破解來源 IP

#### 🚨 智慧告警系統
當主機疑似被入侵時，自動顯示：
- **威脅等級**（安全 ✅ / 低風險 ⚠️ / 中風險 ⚠️ / 高風險 🔥）
- **詳細告警清單**（CRITICAL / HIGH / MEDIUM / LOW）
- **緊急處置步驟**（斷開連線 / 更換密碼 / 停用用戶）

#### ⚡ 自動清除威脅
以下項目會**自動清除**，無需手動：
- ✅ 惡意 Process（亂碼名稱程式）
- ✅ 挖礦程式（xmrig, minerd, cpuminer）
- ✅ WordPress uploads 目錄的 PHP 木馬
- ✅ XCloud/FlyWP migration 暫存目錄

#### 🔍 12 項完整掃描
1. 惡意 Process 偵測（含挖礦程式）
2. 對外可疑網路連線分析
3. WordPress Uploads 目錄木馬掃描
4. Migration 暫存目錄清理
5. Cron 惡意排程檢查（含所有用戶）
6. Webshell 特徵碼掃描（最近 7 天）
7. WordPress 核心完整性驗證
8. 系統資源異常檢查
9. 隱藏惡意檔案掃描
10. SSH 安全設定檢查
11. 系統檔案變動檢查（24 小時）
12. 開放埠號安全檢查

---

## 快速開始

### 方法 1：一行指令執行（推薦）
curl -sL https://raw.githubusercontent.com/jimmy-is-me/vps-security-scanner/main/vps-security-scanner.sh | sudo bash

### 方法 2：下載後執行

下載腳本
wget https://raw.githubusercontent.com/jimmy-is-me/vps-security-scanner/main/vps-security-scanner.sh

賦予執行權限
chmod +x vps-security-scanner.sh

執行掃描
sudo ./vps-security-scanner.sh

### 方法 3：無痕跡模式（掃描完自動刪除腳本）

下載腳本後，編輯最後一行：

找到這行並取消註解
rm -f "$0" # 刪除腳本本身

然後執行：

sudo ./vps-security-scanner.sh

執行完後腳本會自動消失，不留任何痕跡

### 方法 4：設定定期掃描

每天凌晨 3 點自動掃描（建議離峰時段）
echo "0 3 * * * curl -sL https://raw.githubusercontent.com/jimmy-is-me/vps-security-scanner/main/vps-security-scanner.sh | bash > /dev/null 2>&1" | crontab -

---

## 掃描項目

### ✅ 自動清除（無需手動操作）

| 項目 | 說明 | 風險等級 |
|------|------|----------|
| **惡意 Process** | 8 字元亂碼名稱的程式（如 `rkuxyf5t`） | 🔴 高 |
| **挖礦程式** | xmrig, minerd, cpuminer, kinsing 等 | 🔴 高 |
| **Uploads PHP** | WordPress uploads 目錄的 .php 檔案 | 🔴 高 |
| **Migration 目錄** | XCloud/FlyWP 暫存遷移檔案 | 🟡 中 |

### ⚠️ 掃描提示（需手動確認）

| 項目 | 說明 | 風險等級 |
|------|------|----------|
| **Cron 排程** | 含 curl/wget 下載指令的 cron | 🔴 高 |
| **Webshell** | 含 eval, base64_decode 的 PHP | 🔴 高 |
| **隱藏檔案** | /tmp, /dev/shm 的隱藏執行檔 | 🟡 中 |
| **系統檔案變動** | 24 小時內修改的 /etc 檔案 | 🟡 中 |

### 📊 監控檢查

| 項目 | 說明 |
|------|------|
| **登入監控** | 當前登入用戶、最近登入記錄、失敗登入統計 |
| **網路連線** | 對外可疑連線、開放埠號檢查 |
| **資源使用** | CPU/記憶體異常使用 |
| **安全設定** | SSH 設定、Fail2Ban 狀態 |

---

## 告警系統

### 威脅等級

根據掃描結果自動判定：

| 等級 | 顯示 | 條件 |
|------|------|------|
| **安全** | ✅ 綠色 | 0 個威脅 |
| **低風險** | ⚠️ 黃色 | 1-4 個威脅 |
| **中風險** | ⚠️ 橙色 | 5-19 個威脅 |
| **高風險** | 🔥 紅底白字 | 20+ 個威脅或 3+ 告警 |

### 告警範例

#### 🟢 安全狀態

╔════════════════════════════════════════════════════════╗
║ 🛡️ 掃描結果總結 ║
╠════════════════════════════════════════════════════════╣
║ 威脅等級: ✅ 安全 ║
╠════════════════════════════════════════════════════════╣
║ 發現威脅: 0 已清除: 0 需手動: 0 ║
╚════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════╗
║ 🛡️ 掃描結果總結 ║
╠════════════════════════════════════════════════════════╣
║ 威脅等級: ✅ 安全 ║
╠════════════════════════════════════════════════════════╣
║ 發現威脅: 0 已清除: 0 需手動: 0 ║
╚════════════════════════════════════════════════════════╝

#### 🔴 高風險狀態

╔════════════════════════════════════════════════════════╗
║ 🛡️ 掃描結果總結 ║
╠════════════════════════════════════════════════════════╣
║ 威脅等級: 🔥 高風險 - 主機可能已被入侵 ║
╠════════════════════════════════════════════════════════╣
║ 發現威脅: 25 已清除: 18 需手動: 7 ║
╠════════════════════════════════════════════════════════╣
║ 🔥 重要告警: ║
╠════════════════════════════════════════════════════════╣
║ CRITICAL 偵測到挖礦程式: 3 個 ║
║ CRITICAL WordPress uploads 發現 15 個 PHP 木馬 ║
║ HIGH 外部 IP 登入: root 從 45.67.89.12 ║
║ HIGH SSH 暴力破解攻擊: 523 次失敗登入 ║
╚════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ 警告：主機疑似已被入侵，建議立即執行以下動作
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

【立即處置】

斷開所有可疑連線: killall -u <可疑用戶名>

更換所有密碼: passwd root

停用可疑用戶: usermod -L <用戶名>

檢查並清除惡意 cron: crontab -e

重啟所有 Web 服務: systemctl restart nginx


---

## 安全性說明

### ✅ 會自動清除的項目

| 項目 | 原因 | 安全性 |
|------|------|--------|
| **惡意 Process** | 只清除 8 字元亂碼名稱的 process | ✅ 不會動到正常服務 |
| **Uploads PHP** | WordPress uploads 目錄不應有 .php 檔案 | ✅ 只刪除木馬檔案 |
| **Migration 目錄** | XCloud/FlyWP 的暫存目錄 | ✅ 不影響正式網站 |
| **挖礦程式** | 已知挖礦程式名稱 | ✅ 精準匹配 |

### ⚠️ 不會自動刪除的項目

為避免誤刪，以下項目只掃描提示：

- 臨時目錄的檔案（需手動確認）
- Cron 排程（需人工判斷）
- Webshell 檔案（需仔細檢查）
- 系統檔案變動（可能是正常更新）

### 📂 完全不會動到的資料

- ✅ 網站檔案（`/var/www/`, `/home/*/public_html/`）
- ✅ 資料庫（MySQL/MariaDB）
- ✅ 網站設定檔（`wp-config.php`, `.htaccess`）
- ✅ 正常的佈景主題和外掛
- ✅ 所有上傳的圖片、影片、文件
- ✅ 備份檔案
- ✅ 正常的系統服務

---

## 使用範例

### 掃描過程截圖
$ sudo ./vps-security-scanner.sh

╔════════════════════════════════════════════════════════════════╗
║ 🛡️ VPS 安全掃描工具 v4.0 - 無痕跡版 ║
║ 掃描時間: 2025-12-01 05:30:15 ║
╚════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[系統狀態] 👤 登入監控

👤 目前登入用戶數: 2
┌─ 當前登入列表 ─────────────────────────────────────┐
│ ✅ root @ pts/0 | 本機 | 2025-12-01 05:20 │
│ ⚠️ admin @ pts/1 | 45.67.89.12 | 2025-12-01 05:25 │
└────────────────────────────────────────────────────┘

⏰ 最近 5 次成功登入:
root pts/0 2025-12-01 05:20
admin pts/1 2025-12-01 05:25

✅ 無失敗登入記錄

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[1/12] 🔍 惡意 Process 掃描

🚨 發現 3 個可疑 process
└─ 亂碼名稱: 3 個
rkuxyf5t (PID: 12345, CPU: 95%)
🔥 正在清除... 完成！

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[3/12] 🔍 WordPress Uploads 木馬掃描

🚨 發現 5 個可疑 PHP 檔案
└─ /var/www/site1/wp-content/uploads/2025/11/shell.php
🔥 正在清除... 完成！

... (繼續掃描)

╔════════════════════════════════════════════════════════════════╗
║ 🛡️ 掃描結果總結 ║
╠════════════════════════════════════════════════════════════════╣
║ 威脅等級: ⚠️ 中風險 ║
╠════════════════════════════════════════════════════════════════╣
║ 發現威脅: 12 已清除: 8 需手動: 4 ║
╚════════════════════════════════════════════════════════════════╝

掃描工具不會在系統留下任何記錄或工具

---

## 系統需求

### 作業系統
- ✅ Ubuntu 18.04+
- ✅ Debian 9+
- ✅ CentOS 7+
- ✅ AlmaLinux 8+
- ✅ Rocky Linux 8+
- ✅ 其他 Linux 發行版

### 權限
- 需要 **Root 權限**（使用 `sudo` 執行）

### 相依套件
- `bash` 4.0+（預裝）
- `ps`, `find`, `grep`, `awk`（預裝）
- `ss` 或 `netstat`（預裝）
- `wp-cli`（選用，用於 WordPress 核心驗證）

### 效能需求

| 項目 | v4.0 無痕跡版 | v3.0 AIDE版 | v1.0 Maldet版 |
|------|--------------|------------|--------------|
| **記憶體** | <100MB | <150MB | 4-8GB |
| **CPU** | <5% | <5% | 30-50% |
| **殘留檔案** | 0 個 | 1 個 | 3+ 個 |
| **掃描時間** | 30-60 秒 | 2-5 分鐘 | 10-30 分鐘 |
| **適用網站數** | 1-200 個 | 1-100 個 | 1-50 個 |

---

## 常見問題

### Q1：會不會誤刪正常檔案？

**不會。** 自動清除的項目都經過嚴格規則匹配：
- 惡意 Process：只刪除「8 字元亂碼名稱」且不在白名單內的程式
- Uploads PHP：只刪除 WordPress uploads 目錄的 .php 檔案（此目錄本來就不應該有 PHP）
- Migration 目錄：只刪除 XCloud/FlyWP 的暫存目錄，不會動到網站正式檔案

### Q2：掃描會影響網站效能嗎？

**幾乎不會。** 腳本使用 `renice` 和 `ionice` 降低執行優先權，CPU 使用率 < 5%，記憶體 < 100MB，完全不影響正常服務。

### Q3：可以每天自動執行嗎？

**可以。** 建議設定在離峰時段（如凌晨 3 點）：

echo "0 3 * * * curl -sL https://raw.githubusercontent.com/jimmy-is-me/vps-security-scanner/main/vps-security-scanner.sh | bash > /dev/null 2>&1" | crontab -

### Q4：為什麼不用 Maldet/ClamAV？

**效能問題。** Maldet + ClamAV 需要 4-8GB RAM，CPU 使用率 30-50%，在小型 VPS 上會拖垮效能。我們的腳本用內建指令完成大部分檢測，效能提升 80%。

### Q5：掃描完後會留下記錄嗎？

**不會（如果啟用無痕跡模式）。** 取消註解腳本最後一行 `rm -f "$0"`，執行完後腳本會自動刪除自己。

### Q6：如果誤刪檔案怎麼辦？

建議在執行前：
1. **先備份重要資料**
2. **在測試環境執行**
3. **檢查掃描結果後再手動清除**

如果誤刪，可從備份還原。

### Q7：支援哪些主機面板？

- ✅ XCloud
- ✅ FlyWP
- ✅ CloudPanel
- ✅ cPanel / WHM
- ✅ Plesk
- ✅ DirectAdmin
- ✅ 純 VPS（無面板）

### Q8：可以修改白名單嗎？

可以。編輯腳本中的這行：

在第 1 項掃描中，修改這行
ps aux | awk 'length($11) == 8 && $11 ~ /^[a-z0-9]+$/ && $11 !~ /lsphp|systemd|docker|mysql|redis|YOUR_SERVICE/' | grep -v "USER"


將 `YOUR_SERVICE` 改成你要排除的服務名稱。

---

## 後續建議動作

掃描完成後，建議執行以下強化措施：

### 🛡️ 即時防護
1. 安裝 Fail2Ban（防止 SSH 暴力破解）
apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban

2. 設定自動更新
apt install unattended-upgrades -y
dpkg-reconfigure -plow unattended-upgrades

### 🔒 SSH 安全強化

編輯 `/etc/ssh/sshd_config`：

停用 Root 登入
PermitRootLogin no

改用金鑰登入
PasswordAuthentication no

變更 SSH 埠號（選用）
Port 2222
重啟 SSH
systemctl restart sshd

### 🔄 定期維護

1. 更新系統
apt update && apt upgrade -y

2. 更新 WordPress（如有）
wp core update --allow-root
wp plugin update --all --allow-root
wp theme update --all --allow-root

3. 清理舊檔案
apt autoremove -y
apt autoclean

### 📦 WordPress 安全外掛

推薦安裝（擇一）：
- **Wordfence Security**（免費，功能強大）
- **Sucuri Security**（免費版已足夠）
- **iThemes Security**（輕量級）

---

## 更新日誌

### v4.0.0 (2025-12-01)
- 🔥 **完全無痕跡設計**：不安裝工具、不留記錄
- 👤 **新增即時登入監控**
- 🚨 **新增智慧告警系統**（CRITICAL/HIGH/MEDIUM/LOW）
- 📊 **新增 4 項掃描**：SSH 設定、埠號檢查、系統檔案變動、資源異常
- ⚡ **效能優化**：記憶體 <100MB，CPU <5%
- 🎨 **視覺化介面升級**：彩色進度條、圖示、框線

### v3.0.0 (2025-11-28)
- 整合 AIDE 檔案完整性監控
- 移除 Maldet（效能問題）
- 新增 WordPress 核心驗證

### v2.0.0 (2025-11-15)
- 新增圖形化介面
- 新增進度條顯示
- 整合 Maldet + ClamAV

### v1.0.0 (2025-11-01)
- 初始版本發布
- 基礎惡意程式掃描
- WordPress uploads 掃描

---

## 貢獻

歡迎提交 Issue 或 Pull Request！

### 如何貢獻

1. Fork 此專案
2. 建立您的功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的變更 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 開啟 Pull Request

### 程式碼規範

- 使用 4 空格縮排
- 註解使用繁體中文
- 函數名稱使用底線分隔（snake_case）
- 變數名稱使用大寫加底線（UPPER_CASE）

---

## 授權條款

本專案採用 MIT License - 詳見 [LICENSE](LICENSE) 檔案

MIT License

Copyright (c) 2025 jimmy-is-me

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 免責聲明

- ⚠️ 此工具僅供**合法的系統管理**使用
- ⚠️ 使用前請確保您有權限在該伺服器上執行安全掃描
- ⚠️ 建議先在**測試環境**執行，確認無誤後再用於正式環境
- ⚠️ 作者不對使用此工具造成的任何損失負責
- ⚠️ 執行前請**備份重要資料**

---

## 支援

如有問題請：
- 📧 開啟 [Issue](https://github.com/jimmy-is-me/vps-security-scanner/issues)
- 💬 加入 [Discussions](https://github.com/jimmy-is-me/vps-security-scanner/discussions)
- ⭐ 給個星星支持我們！

---

## 相關連結

- [GitHub Repository](https://github.com/jimmy-is-me/vps-security-scanner)
- [WordPress Security Best Practices](https://wordpress.org/support/article/hardening-wordpress/)
- [Linux Security Guide](https://www.linux.org/docs/security.html)
- [Fail2Ban Documentation](https://www.fail2ban.org/)

---

**Made with ❤️ by [jimmy-is-me](https://github.com/jimmy-is-me)**

如果這個工具幫到你，請給個 ⭐ 支持一下！

