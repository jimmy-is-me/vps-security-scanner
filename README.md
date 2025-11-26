# VPS 安全掃描與清除工具

🛡️ 一鍵掃描並清除 VPS 上的惡意程式、webshell、木馬等安全威脅。

適用於所有類型的 Linux VPS：XCloud、FlyWP、CloudPanel、cPanel、Plesk、DirectAdmin 等。

## 功能特色

✅ **自動掃描並清除**
- 惡意 Process（亂碼名稱的可疑程式）
- WordPress uploads 目錄的 PHP 木馬
- XCloud/FlyWP migration 目錄的惡意檔案

⚠️ **掃描並提示（需手動處理）**
- 臨時目錄的可執行檔
- Cron 裡的可疑排程
- Webshell 特徵碼
- 隱藏的惡意檔案

📊 **監控檢查**
- 對外可疑連線
- SSH 登入記錄
- 系統資源使用狀況

## 快速使用

### 方法 1：一行指令執行（推薦）
curl -sL https://raw.githubusercontent.com/jimmy-is-me/vps-security-scanner/main/vps-security-scanner.sh | sudo bash

### 方法 2：下載後執行
下載腳本
wget https://raw.githubusercontent.com/jimmy-is-me/vps-security-scanner/main/vps-security-scanner.sh
賦予執行權限
chmod +x vps-security-scanner.sh
執行
sudo ./vps-security-scanner.sh

### 方法 3：複製貼上執行

直接把 `vps-security-scanner.sh` 的內容複製貼到 SSH 終端機執行。


## 安全性說明

### ✅ 會自動清除的項目

1. **惡意 Process**：只清除 8 字元亂碼名稱的 process（如 `rkuxyf5t`），不會動到正常服務
2. **WordPress uploads 目錄的 PHP**：WordPress 的 uploads 目錄正常來說不應該有 .php 檔案
3. **Migration 暫存目錄**：XCloud/FlyWP 的 migration 目錄是暫存目錄，刪除不會影響正式網站

### ⚠️ 不會自動刪除的項目

- 臨時目錄的檔案（避免誤刪）
- Cron 排程（需手動確認）
- Webshell 檔案（需仔細檢查）

### 📂 完全不會動到的資料

- ✅ 你的網站檔案（`/var/www/`, `/home/*/public_html/`）
- ✅ 資料庫（MySQL/MariaDB）
- ✅ 網站設定檔（`wp-config.php`, `.htaccess`）
- ✅ 正常的佈景主題和外掛
- ✅ 所有上傳的圖片、影片、文件
- ✅ 備份檔案
- ✅ 正常的系統服務

## 掃描結果範例

========================================
VPS 安全掃描與清除工具 v1.0.0
[1/10] 掃描惡意 Process...
✗ 發現 15 個可疑 process
正在清除惡意 process...
✓ 已清除

[2/10] 檢查對外連線...
總對外連線數: 25
✓ 連線狀況正常

[3/10] 掃描 WordPress uploads 目錄...
✗ 發現 3 個可疑 PHP 檔案
正在刪除...
✓ 已清除

...

========================================
掃描結果總結
發現威脅: 18
已清除威脅: 18
需手動處理: 0

✓ 所有威脅已自動清除！


## 後續建議動作

完成掃描後，建議執行以下動作加強安全性：

1. **安裝 Wordfence**：在所有 WordPress 網站安裝並執行完整掃描
2. **更新系統**：更新 WordPress 核心、所有外掛、佈景主題
3. **更換密碼**：更換 WP admin、資料庫、SSH、FTP 所有密碼
4. **安裝 Fail2Ban**：防止 SSH 暴力破解
5. **停用 XML-RPC**：如果不需要，請在 WordPress 停用 XML-RPC

## 系統需求

- Linux (Ubuntu, Debian, CentOS, AlmaLinux 等)
- Root 權限
- Bash shell

## License

MIT License - 自由使用、修改、分發

## 貢獻

歡迎提交 Issue 或 Pull Request！

## 免責聲明

此工具僅供合法的系統管理使用。使用前請確保你有權限在該伺服器上執行安全掃描。作者不對使用此工具造成的任何損失負責。

## 支援

如有問題請開 Issue 或聯繫作者。


