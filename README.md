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
- [更新日誌](#更新日誌)
- [授權條款](#授權條款)

---

## ✨ 功能特色

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

## 🚀 快速開始

### 方法 1：一行指令執行（推薦）

