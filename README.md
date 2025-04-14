# 🔍 韌體解包與特徵檢測演示

本專案展示了韌體分析方面的實作探索，主要關注於：

- 🧩 使用 `binwalk` 和 `hexdump` 進行韌體解包
- 🧠 通過 `Ghidra` 進行靜態字串和模式分析
- 🧪 使用 `YARA` 進行基於規則的檢測
- 📑 針對嵌入式系統中元件識別的模擬報告
- 🐳 Docker 容器化與自動化分析流程

---

## 📦 專案結構

```bash
firmware-analysis-demo/
├── firmware.bin                 # 樣本韌體映像檔
├── binwalk-analysis/            # 使用binwalk解包的目錄
├── hexdump-analysis/            # 原始十六進位 + 偏移註釋
├── yara-rules/                  # YARA規則與檢測結果
│   ├── telnetd_rule.yar         # 檢測telnet服務的規則
│   └── network_services_rule.yar # 檢測多種網路服務的規則
├── ghidra-notes.md              # 字串/函數參考 + 註釋
├── simulated_report.md          # 特徵檢測摘要
├── can-log-demo.txt             # 模擬CAN協議片段
├── screenshots/                 # 分析工具截圖
├── firmware_samples/            # 韌體樣本儲存目錄
├── reports/                     # 分析報告輸出目錄
├── firmware_analyzer.sh         # 自動化分析腳本
├── setup_cron.sh                # 定時任務設置腳本
├── Dockerfile                   # Docker映像定義
├── docker-compose.yml           # Docker環境配置
└── README.md                    # 本文檔
```

## 🛠️ 使用工具

| 工具    | 用途                  |
| ------- | --------------------- |
| binwalk | 韌體提取與分析        |
| hexdump | 原始數據檢查          |
| Ghidra  | 二進制分析 + 字串映射 |
| YARA    | 基於規則的特徵匹配    |
| Docker  | 環境容器化與部署      |
| Cron    | 自動化定期執行分析    |

## 🔬 實作過程

### ✅ 步驟 1：使用 binwalk 解包韌體

- 提取檔案系統和元件標頭
- 識別壓縮載荷和 ELF 標頭
- → 查看 `/binwalk-analysis/`

### ✅ 步驟 2：使用 hexdump 進行檢查

- 檢視已知模式的偏移（telnetd, dropbear, /etc/shadow）
- 對潛在規則映射位元組範圍
- → 查看 `/hexdump-analysis/`

### ✅ 步驟 3：使用 Ghidra 進行分析

- 將.bin 載入 Ghidra
- 使用「已定義字串」和「函數圖」視圖
- 定位嵌入式服務（例如，BusyBox, sshd）
- 💡 在 `/screenshots/` 中包含 Ghidra 分析截圖

### ✅ 步驟 4：編寫並運行 YARA 規則

```
rule Detect_Telnetd {
    strings:
        $telnet = "telnetd"
    condition:
        $telnet
}
```

- 成功檢測到解包文件中的 telnetd
- 可能表明存在不安全的傳統服務

### ✅ 步驟 5：自動化與容器化

- 創建自動化分析腳本執行完整流程
- 設置定時任務定期分析新韌體
- 通過 Docker 容器提供一致的分析環境

## 📊 執行方式

以下是不同的執行方式，根據您的需求選擇：

### 本地執行

```bash
# 運行單次分析
./firmware_analyzer.sh

# 設定每30分鐘自動執行
./setup_cron.sh
```

### Docker 容器執行

```bash
# 構建並啟動容器化環境
docker-compose up -d

# 查看執行日誌
docker logs firmware-analyzer
```

## 📑 模擬檢測報告

查看 `simulated_report.md` 了解：

- 匹配元件
- 風險評估
- 映射到檢測特徵格式

## 🎯 實作成果

| 目標               | 達成狀態 |
| ------------------ | -------- |
| 理解嵌入式韌體布局 | ✅       |
| 練習二進制分析工具 | ✅       |
| 創建自定義檢測特徵 | ✅       |
| 自動化分析流程     | ✅       |
| 記錄審查過程       | ✅       |

## 🧠 後續步驟

- 使用 YARA 正則表達式和元數據擴展規則集
- 將模式匹配整合到自動化流程（Python）
- 探索 binwalk -eM 處理多層映像
- 學習 radare2 或 IDA Pro 進行更深入分析
- 擴展容器化部署到雲端環境

## 📚 參考資源

- [Binwalk 文檔](https://github.com/ReFirmLabs/binwalk)
- [YARA 規則指南](https://yara.readthedocs.io/)
- [Ghidra 使用指南](https://ghidra-sre.org/)
- [Docker 容器化最佳實踐](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)

## 💬 聯絡方式

Dennis Lee

- 🔗 GitHub: @dennislee928
- 🔗 作品集: next-js-portfolio
- 📧 需要時可提供電子郵件

---

參考資料：https://sergioprado.blog/reverse-engineering-router-firmware-with-binwalk/
