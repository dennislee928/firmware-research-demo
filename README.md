# 🚘 Automotive Firmware Security Lab

A practical research lab focused on analyzing embedded firmware used in modern automotive systems. This project documents static analysis techniques, firmware unpacking, component detection using YARA rules, and CAN Bus log simulation — all geared toward enhancing automotive cybersecurity.

---

## 🎯 Project Goals

- Analyze infotainment, telematics, and ECU firmware from public sources
- Detect legacy or insecure components (e.g., telnetd, dropbear)
- Build custom YARA signatures for vulnerability scanning
- Simulate CAN Bus logs and develop pattern recognition logic
- Prepare for reverse engineering use cases in automotive security research

---

## 🧰 Tools Used

| Tool         | Purpose                            |
| ------------ | ---------------------------------- |
| `binwalk`    | Unpack and analyze firmware layers |
| `hexdump`    | Inspect firmware in hex form       |
| `Ghidra`     | Static reverse engineering         |
| `YARA`       | Pattern-based signature matching   |
| `python-can` | Parse and simulate CAN Bus logs    |
| `Python`     | Automate analysis workflow         |

---

## 📁 Repository Structure

```bash
automotive-firmware-lab/
├── firmware_samples/        # Collected test firmware (e.g., .bin/.img)
├── unpacked/                # binwalk output
├── yara_rules/              # Custom component detection rules
├── ghidra_projects/         # Ghidra project notes
├── can_logs/                # Simulated CAN Bus logs
├── tools/                   # Python automation scripts
├── reports/                 # Signature-based analysis reports
├── docs/                    # References and learning materials
├── screenshots/             # CLI and GUI screenshots
└── README.md
```

```
📁 firmware_samples/

    📦 原始韌體樣本，用來進行解包與分析

    infotainment_netgear.chk – Linux-based router firmware (模擬 infotainment)

    telematics_qnx.img – QNX image for telematics (模擬車聯網裝置)

    ecu_autosar_fw.bin – Binary blob for embedded ECU with AUTOSAR stack

📁 unpacked/

    🪓 binwalk 解包結果

    infotainment_netgear_extracted/ – binwalk -eM 解包的目錄結構

    qnx_filesystem_tree.txt – QNX image 的檔案系統清單

    autosar_elf_summary.md – ELF 檔整理，含 strings & symbol mapping

📁 yara_rules/

    🎯 偵測 telnetd / dropbear / QNX / AUTOSAR 等元件

    detect_telnetd.yar – 判斷 firmware 是否內含 telnet daemon

    detect_qnx_os.yar – QNX-specific 服務與字串規則

    detect_autosar_stack.yar – AUTOSAR 通訊或 Task pattern 規則

    detect_insecure_keys.yar – 偵測硬編碼金鑰或憑證的 YARA 規則

📁 ghidra_projects/

    🧠 使用 Ghidra 對 ELF / bin 檔案進行靜態分析

    infotainment_telnetd_strings.md – 字串與函式表記錄

    autosar_qnx_function_graph.png – Ghidra 匯出函式圖 screenshot

    qnx_entrypoints.txt – 分析 QNX main/init 函式入口記錄

📁 can_logs/

    🚐 模擬 CAN Bus 日誌（原始 & 解析）

    demo_can_log.txt – 原始模擬 CAN Bus 訊息

    can_log_parser_output.json – 經 Python script 處理後之結構化輸出

    anomaly_flags.yaml – 用來標註異常傳輸的 ID/Frame 定義

📁 tools/

    ⚙️ Python 自動化腳本

    binwalk_auto.py – 自動解包並整理目錄結構

    yara_runner.py – 自動比對 YARA 規則與產生 report

    extract_strings.py – 從 bin 中抽取 ASCII/Unicode 字串

    can_log_parser.py – 將 CAN log 轉成 JSON + 偵測異常訊息

📁 reports/

    📝 分析報告與 YARA 偵測結果

    telnetd_scan_report.md – 偵測 telnetd 的報告與風險評估

    qnx_init_detect_summary.md – QNX image 的啟動順序分析

    autosar_finder_results.md – 找到 AUTOSAR task 與記憶體配置之記錄

📁 docs/

    📚 學習筆記與外部連結整理

    references.md – 工具使用教學、部落格文章整理

    tools_installation_guide.md – binwalk/Ghidra/YARA 安裝步驟

    useful_links.md – CAN bus spec, firmware source, training course

📁 screenshots/

    🖼️ CLI 與 GUI 使用畫面截圖

    binwalk_scan_result.png – 執行 binwalk 後的終端畫面

    ghidra_telnetd_function_view.png – Ghidra string/function graph

    can_log_parser_cli.png – Python log parser 的輸出範例
```

🧱 Planned Modules

    autosar-finder: detect common AUTOSAR configs inside firmware

    firmware-ai-signature-gen: generate YARA via prompt + LLM

    secureboot-check: map secure boot flags if present

    qnx-analyzer: detect QNX services and verify microkernel layouts

📚 References

    Binwalk

    Ghidra

    YARA

    python-can

    Firmware Archive

    CAN Bus Explained

🙋 Author

Dennis Lee

This repository uses publicly available firmware for research and educational purposes only. No proprietary or illegally obtained firmware is included.
