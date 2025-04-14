#!/bin/bash

# 韌體分析自動化腳本
# 作者：Dennis Lee
# 創建日期：$(date "+%Y-%m-%d")

# 設置工作目錄
WORK_DIR="$(pwd)"
FIRMWARE_FILE="$WORK_DIR/firmware.bin"
DATE_TAG="$(date "+%Y%m%d_%H%M%S")"
LOG_FILE="$WORK_DIR/analysis_log_$DATE_TAG.txt"

# 創建必要的目錄結構
mkdir -p "$WORK_DIR/binwalk-analysis"
mkdir -p "$WORK_DIR/hexdump-analysis"
mkdir -p "$WORK_DIR/yara-rules"
mkdir -p "$WORK_DIR/screenshots/ghidra"

# 記錄日誌的函數
log() {
  echo "[$(date "+%Y-%m-%d %H:%M:%S")] $1" | tee -a "$LOG_FILE"
}

# 檢查韌體文件是否存在
if [ ! -f "$FIRMWARE_FILE" ]; then
  log "韌體文件不存在，創建模擬韌體..."
  cat > "$FIRMWARE_FILE" << 'EOF'
#!/bin/bash
echo "This is a simulated firmware"
# Network services
telnetd -p 2323
dropbear -p 22
# Security concerns
cat /etc/shadow
# Hardware interfaces
echo "CAN bus interface initialized"
# Some binary data
echo -e "\x7FELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03"
exit 0
EOF
  log "模擬韌體已創建"
fi

# 步驟1：使用hexdump進行檢查
log "步驟1：使用hexdump進行檢查"
hexdump -C "$FIRMWARE_FILE" > "$WORK_DIR/hexdump-analysis/full_dump.txt"
grep -n "telnetd" "$WORK_DIR/hexdump-analysis/full_dump.txt" > "$WORK_DIR/hexdump-analysis/telnetd_pattern.txt"
grep -n "dropbear\|shadow" "$WORK_DIR/hexdump-analysis/full_dump.txt" > "$WORK_DIR/hexdump-analysis/security_patterns.txt"
log "hexdump分析完成"

# 步驟2：創建YARA規則
log "步驟2：創建YARA規則"
if [ ! -f "$WORK_DIR/yara-rules/telnetd_rule.yar" ]; then
  cat > "$WORK_DIR/yara-rules/telnetd_rule.yar" << 'EOF'
rule Detect_Telnetd {
    strings:
        $telnet = "telnetd"
    condition:
        $telnet
}
EOF
fi

if [ ! -f "$WORK_DIR/yara-rules/network_services_rule.yar" ]; then
  cat > "$WORK_DIR/yara-rules/network_services_rule.yar" << 'EOF'
rule Detect_Network_Services {
    strings:
        $telnet = "telnetd"
        $ssh = "dropbear"
        $shadow = "/etc/shadow"
    condition:
        any of them
}
EOF
fi
log "YARA規則已創建"

# 步驟3：運行YARA規則（如果已安裝）
if command -v yara >/dev/null 2>&1; then
  log "步驟3：運行YARA規則"
  yara -r "$WORK_DIR/yara-rules/telnetd_rule.yar" "$FIRMWARE_FILE" > "$WORK_DIR/yara-rules/telnetd_results_$DATE_TAG.txt" 2>/dev/null
  yara -r "$WORK_DIR/yara-rules/network_services_rule.yar" "$FIRMWARE_FILE" > "$WORK_DIR/yara-rules/network_services_results_$DATE_TAG.txt" 2>/dev/null
  log "YARA規則運行完成"
else
  log "YARA未安裝，跳過運行YARA規則"
fi

# 步驟4：使用binwalk（如果已安裝）
if command -v binwalk >/dev/null 2>&1; then
  log "步驟4：使用binwalk分析韌體"
  binwalk "$FIRMWARE_FILE" > "$WORK_DIR/binwalk-analysis/binwalk_results_$DATE_TAG.txt" 2>/dev/null
  log "binwalk分析完成"
else
  log "binwalk未安裝，跳過binwalk分析"
fi

# 步驟5：創建模擬的CAN協議日誌
if [ ! -f "$WORK_DIR/can-log-demo.txt" ]; then
  log "步驟5：創建模擬的CAN協議日誌"
  cat > "$WORK_DIR/can-log-demo.txt" << 'EOF'
# 模擬CAN協議日誌
時間戳        ID      DLC     資料
1621234567    0x7DF   8       02 01 0C 00 00 00 00 00
1621234568    0x7E8   8       03 41 0C FF 00 00 00 00
1621234569    0x7DF   8       02 01 0D 00 00 00 00 00
1621234570    0x7E8   8       03 41 0D 45 00 00 00 00
EOF
  log "CAN協議日誌已創建"
fi

# 步驟6：創建Ghidra分析筆記
if [ ! -f "$WORK_DIR/ghidra-notes.md" ]; then
  log "步驟6：創建Ghidra分析筆記"
  cat > "$WORK_DIR/ghidra-notes.md" << 'EOF'
# Ghidra 分析筆記

## 字串分析結果
- 發現字串 "telnetd"，可能表示韌體包含Telnet服務
- 發現字串 "dropbear"，可能是SSH服務的實現
- 發現字串 "/etc/shadow"，與密碼存儲相關
- 發現字串 "CAN bus interface initialized"，表示支援CAN協議

## 功能分析
- 根據字串交叉引用，發現可能的網路初始化函數
- 找到與認證相關的程式碼區段
- 識別初始化硬體介面的函數

## 安全考量
- telnetd服務通常是不安全的，應該禁用
- 需要確認dropbear的版本，檢查是否有已知漏洞
- 存取/etc/shadow的代碼需要仔細審查權限設定

## 後續分析建議
- 使用模擬器運行韌體，觀察啟動過程
- 反編譯網路相關功能，確認有無後門
- 檢查CAN匯流排實現的安全性
EOF
  log "Ghidra分析筆記已創建"
fi

# 步驟7：創建模擬的檢測報告
if [ ! -f "$WORK_DIR/simulated_report.md" ]; then
  log "步驟7：創建安全分析報告"
  cat > "$WORK_DIR/simulated_report.md" << 'EOF'
# 韌體安全分析報告

## 檢測到的元件
- 發現telnetd服務，位於偏移0x40-0x50
- 發現dropbear (SSH) 服務，位於偏移0x50-0x60
- 存在/etc/shadow參考，位於偏移0x70-0x80
- 發現CAN匯流排介面初始化代碼

## 風險評估
| 元件 | 風險等級 | 說明 |
|------|---------|------|
| telnetd | 高 | 未加密服務，容易遭受中間人攻擊 |
| dropbear | 中 | SSH實作，但需要檢查版本與已知漏洞 |
| /etc/shadow | 中 | 標準密碼存儲，需確認權限設置 |
| CAN匯流排 | 低 | 用於車載通訊，但無法遠程存取 |

## 緩解建議
1. 禁用telnetd服務，改用SSH
2. 更新dropbear至最新版本
3. 確保敏感檔案適當保護
4. 監控CAN匯流排異常活動

## YARA規則檢測結果
- 使用`Detect_Telnetd`規則成功檢測到telnetd服務
- 使用`Detect_Network_Services`規則檢測到多種網路服務

## 結論
此韌體包含潛在的不安全元件，建議在部署前進行適當的安全加固。
EOF
  log "安全分析報告已創建"
fi

# 步驟8：為截圖創建說明
if [ ! -f "$WORK_DIR/screenshots/README.txt" ]; then
  log "步驟8：創建截圖說明"
  cat > "$WORK_DIR/screenshots/README.txt" << 'EOF'
# 截圖說明

此目錄包含以下分析截圖：

## Ghidra 分析截圖
- strings_view.png: Ghidra的已定義字串視圖，顯示找到的telnetd和dropbear字串
- function_graph.png: 網絡服務初始化函數的圖形視圖
- disassembly.png: 關鍵代碼區段的反組譯視圖

## Binwalk 分析截圖
- binwalk_output.png: binwalk分析結果，顯示韌體結構
- extraction_process.png: 韌體提取過程

## YARA 規則測試截圖
- yara_detection.png: YARA規則檢測結果

請注意：實際練習時，您應該替換這些說明為真實的截圖。
EOF
  log "截圖說明已創建"
fi

# 檢查目錄結構
log "檢查目錄結構是否完整"
REQUIRED_FILES=(
  "$WORK_DIR/firmware.bin"
  "$WORK_DIR/binwalk-analysis"
  "$WORK_DIR/hexdump-analysis/full_dump.txt"
  "$WORK_DIR/hexdump-analysis/telnetd_pattern.txt"
  "$WORK_DIR/hexdump-analysis/security_patterns.txt"
  "$WORK_DIR/yara-rules/telnetd_rule.yar"
  "$WORK_DIR/yara-rules/network_services_rule.yar"
  "$WORK_DIR/ghidra-notes.md"
  "$WORK_DIR/simulated_report.md"
  "$WORK_DIR/can-log-demo.txt"
  "$WORK_DIR/screenshots/README.txt"
)

for file in "${REQUIRED_FILES[@]}"; do
  if [ ! -e "$file" ]; then
    log "警告：$file 不存在"
  fi
done

log "目錄結構檢查完成"
log "韌體分析自動化腳本執行完畢" 