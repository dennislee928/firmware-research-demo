#!/bin/bash
#===============================================================================
# 韌體分析自動化腳本
# 版本: 2.0
# 作者: Dennis Lee
# 描述: 自動化執行韌體分析，包含hexdump分析、YARA規則檢測、
#       binwalk分析，以及生成各類分析報告
#===============================================================================

# 嚴格模式，避免常見錯誤
set -euo pipefail

#===============================================================================
# 配置變量
#===============================================================================
# 從環境變數獲取分析間隔（分鐘），默認為30分鐘
ANALYSIS_INTERVAL=${ANALYSIS_INTERVAL:-30}

# 設置工作目錄
WORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
FIRMWARE_SAMPLES="$WORK_DIR/firmware_samples"
FIRMWARE_FILE="${1:-$WORK_DIR/firmware.bin}"
FIRMWARE_NAME=$(basename "$FIRMWARE_FILE")
DATE_TAG="$(date "+%Y%m%d_%H%M%S")"
LOG_DIR="$WORK_DIR/logs"
LOG_FILE="$LOG_DIR/analysis_${FIRMWARE_NAME}_$DATE_TAG.log"
REPORT_DIR="$WORK_DIR/reports"
REPORT_FILE="$REPORT_DIR/report_${FIRMWARE_NAME}_$DATE_TAG.md"

# 顏色代碼
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#===============================================================================
# 函數定義
#===============================================================================

# 記錄日誌的函數
log() {
  local level="$1"
  local message="$2"
  local color="$NC"
  
  case "$level" in
    "INFO")
      color="$BLUE"
      ;;
    "SUCCESS")
      color="$GREEN"
      ;;
    "WARNING")
      color="$YELLOW"
      ;;
    "ERROR")
      color="$RED"
      ;;
  esac
  
  echo -e "${color}[$(date "+%Y-%m-%d %H:%M:%S")] [$level] $message${NC}" | tee -a "$LOG_FILE"
}

# 檢查命令是否存在
check_command() {
  if ! command -v "$1" &> /dev/null; then
    log "WARNING" "命令 '$1' 未安裝，相關功能將被跳過"
    return 1
  fi
  return 0
}

# 初始化目錄結構
initialize_directories() {
  log "INFO" "初始化目錄結構..."
  mkdir -p "$WORK_DIR/binwalk-analysis"
  mkdir -p "$WORK_DIR/hexdump-analysis"
  mkdir -p "$WORK_DIR/yara-rules"
  mkdir -p "$WORK_DIR/screenshots/ghidra"
  mkdir -p "$LOG_DIR"
  mkdir -p "$REPORT_DIR"
  mkdir -p "$FIRMWARE_SAMPLES"
  log "SUCCESS" "目錄結構初始化完成"
}

# 創建示例韌體
create_sample_firmware() {
  log "INFO" "韌體文件不存在，創建模擬韌體..."
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
  log "SUCCESS" "模擬韌體已創建: $FIRMWARE_FILE"
}

# 使用hexdump進行分析
perform_hexdump_analysis() {
  log "INFO" "步驟1：使用hexdump進行檢查"
  
  local hexdump_dir="$WORK_DIR/hexdump-analysis"
  local base_name=$(basename "$FIRMWARE_FILE")
  local full_dump="$hexdump_dir/${base_name}_full_dump_$DATE_TAG.txt"
  
  hexdump -C "$FIRMWARE_FILE" > "$full_dump"
  log "INFO" "生成完整hexdump: $full_dump"
  
  grep -n "telnetd" "$full_dump" > "$hexdump_dir/${base_name}_telnetd_pattern_$DATE_TAG.txt" || log "INFO" "未發現telnetd模式"
  grep -n "dropbear\|shadow" "$full_dump" > "$hexdump_dir/${base_name}_security_patterns_$DATE_TAG.txt" || log "INFO" "未發現dropbear或shadow模式"
  
  # 將最新的分析結果建立軟鏈接
  ln -sf "${base_name}_full_dump_$DATE_TAG.txt" "$hexdump_dir/full_dump.txt"
  ln -sf "${base_name}_telnetd_pattern_$DATE_TAG.txt" "$hexdump_dir/telnetd_pattern.txt"
  ln -sf "${base_name}_security_patterns_$DATE_TAG.txt" "$hexdump_dir/security_patterns.txt"
  
  log "SUCCESS" "hexdump分析完成"
}

# 創建YARA規則
create_yara_rules() {
  log "INFO" "步驟2：創建或更新YARA規則"
  
  local yara_dir="$WORK_DIR/yara-rules"
  
  # 檢查telnetd規則
  if [ ! -f "$yara_dir/telnetd_rule.yar" ]; then
    cat > "$yara_dir/telnetd_rule.yar" << 'EOF'
rule Detect_Telnetd {
    meta:
        description = "檢測韌體中的Telnet服務"
        author = "Dennis Lee"
        date = "2023-04-14"
        severity = "high"
    strings:
        $telnet = "telnetd"
    condition:
        $telnet
}
EOF
    log "INFO" "已創建telnetd檢測規則"
  fi

  # 檢查網絡服務規則
  if [ ! -f "$yara_dir/network_services_rule.yar" ]; then
    cat > "$yara_dir/network_services_rule.yar" << 'EOF'
rule Detect_Network_Services {
    meta:
        description = "檢測韌體中的多種網絡服務"
        author = "Dennis Lee"
        date = "2023-04-14"
        severity = "medium"
    strings:
        $telnet = "telnetd"
        $ssh = "dropbear"
        $shadow = "/etc/shadow"
    condition:
        any of them
}
EOF
    log "INFO" "已創建網絡服務檢測規則"
  fi
  
  log "SUCCESS" "YARA規則已創建"
}

# 運行YARA規則
run_yara_rules() {
  log "INFO" "步驟3：運行YARA規則"
  
  if ! check_command "yara"; then
    return
  fi

  local yara_dir="$WORK_DIR/yara-rules"
  local base_name=$(basename "$FIRMWARE_FILE")
  
  yara -r "$yara_dir/telnetd_rule.yar" "$FIRMWARE_FILE" > "$yara_dir/${base_name}_telnetd_results_$DATE_TAG.txt" 2>/dev/null || log "INFO" "未檢測到telnetd"
  yara -r "$yara_dir/network_services_rule.yar" "$FIRMWARE_FILE" > "$yara_dir/${base_name}_network_services_results_$DATE_TAG.txt" 2>/dev/null || log "INFO" "未檢測到網絡服務"
  
  log "SUCCESS" "YARA規則運行完成"
}

# 使用binwalk分析
run_binwalk_analysis() {
  log "INFO" "步驟4：使用binwalk分析韌體"
  
  if ! check_command "binwalk"; then
    return
  fi

  local binwalk_dir="$WORK_DIR/binwalk-analysis"
  local base_name=$(basename "$FIRMWARE_FILE")
  
  # 基本分析
  binwalk "$FIRMWARE_FILE" > "$binwalk_dir/${base_name}_binwalk_results_$DATE_TAG.txt" 2>/dev/null
  log "INFO" "完成基本binwalk分析"
  
  # 提取文件系統（如果需要）
  if [ "${EXTRACT_FILESYSTEM:-0}" = "1" ]; then
    log "INFO" "提取韌體中的文件系統..."
    binwalk -e "$FIRMWARE_FILE" -C "$binwalk_dir/${base_name}_extracted_$DATE_TAG" || log "WARNING" "無法提取文件系統"
  fi
  
  log "SUCCESS" "binwalk分析完成"
}

# 創建CAN協議日誌
create_can_log() {
  log "INFO" "步驟5：創建或更新模擬的CAN協議日誌"
  
  if [ ! -f "$WORK_DIR/can-log-demo.txt" ]; then
    cat > "$WORK_DIR/can-log-demo.txt" << 'EOF'
# 模擬CAN協議日誌
時間戳        ID      DLC     資料                          說明
1621234567    0x7DF   8       02 01 0C 00 00 00 00 00       請求引擎轉速
1621234568    0x7E8   8       03 41 0C FF 00 00 00 00       引擎轉速回應
1621234569    0x7DF   8       02 01 0D 00 00 00 00 00       請求車速
1621234570    0x7E8   8       03 41 0D 45 00 00 00 00       車速回應 (69 km/h)
1621234571    0x7DF   8       02 01 05 00 00 00 00 00       請求冷卻液溫度
1621234572    0x7E8   8       03 41 05 7B 00 00 00 00       冷卻液溫度回應 (83°C)
EOF
    log "SUCCESS" "CAN協議日誌已創建"
  fi
}

# 創建Ghidra分析筆記
create_ghidra_notes() {
  log "INFO" "步驟6：創建或更新Ghidra分析筆記"
  
  if [ ! -f "$WORK_DIR/ghidra-notes.md" ]; then
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
    log "SUCCESS" "Ghidra分析筆記已創建"
  fi
}

# 創建安全分析報告
create_security_report() {
  log "INFO" "步驟7：創建安全分析報告"
  
  local base_name=$(basename "$FIRMWARE_FILE")
  
  # 準備報告數據
  local telnetd_found=0
  local dropbear_found=0
  local shadow_found=0
  
  if grep -q "telnetd" "$WORK_DIR/hexdump-analysis/telnetd_pattern.txt" 2>/dev/null; then
    telnetd_found=1
  fi
  
  if grep -q "dropbear" "$WORK_DIR/hexdump-analysis/security_patterns.txt" 2>/dev/null; then
    dropbear_found=1
  fi
  
  if grep -q "shadow" "$WORK_DIR/hexdump-analysis/security_patterns.txt" 2>/dev/null; then
    shadow_found=1
  fi
  
  # 生成報告
  cat > "$REPORT_FILE" << EOF
# 韌體安全分析報告

## 基本信息
- **韌體名稱**: ${base_name}
- **分析時間**: $(date "+%Y-%m-%d %H:%M:%S")
- **檔案大小**: $(du -h "$FIRMWARE_FILE" | cut -f1)

## 檢測到的元件
EOF

  # 根據檢測到的內容添加報告細節
  if [ $telnetd_found -eq 1 ]; then
    echo "- ⚠️ 發現telnetd服務，位於偏移$(grep -n "telnetd" "$WORK_DIR/hexdump-analysis/telnetd_pattern.txt" | head -1 | cut -d: -f2- | awk '{print $1}')" >> "$REPORT_FILE"
  fi
  
  if [ $dropbear_found -eq 1 ]; then
    echo "- 🔍 發現dropbear (SSH) 服務，位於偏移$(grep -n "dropbear" "$WORK_DIR/hexdump-analysis/security_patterns.txt" | head -1 | cut -d: -f2- | awk '{print $1}')" >> "$REPORT_FILE"
  fi
  
  if [ $shadow_found -eq 1 ]; then
    echo "- ⚠️ 存在/etc/shadow參考，位於偏移$(grep -n "shadow" "$WORK_DIR/hexdump-analysis/security_patterns.txt" | head -1 | cut -d: -f2- | awk '{print $1}')" >> "$REPORT_FILE"
  fi
  
  echo "- 📡 發現CAN匯流排介面初始化代碼" >> "$REPORT_FILE"
  
  # 繼續填充報告
  cat >> "$REPORT_FILE" << 'EOF'

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
EOF

  # 添加YARA檢測結果
  if [ -f "$WORK_DIR/yara-rules/${base_name}_telnetd_results_$DATE_TAG.txt" ]; then
    if grep -q "Detect_Telnetd" "$WORK_DIR/yara-rules/${base_name}_telnetd_results_$DATE_TAG.txt"; then
      echo "- ✅ 使用`Detect_Telnetd`規則成功檢測到telnetd服務" >> "$REPORT_FILE"
    else
      echo "- ❌ 使用`Detect_Telnetd`規則未檢測到telnetd服務" >> "$REPORT_FILE"
    fi
  fi
  
  if [ -f "$WORK_DIR/yara-rules/${base_name}_network_services_results_$DATE_TAG.txt" ]; then
    if grep -q "Detect_Network_Services" "$WORK_DIR/yara-rules/${base_name}_network_services_results_$DATE_TAG.txt"; then
      echo "- ✅ 使用`Detect_Network_Services`規則檢測到多種網路服務" >> "$REPORT_FILE"
    else
      echo "- ❌ 使用`Detect_Network_Services`規則未檢測到網路服務" >> "$REPORT_FILE"
    fi
  fi

  # 結論
  cat >> "$REPORT_FILE" << 'EOF'

## 結論
此韌體包含潛在的不安全元件，建議在部署前進行適當的安全加固。
EOF

  # 同步到標準的報告文件
  cp "$REPORT_FILE" "$WORK_DIR/simulated_report.md"
  
  log "SUCCESS" "安全分析報告已創建: $REPORT_FILE"
}

# 創建截圖說明
create_screenshot_readme() {
  log "INFO" "步驟8：創建或更新截圖說明"
  
  if [ ! -f "$WORK_DIR/screenshots/README.txt" ]; then
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
    log "SUCCESS" "截圖說明已創建"
  fi
}

# 檢查目錄結構
check_directory_structure() {
  log "INFO" "檢查目錄結構是否完整"
  
  local REQUIRED_FILES=(
    "$FIRMWARE_FILE"
    "$WORK_DIR/binwalk-analysis"
    "$WORK_DIR/hexdump-analysis/full_dump.txt"
    "$WORK_DIR/yara-rules/telnetd_rule.yar"
    "$WORK_DIR/yara-rules/network_services_rule.yar"
    "$WORK_DIR/ghidra-notes.md"
    "$WORK_DIR/simulated_report.md"
    "$WORK_DIR/can-log-demo.txt"
    "$WORK_DIR/screenshots/README.txt"
  )

  local missing=0
  for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -e "$file" ]; then
      log "WARNING" "文件或目錄不存在: $file"
      missing=1
    fi
  done

  if [ $missing -eq 0 ]; then
    log "SUCCESS" "目錄結構完整性檢查通過"
  else
    log "WARNING" "目錄結構不完整，請檢查上述警告"
  fi
}

#===============================================================================
# 主執行流程
#===============================================================================

# 顯示介紹橫幅
echo -e "${BLUE}====================================================================${NC}"
echo -e "${GREEN}                    韌體分析自動化腳本 v2.0                     ${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "${YELLOW}作者: Dennis Lee${NC}"
echo -e "${YELLOW}分析間隔: ${ANALYSIS_INTERVAL}分鐘${NC}"
echo -e "${YELLOW}當前時間: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BLUE}====================================================================${NC}"

# 初始化日誌目錄
mkdir -p "$LOG_DIR"

# 記錄啟動信息
log "INFO" "韌體分析自動化腳本啟動"
log "INFO" "韌體文件: $FIRMWARE_FILE"
log "INFO" "日誌文件: $LOG_FILE"
log "INFO" "報告文件: $REPORT_FILE"

# 初始化目錄結構
initialize_directories

# 檢查韌體文件是否存在
if [ ! -f "$FIRMWARE_FILE" ]; then
  create_sample_firmware
fi

# 執行分析步驟
perform_hexdump_analysis
create_yara_rules
run_yara_rules
run_binwalk_analysis
create_can_log
create_ghidra_notes
create_security_report
create_screenshot_readme

# 檢查目錄結構完整性
check_directory_structure

# 完成
log "SUCCESS" "韌體分析完成，報告已生成: $REPORT_FILE"
echo -e "${BLUE}====================================================================${NC}"
echo -e "${GREEN}                       分析完成                                  ${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "${YELLOW}您可以在以下位置查看報告:${NC}"
echo -e "${YELLOW}  - $REPORT_FILE${NC}"
echo -e "${YELLOW}  - $WORK_DIR/simulated_report.md${NC}"
echo -e "${BLUE}====================================================================${NC}" 