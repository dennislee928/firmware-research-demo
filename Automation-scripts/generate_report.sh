#!/bin/bash

# 載入環境變數
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../.env"

REPORTS_DIR="$SCRIPT_DIR/../$REPORTS_DIR"
CAN_LOGS_DIR="$SCRIPT_DIR/../$CAN_LOGS_DIR"
FIRMWARE_DIR="$SCRIPT_DIR/../$FIRMWARE_DIR"

# 檢查目錄是否存在
if [ ! -d "$REPORTS_DIR" ] || [ ! -d "$CAN_LOGS_DIR" ] || [ ! -d "$FIRMWARE_DIR" ]; then
    echo "錯誤：必要的目錄不存在"
    echo "請確保以下目錄存在："
    echo "- $REPORTS_DIR"
    echo "- $CAN_LOGS_DIR"
    echo "- $FIRMWARE_DIR"
    exit 1
fi

# 生成報告文件名
REPORT_FILE="$REPORTS_DIR/analysis_report_$(date +%Y%m%d_%H%M%S).md"

# 創建報告
echo "# 韌體分析報告" > "$REPORT_FILE"
echo "## 生成時間: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 添加韌體信息
echo "## 韌體信息" >> "$REPORT_FILE"
FIRMWARE_FILE=$(find "$FIRMWARE_DIR" -type f \( -name "*.bin" -o -name "*.img" -o -name "*.elf" \) | head -n 1)
if [ -n "$FIRMWARE_FILE" ]; then
    echo "- 文件名: $(basename "$FIRMWARE_FILE")" >> "$REPORT_FILE"
    echo "- 大小: $(du -h "$FIRMWARE_FILE" | cut -f1)" >> "$REPORT_FILE"
    echo "- 修改時間: $(stat -f "%Sm" "$FIRMWARE_FILE")" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# 添加 CAN 日誌分析
echo "## CAN 日誌分析" >> "$REPORT_FILE"
LATEST_CAN_LOG=$(find "$CAN_LOGS_DIR" -name "can_log_*.txt" -type f -printf "%T@ %p\n" | sort -n | tail -1 | cut -d' ' -f2-)
if [ -n "$LATEST_CAN_LOG" ]; then
    echo "- 最新日誌: $(basename "$LATEST_CAN_LOG")" >> "$REPORT_FILE"
    echo "- 生成時間: $(stat -f "%Sm" "$LATEST_CAN_LOG")" >> "$REPORT_FILE"
    
    # 添加解析結果
    JSON_FILE="${LATEST_CAN_LOG%.*}_parser_output.json"
    if [ -f "$JSON_FILE" ]; then
        echo "### 解析結果摘要" >> "$REPORT_FILE"
        echo '```json' >> "$REPORT_FILE"
        grep -A 3 "summary" "$JSON_FILE" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
    fi
fi
echo "" >> "$REPORT_FILE"

# 添加 YARA 掃描結果
echo "## YARA 掃描結果" >> "$REPORT_FILE"
LATEST_YARA_REPORT=$(find "$REPORTS_DIR" -name "*_yara_scan_*.md" -type f -printf "%T@ %p\n" | sort -n | tail -1 | cut -d' ' -f2-)
if [ -n "$LATEST_YARA_REPORT" ]; then
    echo "- 最新掃描報告: $(basename "$LATEST_YARA_REPORT")" >> "$REPORT_FILE"
    echo "- 生成時間: $(stat -f "%Sm" "$LATEST_YARA_REPORT")" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "### 掃描結果摘要" >> "$REPORT_FILE"
    cat "$LATEST_YARA_REPORT" | grep -v "^#" >> "$REPORT_FILE"
fi

echo "報告生成完成！"
echo "報告已保存至: $REPORT_FILE" 