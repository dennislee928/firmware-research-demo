#!/bin/bash

# 載入環境變數
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../.env"

FIRMWARE_DIR="$SCRIPT_DIR/../$FIRMWARE_DIR"
YARA_RULES_DIR="$SCRIPT_DIR/../$YARA_RULES_DIR"
REPORTS_DIR="$SCRIPT_DIR/../$REPORTS_DIR"

# 檢查 YARA 是否安裝
if ! command -v yara &> /dev/null; then
    echo "錯誤：YARA 未安裝或不在 PATH 中"
    echo "請安裝 YARA：brew install yara"
    exit 1
fi

# 檢查目錄是否存在
if [ ! -d "$FIRMWARE_DIR" ] || [ ! -d "$YARA_RULES_DIR" ]; then
    echo "錯誤：必要的目錄不存在"
    echo "請確保以下目錄存在："
    echo "- $FIRMWARE_DIR"
    echo "- $YARA_RULES_DIR"
    exit 1
fi

# 創建報告目錄
mkdir -p "$REPORTS_DIR"

# 獲取韌體文件
FIRMWARE_FILE=$(find "$FIRMWARE_DIR" -type f \( -name "*.bin" -o -name "*.img" -o -name "*.elf" \) | head -n 1)

if [ -z "$FIRMWARE_FILE" ]; then
    echo "錯誤：未找到韌體文件"
    echo "請在 $FIRMWARE_DIR 目錄中放置韌體文件"
    exit 1
fi

# 生成報告文件名
REPORT_FILE="$REPORTS_DIR/$(basename "$FIRMWARE_FILE")_yara_scan_$(date +%Y%m%d_%H%M%S).md"

# 執行 YARA 掃描
echo "開始 YARA 掃描..."
echo "# YARA 掃描報告" > "$REPORT_FILE"
echo "## 掃描對象: $(basename "$FIRMWARE_FILE")" >> "$REPORT_FILE"
echo "## 掃描時間: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 掃描每個 YARA 規則
for rule_file in "$YARA_RULES_DIR"/*.yar; do
    if [ -f "$rule_file" ]; then
        echo "### 規則: $(basename "$rule_file")" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        yara "$rule_file" "$FIRMWARE_FILE" >> "$REPORT_FILE" 2>&1
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
done

echo "YARA 掃描完成！"
echo "報告已保存至: $REPORT_FILE" 