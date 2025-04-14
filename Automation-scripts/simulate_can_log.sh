#!/bin/bash

# 設定目錄
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAN_LOGS_DIR="$SCRIPT_DIR/../can_logs"
TOOLS_DIR="$SCRIPT_DIR/../tools"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 檢查目錄是否存在
if [ ! -d "$CAN_LOGS_DIR" ] || [ ! -d "$TOOLS_DIR" ]; then
    echo "錯誤：必要的目錄不存在"
    echo "請確保以下目錄存在："
    echo "- $CAN_LOGS_DIR"
    echo "- $TOOLS_DIR"
    exit 1
fi

# 生成 CAN 日誌
echo "生成 CAN 日誌..."
log_file="$CAN_LOGS_DIR/can_log_$TIMESTAMP.txt"

# 獲取當前時間戳（兼容 macOS）
get_timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

# 生成示例 CAN 訊息
cat > "$log_file" << EOF
# CAN Bus 日誌示例
# 時間戳, CAN ID, 數據長度, 數據

$(get_timestamp), 0x123, 8, 01 02 03 04 05 06 07 08
$(get_timestamp), 0x456, 4, AA BB CC DD
$(get_timestamp), 0x789, 2, FF EE
$(get_timestamp), 0xABC, 8, 11 22 33 44 55 66 77 88
$(get_timestamp), 0xDEF, 1, 99

# 錯誤示例
$(get_timestamp), 0x123, 8, FF FF FF FF FF FF FF FF  # 錯誤：數據長度不匹配
$(get_timestamp), 0x456, 4, XX YY ZZ WW  # 錯誤：無效數據

# 正常通訊
$(get_timestamp), 0x789, 2, 00 00
$(get_timestamp), 0xABC, 8, 00 00 00 00 00 00 00 00
$(get_timestamp), 0xDEF, 1, 00
EOF

echo "CAN 日誌已生成: $log_file"

# 執行 Python 解析器
echo "執行 CAN 日誌解析器..."
python3 "$TOOLS_DIR/can_log_parser.py" "$log_file"

# 檢查執行結果
if [ $? -eq 0 ]; then
    echo "CAN 日誌解析完成"
    echo "輸出檔案:"
    echo "- ${log_file%.*}_parser_output.json"
    echo "- ${log_file%.*}_anomaly_flags.yaml"
else
    echo "錯誤：CAN 日誌解析失敗"
fi 