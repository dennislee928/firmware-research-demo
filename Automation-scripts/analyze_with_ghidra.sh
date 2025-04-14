#!/bin/bash

# 設定目錄
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIRMWARE_DIR="$SCRIPT_DIR/../firmware_samples"
GHIDRA_DIR="$SCRIPT_DIR/../ghidra_projects"

# 檢查 Ghidra 是否安裝
if ! command -v analyzeHeadless &> /dev/null; then
    echo "錯誤：Ghidra 未安裝或不在 PATH 中"
    echo "請確保 Ghidra 已正確安裝並設置環境變數"
    exit 1
fi

# 檢查目錄是否存在
if [ ! -d "$FIRMWARE_DIR" ]; then
    echo "錯誤：韌體目錄不存在"
    echo "請確保以下目錄存在："
    echo "- $FIRMWARE_DIR"
    exit 1
fi

# 創建 Ghidra 專案目錄
mkdir -p "$GHIDRA_DIR"

# 獲取韌體文件
FIRMWARE_FILE=$(find "$FIRMWARE_DIR" -type f \( -name "*.bin" -o -name "*.img" -o -name "*.elf" \) | head -n 1)

if [ -z "$FIRMWARE_FILE" ]; then
    echo "錯誤：未找到韌體文件"
    echo "請在 $FIRMWARE_DIR 目錄中放置韌體文件"
    exit 1
fi

# 生成專案名稱
PROJECT_NAME=$(basename "$FIRMWARE_FILE" | cut -d. -f1)
PROJECT_PATH="$GHIDRA_DIR/$PROJECT_NAME"

echo "開始分析韌體: $FIRMWARE_FILE"
echo "專案將保存在: $PROJECT_PATH"

# 執行 Ghidra 分析
analyzeHeadless "$PROJECT_PATH" "$PROJECT_NAME" \
    -import "$FIRMWARE_FILE" \
    -postScript ExtractStrings.java \
    -scriptPath "$SCRIPT_DIR/../tools" \
    -deleteProject

if [ $? -eq 0 ]; then
    echo "分析完成！"
    echo "結果保存在: $PROJECT_PATH"
else
    echo "錯誤：分析失敗"
fi 