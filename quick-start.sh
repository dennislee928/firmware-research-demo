#!/bin/bash

# 載入環境變數
source .env

# 檢查必要的目錄
check_directories() {
    local dirs=("$CAN_LOGS_DIR" "$TOOLS_DIR" "$FIRMWARE_DIR" "$YARA_RULES_DIR" "$REPORTS_DIR")
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            echo "錯誤：目錄 $dir 不存在"
            return 1
        fi
    done
    return 0
}

# 檢查必要的工具
echo "開始環境檢查..."

# 檢查 Ghidra
if [ -f "/opt/homebrew/bin/ghidraRun" ]; then
    echo "Ghidra 已安裝"
    GHIDRA_INSTALLED=true
else
    echo "警告：Ghidra 未安裝或路徑不正確"
    echo "將跳過 Ghidra 分析步驟"
    GHIDRA_INSTALLED=false
fi

# 檢查其他工具
if ! command -v python3 &> /dev/null; then
    echo "錯誤：Python 3 未安裝"
    exit 1
fi

if ! command -v yara &> /dev/null; then
    echo "錯誤：YARA 未安裝"
    exit 1
fi

if ! command -v gnuplot &> /dev/null; then
    echo "警告：gnuplot 未安裝，將無法生成報表圖片"
    echo "請執行：brew install gnuplot"
    GNUPLOT_INSTALLED=false
else
    GNUPLOT_INSTALLED=true
fi

# 檢查必要的工具
check_tools() {
    local tools=("python3" "pip3" "make")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "錯誤：$tool 未安裝或不在 PATH 中"
            return 1
        fi
    done
    return 0
}

# 檢查 Python 依賴
check_python_deps() {
    if ! pip3 show pyyaml &> /dev/null || ! pip3 show python-can &> /dev/null; then
        echo "警告：缺少必要的 Python 依賴"
        echo "正在安裝依賴..."
        pip3 install -r requirements.txt
        if [ $? -ne 0 ]; then
            echo "錯誤：安裝 Python 依賴失敗"
            return 1
        fi
    fi
    return 0
}

# 檢查韌體文件
check_firmware() {
    if [ ! -d "$FIRMWARE_DIR" ] || [ -z "$(find "$FIRMWARE_DIR" -type f \( -name "*.bin" -o -name "*.img" -o -name "*.elf" \))" ]; then
        echo "警告：未找到韌體文件"
        echo "請在 $FIRMWARE_DIR 目錄中放置韌體文件"
        return 1
    fi
    return 0
}

# 主程序
main() {
    echo "開始環境檢查..."
    
    # 執行基本檢查
    check_directories || exit 1
    check_tools || exit 1
    check_python_deps || exit 1
    check_firmware || exit 1
    
    echo "環境檢查完成，開始執行分析流程..."
    
    # 清理舊文件
    make clean

    # 安裝依賴
    make install-deps

    # 創建目錄結構
    make setup

    # 模擬 CAN 日誌
    make simulate-can

    # 解析 CAN 日誌
    make parse-can

    # 執行 YARA 掃描
    make run-yara-scan

    # 如果 Ghidra 已安裝，執行 Ghidra 分析
    if [ "$GHIDRA_INSTALLED" = true ]; then
        make analyze-with-ghidra
    fi

    # 生成報告
    make generate-report

    # 如果 gnuplot 已安裝，生成報表圖片
    if [ "$GNUPLOT_INSTALLED" = true ]; then
        make generate-report-image
    fi
    
    if [ $? -eq 0 ]; then
        echo "分析流程完成！"
        if [ "$GHIDRA_INSTALLED" = false ]; then
            echo "注意：Ghidra 分析步驟被跳過"
        fi
        if [ "$GNUPLOT_INSTALLED" = false ]; then
            echo "注意：報表圖片生成步驟被跳過"
        fi
    else
        echo "錯誤：分析流程失敗"
        exit 1
    fi
}

# 執行主程序
main