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

# 檢查 Ghidra
check_ghidra() {
    if [ ! -d "$GHIDRA_INSTALL_PATH" ]; then
        echo "警告：Ghidra 未安裝或路徑不正確"
        echo "將跳過 Ghidra 分析步驟"
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
    
    # 檢查 Ghidra
    GHIDRA_AVAILABLE=0
    check_ghidra && GHIDRA_AVAILABLE=1
    
    echo "環境檢查完成，開始執行分析流程..."
    
    # 執行分析流程
    make clean && \
    make setup && \
    make simulate-can
    
    # 只在 Ghidra 可用時執行 Ghidra 分析
    if [ $GHIDRA_AVAILABLE -eq 1 ]; then
        make analyze-with-ghidra
    fi
    
    # 繼續執行其他步驟
    make run-yara-scan && \
    make generate-report
    
    if [ $? -eq 0 ]; then
        echo "分析流程完成！"
        if [ $GHIDRA_AVAILABLE -eq 0 ]; then
            echo "注意：Ghidra 分析步驟被跳過"
        fi
    else
        echo "錯誤：分析流程失敗"
        exit 1
    fi
}

# 執行主程序
main