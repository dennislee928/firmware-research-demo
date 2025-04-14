#!/bin/bash

# 設定目錄
FIRMWARE_DIR="../firmware_samples"
GHIDRA_DIR="../ghidra_projects"
GHIDRA_INSTALL="/path/to/ghidra"  # 請修改為實際的 Ghidra 安裝路徑
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 檢查 Ghidra 是否安裝
if [ ! -d "$GHIDRA_INSTALL" ]; then
    echo "錯誤：Ghidra 未安裝或路徑不正確"
    exit 1
fi

# 檢查目錄是否存在
if [ ! -d "$FIRMWARE_DIR" ]; then
    echo "錯誤：$FIRMWARE_DIR 目錄不存在"
    exit 1
fi

# 創建 Ghidra 專案目錄
mkdir -p "$GHIDRA_DIR"

# 處理所有韌體檔案
for firmware in "$FIRMWARE_DIR"/*.{bin,img,chk}; do
    if [ -f "$firmware" ]; then
        echo "分析韌體: $(basename "$firmware")"
        
        # 創建專案名稱
        project_name="$(basename "$firmware")_$TIMESTAMP"
        project_path="$GHIDRA_DIR/$project_name"
        
        # 創建專案目錄
        mkdir -p "$project_path"
        
        # 執行 Ghidra 分析
        echo "執行 Ghidra 分析..."
        "$GHIDRA_INSTALL/support/analyzeHeadless" \
            "$project_path" \
            "$project_name" \
            -import "$firmware" \
            -postScript ExtractStrings.java \
            -deleteProject
        
        # 檢查執行結果
        if [ $? -eq 0 ]; then
            echo "成功分析: $(basename "$firmware")"
            echo "專案目錄: $project_path"
        else
            echo "錯誤：分析失敗: $(basename "$firmware")"
        fi
    fi
done

echo "所有韌體分析完成" 