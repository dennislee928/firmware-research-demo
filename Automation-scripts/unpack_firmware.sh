#!/bin/bash

# 設定目錄
FIRMWARE_DIR="../firmware_samples"
OUTPUT_DIR="../unpacked"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 檢查目錄是否存在
if [ ! -d "$FIRMWARE_DIR" ]; then
    echo "錯誤：$FIRMWARE_DIR 目錄不存在"
    exit 1
fi

# 創建輸出目錄
mkdir -p "$OUTPUT_DIR"

# 處理所有韌體檔案
for firmware in "$FIRMWARE_DIR"/*.{bin,img,chk}; do
    if [ -f "$firmware" ]; then
        echo "處理韌體: $(basename "$firmware")"
        
        # 創建時間戳記目錄
        output_path="$OUTPUT_DIR/$(basename "$firmware")_$TIMESTAMP"
        mkdir -p "$output_path"
        
        # 執行 binwalk
        echo "執行 binwalk..."
        binwalk -eM -C "$output_path" "$firmware"
        
        # 檢查執行結果
        if [ $? -eq 0 ]; then
            echo "成功解包: $(basename "$firmware")"
            echo "輸出目錄: $output_path"
        else
            echo "錯誤：解包失敗: $(basename "$firmware")"
        fi
    fi
done

echo "所有韌體處理完成" 