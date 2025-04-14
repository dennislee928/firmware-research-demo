#!/bin/bash

# 設定目錄
RULES_DIR="../yara_rules"
FIRMWARE_DIR="../firmware_samples"
REPORTS_DIR="../reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 檢查目錄是否存在
if [ ! -d "$RULES_DIR" ] || [ ! -d "$FIRMWARE_DIR" ]; then
    echo "錯誤：必要的目錄不存在"
    exit 1
fi

# 創建報告目錄
mkdir -p "$REPORTS_DIR"

# 編譯所有 YARA 規則
echo "編譯 YARA 規則..."
for rule in "$RULES_DIR"/*.yar; do
    if [ -f "$rule" ]; then
        echo "編譯規則: $(basename "$rule")"
        yara -C "$rule" || echo "警告：規則編譯失敗: $(basename "$rule")"
    fi
done

# 掃描所有韌體
for firmware in "$FIRMWARE_DIR"/*.{bin,img,chk}; do
    if [ -f "$firmware" ]; then
        echo "掃描韌體: $(basename "$firmware")"
        
        # 創建報告檔案
        report_file="$REPORTS_DIR/$(basename "$firmware")_yara_scan_$TIMESTAMP.md"
        echo "# YARA 掃描報告 - $(basename "$firmware")" > "$report_file"
        echo "掃描時間: $(date)" >> "$report_file"
        echo "" >> "$report_file"
        
        # 對每個規則執行掃描
        for rule in "$RULES_DIR"/*.yar; do
            if [ -f "$rule" ]; then
                echo "## $(basename "$rule")" >> "$report_file"
                echo "執行規則: $(basename "$rule")"
                
                # 執行 YARA 掃描
                yara "$rule" "$firmware" >> "$report_file" 2>&1
                echo "" >> "$report_file"
            fi
        done
        
        echo "報告已生成: $report_file"
    fi
done

echo "所有掃描完成" 