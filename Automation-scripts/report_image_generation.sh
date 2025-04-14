#!/bin/bash

# 載入環境變數
source .env

# 檢查依賴
if ! command -v gnuplot &> /dev/null; then
    echo "錯誤：需要安裝 gnuplot"
    echo "請執行：brew install gnuplot"
    exit 1
fi

# 設置時間戳
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="$REPORTS_DIR/analysis_report_${TIMESTAMP}.png"

# 從最新的 MD 報告中提取數據
LATEST_REPORT=$(ls -t "$REPORTS_DIR"/*.md | head -n1)

echo "正在從報告生成圖表：$LATEST_REPORT"

# 創建臨時數據文件
TMP_DATA="/tmp/report_data_$TIMESTAMP.txt"

# 提取數據
{
    echo "# 分析項目統計"
    grep -A5 "## 分析統計" "$LATEST_REPORT" | tail -n5 | sed 's/- //'
} > "$TMP_DATA"

# 生成 gnuplot 腳本
cat << EOF > /tmp/plot_script.gnu
set terminal pngcairo enhanced font "Arial,12" size 800,600
set output "$OUTPUT_FILE"
set style data histograms
set style fill solid 1.0
set title "韌體分析報告統計"
set ylabel "數量"
set xtics rotate by -45
set grid ytics
plot "$TMP_DATA" using 2:xtic(1) title "分析項目" linecolor rgb "#4488CC"
EOF

# 執行 gnuplot
gnuplot /tmp/plot_script.gnu

# 清理臨時文件
rm -f "$TMP_DATA" /tmp/plot_script.gnu

if [ -f "$OUTPUT_FILE" ]; then
    echo "圖表已生成：$OUTPUT_FILE"
else
    echo "錯誤：圖表生成失敗"
    exit 1
fi
