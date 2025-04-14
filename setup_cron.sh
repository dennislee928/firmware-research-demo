#!/bin/bash

# 設置cron任務，每30分鐘執行一次韌體分析腳本

# 獲取當前目錄的絕對路徑
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
FIRMWARE_ANALYZER="$SCRIPT_DIR/firmware_analyzer.sh"

# 確保腳本有執行權限
chmod +x "$FIRMWARE_ANALYZER"

# 臨時crontab文件
TEMP_CRON=$(mktemp)

# 提取現有的crontab
crontab -l > "$TEMP_CRON" 2>/dev/null

# 檢查是否已經有相同的cron任務
if ! grep -q "$FIRMWARE_ANALYZER" "$TEMP_CRON"; then
  # 添加新的cron任務，每30分鐘執行一次
  echo "*/30 * * * * $FIRMWARE_ANALYZER >> $SCRIPT_DIR/cron_execution.log 2>&1" >> "$TEMP_CRON"
  
  # 安裝新的crontab
  crontab "$TEMP_CRON"
  
  echo "成功設置cron任務，每30分鐘執行一次韌體分析腳本"
else
  echo "cron任務已經存在，無需重新設置"
fi

# 清理臨時文件
rm -f "$TEMP_CRON"

echo "您可以使用 'crontab -l' 命令查看當前的cron任務" 