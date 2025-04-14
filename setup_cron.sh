#!/bin/bash

# 設置cron任務，每30分鐘執行一次韌體分析腳本
# 作者：Dennis Lee
# 版本：1.1

# 獲取當前目錄的絕對路徑
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
FIRMWARE_ANALYZER="$SCRIPT_DIR/firmware_analyzer.sh"
LOG_DIR="$SCRIPT_DIR/logs"
CRON_LOG="$LOG_DIR/cron_execution.log"

# 確保日誌目錄存在
mkdir -p "$LOG_DIR"

# 確保腳本有執行權限
chmod +x "$FIRMWARE_ANALYZER"

# 顯示腳本信息
echo "==== 設置韌體分析自動化排程 ===="
echo "分析腳本路徑: $FIRMWARE_ANALYZER"
echo "日誌目錄: $LOG_DIR"

# 臨時crontab文件
TEMP_CRON=$(mktemp)

# 提取現有的crontab
crontab -l > "$TEMP_CRON" 2>/dev/null || echo "# 新建crontab文件" > "$TEMP_CRON"

# 檢查是否已經有相同的cron任務
if ! grep -q "$FIRMWARE_ANALYZER" "$TEMP_CRON"; then
  echo "添加新的cron任務，每30分鐘執行一次..."
  
  # 添加新的cron任務，每30分鐘執行一次，並記錄日期時間
  echo "*/30 * * * * cd $SCRIPT_DIR && $FIRMWARE_ANALYZER >> $CRON_LOG 2>&1" >> "$TEMP_CRON"
  
  # 每天午夜輪替日誌文件
  echo "0 0 * * * cd $SCRIPT_DIR && mv $CRON_LOG ${CRON_LOG}_\$(date +\%Y\%m\%d) && touch $CRON_LOG" >> "$TEMP_CRON"
  
  # 安裝新的crontab
  crontab "$TEMP_CRON"
  
  echo "✅ 成功設置cron任務，每30分鐘執行一次韌體分析腳本"
  echo "✅ 已設置每日日誌輪替"
else
  echo "⚠️ cron任務已經存在，無需重新設置"
  echo "若要更新現有任務，請先執行: crontab -e 手動編輯或刪除現有任務"
fi

# 清理臨時文件
rm -f "$TEMP_CRON"

echo "您可以使用以下命令查看當前的cron任務:"
echo "  crontab -l"
echo ""
echo "您可以使用以下命令查看cron執行日誌:"
echo "  tail -f $CRON_LOG" 