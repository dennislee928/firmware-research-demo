.PHONY: all setup clean simulate-can parse-can help

# 載入環境變數
include .env

# 預設目標
all: help

# 創建必要目錄
setup:
	@mkdir -p $(CAN_LOGS_DIR)
	@mkdir -p $(TOOLS_DIR)
	@mkdir -p $(FIRMWARE_DIR)
	@mkdir -p $(YARA_RULES_DIR)
	@mkdir -p $(REPORTS_DIR)
	@echo "目錄結構已創建完成"

# 清理生成的文件
clean:
	@rm -f $(CAN_LOGS_DIR)/*.txt
	@rm -f $(CAN_LOGS_DIR)/*.json
	@rm -f $(CAN_LOGS_DIR)/*.yaml
	@echo "已清理所有生成的文件"

# 模擬 CAN 日誌
simulate-can:
	@echo "開始模擬 CAN 日誌..."
	@./automation-scripts/simulate_can_log.sh

# 解析現有的 CAN 日誌
parse-can:
	@echo "解析 CAN 日誌..."
	@find $(CAN_LOGS_DIR) -name "*.txt" -type f -exec python3 $(TOOLS_DIR)/can_log_parser.py {} \;

# 顯示幫助信息
help:
	@echo "使用方法："
	@echo "  make setup        - 創建必要的目錄結構"
	@echo "  make simulate-can - 生成模擬的 CAN 日誌"
	@echo "  make parse-can    - 解析現有的 CAN 日誌"
	@echo "  make clean        - 清理生成的文件" 