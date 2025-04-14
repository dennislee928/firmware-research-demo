.PHONY: all setup clean simulate-can parse-can help install-deps analyze-with-ghidra

# 載入環境變數
include .env

# 預設目標
all: help

# 安裝 Python 依賴
install-deps:
	@echo "安裝 Python 依賴..."
	@pip3 install -r requirements.txt

# 創建必要目錄
setup: install-deps
	@mkdir -p $(CAN_LOGS_DIR)
	@mkdir -p $(TOOLS_DIR)
	@mkdir -p $(FIRMWARE_DIR)
	@mkdir -p $(YARA_RULES_DIR)
	@mkdir -p $(REPORTS_DIR)
	@mkdir -p $(GHIDRA_DIR)
	@echo "目錄結構已創建完成"

# 清理生成的文件
clean:
	@rm -f $(CAN_LOGS_DIR)/*.txt
	@rm -f $(CAN_LOGS_DIR)/*.json
	@rm -f $(CAN_LOGS_DIR)/*.yaml
	@rm -f $(GHIDRA_DIR)/*.txt
	@echo "已清理所有生成的文件"

# 模擬 CAN 日誌
simulate-can:
	@echo "開始模擬 CAN 日誌..."
	@./automation-scripts/simulate_can_log.sh

# 解析現有的 CAN 日誌
parse-can:
	@echo "解析 CAN 日誌..."
	@find $(CAN_LOGS_DIR) -name "*.txt" -type f -exec python3 $(TOOLS_DIR)/can_log_parser.py {} \;

# 使用 Ghidra 分析韌體
analyze-with-ghidra:
	@echo "開始使用 Ghidra 分析韌體..."
	@./automation-scripts/analyze_with_ghidra.sh

# 顯示幫助信息
help:
	@echo "使用方法："
	@echo "  make setup              - 創建必要的目錄結構並安裝依賴"
	@echo "  make install-deps       - 安裝 Python 依賴"
	@echo "  make simulate-can       - 生成模擬的 CAN 日誌"
	@echo "  make parse-can          - 解析現有的 CAN 日誌"
	@echo "  make analyze-with-ghidra - 使用 Ghidra 分析韌體"
	@echo "  make clean              - 清理生成的文件" 