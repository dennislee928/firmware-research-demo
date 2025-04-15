#!/bin/bash

# 檢查是否為 macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "錯誤：此腳本僅支援 macOS"
    exit 1
fi

# 檢查是否已安裝 Homebrew
if ! command -v brew &> /dev/null; then
    echo "錯誤：請先安裝 Homebrew (https://brew.sh/)"
    exit 1
fi

echo "開始安裝必要的工具..."

# 安裝基本工具
echo "安裝基本工具..."
brew install yara
brew install binwalk
brew install pyenv
brew install pyenv-virtualenv
brew install pyenv-virtualenvwrapper
brew install git

# 初始化 pyenv
echo "初始化 pyenv..."
if ! grep -q "pyenv init" ~/.zshrc; then
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
    echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
    echo 'eval "$(pyenv init -)"' >> ~/.zshrc
    echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.zshrc
    source ~/.zshrc
fi

# 安裝 Python 依賴
echo "安裝 Python 依賴..."
pip3 install yara-python
pip3 install pyelftools
pip3 install python-magic
pip3 install colorama
pip3 install tqdm

# 創建 requirements.txt
echo "創建 requirements.txt..."
cat > requirements.txt << 'EOL'
yara-python>=4.5.1
pyelftools>=0.32
python-magic>=0.4.27
colorama>=0.4.6
tqdm>=4.67.1
EOL

# 設定 Python 環境
echo "設定 Python 環境..."
if ! pyenv versions | grep -q "3.10.10"; then
    pyenv install 3.10.10
fi

# 創建虛擬環境
echo "創建虛擬環境..."
if ! pyenv versions | grep -q "firmware-analysis"; then
    pyenv virtualenv 3.10.10 firmware-analysis
fi
pyenv local firmware-analysis

# 安裝專案依賴
echo "安裝專案依賴..."
pip3 install -r requirements.txt

# 安裝 volatility3
echo "安裝 volatility3..."
if [ ! -d "tools/volatility3" ]; then
    git clone https://github.com/volatilityfoundation/volatility3.git tools/volatility3
    cd tools/volatility3
    pip3 install -e .
    cd ../..
fi

# 創建必要的目錄結構
echo "創建目錄結構..."
mkdir -p firmware_samples
mkdir -p yara_rules
mkdir -p unpacked
mkdir -p reports
mkdir -p tools
mkdir -p docs

# 複製基本 YARA 規則
echo "設定基本 YARA 規則..."
if [ ! -f "yara_rules/basic_rules.yar" ]; then
    cat > yara_rules/basic_rules.yar << 'EOL'
rule detect_telnetd {
    meta:
        description = "Detect telnetd executable or related strings"
        severity = "high"
    strings:
        $a = "telnetd"
        $b = "telnet server"
    condition:
        any of them
}

rule detect_busybox {
    meta:
        description = "Detect BusyBox executable"
        severity = "medium"
    strings:
        $a = "BusyBox v"
        $b = "applets:"
    condition:
        all of them
}

rule detect_libcrypto {
    meta:
        description = "Detect usage of libcrypto (OpenSSL)"
        severity = "medium"
    strings:
        $a = "OpenSSL"
        $b = "libcrypto.so"
    condition:
        any of them
}
EOL
fi

# 創建測試韌體檔案
echo "創建測試韌體檔案..."
if [ ! -f "firmware_samples/test_firmware.bin" ]; then
    cat > firmware_samples/test_firmware.bin << 'EOL'
This is a test firmware file.
It contains some test strings:
- BusyBox v1.0.0
- applets: ls, cat, echo
- OpenSSL 1.1.1
- libcrypto.so.1.1
EOL
fi

# 設定環境變數
echo "設定環境變數..."
cat > .env << 'EOL'
# 預設目錄設定
CAN_LOGS_DIR=can_logs
TOOLS_DIR=tools
FIRMWARE_DIR=firmware_samples
YARA_RULES_DIR=yara_rules
REPORTS_DIR=reports
# 工具路徑
VOLATILITY3_PATH=tools/volatility3
EOL

# 創建報告目錄結構
echo "創建報告目錄結構..."
mkdir -p reports/{raw,processed,summary}

# 更新 pip
echo "更新 pip..."
python -m pip install --upgrade pip

# 執行分析腳本
echo "執行分析腳本..."
chmod +x scripts/firmware_analyzer.py
python scripts/firmware_analyzer.py

# 查看分析結果
echo "查看分析結果..."
echo -e "\n${Fore.CYAN}[*] 分析結果摘要${Style.RESET_ALL}"
echo "原始分析結果："
ls -l reports/raw/
echo -e "\n處理後結果："
ls -l reports/processed/
echo -e "\n總結報告："
ls -l reports/summary/

echo -e "\n${Fore.GREEN}安裝和分析完成！${Style.RESET_ALL}"
echo "請執行以下命令來啟動虛擬環境："
echo "source ~/.zshrc"
echo "pyenv activate firmware-analysis"
