FROM ubuntu:22.04

# 避免交互式提示
ENV DEBIAN_FRONTEND=noninteractive

# 設置工作目錄
WORKDIR /firmware-analysis

# 安裝必要工具
RUN apt-get update && apt-get install -y \
    binwalk \
    hexdump \
    yara \
    wget \
    unzip \
    file \
    cron \
    iproute2 \
    tshark \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# 安裝Python工具
RUN pip3 install --no-cache-dir \
    pyyaml \
    colorlog \
    requests

# 創建必要的目錄結構
RUN mkdir -p /firmware-analysis/binwalk-analysis \
    /firmware-analysis/hexdump-analysis \
    /firmware-analysis/yara-rules \
    /firmware-analysis/screenshots/ghidra

# 複製腳本和配置文件
COPY firmware_analyzer.sh /firmware-analysis/
COPY setup_cron.sh /firmware-analysis/
COPY README.md /firmware-analysis/

# 設置腳本執行權限
RUN chmod +x /firmware-analysis/firmware_analyzer.sh
RUN chmod +x /firmware-analysis/setup_cron.sh

# 暴露端口（若有Web界面可取消注釋）
# EXPOSE 8080

# 設置入口點
ENTRYPOINT ["/bin/bash", "-c"]

# 默認命令
CMD ["/firmware-analysis/firmware_analyzer.sh && tail -f /dev/null"]

# 元數據
LABEL maintainer="Dennis Lee"
LABEL version="1.0"
LABEL description="韌體分析環境，包含binwalk、hexdump和YARA等工具" 