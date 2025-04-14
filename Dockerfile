FROM ubuntu:22.04

# 元數據標籤
LABEL maintainer="Dennis Lee"
LABEL version="1.1"
LABEL description="韌體分析環境，包含binwalk、hexdump和YARA等工具"

# 避免交互式提示
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Taipei

# 設置工作目錄
WORKDIR /firmware-analysis

# 安裝必要工具 (分層安裝以優化緩存)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    unzip \
    file \
    cron \
    && rm -rf /var/lib/apt/lists/*

# 安裝分析工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    hexdump \
    yara \
    python3 \
    python3-pip \
    tshark \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# 安裝Python工具
RUN pip3 install --no-cache-dir \
    pyyaml \
    colorlog \
    requests \
    python-magic

# 創建必要的目錄結構
RUN mkdir -p /firmware-analysis/binwalk-analysis \
    /firmware-analysis/hexdump-analysis \
    /firmware-analysis/yara-rules \
    /firmware-analysis/screenshots/ghidra \
    /firmware-analysis/firmware_samples \
    /firmware-analysis/reports \
    /firmware-analysis/logs

# 複製腳本和配置文件
COPY firmware_analyzer.sh setup_cron.sh README.md /firmware-analysis/

# 複製YARA規則（如果存在）
COPY yara-rules/*.yar /firmware-analysis/yara-rules/ 2>/dev/null || :

# 設置腳本執行權限
RUN chmod +x /firmware-analysis/firmware_analyzer.sh /firmware-analysis/setup_cron.sh

# 創建一個示例韌體文件
RUN echo -e "#!/bin/bash\necho 'This is a demo firmware'\ntelnetd -p 2323\ndropbear -p 22\n" > /firmware-analysis/firmware.bin

# 設置健康檢查
HEALTHCHECK --interval=5m --timeout=3s \
  CMD test -f /firmware-analysis/firmware.bin || exit 1

# 初始化cron（可選）
# RUN /firmware-analysis/setup_cron.sh

# 暴露端口（若有Web界面可取消注釋）
# EXPOSE 8080

# 設置使用非root用戶執行（可選，提高安全性）
# RUN groupadd -r firmware && useradd -r -g firmware firmware
# RUN chown -R firmware:firmware /firmware-analysis
# USER firmware

# 設置入口點
ENTRYPOINT ["/bin/bash", "-c"]

# 默認命令：執行分析後保持容器運行
CMD ["/firmware-analysis/firmware_analyzer.sh && tail -f /dev/null"] 