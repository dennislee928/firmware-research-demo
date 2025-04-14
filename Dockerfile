FROM ubuntu:22.04

# 元數據標籤
LABEL maintainer="Dennis Lee"
LABEL version="1.2"
LABEL description="韌體分析環境，包含binwalk、hexdump、YARA和Next.js前端界面"

# 避免交互式提示
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Taipei
ENV NODE_VERSION=18.x

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
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# 安裝分析工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    util-linux \
    yara \
    python3 \
    python3-pip \
    tshark \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# 安裝Node.js和npm
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION} | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# 檢查Node.js和npm版本
RUN node -v && npm -v
# 先apt-get update前添加簽名
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/* \
    && apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 871920D1991BC93C

# 再嘗試安裝dmg2img
RUN apt-get update && apt-get install -y dmg2img

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
    /firmware-analysis/logs \
    /firmware-analysis/webapp

# 複製腳本和配置文件
COPY firmware_analyzer.sh setup_cron.sh README.md /firmware-analysis/

# 複製YARA規則
# 先創建一個空的規則文件，確保目錄非空
RUN touch /firmware-analysis/yara-rules/empty.yar

# 如果存在yara-rules目錄，則複製其內容
COPY yara-rules/ /firmware-analysis/yara-rules/

# 設置腳本執行權限
RUN chmod +x /firmware-analysis/firmware_analyzer.sh /firmware-analysis/setup_cron.sh

# 創建一個示例韌體文件
RUN echo -e "#!/bin/bash\necho 'This is a demo firmware'\ntelnetd -p 2323\ndropbear -p 22\n" > /firmware-analysis/firmware.bin

# 建立前端應用
WORKDIR /firmware-analysis/webapp

# 初始化 Next.js 應用
RUN npm init -y && \
    npm install next@13 react@18 react-dom@18 axios formidable tailwindcss postcss autoprefixer

# 建立 Next.js 目錄結構
RUN mkdir -p pages api public styles components

# 設置健康檢查
HEALTHCHECK --interval=5m --timeout=3s \
  CMD test -f /firmware-analysis/firmware.bin || exit 1

# 暴露前端界面端口
EXPOSE 3000

# 複製 Next.js 應用程式
COPY webapp/ /firmware-analysis/webapp/

# 回到主工作目錄
WORKDIR /firmware-analysis

# 建立啟動腳本
RUN echo '#!/bin/bash\ncd /firmware-analysis/webapp\nnpm run dev & cd /firmware-analysis\nexec "$@"' > /firmware-analysis/start.sh && \
    chmod +x /firmware-analysis/start.sh

# 設置入口點
ENTRYPOINT ["/firmware-analysis/start.sh"]

# 默認命令：執行分析後保持容器運行
CMD ["tail", "-f", "/dev/null"] 