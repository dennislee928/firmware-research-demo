FROM node:18-slim AS builder

WORKDIR /app/webapp
COPY webapp/package*.json ./
RUN npm install

COPY webapp/ .
RUN npm run build

FROM ubuntu:22.04

LABEL maintainer="Dennis Lee"
LABEL version="1.3"

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Taipei

WORKDIR /firmware-analysis

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    unzip \
    file \
    cron \
    gnupg \
    binwalk \
    util-linux \
    yara \
    python3 \
    python3-pip \
    xxd \
    dmg2img \
    p7zip-full \
    xar \
    genisoimage \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (needed for running the app, but we used slim for builder)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Python tools
RUN pip3 install --no-cache-dir \
    pyyaml \
    colorlog \
    requests \
    python-magic

# Create directory structure
RUN mkdir -p /firmware-analysis/binwalk-analysis \
    /firmware-analysis/hexdump-analysis \
    /firmware-analysis/yara-rules \
    /firmware-analysis/screenshots/ghidra \
    /firmware-analysis/firmware_samples \
    /firmware-analysis/reports \
    /firmware-analysis/logs

# Copy scripts
COPY firmware_analyzer.sh setup_cron.sh README.md /firmware-analysis/
RUN chmod +x /firmware-analysis/firmware_analyzer.sh /firmware-analysis/setup_cron.sh

# Copy YARA rules
COPY yara-rules/ /firmware-analysis/yara-rules/

# Copy webapp from builder
COPY --from=builder /app/webapp /firmware-analysis/webapp

# Create startup script
RUN echo '#!/bin/bash\n\
# Start cron in background\n\
service cron start\n\
\n\
echo "Starting Next.js app on port 3000..."\n\
cd /firmware-analysis/webapp\n\
# Use exec to make npm the primary process for better signal handling\n\
export PORT=3000\n\
export HOSTNAME=0.0.0.0\n\
exec npm run start' > /firmware-analysis/start.sh && \
    chmod +x /firmware-analysis/start.sh

# Create dummy firmware if not exists
RUN echo -e "#!/bin/bash\necho 'This is a demo firmware'\ntelnetd -p 2323\ndropbear -p 22\n" > /firmware-analysis/firmware.bin

EXPOSE 3000

ENTRYPOINT ["/firmware-analysis/start.sh"]
