#!/bin/bash
#===============================================================================
# 發布Docker映像到Docker Hub的自動化腳本
# 作者: Dennis Lee
# 版本: 1.0
#===============================================================================

# 嚴格模式
set -euo pipefail

# 顏色代碼
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置(可修改)
DOCKER_USERNAME=${DOCKER_USERNAME:-dennislee928}
IMAGE_NAME="firmware-analyzer"
VERSION="1.0"
LATEST=true

# 標題
echo -e "${BLUE}====================================================================${NC}"
echo -e "${GREEN}              發布韌體分析Docker映像到Docker Hub               ${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "${YELLOW}Docker用戶名: ${DOCKER_USERNAME}${NC}"
echo -e "${YELLOW}映像名稱: ${IMAGE_NAME}${NC}"
echo -e "${YELLOW}版本: ${VERSION}${NC}"
echo -e "${BLUE}====================================================================${NC}"

# 檢查Docker是否安裝
if ! command -v docker &> /dev/null; then
    echo -e "${RED}錯誤: Docker未安裝，請先安裝Docker${NC}"
    exit 1
fi

# 檢查是否已登入Docker Hub
echo -e "${YELLOW}檢查Docker Hub登入狀態...${NC}"
if ! docker info | grep -q "Username"; then
    echo -e "${YELLOW}請登入Docker Hub...${NC}"
    docker login
else
    echo -e "${GREEN}已登入Docker Hub${NC}"
fi

# 構建Docker映像
echo -e "${YELLOW}開始構建Docker映像...${NC}"
docker build -t "${DOCKER_USERNAME}/${IMAGE_NAME}:${VERSION}" .

# 標記為latest版本（如果需要）
if [ "$LATEST" = true ]; then
    echo -e "${YELLOW}標記為latest版本...${NC}"
    docker tag "${DOCKER_USERNAME}/${IMAGE_NAME}:${VERSION}" "${DOCKER_USERNAME}/${IMAGE_NAME}:latest"
fi

# 推送到Docker Hub
echo -e "${YELLOW}推送映像到Docker Hub...${NC}"
docker push "${DOCKER_USERNAME}/${IMAGE_NAME}:${VERSION}"

if [ "$LATEST" = true ]; then
    echo -e "${YELLOW}推送latest版本...${NC}"
    docker push "${DOCKER_USERNAME}/${IMAGE_NAME}:latest"
fi

# 完成
echo -e "${BLUE}====================================================================${NC}"
echo -e "${GREEN}                     發布完成                                   ${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "${YELLOW}映像已成功推送到Docker Hub:${NC}"
echo -e "${YELLOW}  - ${DOCKER_USERNAME}/${IMAGE_NAME}:${VERSION}${NC}"
if [ "$LATEST" = true ]; then
    echo -e "${YELLOW}  - ${DOCKER_USERNAME}/${IMAGE_NAME}:latest${NC}"
fi
echo -e "${YELLOW}您可以使用以下命令拉取此映像:${NC}"
echo -e "${GREEN}  docker pull ${DOCKER_USERNAME}/${IMAGE_NAME}:latest${NC}"
echo -e "${BLUE}====================================================================${NC}" 