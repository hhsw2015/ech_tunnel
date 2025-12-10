#!/bin/bash

# cd ~ && curl -L https://raw.githubusercontent.com/hhsw2015/ech_tunnel/refs/heads/main/install.sh -o install.sh && chmod +x install.sh && ./install.sh

set -e
# === 颜色定义 ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # 清除颜色


CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/download/2025.11.1/cloudflared-linux-amd64"
ECH_TUNNEL_URL="https://github.com/hhsw2015/ech_tunnel/releases/download/v1.0/ech-tunnel-linux-amd64.tar.gz"

cd ~

ROOT_DIR="$HOME/et"
mkdir $ROOT_DIR
CLOUDFLARED_BIN="${ROOT_DIR}/cld"
ECH_TUNNEL_BIN="${ROOT_DIR}/et"
CLOUDFLARED_LOG="${ROOT_DIR}/cld.bin"
ECH_TUNNEL_LOG="${ROOT_DIR}/et.bin"
touch $CLOUDFLARED_LOG
touch $ECH_TUNNEL_LOG

LOCAL_ADDR="127.0.0.1:8889"
ECH_TUNNEL_TOKEN="7bd57098-82bd-4dfa-b32c-9943a52d354f"


# 检查 cloudflared 是否已存在
if [[ -f "$CLOUDFLARED_BIN" ]]; then
    echo -e "${GREEN}已存在文件，跳过下载。${NC}"
else
    echo -e "${BLUE}正在下载 cloudflared...${NC}"
    if ! curl -L "$CLOUDFLARED_URL" -o "$CLOUDFLARED_BIN"; then
        echo -e "${RED}下载失败，请检查网络连接或 URL。${NC}"
        exit 1
    fi
    chmod +x "$CLOUDFLARED_BIN"
fi

if [[ -f "$ECH_TUNNEL_BIN" ]]; then
    echo -e "${GREEN}已存在文件，跳过下载。${NC}"
else
    echo -e "${BLUE}正在下载 ech_tunnel...${NC}"
    if ! curl -L "$ECH_TUNNEL_URL" -o "ech_tunnel.tar.gz"; then
        echo -e "${RED}下载失败，请检查网络连接或 URL。${NC}"
        exit 1
    fi
    tar -xzf ech_tunnel.tar.gz
    rm ech_tunnel.tar.gz
    mv ech-tunnel-linux-amd64 "$ECH_TUNNEL_BIN"
    
    chmod +x "$ECH_TUNNEL_BIN"
fi


echo -e "${BLUE}正在运行 ech_tunnel...${NC}"
nohup $ECH_TUNNEL_BIN -l ws://${LOCAL_ADDR} -token ${ECH_TUNNEL_TOKEN} 2>&1 | tee -a $ECH_TUNNEL_LOG &

echo -e "${BLUE}等待3s...${NC}"
sleep 3

max_retries=3
retry_delay=2
attempt=1

echo "" > $CLOUDFLARED_LOG

echo "[INFO] Starting Cloudflare tunnel..."
attempt=1
while [ $attempt -le $max_retries ]; do
  echo "[INFO] Attempt $attempt/$max_retries to start Cloudflare tunnel..."
  nohup $CLOUDFLARED_BIN tunnel --protocol http2 --no-tls-verify --url http://${LOCAL_ADDR} 2>&1 | tee -a $CLOUDFLARED_LOG &
  sleep 5
  if grep -q 'https://.*\.trycloudflare\.com' "$CLOUDFLARED_LOG"; then
    echo "[SUCCESS] Cloudflare tunnel started successfully"
    break
  else
    echo "[ERROR] Cloudflare tunnel failed to start, cleaning up..."
    pkill -9 cloudflared 2>/dev/null || true
    if [ $attempt -eq $max_retries ]; then
      echo "[ERROR] Failed to start cloudflared after $max_retries attempts"
      exit 1
    fi
    echo "[INFO] Waiting $retry_delay seconds before retry..."
    sleep $retry_delay
    attempt=$((attempt + 1))
  fi
done


# Step 8: Extract and display Cloudflare tunnel URL
echo "[INFO] Checking Cloudflare tunnel URL..."
TUNNEL_URL=$(grep -o 'https://[^ ]*\.trycloudflare\.com' "$CLOUDFLARED_LOG" | head -1 | sed 's/https:\/\///')
if [[ -n "$TUNNEL_URL" ]]; then
  echo "[SUCCESS] Cloudflare tunnel URL: $TUNNEL_URL"
else
  echo "[ERROR] No tunnel URL found in $CLOUDFLARED_LOG."
  exit 1
fi


echo -e "${BLUE}请在客户端运行ech_tunnel...${NC}"
echo "./ech_tunnel -l proxy://127.0.0.1:30007 -f wss://${TUNNEL_URL}:443 -ip 104.16.16.16,104.19.237.82 -token ${ECH_TUNNEL_TOKEN} -n 4"

cd $HOME

rm -rf $ROOT_DIR
rm -rf install.sh
