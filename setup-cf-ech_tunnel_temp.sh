#!/bin/bash

set -e
# === 颜色定义 ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # 清除颜色


CLOUDFLARE_URL=""
CLOUDFLARE_TOKEN=""

CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/download/2025.11.1/cloudflared-linux-amd64"
ECH_TUNNEL_URL="https://github.com/hhsw2015/ech_tunnel/releases/download/v1.0/ech-tunnel-linux-amd64.tar.gz"
ECH_TUNNEL_BIN_NAME="ech-tunnel-linux-amd64"
CLOUDFLARED_PROTOCOL=""

HOME_DIR="/home/container"
ARCH=$(uname -m)

if [[ "$ARCH" == "aarch64" ]]; then
  CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/download/2025.11.1/cloudflared-linux-arm64"
  ECH_TUNNEL_URL="https://github.com/hhsw2015/ech_tunnel/releases/download/v1.0/ech-tunnel-linux-arm64.tar.gz"
  ECH_TUNNEL_BIN_NAME="ech-tunnel-linux-arm64"
  CLOUDFLARED_PROTOCOL="--protocol http2"
fi
echo "HOME_DIR: $HOME_DIR"

mkdir -p $HOME_DIR
ROOT_DIR="$HOME_DIR/ech_tunnel_temp"
mkdir -p $ROOT_DIR
cd $ROOT_DIR
CLOUDFLARED_BIN="${ROOT_DIR}/cloudflared"
ECH_TUNNEL_BIN="${ROOT_DIR}/ech_tunnel"
CLOUDFLARED_LOG="${ROOT_DIR}/cloudflared.log"
ECH_TUNNEL_LOG="${ROOT_DIR}/ech_tunnel.log"
touch $CLOUDFLARED_LOG
touch $ECH_TUNNEL_LOG

LOCAL_ADDR="127.0.0.1:8889"
ECH_TUNNEL_TOKEN="7bd57098-82bd-4dfa-b32c-9943a52d354f"

TMUX_CLOUDFLARED="ech_cloudflared_temp"
TMUX_ECH_TUNNEL="ech_tunnel_temp"

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
    mv $ECH_TUNNEL_BIN_NAME "$ECH_TUNNEL_BIN"
    
    chmod +x "$ECH_TUNNEL_BIN"
fi

echo -e "${BLUE}正在运行 ech_tunnel...${NC}"

if command -v tmux &> /dev/null
then
    tmux kill-session -t "$TMUX_ECH_TUNNEL" 2>/dev/null || true
    tmux new-session -d -s "$TMUX_ECH_TUNNEL" "$ECH_TUNNEL_BIN -l ws://${LOCAL_ADDR} -token ${ECH_TUNNEL_TOKEN} 2>&1 | tee -a $ECH_TUNNEL_LOG"
else
    nohup $ECH_TUNNEL_BIN -l ws://$LOCAL_ADDR -token $ECH_TUNNEL_TOKEN > /dev/null 2>&1 &
    # nohup /home/appuser/ech_tunnel_temp/ech_tunnel -l ws://127.0.0.1:8888 -token 7bd57098-82bd-4dfa-b32c-9943a52d354f 2>&1 | tee -a /home/appuser/ech_tunnel_temp/ech_tunnel.log &

fi



echo -e "${BLUE}等待3s...${NC}"
sleep 3

if command -v tmux &> /dev/null
then
    tmux kill-session -t "$TMUX_CLOUDFLARED" 2>/dev/null || true
fi

TUNNEL_URL=""

if [[ -n "$CLOUDFLARE_URL" && -n "$CLOUDFLARE_TOKEN" ]]; then

    # --- 固定隧道流程 ---
    echo -e "${YELLOW}检测到固定隧道配置，正在启动命名隧道...${NC}"
    
    echo "" > $CLOUDFLARED_LOG
    
    # 启动命名隧道
    if command -v tmux &> /dev/null; then
        tmux new-session -d -s "$TMUX_CLOUDFLARED" "$CLOUDFLARED_BIN tunnel run --no-tls-verify  --url http://${LOCAL_ADDR} --token ${CLOUDFLARE_TOKEN} $CLOUDFLARED_PROTOCOL 2>&1 | tee -a $CLOUDFLARED_LOG"
    else
        nohup $CLOUDFLARED_BIN tunnel run --no-tls-verify --url http://${LOCAL_ADDR} --token ${CLOUDFLARE_TOKEN} $CLOUDFLARED_PROTOCOL> $CLOUDFLARED_LOG 2>&1 &
    fi

    TUNNEL_URL="$CLOUDFLARE_URL"

else

  max_retries=3
  retry_delay=2
  attempt=1
  
  echo "" > $CLOUDFLARED_LOG
  
  echo "[INFO] Starting Cloudflare tunnel..."
  attempt=1
  while [ $attempt -le $max_retries ]; do
    echo "[INFO] Attempt $attempt/$max_retries to start Cloudflare tunnel..."
    if command -v tmux &> /dev/null
    then
        tmux new-session -d -s "$TMUX_CLOUDFLARED" "$CLOUDFLARED_BIN tunnel --no-tls-verify --url http://${LOCAL_ADDR} $CLOUDFLARED_PROTOCOL 2>&1 | tee -a $CLOUDFLARED_LOG"
    else
        nohup $CLOUDFLARED_BIN tunnel --no-tls-verify --url http://$LOCAL_ADDR $CLOUDFLARED_PROTOCOL 2>&1 | tee -a $CLOUDFLARED_LOG &
        # nohup /home/appuser/ech_tunnel_temp/cloudflared tunnel --no-tls-verify --url http://127.0.0.1:8888 2>&1 | tee -a /home/appuser/ech_tunnel_temp/cloudflared.log &
    fi
    sleep 5
    if grep -q 'https://.*\.trycloudflare\.com' "$CLOUDFLARED_LOG"; then
      echo "[SUCCESS] Cloudflare tunnel started successfully"
      break
    else
      echo "[ERROR] Cloudflare tunnel failed to start, cleaning up..."
      if command -v tmux &> /dev/null
      then
          tmux kill-session -t "$TMUX_CLOUDFLARED" 2>/dev/null || true
      fi
      pkill -9 cloudflared 2>/dev/null || true
      if [ $attempt -eq $max_retries ]; then
        echo "[ERROR] Failed to start cloudflared after $max_retries attempts, check logs with: tmux attach -t $TMUX_CLOUDFLARED"
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

fi

if [[ -n "$TUNNEL_URL" ]]; then
  echo "[SUCCESS] Cloudflare tunnel URL: $TUNNEL_URL"
else
  echo "[ERROR] No tunnel URL found in $CLOUDFLARED_LOG. Check logs with: tmux attach -t $TMUX_CLOUDFLARED"
  exit 1
fi


echo -e "${BLUE}请在客户端运行ech_tunnel...${NC}"
echo "./ech_tunnel -l proxy://127.0.0.1:30007 -f wss://${TUNNEL_URL}:443 -ip 104.17.0.134,104.19.237.82,104.19.241.108,104.18.98.115,104.16.19.20,104.16.149.42,104.16.29.34,104.16.132.70,104.16.231.226,104.19.157.56 -token ${ECH_TUNNEL_TOKEN} -n 2"
