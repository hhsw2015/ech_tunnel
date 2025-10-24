# ECH Tunnel

ECH Tunnel 是一个单文件实现的轻量级加密隧道工具，利用 TLS 1.3 Encrypted Client Hello（ECH）技术，在 WebSocket 上安全地转发 TCP／SOCKS5 流量，可用于内网穿透、安全跳板等场景。

## 主要特性

- **WebSocket 服务端**：支持 `ws://` 与 `wss://`，可自动生成自签名证书或使用自备证书。
- **TCP 正向隧道**：本地监听 TCP，流量通过 `wss+ECH` 转发至服务器。
- **SOCKS5 代理**：零配置 SOCKS5 → `wss+ECH` 隧道。
- **强制 TLS 1.3 + ECH**：禁止降级回退，提升隐私与安全性。
- **Token 认证 & CIDR 白名单**：简单易用的访问控制。
- **单文件部署**：仅依赖 Go 1.22+，`go build` 即得可执行文件。

## 快速开始

### 编译
```bash
# 进入项目目录
cd trae
# 生成可执行文件
go build -o ech-tunnel ech-tunnel.go
```

### 运行示例

1. **启动 WebSocket 服务端（带自签名证书）**
```bash
./ech-tunnel -l wss://0.0.0.0:8443 -cidr "0.0.0.0/0,::/0" -token mytoken
```

2. **TCP 正向隧道客户端**（把本地 1080 端口的流量转到远端）
```bash
./ech-tunnel -l tcp://127.0.0.1:1080/www.example.com:443 \
            -f wss://server-ip:8443 \
            -token mytoken
```

3. **SOCKS5 代理客户端**
```bash
./ech-tunnel -l socks5://0.0.0.0:1080 -f wss://server-ip:8443 -token mytoken
```

## 常用参数说明
| 参数 | 说明 |
|------|------|
| `-l` | 监听地址／模式：`ws://`/`wss://` = 服务端；`tcp://监听/目标` 或 `socks5://` = 客户端 |
| `-f` | 远端 WebSocket 地址（仅客户端需要） |
| `-ip` | 将目标域名解析到指定 IP（绕过 DNS）|
| `-token` | WebSocket 子协议令牌，用于简单身份认证 |
| `-cidr` | 服务端允许的来源 IP 白名单（逗号分隔） |
| `-dns` / `-ech` | 指定查询 ECH 公钥的 DNS 服务器与域名 |

## License

[MIT](LICENSE)
