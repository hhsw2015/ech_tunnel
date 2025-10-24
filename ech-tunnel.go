package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== 全局参数 ========================

var (
	listenAddr  string
	forwardAddr string
	ipAddr      string
	certFile    string
	keyFile     string
	token       string
	cidrs       string

	// 新增 ECH/DNS 参数
	dnsServer string // -dns
	echDomain string // -ech

	// 运行期缓存的 ECHConfigList
	echListMu sync.RWMutex
	echList   []byte
)

func init() {
	flag.StringVar(&listenAddr, "l", "", "监听地址 (格式: tcp://localAddr/targetAddr 或 ws://ip:port 或 wss://ip:port 或 socks5://[user:pass@]ip:port)")
	flag.StringVar(&forwardAddr, "f", "", "服务地址 (格式: wss://host:port/path)")
	flag.StringVar(&ipAddr, "ip", "", "指定解析的IP地址（仅客户端：将 wss 主机名定向到该 IP 连接）")
	flag.StringVar(&certFile, "cert", "", "TLS证书文件路径（默认:自动生成，仅服务端）")
	flag.StringVar(&keyFile, "key", "", "TLS密钥文件路径（默认:自动生成，仅服务端）")
	flag.StringVar(&token, "token", "", "身份验证令牌（WebSocket Subprotocol）")
	flag.StringVar(&cidrs, "cidr", "0.0.0.0/0,::/0", "允许的来源 IP 范围 (CIDR),多个范围用逗号分隔")
	flag.StringVar(&dnsServer, "dns", "119.29.29.29:53", "查询 ECH 公钥所用的 DNS 服务器")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "用于查询 ECH 公钥的域名")
}

func main() {
	flag.Parse()

	if strings.HasPrefix(listenAddr, "ws://") || strings.HasPrefix(listenAddr, "wss://") {
		runWebSocketServer(listenAddr)
		return
	}
	if strings.HasPrefix(listenAddr, "tcp://") {
		// 客户端模式：预先获取 ECH 公钥（失败则直接退出，严格禁止回退）
		if err := prepareECH(); err != nil {
			log.Fatalf("[客户端] 获取 ECH 公钥失败: %v", err)
		}
		runTCPClient(listenAddr, forwardAddr)
		return
	}
	if strings.HasPrefix(listenAddr, "socks5://") {
		// SOCKS5 代理模式：预先获取 ECH 公钥
		if err := prepareECH(); err != nil {
			log.Fatalf("[SOCKS5] 获取 ECH 公钥失败: %v", err)
		}
		runSOCKS5Server(listenAddr, forwardAddr)
		return
	}

	log.Fatal("监听地址格式错误，请使用 ws://, wss://, tcp:// 或 socks5:// 前缀")
}

// 判断是否为正常的网络关闭错误
func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure")
}

// ======================== ECH 相关（客户端） ========================

const (
	typeHTTPS = 65 // DNS HTTPS 记录类型
)

// 客户端启动时查询 ECH 配置并缓存
func prepareECH() error {
	log.Printf("[客户端] 使用 DNS 服务器查询 ECH: %s -> %s", dnsServer, echDomain)
	echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
	if err != nil {
		return fmt.Errorf("DNS 查询失败: %w", err)
	}
	if echBase64 == "" {
		return errors.New("未找到 ECH 参数（HTTPS RR key=echconfig/5）")
	}
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH Base64 解码失败: %w", err)
	}
	echListMu.Lock()
	echList = raw
	echListMu.Unlock()
	log.Printf("[客户端] ECHConfigList 长度: %d 字节", len(raw))
	return nil
}

// 刷新 ECH 配置（用于重试）
func refreshECH() error {
	log.Printf("[ECH] 刷新 ECH 公钥配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置尚未加载")
	}
	return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}
	tcfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		// 完全采用 ECH，禁止回退
		EncryptedClientHelloConfigList: echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH（禁止回退）")
		},
		RootCAs: roots,
	}
	return tcfg, nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	query := buildDNSQuery(domain, typeHTTPS)

	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		return "", fmt.Errorf("连接 DNS 服务器失败: %v", err)
	}
	defer conn.Close()

	if _, err = conn.Write(query); err != nil {
		return "", fmt.Errorf("发送查询失败: %v", err)
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("读取 DNS 响应失败: %v", err)
	}
	return parseDNSResponse(response[:n])
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	// Header
	query = append(query, 0x00, 0x01)                         // ID
	query = append(query, 0x01, 0x00)                         // 标准查询
	query = append(query, 0x00, 0x01)                         // QDCOUNT = 1
	query = append(query, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // AN/NS/AR = 0
	// QNAME
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00) // root
	// QTYPE/QCLASS
	query = append(query, byte(qtype>>8), byte(qtype))
	query = append(query, 0x00, 0x01) // IN
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("响应长度无效")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("未找到回答记录")
	}
	// 跳过 Question
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5 // null + type + class

	// Answers
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		// NAME（可能压缩）
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8 // type(2) + class(2) + ttl(4)
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

// 仅抽取 SvcParamKey == 5 (ECHConfigList/echconfig)
func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// 跳 priority(2)
	offset := 2
	// 跳 targetName
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	// SvcParams
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== WebSocket 服务端 ========================

func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"自签名组织"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func runWebSocketServer(addr string) {
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatal("无效的 WebSocket 地址:", err)
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	// 解析多个 CIDR 范围
	var allowedNets []*net.IPNet
	for _, cidr := range strings.Split(cidrs, ",") {
		_, allowedNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			log.Fatalf("无法解析 CIDR: %v", err)
		}
		allowedNets = append(allowedNets, allowedNet)
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
		Subprotocols: func() []string {
			if token == "" {
				return nil
			}
			return []string{token}
		}(),
	}

	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		// 验证来源IP
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("无法解析客户端地址: %v", err)
			w.Header().Set("Connection", "close")
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		clientIPAddr := net.ParseIP(clientIP)
		allowed := false
		for _, allowedNet := range allowedNets {
			if allowedNet.Contains(clientIPAddr) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("拒绝访问: IP %s 不在允许的范围内 (%s)", clientIP, cidrs)
			w.Header().Set("Connection", "close")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// 验证 Subprotocol token
		if token != "" {
			clientToken := r.Header.Get("Sec-WebSocket-Protocol")
			if clientToken != token {
				log.Printf("Token验证失败，来自 %s", r.RemoteAddr)
				w.Header().Set("Connection", "close")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("WebSocket 升级失败:", err)
			return
		}

		log.Printf("新的 WebSocket 连接来自 %s", r.RemoteAddr)
		go handleWebSocket(wsConn)
	})

	// 启动服务器
	if u.Scheme == "wss" {
		server := &http.Server{
			Addr: u.Host,
		}

		if certFile != "" && keyFile != "" {
			log.Printf("WebSocket 服务端使用提供的TLS证书启动，监听 %s%s", u.Host, path)
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
		} else {
			cert, err := generateSelfSignedCert()
			if err != nil {
				log.Fatalf("生成自签名证书时出错: %v", err)
			}
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
			}
			server.TLSConfig = tlsConfig
			log.Printf("WebSocket 服务端使用自签名证书启动，监听 %s%s", u.Host, path)
			log.Fatal(server.ListenAndServeTLS("", ""))
		}
	} else {
		log.Printf("WebSocket 服务端启动，监听 %s%s", u.Host, path)
		log.Fatal(http.ListenAndServe(u.Host, nil))
	}
}

func handleWebSocket(wsConn *websocket.Conn) {
	var mu sync.Mutex
	var tcpConn net.Conn

	defer func() {
		if tcpConn != nil {
			_ = tcpConn.Close()
		}
		_ = wsConn.Close()
		log.Printf("WebSocket 连接 %s 已关闭", wsConn.RemoteAddr())
	}()

	// 设置WebSocket保活
	wsConn.SetPingHandler(func(message string) error {
		mu.Lock()
		defer mu.Unlock()
		return wsConn.WriteMessage(websocket.PongMessage, []byte(message))
	})

	for {
		typ, msg, readErr := wsConn.ReadMessage()
		if readErr != nil {
			if !isNormalCloseError(readErr) {
				log.Printf("WebSocket 读取失败 %s: %v", wsConn.RemoteAddr(), readErr)
			}
			return
		}

		if typ == websocket.BinaryMessage {
			// 二进制消息直接转写
			if tcpConn != nil {
				if _, err := tcpConn.Write(msg); err != nil && !isNormalCloseError(err) {
					log.Printf("[服务端] 向目标写入二进制失败: %v", err)
					return
				}
			}
			continue
		}

		data := string(msg)

		// CONNECT: 客户端请求连接到目标
		if strings.HasPrefix(data, "CONNECT:") {
			parts := strings.SplitN(data[8:], "|", 2)
			if len(parts) != 2 {
				log.Printf("无效的CONNECT消息格式: %s", data)
				continue
			}

			targetAddr := parts[0]
			firstFrameData := parts[1]

			log.Printf("[服务端] 收到连接请求，目标: %s，首帧数据长度: %d", targetAddr, len(firstFrameData))

			// 连接到目标地址
			var dialErr error
			tcpConn, dialErr = net.DialTimeout("tcp", targetAddr, 10*time.Second)
			if dialErr != nil {
				log.Printf("[服务端] 连接目标地址 %s 失败: %v", targetAddr, dialErr)
				mu.Lock()
				_ = wsConn.WriteMessage(websocket.TextMessage, []byte("ERROR:连接目标失败"))
				mu.Unlock()
				return
			}

			log.Printf("[服务端] 成功连接到目标地址 %s", targetAddr)

			// 立即发送第一帧数据
			if firstFrameData != "" {
				if _, err := tcpConn.Write([]byte(firstFrameData)); err != nil {
					log.Printf("[服务端] 发送第一帧数据失败: %v", err)
					_ = tcpConn.Close()
					return
				}
				log.Printf("[服务端] 已发送第一帧数据，长度: %d", len(firstFrameData))
			}

			// 发送连接成功消息
			mu.Lock()
			_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CONNECTED"))
			mu.Unlock()

			// 启动从目标读取数据的goroutine
			go func() {
				buf := make([]byte, 32768)
				for {
					n, err := tcpConn.Read(buf)
					if err != nil {
						if !isNormalCloseError(err) {
							log.Printf("[服务端] 从目标读取失败: %v", err)
						}
						mu.Lock()
						_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
						mu.Unlock()
						return
					}

					mu.Lock()
					err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
					mu.Unlock()
					if err != nil {
						if !isNormalCloseError(err) {
							log.Printf("[服务端] 发送数据到WebSocket失败: %v", err)
						}
						_ = tcpConn.Close()
						return
					}
				}
			}()

		} else if strings.HasPrefix(data, "DATA:") {
			// 客户端发来的数据
			payload := data[5:]
			if tcpConn != nil {
				if _, err := tcpConn.Write([]byte(payload)); err != nil {
					if !isNormalCloseError(err) {
						log.Printf("[服务端] 写入目标失败: %v", err)
					}
					return
				}
			}
		} else if data == "CLOSE" {
			// 客户端关闭连接
			log.Printf("[服务端] 收到客户端关闭通知")
			return
		}
	}
}

// ======================== TCP 正向转发客户端（采用 ECH） ========================

func runTCPClient(listenForwardAddr, wsServerAddr string) {
	parts := strings.Split(strings.TrimPrefix(listenForwardAddr, "tcp://"), "/")
	if len(parts) != 2 {
		log.Fatal("tcp 地址格式错误，应为 tcp://监听地址/目标地址")
	}
	listenAddress := parts[0]
	targetAddress := parts[1]

	if wsServerAddr == "" {
		log.Fatal("TCP 正向转发客户端需要指定 WebSocket 服务端地址 (-f)")
	}

	u, err := url.Parse(wsServerAddr)
	if err != nil {
		log.Fatalf("[客户端] 无效的 WebSocket 服务端地址: %v", err)
	}
	if u.Scheme != "wss" {
		log.Fatalf("[客户端] 仅支持 wss:// 客户端必须使用 ECH/TLS1.3）")
	}

	// 启动本地TCP监听器
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatalf("TCP监听失败 %s: %v", listenAddress, err)
	}
	defer listener.Close()

	log.Printf("TCP正向转发监听器启动: %s -> (WebSocket) -> %s", listenAddress, targetAddress)

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("接受TCP连接失败: %v", err)
			continue
		}

		log.Printf("[客户端] 新的TCP连接来自 %s", tcpConn.RemoteAddr())

		// 为每个TCP连接创建独立的WebSocket连接
		go handleTCPConnection(tcpConn, wsServerAddr, targetAddress)
	}
}

func handleTCPConnection(tcpConn net.Conn, wsServerAddr, targetAddr string) {
	defer tcpConn.Close()

	// 尝试建立 WebSocket 连接（带 ECH 重试机制）
	wsConn, err := dialWebSocketWithECH(wsServerAddr, 2)
	if err != nil {
		log.Printf("[客户端] WebSocket(ECH) 连接失败: %v", err)
		return
	}
	defer wsConn.Close()

	log.Printf("[客户端] WebSocket(ECH) 连接已建立: %s", wsServerAddr)

	var mu sync.Mutex

	// 设置保活机制（Ping）
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			pingErr := wsConn.WriteMessage(websocket.PingMessage, nil)
			mu.Unlock()
			if pingErr != nil {
				return
			}
		}
	}()

	// 读取第一帧数据
	_ = tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 32768)
	n, readErr := tcpConn.Read(buffer)
	_ = tcpConn.SetReadDeadline(time.Time{})

	var firstFrameData string
	if readErr != nil && readErr != io.EOF {
		log.Printf("[客户端] 读取第一帧数据失败: %v", readErr)
		firstFrameData = ""
	} else if n > 0 {
		firstFrameData = string(buffer[:n])
		log.Printf("[客户端] 读取第一帧数据，长度: %d", n)
	}

	// 发送连接请求
	connectMsg := fmt.Sprintf("CONNECT:%s|%s", targetAddr, firstFrameData)
	mu.Lock()
	writeErr := wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg))
	mu.Unlock()
	if writeErr != nil {
		log.Printf("[客户端] 发送CONNECT消息失败: %v", writeErr)
		return
	}

	log.Printf("[客户端] 已发送连接请求: %s", targetAddr)

	// 等待服务端响应
	_, msg, respErr := wsConn.ReadMessage()
	if respErr != nil {
		log.Printf("[客户端] 等待服务端响应失败: %v", respErr)
		return
	}

	response := string(msg)
	if strings.HasPrefix(response, "ERROR:") {
		log.Printf("[客户端] 服务端返回错误: %s", response)
		return
	}
	if response != "CONNECTED" {
		log.Printf("[客户端] 意外的服务端响应: %s", response)
		return
	}

	log.Printf("[客户端] 连接已建立，开始数据转发")

	// 启动双向数据转发
	done := make(chan bool, 2)

	// TCP -> WebSocket
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := tcpConn.Read(buf)
			if err != nil {
				if !isNormalCloseError(err) {
					log.Printf("[客户端] TCP读取失败: %v", err)
				}
				mu.Lock()
				_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				mu.Unlock()
				done <- true
				return
			}

			mu.Lock()
			err = wsConn.WriteMessage(websocket.TextMessage, []byte("DATA:"+string(buf[:n])))
			mu.Unlock()
			if err != nil {
				if !isNormalCloseError(err) {
					log.Printf("[客户端] WebSocket发送失败: %v", err)
				}
				done <- true
				return
			}
		}
	}()

	// WebSocket -> TCP
	go func() {
		for {
			mt, msg, err := wsConn.ReadMessage()
			if err != nil {
				if !isNormalCloseError(err) {
					log.Printf("[客户端] WebSocket读取失败: %v", err)
				}
				done <- true
				return
			}

			// 文本 CLOSE 控制，二进制直接转写
			if mt == websocket.TextMessage {
				data := string(msg)
				if data == "CLOSE" {
					log.Printf("[客户端] 收到服务端关闭通知")
					done <- true
					return
				}
				// 文本数据当作透传负载也写入
				if _, err := tcpConn.Write(msg); err != nil {
					if !isNormalCloseError(err) {
						log.Printf("[客户端] TCP写入失败: %v", err)
					}
					done <- true
					return
				}
			} else {
				if _, err := tcpConn.Write(msg); err != nil {
					if !isNormalCloseError(err) {
						log.Printf("[客户端] TCP写入失败: %v", err)
					}
					done <- true
					return
				}
			}
		}
	}()

	<-done
	log.Printf("[客户端] 连接 %s 已关闭", tcpConn.RemoteAddr())
}

// dialWebSocketWithECH 建立 WebSocket 连接（带 ECH 重试）
func dialWebSocketWithECH(wsServerAddr string, maxRetries int) (*websocket.Conn, error) {
	u, err := url.Parse(wsServerAddr)
	if err != nil {
		return nil, fmt.Errorf("解析 wsServerAddr 失败: %v", err)
	}
	serverName := u.Hostname()

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := getECHList()
		if echErr != nil {
			log.Printf("[ECH] 获取 ECH 配置失败: %v", echErr)
			if attempt < maxRetries {
				log.Printf("[ECH] 尝试刷新 ECH 配置...")
				if refreshErr := refreshECH(); refreshErr != nil {
					log.Printf("[ECH] 刷新失败: %v", refreshErr)
				}
				continue
			}
			return nil, fmt.Errorf("ECH 配置不可用: %v", echErr)
		}

		tlsCfg, tlsErr := buildTLSConfigWithECH(serverName, echBytes)
		if tlsErr != nil {
			return nil, fmt.Errorf("构建 TLS(ECH) 配置失败: %v", tlsErr)
		}

		// 配置WebSocket Dialer
		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			Subprotocols: func() []string {
				if token == "" {
					return nil
				}
				return []string{token}
			}(),
			HandshakeTimeout: 10 * time.Second,
		}

		// 如果指定了IP地址，配置自定义拨号器（SNI 仍为 serverName）
		if ipAddr != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				address = net.JoinHostPort(ipAddr, port)
				return net.DialTimeout(network, address, 10*time.Second)
			}
		}

		// 连接到WebSocket服务端（必须 wss）
		wsConn, _, dialErr := dialer.Dial(wsServerAddr, nil)
		if dialErr != nil {
			// 检查是否为 ECH 相关错误
			if strings.Contains(dialErr.Error(), "ECH") || strings.Contains(dialErr.Error(), "ech") {
				log.Printf("[ECH] 连接失败（可能 ECH 公钥已轮换）: %v", dialErr)
				if attempt < maxRetries {
					log.Printf("[ECH] 尝试刷新 ECH 配置并重试 (尝试 %d/%d)...", attempt, maxRetries)
					if refreshErr := refreshECH(); refreshErr != nil {
						log.Printf("[ECH] 刷新失败: %v", refreshErr)
					}
					time.Sleep(time.Second)
					continue
				}
			}
			return nil, dialErr
		}

		return wsConn, nil
	}

	return nil, fmt.Errorf("WebSocket 连接失败，已达最大重试次数")
}

// ======================== SOCKS5 服务器 ========================

// SOCKS5 认证方法常量
const (
	NoAuth       = uint8(0x00)
	UserPassAuth = uint8(0x02)
	NoAcceptable = uint8(0xFF)
)

// SOCKS5 请求命令
const (
	ConnectCmd      = uint8(0x01)
	BindCmd         = uint8(0x02)
	UDPAssociateCmd = uint8(0x03)
)

// SOCKS5 地址类型
const (
	IPv4Addr   = uint8(0x01)
	DomainAddr = uint8(0x03)
	IPv6Addr   = uint8(0x04)
)

// SOCKS5 响应状态码
const (
	Succeeded               = uint8(0x00)
	GeneralFailure          = uint8(0x01)
	ConnectionNotAllowed    = uint8(0x02)
	NetworkUnreachable      = uint8(0x03)
	HostUnreachable         = uint8(0x04)
	ConnectionRefused       = uint8(0x05)
	TTLExpired              = uint8(0x06)
	CommandNotSupported     = uint8(0x07)
	AddressTypeNotSupported = uint8(0x08)
)

type SOCKS5Config struct {
	Username string
	Password string
	Host     string
}

func parseSOCKS5Addr(addr string) (*SOCKS5Config, error) {
	// 格式: socks5://[user:pass@]ip:port
	addr = strings.TrimPrefix(addr, "socks5://")

	config := &SOCKS5Config{}

	// 检查是否有认证信息
	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的 SOCKS5 地址格式")
		}

		// 解析用户名密码
		auth := parts[0]
		if strings.Contains(auth, ":") {
			authParts := strings.SplitN(auth, ":", 2)
			config.Username = authParts[0]
			config.Password = authParts[1]
		}

		config.Host = parts[1]
	} else {
		config.Host = addr
	}

	return config, nil
}

func runSOCKS5Server(addr, wsServerAddr string) {
	if wsServerAddr == "" {
		log.Fatal("SOCKS5 代理需要指定 WebSocket 服务端地址 (-f)")
	}

	// 验证必须使用 wss://（强制 ECH）
	u, err := url.Parse(wsServerAddr)
	if err != nil {
		log.Fatalf("解析 WebSocket 服务端地址失败: %v", err)
	}
	if u.Scheme != "wss" {
		log.Fatalf("[SOCKS5] 仅支持 wss://（客户端必须使用 ECH/TLS1.3）")
	}

	config, err := parseSOCKS5Addr(addr)
	if err != nil {
		log.Fatalf("解析 SOCKS5 地址失败: %v", err)
	}

	listener, err := net.Listen("tcp", config.Host)
	if err != nil {
		log.Fatalf("SOCKS5 监听失败 %s: %v", config.Host, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 服务器启动，监听: %s", config.Host)
	if config.Username != "" {
		log.Printf("SOCKS5 认证已启用，用户名: %s", config.Username)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go handleSOCKS5Connection(conn, config, wsServerAddr)
	}
}

func handleSOCKS5Connection(conn net.Conn, config *SOCKS5Config, wsServerAddr string) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[SOCKS5:%s] 新连接", clientAddr)

	// 设置连接超时
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 处理认证方法协商
	if err := handleSOCKS5AuthNegotiation(conn, config); err != nil {
		log.Printf("[SOCKS5:%s] 认证方法协商失败: %v", clientAddr, err)
		return
	}

	// 处理用户名密码认证
	if config.Username != "" && config.Password != "" {
		if err := handleSOCKS5UserPassAuth(conn, config); err != nil {
			log.Printf("[SOCKS5:%s] 用户名密码认证失败: %v", clientAddr, err)
			return
		}
	}

	// 处理客户端请求
	if err := handleSOCKS5Request(conn, clientAddr, wsServerAddr); err != nil {
		log.Printf("[SOCKS5:%s] 处理请求失败: %v", clientAddr, err)
		return
	}
}

func handleSOCKS5AuthNegotiation(conn net.Conn, config *SOCKS5Config) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取认证方法头失败: %v", err)
	}

	version := buf[0]
	nMethods := buf[1]

	if version != 5 {
		return fmt.Errorf("不支持的SOCKS版本: %d", version)
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("读取认证方法失败: %v", err)
	}

	// 选择认证方法
	var method uint8 = NoAuth
	if config.Username != "" && config.Password != "" {
		method = UserPassAuth
		found := false
		for _, m := range methods {
			if m == UserPassAuth {
				found = true
				break
			}
		}
		if !found {
			method = NoAcceptable
		}
	}

	// 发送选择的认证方法
	response := []byte{0x05, method}
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("发送认证方法响应失败: %v", err)
	}

	if method == NoAcceptable {
		return fmt.Errorf("没有可接受的认证方法")
	}

	return nil
}

func handleSOCKS5UserPassAuth(conn net.Conn, config *SOCKS5Config) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取用户名密码认证头失败: %v", err)
	}

	version := buf[0]
	userLen := buf[1]

	if version != 1 {
		return fmt.Errorf("不支持的认证版本: %d", version)
	}

	// 读取用户名
	userBuf := make([]byte, userLen)
	if _, err := io.ReadFull(conn, userBuf); err != nil {
		return fmt.Errorf("读取用户名失败: %v", err)
	}

	// 读取密码长度
	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return fmt.Errorf("读取密码长度失败: %v", err)
	}
	passLen := passLenBuf[0]

	// 读取密码
	passBuf := make([]byte, passLen)
	if _, err := io.ReadFull(conn, passBuf); err != nil {
		return fmt.Errorf("读取密码失败: %v", err)
	}

	// 验证用户名密码
	user := string(userBuf)
	pass := string(passBuf)

	var status byte = 0x00 // 0x00表示成功
	if user != config.Username || pass != config.Password {
		status = 0x01 // 认证失败
	}

	// 发送认证结果
	response := []byte{0x01, status}
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("发送认证响应失败: %v", err)
	}

	if status != 0x00 {
		return fmt.Errorf("用户名或密码错误")
	}

	return nil
}

func handleSOCKS5Request(conn net.Conn, clientAddr, wsServerAddr string) error {
	// 读取请求头
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取请求头失败: %v", err)
	}

	version := buf[0]
	command := buf[1]
	atyp := buf[3]

	if version != 5 {
		return fmt.Errorf("不支持的SOCKS版本: %d", version)
	}

	// 读取目标地址
	var host string
	switch atyp {
	case IPv4Addr:
		buf = make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取IPv4地址失败: %v", err)
		}
		host = net.IP(buf).String()

	case DomainAddr:
		buf = make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取域名长度失败: %v", err)
		}
		domainLen := buf[0]
		buf = make([]byte, domainLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取域名失败: %v", err)
		}
		host = string(buf)

	case IPv6Addr:
		buf = make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取IPv6地址失败: %v", err)
		}
		host = net.IP(buf).String()

	default:
		sendSOCKS5ErrorResponse(conn, AddressTypeNotSupported)
		return fmt.Errorf("不支持的地址类型: %d", atyp)
	}

	// 读取端口
	buf = make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取端口失败: %v", err)
	}
	port := int(buf[0])<<8 | int(buf[1])

	// 目标地址
	var target string
	if atyp == IPv6Addr {
		target = fmt.Sprintf("[%s]:%d", host, port)
	} else {
		target = fmt.Sprintf("%s:%d", host, port)
	}

	log.Printf("[SOCKS5:%s] 请求访问目标: %s (命令: %d)", clientAddr, target, command)

	// 只支持 CONNECT 命令
	if command != ConnectCmd {
		sendSOCKS5ErrorResponse(conn, CommandNotSupported)
		return fmt.Errorf("不支持的命令类型: %d", command)
	}

	return handleSOCKS5Connect(conn, target, clientAddr, wsServerAddr)
}

func sendSOCKS5ErrorResponse(conn net.Conn, status uint8) {
	response := []byte{0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.Write(response)
}

func sendSOCKS5SuccessResponse(conn net.Conn) error {
	// 简单返回成功响应（绑定地址为 0.0.0.0:0）
	response := []byte{0x05, Succeeded, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(response)
	return err
}

func handleSOCKS5Connect(conn net.Conn, target, clientAddr, wsServerAddr string) error {
	// 建立 WebSocket 连接（带 ECH 重试）
	wsConn, err := dialWebSocketWithECH(wsServerAddr, 2)
	if err != nil {
		sendSOCKS5ErrorResponse(conn, HostUnreachable)
		return fmt.Errorf("WebSocket(ECH) 连接失败: %v", err)
	}
	defer wsConn.Close()

	log.Printf("[SOCKS5:%s] WebSocket(ECH) 连接已建立", clientAddr)

	var mu sync.Mutex

	// 设置保活机制
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			pingErr := wsConn.WriteMessage(websocket.PingMessage, nil)
			mu.Unlock()
			if pingErr != nil {
				return
			}
		}
	}()

	// 清除连接超时
	conn.SetDeadline(time.Time{})

	// 读取第一帧数据（如果有）
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buffer := make([]byte, 32768)
	n, _ := conn.Read(buffer)
	_ = conn.SetReadDeadline(time.Time{})

	var firstFrameData string
	if n > 0 {
		firstFrameData = string(buffer[:n])
		log.Printf("[SOCKS5:%s] 读取第一帧数据，长度: %d", clientAddr, n)
	}

	// 发送连接请求
	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, firstFrameData)
	mu.Lock()
	writeErr := wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg))
	mu.Unlock()
	if writeErr != nil {
		sendSOCKS5ErrorResponse(conn, GeneralFailure)
		return fmt.Errorf("发送CONNECT消息失败: %v", writeErr)
	}

	log.Printf("[SOCKS5:%s] 已发送连接请求: %s", clientAddr, target)

	// 等待服务端响应
	_, msg, respErr := wsConn.ReadMessage()
	if respErr != nil {
		sendSOCKS5ErrorResponse(conn, GeneralFailure)
		return fmt.Errorf("等待服务端响应失败: %v", respErr)
	}

	response := string(msg)
	if strings.HasPrefix(response, "ERROR:") {
		sendSOCKS5ErrorResponse(conn, HostUnreachable)
		return fmt.Errorf("服务端返回错误: %s", response)
	}
	if response != "CONNECTED" {
		sendSOCKS5ErrorResponse(conn, GeneralFailure)
		return fmt.Errorf("意外的服务端响应: %s", response)
	}

	// 发送 SOCKS5 成功响应
	if err := sendSOCKS5SuccessResponse(conn); err != nil {
		return fmt.Errorf("发送SOCKS5成功响应失败: %v", err)
	}

	log.Printf("[SOCKS5:%s] 连接已建立，开始数据转发", clientAddr)

	// 启动双向数据转发
	done := make(chan bool, 2)

	// SOCKS5 Client -> WebSocket
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if !isNormalCloseError(err) {
					log.Printf("[SOCKS5:%s] 读取失败: %v", clientAddr, err)
				}
				mu.Lock()
				_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				mu.Unlock()
				done <- true
				return
			}

			mu.Lock()
			err = wsConn.WriteMessage(websocket.TextMessage, []byte("DATA:"+string(buf[:n])))
			mu.Unlock()
			if err != nil {
				if !isNormalCloseError(err) {
					log.Printf("[SOCKS5:%s] WebSocket发送失败: %v", clientAddr, err)
				}
				done <- true
				return
			}
		}
	}()

	// WebSocket -> SOCKS5 Client
	go func() {
		for {
			mt, msg, err := wsConn.ReadMessage()
			if err != nil {
				if !isNormalCloseError(err) {
					log.Printf("[SOCKS5:%s] WebSocket读取失败: %v", clientAddr, err)
				}
				done <- true
				return
			}

			if mt == websocket.TextMessage {
				data := string(msg)
				if data == "CLOSE" {
					log.Printf("[SOCKS5:%s] 收到服务端关闭通知", clientAddr)
					done <- true
					return
				}
				// 文本数据透传
				if _, err := conn.Write(msg); err != nil {
					if !isNormalCloseError(err) {
						log.Printf("[SOCKS5:%s] 写入失败: %v", clientAddr, err)
					}
					done <- true
					return
				}
			} else {
				// 二进制数据
				if _, err := conn.Write(msg); err != nil {
					if !isNormalCloseError(err) {
						log.Printf("[SOCKS5:%s] 写入失败: %v", clientAddr, err)
					}
					done <- true
					return
				}
			}
		}
	}()

	<-done
	log.Printf("[SOCKS5:%s] 连接已关闭", clientAddr)
	return nil
}
