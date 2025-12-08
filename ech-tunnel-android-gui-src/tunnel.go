package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// ======================== 全局参数 ========================

var (
	// 原始参数保持
	token         string
	connectionNum int
	dnsServer     string
	echDomain     string

	// 新增/修改参数
	targetIPs []string // 解析后的多IP列表
	fallback  bool     // 是否回落到普通 TLS

	echListMu sync.RWMutex
	echList   []byte

	echPool       *ECHPool
	proxyListener net.Listener
)

// StartSocksProxy 启动 SOCKS5/HTTP 代理，供 Android 调用
func StartSocksProxy(host, wsServer string, n int, dns, ech, ip string, tkn string, fb bool) error {
	if wsServer == "" {
		return fmt.Errorf("缺少 wss 服务地址")
	}
	if !strings.HasPrefix(wsServer, "wss://") {
		return fmt.Errorf("仅支持 wss://")
	}

	// 初始化参数
	connectionNum = n
	if connectionNum <= 0 {
		connectionNum = 1
	}

	dnsServer = dns
	if dnsServer == "" {
		dnsServer = "dns.alidns.com/dns-query"
	}

	echDomain = ech
	if echDomain == "" {
		echDomain = "cloudflare-ech.com"
	}

	token = tkn
	fallback = fb // 设置 Fallback 状态

	// 解析多 IP 参数 (逗号分隔)
	targetIPs = nil
	if ip != "" {
		parts := strings.Split(ip, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				targetIPs = append(targetIPs, trimmed)
			}
		}
	}

	// 如果不是 fallback 模式，准备 ECH
	if !fallback {
		if err := prepareECH(); err != nil {
			return fmt.Errorf("ECH 初始化失败: %v", err)
		}
	} else {
		log.Printf("[Tunnel] Fallback 模式已启用：禁用 ECH，使用标准 TLS 1.3")
	}

	go runProxyServer(host, wsServer)
	return nil
}

// StopSocksProxy 停止代理并关闭连接池
func StopSocksProxy() {
	go func() {
		if proxyListener != nil {
			_ = proxyListener.Close()
			proxyListener = nil
		}
		if echPool != nil {
			echPool.Close()
			echPool = nil
		}
	}()
}

// 修复点1：此函数现在会被 runProxyServer 和 handleChannel 调用
func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	// 增加 net.ErrClosed 判断
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure")
}

// ======================== ECH 相关 ========================

const typeHTTPS = 65

func prepareECH() error {
	// 如果开启 fallback，不需要查询 ECH
	if fallback {
		return nil
	}

	for {
		log.Printf("[客户端] 使用 DNS 服务器查询 ECH: %s -> %s", dnsServer, echDomain)
		echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
		if err != nil {
			log.Printf("[客户端] DNS 查询失败: %v，2秒后重试...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if echBase64 == "" {
			log.Printf("[客户端] 未找到 ECH 参数，2秒后重试...")
			time.Sleep(2 * time.Second)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(echBase64)
		if err != nil {
			log.Printf("[客户端] ECH Base64 解码失败: %v，2秒后重试...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		echListMu.Lock()
		echList = raw
		echListMu.Unlock()
		log.Printf("[客户端] ECHConfigList 长度: %d 字节", len(raw))
		return nil
	}
}

func refreshECH() error {
	if fallback {
		return nil
	}
	log.Printf("[ECH] 刷新 ECH 公钥配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	if fallback {
		return nil, nil
	}
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置尚未加载")
	}
	return echList, nil
}

// 带 ECH 的 TLS 配置
func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}
	return &tls.Config{
		MinVersion:                          tls.VersionTLS13,
		ServerName:                          serverName,
		EncryptedClientHelloConfigList:      echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error { return errors.New("服务器拒绝 ECH") },
		RootCAs:                             roots,
	}, nil
}

// 标准 TLS 配置 (Fallback 模式用)
func buildStandardTLSConfig(serverName string) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    roots,
	}, nil
}

func queryHTTPSRecord(domain, server string) (string, error) {
	dohURL := server
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return queryDoH(domain, dohURL)
}

func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效的 DoH URL: %v", err)
	}
	q := u.Query()
	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	q.Set("dns", base64.RawURLEncoding.EncodeToString(dnsQuery))
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 DoH 响应失败: %v", err)
	}
	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
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
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5

	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
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
		offset += 8
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

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
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

// ======================== WebSocket 连接 ========================

// dialWebSocketWithECH 建立连接，支持 ECH 重试、Fallback 和指定 IP
func dialWebSocketWithECH(wsServerAddr string, maxRetries int, remoteIP string) (*websocket.Conn, error) {
	u, err := url.Parse(wsServerAddr)
	if err != nil {
		return nil, fmt.Errorf("解析地址失败: %v", err)
	}
	serverName := u.Hostname()

	for attempt := 1; attempt <= maxRetries; attempt++ {
		var tlsCfg *tls.Config
		var tlsErr error

		if fallback {
			// Fallback 模式：使用标准 TLS
			tlsCfg, tlsErr = buildStandardTLSConfig(serverName)
		} else {
			// ECH 模式
			echBytes, echErr := getECHList()
			if echErr != nil {
				if attempt < maxRetries {
					_ = refreshECH()
					continue
				}
				return nil, fmt.Errorf("ECH 配置不可用: %v", echErr)
			}
			tlsCfg, tlsErr = buildTLSConfigWithECH(serverName, echBytes)
		}

		if tlsErr != nil {
			return nil, fmt.Errorf("构建 TLS 配置失败: %v", tlsErr)
		}

		dialer := websocket.Dialer{
			TLSClientConfig:  tlsCfg,
			HandshakeTimeout: 10 * time.Second,
			ReadBufferSize:   65536,
			WriteBufferSize:  65536,
		}
		if token != "" {
			dialer.Subprotocols = []string{token}
		}

		// 指定 IP 连接逻辑
		if remoteIP != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(address)
				// 强制使用 remoteIP 和 目标端口连接，忽略 address 中的 hostname
				return net.DialTimeout(network, net.JoinHostPort(remoteIP, port), 10*time.Second)
			}
		}

		wsConn, _, dialErr := dialer.Dial(wsServerAddr, nil)
		if dialErr != nil {
			// 如果不是 fallback 模式且遇到 ECH 相关错误，尝试重试
			if !fallback && strings.Contains(strings.ToLower(dialErr.Error()), "ech") && attempt < maxRetries {
				_ = refreshECH()
				time.Sleep(time.Second)
				continue
			}
			return nil, dialErr
		}
		return wsConn, nil
	}
	return nil, fmt.Errorf("WebSocket 连接失败")
}

// ======================== 代理常量 ========================

const (
	noAuth       = 0x00
	userPassAuth = 0x02
	noAcceptable = 0xFF

	connectCmd      = 0x01
	udpAssociateCmd = 0x03

	ipv4Addr   = 0x01
	domainAddr = 0x03
	ipv6Addr   = 0x04

	succeeded           = 0x00
	generalFailure      = 0x01
	commandNotSupported = 0x07
	// addressTypeNotSupported = 0x08 // 未使用，屏蔽以避免未使用警告
)

// ======================== 连接池 ========================

type ECHPool struct {
	wsServerAddr  string
	connectionNum int
	targetIPs     []string // 存储解析后的 IP 列表

	// 读写锁保护 WebSocket 连接数组
	wsConnsMu sync.RWMutex
	wsConns   []*websocket.Conn
	wsMutexes []sync.Mutex

	mu             sync.RWMutex
	tcpMap         map[string]net.Conn
	udpMap         map[string]*UDPAssociation
	channelMap     map[string]int
	connInfo       map[string]struct{ targetAddr, firstFrameData string }
	claimTimes     map[string]map[int]time.Time
	connected      map[string]chan bool
	boundByChannel map[int]string
	closing        bool
}

type UDPAssociation struct {
	connID        string
	tcpConn       net.Conn
	udpListener   *net.UDPConn
	clientUDPAddr *net.UDPAddr
	pool          *ECHPool
	mu            sync.Mutex
	closed        bool
	done          chan bool
	receiving     bool
}

// NewECHPool 初始化连接池
func NewECHPool(wsServerAddr string, n int, ips []string) *ECHPool {
	// 计算总连接数 = n * IP数量 (如果 ips 为空，则仅 n)
	totalConns := n
	if len(ips) > 0 {
		totalConns = len(ips) * n
	}

	return &ECHPool{
		wsServerAddr:   wsServerAddr,
		connectionNum:  n,
		targetIPs:      ips,
		wsConns:        make([]*websocket.Conn, totalConns),
		wsMutexes:      make([]sync.Mutex, totalConns),
		tcpMap:         make(map[string]net.Conn),
		udpMap:         make(map[string]*UDPAssociation),
		channelMap:     make(map[string]int),
		connInfo:       make(map[string]struct{ targetAddr, firstFrameData string }),
		claimTimes:     make(map[string]map[int]time.Time),
		connected:      make(map[string]chan bool),
		boundByChannel: make(map[int]string),
	}
}

func (p *ECHPool) Start() {
	totalConns := len(p.wsConns)
	for i := 0; i < totalConns; i++ {
		// 计算当前连接应该使用的 IP
		var specificIP string
		if len(p.targetIPs) > 0 {
			// 比如 2 个 IP，每个 IP 2 连接
			// i=0 -> ip[0], i=1 -> ip[0], i=2 -> ip[1], i=3 -> ip[1]
			ipIndex := i / p.connectionNum
			if ipIndex < len(p.targetIPs) {
				specificIP = p.targetIPs[ipIndex]
			}
		}
		go p.dialOnce(i, specificIP)
	}
}

func (p *ECHPool) Close() {
	p.mu.Lock()
	p.closing = true
	for _, c := range p.tcpMap {
		_ = c.Close()
	}
	for _, a := range p.udpMap {
		a.Close()
	}
	p.mu.Unlock()

	// 关闭 WebSocket
	p.wsConnsMu.Lock()
	for i, ws := range p.wsConns {
		if ws != nil {
			p.wsMutexes[i].Lock()
			_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(300*time.Millisecond))
			_ = ws.Close()
			p.wsMutexes[i].Unlock()
		}
	}
	p.wsConnsMu.Unlock()
}

func (p *ECHPool) dialOnce(index int, specificIP string) {
	for {
		if p.closing {
			return
		}
		wsConn, err := dialWebSocketWithECH(p.wsServerAddr, 2, specificIP)
		if err != nil {
			ipLog := specificIP
			if ipLog == "" {
				ipLog = "默认"
			}
			log.Printf("[客户端] 通道 %d (IP:%s) 连接失败: %v，2秒后重试", index, ipLog, err)
			time.Sleep(2 * time.Second)
			continue
		}

		p.wsConnsMu.Lock()
		p.wsConns[index] = wsConn
		p.wsConnsMu.Unlock()

		log.Printf("[客户端] 通道 %d 已连接", index)
		go p.handleChannel(index, wsConn)
		return
	}
}

func (p *ECHPool) RegisterAndClaim(connID, target, firstFrame string, tcpConn net.Conn) {
	p.mu.Lock()
	p.tcpMap[connID] = tcpConn
	p.connInfo[connID] = struct{ targetAddr, firstFrameData string }{target, firstFrame}
	if p.claimTimes[connID] == nil {
		p.claimTimes[connID] = make(map[int]time.Time)
	}
	if _, ok := p.connected[connID]; !ok {
		p.connected[connID] = make(chan bool, 1)
	}
	p.mu.Unlock()

	p.wsConnsMu.RLock()
	defer p.wsConnsMu.RUnlock()

	for i, ws := range p.wsConns {
		if ws == nil {
			continue
		}
		p.mu.Lock()
		// 确保 map 存在
		if times, ok := p.claimTimes[connID]; ok {
			times[i] = time.Now()
		}
		p.mu.Unlock()

		p.wsMutexes[i].Lock()
		_ = ws.WriteMessage(websocket.TextMessage, []byte("CLAIM:"+connID+"|"+fmt.Sprintf("%d", i)))
		p.wsMutexes[i].Unlock()
	}
}

func (p *ECHPool) RegisterUDP(connID string, assoc *UDPAssociation) {
	p.mu.Lock()
	p.udpMap[connID] = assoc
	if _, ok := p.connected[connID]; !ok {
		p.connected[connID] = make(chan bool, 1)
	}
	p.mu.Unlock()
}

func (p *ECHPool) SendUDPConnect(connID, target string) error {
	p.mu.RLock()
	p.wsConnsMu.RLock()
	var ws *websocket.Conn
	var chID int
	for i, w := range p.wsConns {
		if w != nil {
			ws, chID = w, i
			break
		}
	}
	p.wsConnsMu.RUnlock()
	p.mu.RUnlock()

	if ws == nil {
		return fmt.Errorf("没有可用连接")
	}
	p.mu.Lock()
	p.channelMap[connID] = chID
	p.boundByChannel[chID] = connID
	p.mu.Unlock()
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("UDP_CONNECT:"+connID+"|"+target))
	p.wsMutexes[chID].Unlock()
	return err
}

func (p *ECHPool) SendUDPData(connID string, data []byte) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	p.wsConnsMu.RLock()
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.wsConnsMu.RUnlock()
	p.mu.RUnlock()

	if !ok || ws == nil {
		return fmt.Errorf("未分配通道")
	}
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.BinaryMessage, append([]byte("UDP_DATA:"+connID+"|"), data...))
	p.wsMutexes[chID].Unlock()
	return err
}

func (p *ECHPool) SendUDPClose(connID string) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	p.wsConnsMu.RLock()
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.wsConnsMu.RUnlock()
	p.mu.RUnlock()

	if !ok || ws == nil {
		return nil
	}
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("UDP_CLOSE:"+connID))
	p.wsMutexes[chID].Unlock()
	p.mu.Lock()
	delete(p.channelMap, connID)
	delete(p.boundByChannel, chID)
	delete(p.udpMap, connID)
	p.mu.Unlock()
	return err
}

func (p *ECHPool) WaitConnected(connID string, timeout time.Duration) bool {
	p.mu.RLock()
	ch := p.connected[connID]
	p.mu.RUnlock()
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (p *ECHPool) handleChannel(channelID int, wsConn *websocket.Conn) {
	// 使用 context 处理生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wsConn.SetPingHandler(func(msg string) error {
		p.wsMutexes[channelID].Lock()
		err := wsConn.WriteMessage(websocket.PongMessage, []byte(msg))
		p.wsMutexes[channelID].Unlock()
		return err
	})

	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if p.closing {
					return
				}
				p.wsMutexes[channelID].Lock()
				_ = wsConn.WriteMessage(websocket.PingMessage, nil)
				p.wsMutexes[channelID].Unlock()
			}
		}
	}()

	for {
		if p.closing {
			return
		}
		mt, msg, err := wsConn.ReadMessage()
		if err != nil {
			// 修复点1：使用 isNormalCloseError 过滤日志
			if !isNormalCloseError(err) {
				log.Printf("[客户端] 通道 %d 读取失败: %v", channelID, err)
			}
			if !p.closing {
				go p.redialChannel(channelID)
			}
			return
		}

		if mt == websocket.BinaryMessage {
			if len(msg) > 9 && string(msg[:9]) == "UDP_DATA:" {
				parts := bytes.SplitN(msg[9:], []byte("|"), 3)
				if len(parts) == 3 {
					p.mu.RLock()
					assoc := p.udpMap[string(parts[0])]
					p.mu.RUnlock()
					if assoc != nil {
						assoc.handleUDPResponse(string(parts[1]), parts[2])
					}
				}
				continue
			}
			if len(msg) > 5 && string(msg[:5]) == "DATA:" {
				parts := strings.SplitN(string(msg[5:]), "|", 2)
				if len(parts) == 2 {
					p.mu.RLock()
					c := p.tcpMap[parts[0]]
					p.mu.RUnlock()
					if c != nil {
						if _, err := c.Write([]byte(parts[1])); err != nil {
							go p.SendClose(parts[0])
							c.Close()
							p.mu.Lock()
							delete(p.tcpMap, parts[0])
							p.mu.Unlock()
						}
					} else {
						go p.SendClose(parts[0])
					}
				}
				continue
			}
			p.mu.RLock()
			connID := p.boundByChannel[channelID]
			c := p.tcpMap[connID]
			p.mu.RUnlock()
			if connID != "" && c != nil {
				if _, err := c.Write(msg); err != nil {
					go p.SendClose(connID)
					c.Close()
					p.mu.Lock()
					delete(p.tcpMap, connID)
					p.mu.Unlock()
				}
			}
			continue
		}

		if mt == websocket.TextMessage {
			data := string(msg)
			switch {
			case strings.HasPrefix(data, "UDP_CONNECTED:"):
				connID := data[14:]
				p.mu.RLock()
				ch := p.connected[connID]
				p.mu.RUnlock()
				if ch != nil {
					select {
					case ch <- true:
					default:
					}
				}
			case strings.HasPrefix(data, "UDP_ERROR:"):
				parts := strings.SplitN(data[10:], "|", 2)
				if len(parts) == 2 {
					log.Printf("[UDP:%s] 错误: %s", parts[0], parts[1])
				}
			case strings.HasPrefix(data, "CLAIM_ACK:"):
				parts := strings.SplitN(data[10:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					p.mu.Lock()
					if _, exists := p.channelMap[connID]; exists {
						p.mu.Unlock()
						continue
					}
					info, ok := p.connInfo[connID]
					if !ok {
						p.mu.Unlock()
						continue
					}

					// 记录延迟信息（可选）
					if chTimes, ok := p.claimTimes[connID]; ok {
						delete(chTimes, channelID)
						if len(chTimes) == 0 {
							delete(p.claimTimes, connID)
						}
					}

					p.channelMap[connID] = channelID
					p.boundByChannel[channelID] = connID
					delete(p.connInfo, connID)
					p.mu.Unlock()
					p.wsMutexes[channelID].Lock()
					err := wsConn.WriteMessage(websocket.TextMessage, []byte("TCP:"+connID+"|"+info.targetAddr+"|"+info.firstFrameData))
					p.wsMutexes[channelID].Unlock()
					if err != nil {
						p.mu.Lock()
						if c, ok := p.tcpMap[connID]; ok {
							c.Close()
							delete(p.tcpMap, connID)
						}
						delete(p.channelMap, connID)
						delete(p.boundByChannel, channelID)
						delete(p.connInfo, connID)
						delete(p.claimTimes, connID)
						p.mu.Unlock()
					}
				}
			case strings.HasPrefix(data, "CONNECTED:"):
				connID := data[10:]
				p.mu.RLock()
				ch := p.connected[connID]
				p.mu.RUnlock()
				if ch != nil {
					select {
					case ch <- true:
					default:
					}
				}
			case strings.HasPrefix(data, "CLOSE:"):
				id := data[6:]
				p.mu.Lock()
				if c, ok := p.tcpMap[id]; ok {
					_ = c.Close()
					delete(p.tcpMap, id)
				}
				delete(p.channelMap, id)
				delete(p.connInfo, id)
				delete(p.claimTimes, id)
				delete(p.boundByChannel, channelID)
				p.mu.Unlock()
			}
		}
	}
}

func (p *ECHPool) redialChannel(channelID int) {
	var specificIP string
	if len(p.targetIPs) > 0 {
		ipIndex := channelID / p.connectionNum
		if ipIndex < len(p.targetIPs) {
			specificIP = p.targetIPs[ipIndex]
		}
	}

	for {
		if p.closing {
			return
		}
		newConn, err := dialWebSocketWithECH(p.wsServerAddr, 2, specificIP)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		p.wsConnsMu.Lock()
		p.wsConns[channelID] = newConn
		p.wsConnsMu.Unlock()
		log.Printf("[客户端] 通道 %d 已重连", channelID)
		go p.handleChannel(channelID, newConn)
		return
	}
}

func (p *ECHPool) SendData(connID string, b []byte) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	p.wsConnsMu.RLock()
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.wsConnsMu.RUnlock()
	p.mu.RUnlock()
	if !ok || ws == nil {
		return fmt.Errorf("未分配通道")
	}
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("DATA:"+connID+"|"+string(b)))
	p.wsMutexes[chID].Unlock()
	return err
}

func (p *ECHPool) SendClose(connID string) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	p.wsConnsMu.RLock()
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.wsConnsMu.RUnlock()
	p.mu.RUnlock()
	if !ok || ws == nil {
		return nil
	}
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+connID))
	p.wsMutexes[chID].Unlock()
	return err
}

// ======================== 代理服务器 ========================

type ProxyConfig struct {
	Username string
	Password string
	Host     string
}

func parseProxyAddr(addr string) (*ProxyConfig, error) {
	config := &ProxyConfig{}
	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的代理地址格式")
		}
		if strings.Contains(parts[0], ":") {
			authParts := strings.SplitN(parts[0], ":", 2)
			config.Username = authParts[0]
			config.Password = authParts[1]
		}
		config.Host = parts[1]
	} else {
		config.Host = addr
	}
	return config, nil
}

func runProxyServer(addr, wsServerAddr string) {
	config, err := parseProxyAddr(addr)
	if err != nil {
		log.Fatalf("解析代理地址失败: %v", err)
	}

	listener, err := net.Listen("tcp", config.Host)
	if err != nil {
		log.Fatalf("代理监听失败 %s: %v", config.Host, err)
	}
	proxyListener = listener
	log.Printf("代理服务器启动: %s (Fallback: %v, IPs: %v)", config.Host, fallback, targetIPs)

	echPool = NewECHPool(wsServerAddr, connectionNum, targetIPs)
	echPool.Start()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// 修复点1：使用 isNormalCloseError 替换硬编码检查
			if isNormalCloseError(err) {
				return
			}
			continue
		}
		go handleProxyConnection(conn, config)
	}
}

func handleProxyConnection(conn net.Conn, config *ProxyConfig) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	// 修复点2：使用 switch 语句替换连续的 if，解决 QF1003 提示
	switch buf[0] {
	case 0x05:
		handleSOCKS5(conn, config)
	case 'G', 'P', 'C', 'H', 'D', 'O':
		handleHTTP(conn, config, buf[0])
	}
}

// ======================== SOCKS5 ========================

func handleSOCKS5(conn net.Conn, config *ProxyConfig) {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	methods := make([]byte, buf[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	var method uint8 = noAuth
	if config.Username != "" {
		method = userPassAuth
		found := false
		for _, m := range methods {
			if m == userPassAuth {
				found = true
				break
			}
		}
		if !found {
			method = noAcceptable
		}
	}

	conn.Write([]byte{0x05, method})
	if method == noAcceptable {
		return
	}

	if method == userPassAuth {
		if !handleSOCKS5Auth(conn, config) {
			return
		}
	}

	handleSOCKS5Request(conn, config)
}

func handleSOCKS5Auth(conn net.Conn, config *ProxyConfig) bool {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 1 {
		return false
	}
	user := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, user); err != nil {
		return false
	}
	buf = make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	pass := make([]byte, buf[0])
	if _, err := io.ReadFull(conn, pass); err != nil {
		return false
	}

	status := byte(0x00)
	if string(user) != config.Username || string(pass) != config.Password {
		status = 0x01
	}
	conn.Write([]byte{0x01, status})
	return status == 0x00
}

func handleSOCKS5Request(conn net.Conn, config *ProxyConfig) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 5 {
		return
	}
	cmd, atyp := buf[1], buf[3]

	var host string
	switch atyp {
	case ipv4Addr:
		b := make([]byte, 4)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	case domainAddr:
		b := make([]byte, 1)
		io.ReadFull(conn, b)
		d := make([]byte, b[0])
		io.ReadFull(conn, d)
		host = string(d)
	case ipv6Addr:
		b := make([]byte, 16)
		io.ReadFull(conn, b)
		host = net.IP(b).String()
	default:
		// 使用 addressTypeNotSupported 需要在 const 定义，或直接使用 hex
		conn.Write([]byte{0x05, 0x08, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	io.ReadFull(conn, portBuf)
	port := int(portBuf[0])<<8 | int(portBuf[1])

	target := fmt.Sprintf("%s:%d", host, port)
	if atyp == ipv6Addr {
		target = fmt.Sprintf("[%s]:%d", host, port)
	}

	switch cmd {
	case connectCmd:
		handleSOCKS5Connect(conn, target)
	case udpAssociateCmd:
		handleSOCKS5UDP(conn, config)
	default:
		conn.Write([]byte{0x05, commandNotSupported, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func handleSOCKS5Connect(conn net.Conn, target string) {
	connID := uuid.New().String()
	conn.SetDeadline(time.Time{})
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 32768)
	n, _ := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	first := ""
	if n > 0 {
		first = string(buf[:n])
	}

	echPool.RegisterAndClaim(connID, target, first, conn)
	if !echPool.WaitConnected(connID, 5*time.Second) {
		conn.Write([]byte{0x05, generalFailure, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	conn.Write([]byte{0x05, succeeded, 0, 1, 0, 0, 0, 0, 0, 0})

	defer func() {
		echPool.SendClose(connID)
		conn.Close()
		echPool.mu.Lock()
		delete(echPool.tcpMap, connID)
		echPool.mu.Unlock()
	}()

	buf = make([]byte, 32768)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if echPool.SendData(connID, buf[:n]) != nil {
			return
		}
	}
}

func handleSOCKS5UDP(conn net.Conn, config *ProxyConfig) {
	host, _, _ := net.SplitHostPort(config.Host)
	udpAddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		conn.Write([]byte{0x05, generalFailure, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpListener.Close()

	actualAddr := udpListener.LocalAddr().(*net.UDPAddr)
	resp := []byte{0x05, succeeded, 0x00}
	if ip4 := actualAddr.IP.To4(); ip4 != nil {
		resp = append(resp, ipv4Addr)
		resp = append(resp, ip4...)
	} else {
		resp = append(resp, ipv6Addr)
		resp = append(resp, actualAddr.IP...)
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(actualAddr.Port))
	resp = append(resp, port...)
	conn.Write(resp)

	connID := uuid.New().String()
	assoc := &UDPAssociation{
		connID:      connID,
		tcpConn:     conn,
		udpListener: udpListener,
		pool:        echPool,
		done:        make(chan bool, 2),
	}
	echPool.RegisterUDP(connID, assoc)
	conn.SetDeadline(time.Time{})

	go assoc.handleUDPRelay()
	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := conn.Read(buf); err != nil {
				assoc.done <- true
				return
			}
		}
	}()

	<-assoc.done
	assoc.Close()
}

func (a *UDPAssociation) handleUDPRelay() {
	buf := make([]byte, 65535)
	for {
		n, src, err := a.udpListener.ReadFromUDP(buf)
		if err != nil {
			a.done <- true
			return
		}
		if a.clientUDPAddr == nil {
			a.mu.Lock()
			a.clientUDPAddr = src
			a.mu.Unlock()
		} else if a.clientUDPAddr.String() != src.String() {
			continue
		}
		go a.handlePacket(buf[:n])
	}
}

func (a *UDPAssociation) handlePacket(pkt []byte) {
	target, data, err := parseSOCKS5UDP(pkt)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	if !a.receiving {
		a.receiving = true
		a.pool.SendUDPConnect(a.connID, target)
		go func() {
			if !a.pool.WaitConnected(a.connID, 5*time.Second) {
				a.done <- true
			}
		}()
	}
	a.pool.SendUDPData(a.connID, data)
}

func (a *UDPAssociation) handleUDPResponse(addr string, data []byte) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return
	}
	var port int
	fmt.Sscanf(parts[1], "%d", &port)
	pkt, _ := buildSOCKS5UDP(parts[0], port, data)
	if a.clientUDPAddr != nil {
		a.mu.Lock()
		a.udpListener.WriteToUDP(pkt, a.clientUDPAddr)
		a.mu.Unlock()
	}
}

func (a *UDPAssociation) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	if a.pool != nil {
		a.pool.SendUDPClose(a.connID)
	}
	if a.udpListener != nil {
		a.udpListener.Close()
	}
}

func parseSOCKS5UDP(pkt []byte) (string, []byte, error) {
	if len(pkt) < 10 || pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
		return "", nil, fmt.Errorf("invalid")
	}
	atyp := pkt[3]
	offset := 4
	var host string
	switch atyp {
	case ipv4Addr:
		host = net.IP(pkt[offset : offset+4]).String()
		offset += 4
	case domainAddr:
		l := int(pkt[offset])
		offset++
		host = string(pkt[offset : offset+l])
		offset += l
	case ipv6Addr:
		host = net.IP(pkt[offset : offset+16]).String()
		offset += 16
	default:
		return "", nil, fmt.Errorf("unsupported")
	}
	port := int(pkt[offset])<<8 | int(pkt[offset+1])
	offset += 2
	target := fmt.Sprintf("%s:%d", host, port)
	if atyp == ipv6Addr {
		target = fmt.Sprintf("[%s]:%d", host, port)
	}
	return target, pkt[offset:], nil
}

func buildSOCKS5UDP(host string, port int, data []byte) ([]byte, error) {
	pkt := []byte{0, 0, 0}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			pkt = append(pkt, ipv4Addr)
			pkt = append(pkt, ip4...)
		} else {
			pkt = append(pkt, ipv6Addr)
			pkt = append(pkt, ip...)
		}
	} else {
		pkt = append(pkt, domainAddr, byte(len(host)))
		pkt = append(pkt, []byte(host)...)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	pkt = append(pkt, p...)
	pkt = append(pkt, data...)
	return pkt, nil
}

// ======================== HTTP ========================

func handleHTTP(conn net.Conn, config *ProxyConfig, first byte) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{first}), conn))
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) != 3 {
		return
	}
	method, reqURL := parts[0], parts[1]

	if method == "CONNECT" {
		handleHTTPConnect(conn, reader, config, reqURL)
	} else {
		handleHTTPForward(conn, reader, config, method, reqURL)
	}
}

func handleHTTPConnect(conn net.Conn, reader *bufio.Reader, config *ProxyConfig, target string) {
	headers := readHeaders(reader)
	if config.Username != "" && !validateAuth(headers["Proxy-Authorization"], config.Username, config.Password) {
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
		return
	}

	connID := uuid.New().String()
	conn.SetDeadline(time.Time{})
	echPool.RegisterAndClaim(connID, target, "", conn)
	if !echPool.WaitConnected(connID, 5*time.Second) {
		conn.Write([]byte("HTTP/1.1 504 Gateway Timeout\r\n\r\n"))
		return
	}
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	defer func() {
		echPool.SendClose(connID)
		conn.Close()
		echPool.mu.Lock()
		delete(echPool.tcpMap, connID)
		echPool.mu.Unlock()
	}()

	buf := make([]byte, 32768)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if echPool.SendData(connID, buf[:n]) != nil {
			return
		}
	}
}

func handleHTTPForward(conn net.Conn, reader *bufio.Reader, config *ProxyConfig, method, reqURL string) {
	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	headers := readHeaders(reader)
	if config.Username != "" && !validateAuth(headers["Proxy-Authorization"], config.Username, config.Password) {
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
		return
	}

	target := parsedURL.Host
	if !strings.Contains(target, ":") {
		if parsedURL.Scheme == "https" {
			target += ":443"
		} else {
			target += ":80"
		}
	}

	var body []byte
	if cl, ok := headers["Content-Length"]; ok {
		var l int
		fmt.Sscanf(cl, "%d", &l)
		if l > 0 && l < 10*1024*1024 {
			body = make([]byte, l)
			io.ReadFull(reader, body)
		}
	}

	var buf bytes.Buffer
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	buf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	for k, v := range headers {
		if k != "Proxy-Authorization" && k != "Proxy-Connection" {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	if _, ok := headers["Host"]; !ok {
		buf.WriteString(fmt.Sprintf("Host: %s\r\n", parsedURL.Host))
	}
	buf.WriteString("\r\n")
	buf.Write(body)

	connID := uuid.New().String()
	conn.SetDeadline(time.Time{})
	echPool.RegisterAndClaim(connID, target, buf.String(), conn)
	if !echPool.WaitConnected(connID, 5*time.Second) {
		conn.Write([]byte("HTTP/1.1 504 Gateway Timeout\r\n\r\n"))
		return
	}

	defer func() {
		echPool.SendClose(connID)
		conn.Close()
		echPool.mu.Lock()
		delete(echPool.tcpMap, connID)
		echPool.mu.Unlock()
	}()

	b := make([]byte, 32768)
	for {
		n, err := conn.Read(b)
		if err != nil {
			return
		}
		if echPool.SendData(connID, b[:n]) != nil {
			return
		}
	}
}

func readHeaders(r *bufio.Reader) map[string]string {
	h := make(map[string]string)
	for {
		line, err := r.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
		if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
			h[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return h
}

func validateAuth(auth, user, pass string) bool {
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		return false
	}
	dec, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(dec), ":", 2)
	return len(parts) == 2 && parts[0] == user && parts[1] == pass
}
