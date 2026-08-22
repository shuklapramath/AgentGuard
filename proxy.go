package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type ProxyPolicy struct {
	PolicyID		uint32
	Feedback		string
	AllowedHosts	[]string		// "api.anthropic.com"
	AllowedPorts	map[int]bool	// {443 : true}
	AllowIPLiteral	bool			// default false. The AI Agent may do a local DNS lookup instead of a domain name. Reject those.

}
func hostMatches(pattern, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1 : ]
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return host == pattern
}

func (p *ProxyPolicy) permit(host string, port int) error {
	if !p.AllowedPorts[port] {
		return fmt.Errorf("port %d not permitted", port)
	}
	// An IP-literal CONNECT bypasses hostname policy entirely. Reject it.
	if ip := net.ParseIP(host); ip != nil && !p.AllowIPLiteral {
		return fmt.Errorf("IP-literal destination %s not permitted", ip)
	}
	for _, pat := range p.AllowedHosts{
		if hostMatches(pat, host){
			return nil
		}
	}
	return fmt.Errorf("host %q not in allowlist", host)
}
var blockedNets = func()  []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
              "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/4",
              "::1/128", "fc00::/7", "fe80::/10",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

func isBlockedIP(ip net.IP) bool {
	for _,n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

var upstreamDialer = &net.Dialer{
	Timeout: 10 * time.Second,
	Control: func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil || isBlockedIP(ip) {
			return fmt.Errorf("egress to %s denied (private/loopback address)", address)
		}
		return nil
	},
}

// peekSNI reads the ClientHello from br without consuming it from the kernel,
// Since br is what handle() subsequently splices upstream. It assumes the 
// ClientHello fits in a single TLS record (true for almost all real clients;
// a ClientHello fragmented across records is rejected as non-TLS)
func peekSNI(br *bufio.Reader) (string, error) {
	hdr, err := br.Peek(5)
	if err != nil {
		return "", err
	}
	if hdr[0] != 0x16 {
		// not a TLS handshake record
		return "", errors.New("tunnel payload is not TLS")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > 16384 {
		return "", errors.New("bad TLS record length")
	}
	buf, err := br.Peek(5 + recLen)
	if err != nil {
		return "", err
	}
	sni, err := parseClientHelloSNI(buf[5 : ])
	if err != nil {
		return "", err
	}
	return sni, nil
}
/*
sni, err := peekSNI(clientReader)
if err != nil {
	deny(clientPID, host, fmt.Sprintf("non-TLS tunnel payload: %v", err))
	return
}
if !strings.EqualFold(strings.TrimSuffix(sni, "."), strings.TrimSuffix(host, ".")){
	deny(clientPID, host, fmt.Sprintf("SNI %q does not match CONNECT host %q domain fronting", sni, host))
	return
}
*/

// parseClientHelloSNI extracts the server_name extension (type 0x0000, host_name
// entries only) from a TLS ClientHello handshake message. body is the record
// payload, i.e. it starts at the Handshake Type byte (0x01 for ClientHello).
func parseClientHelloSNI(body []byte) (string, error) {
      if len(body) < 4 || body[0] != 0x01 {
              return "", errors.New("not a ClientHello")
      }
      pos := 4 // handshake type (1) + length (3)

      if pos+2+32+1 > len(body) {
              return "", errors.New("truncated client hello")
      }
      pos += 2  // client_version
      pos += 32 // random

      sidLen := int(body[pos])
      pos++
      pos += sidLen
      if pos+2 > len(body) {
              return "", errors.New("truncated client hello (session_id)")
      }

      csLen := int(body[pos])<<8 | int(body[pos+1])
      pos += 2 + csLen
      if pos+1 > len(body) {
              return "", errors.New("truncated client hello (cipher_suites)")
      }

      cmLen := int(body[pos])
      pos += 1 + cmLen
      if pos+2 > len(body) {
              return "", errors.New("no extensions present (no SNI)")
      }

      extTotalLen := int(body[pos])<<8 | int(body[pos+1])
      pos += 2
      end := pos + extTotalLen
      if end > len(body) {
              end = len(body) // our peek window may be shorter than the declared length; be lenient
      }

      for pos+4 <= end {
              extType := int(body[pos])<<8 | int(body[pos+1])
              extLen := int(body[pos+2])<<8 | int(body[pos+3])
              pos += 4
              if pos+extLen > len(body) {
                      break
              }
              if extType == 0x0000 { // server_name
                      extData := body[pos : pos+extLen]
                      if len(extData) < 2 {
                              return "", errors.New("malformed server_name extension")
                      }
                      listLen := int(extData[0])<<8 | int(extData[1])
                      p := 2
                      for p+3 <= len(extData) && p+3 <= 2+listLen {
                              nameType := extData[p]
                              nameLen := int(extData[p+1])<<8 | int(extData[p+2])
                              p += 3
                              if p+nameLen > len(extData) {
                                      break
                              }
                              if nameType == 0 {
                                      return string(extData[p : p+nameLen]), nil
                              }
                              p += nameLen
                      }
                      return "", errors.New("no host_name entry in server_name extension")
              }
              pos += extLen
      }
      return "", errors.New("no SNI extension present")
}


type ProxyServer struct {
	policy		*ProxyPolicy
	token		string
	listener	net.Listener
	port		int
}

// NewProxyServer binds the listener immediately so the caller can read back
// the actual port (e.g. when "listen" in the YAML uses port 0) before wiring
// it into the enforcer's proxy_addr_host / proxy_port_host constants, which
// must be set before the eBPF object is loaded. 
func NewProxyServer(policy *ProxyPolicy, listen string) (*ProxyServer, error) {
      tokenBytes := make([]byte, 32)
      if _, err := rand.Read(tokenBytes); err != nil {
              return nil, fmt.Errorf("generating proxy token: %w", err)
      }
      token := base64.RawURLEncoding.EncodeToString(tokenBytes)

      ln, err := net.Listen("tcp", listen)
      if err != nil {
              return nil, fmt.Errorf("binding proxy listener on %s: %w", listen, err)
      }

      _, portStr, err := net.SplitHostPort(ln.Addr().String())
      if err != nil {
              ln.Close()
              return nil, err
      }
      port, err := strconv.Atoi(portStr)
      if err != nil {
              ln.Close()
              return nil, err
      }

      return &ProxyServer{
              policy:   policy,
              token:    token,
              listener: ln,
              port:     port,
      }, nil
}

func (s *ProxyServer) Token() string {return s.token}
func (s *ProxyServer) Addr() string {return s.listener.Addr().String()}

// Serve blocks, accepting connections until the listener is closed.
func (s *ProxyServer) Serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed){
				return
			}
			log.Printf("⚠️  proxy accept error: %v", err)
			continue
		}
		go s.handle(conn)
	}
}

func (s *ProxyServer) Close() error {
	return s.listener.Close()
}

//func (s *ProxyServer) Start           // net.Listen("tcp", "127.0.0.1:PORT") + accept loop

func (s *ProxyServer) identify(conn net.Conn) uint32 {
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("⚠️  unexpected proxy client remote addr type %T", conn.RemoteAddr())
		return 0
	}
	pid, err := findClientPID(uint16(tcpAddr.Port), uint16(s.port))
	if err != nil {
		log.Printf("⚠️  could not identify proxy client pid: %v", err)
		return 0
	}
	return pid
}      
func findClientPID(localPort, remotePort uint16) (uint32, error){
	inode, err := findSocketInode(localPort, remotePort)
	if err != nil {
		return 0, err
	}
	return findPidOwningInode(inode)
} 

// findSocketInode scans /proc/net/tcp for the socket the client opened to
// reach the proxy: the entry whose local port is the client's own ephemeral
// port and whose remote port is the proxy's listening port. 
func findSocketInode(localPort, remotePort uint16) (string, error){
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return "", err
	}
	defer f.Close()

	wantLocal := fmt.Sprintf(":%04X", localPort)
	wantRemote := fmt.Sprintf(":%04X", remotePort)

	sc := bufio.NewScanner(f)
	sc.Scan() 	// header line
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		if strings.HasSuffix(fields[1], wantLocal) && strings.HasSuffix(fields[2], wantRemote) {
			return fields[9], nil 	// inode column
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("no matching /proc/net/tcp entry")
}

func findPidOwningInode(inode string) (uint32, error) {
    target := "socket:[" + inode + "]"
	entries, err := os.ReadDir("/proc")
    if err != nil {
        return 0, err
    }
    for _, e := range entries {
        pid, err := strconv.Atoi(e.Name())
        if err != nil {
            continue // not a PID directory
        }
        fdDir := fmt.Sprintf("/proc/%d/fd", pid)
        fds, err := os.ReadDir(fdDir)
        if err != nil {
            continue // process exited, or /proc/<pid>/fd unreadable
        }
        for _, fd := range fds {
            link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fd.Name()))
            if err != nil {
                continue
            }
            if link == target {
				return uint32(pid), nil
            }
        }
    }
    return 0, errors.New("no process owns that socket inode")
}

func (s *ProxyServer) authOK(header string) bool {
	if header == "" {
		return false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix){
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	return parts[1] == s.token
}

// ---- TEMPORARY FIX ----
// isTelemetryHost checks if the target is a known telemetry host.
// Ignore telemetry denials from the agent. 
func isTelemetryHost(target string) bool {
	h := strings.ToLower(target)
	return strings.Contains(h, "datadoghq.com") ||
		strings.Contains(h, "sentry.io") ||
		strings.Contains(h, "statsig") ||
		strings.Contains(h, "segment.io") ||
		strings.Contains(h, "api.event_logging")
}

func (s *ProxyServer) deny(clientPID uint32, target, why string) {
	log.Printf("🚨 EGRESS BLOCKED: pif=%d target=%s (%s)", clientPID, target, why)

	// Telemetry denials must not overwrite IPC meant for real tool/user egress.
	if isTelemetryHost(target) {
		return
	}

	sessionID := resolveSessionID(clientPID)
	reason := fmt.Sprintf("%s (destination: %s)", s.policy.Feedback, target)
	feedbackSent := false
	if sessionID == "" {
		log.Printf("⚠️ no session mapped for pid %d; violation not surfaced to agent", clientPID)
	} else if err := writePendingViolation(sessionID, PendingViolation{
		Reason:			reason,
		PolicyType: 	uint8(s.policy.PolicyID),
		Path:			target,
		TimestampNs:    monotonicNowNs(),
	}); err != nil {
		log.Printf("❌ writing violation file: %v", err)
	} else {
		feedbackSent = true
		log.Printf("[STEP 5] wrote IPC violation for session %s (target=%s)", sessionID, target)
	}

	recordViolation(clientPID, s.policy.PolicyID, "", target, reason, sessionID, "proxy", monotonicNowNs(), feedbackSent)
}

func (s *ProxyServer) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	clientPID := s.identify(conn)

	if !s.authOK(req.Header.Get("Proxy-Authorization")) {
		io.WriteString(conn, "HTTP/1.1 407 Proxy AuthenticationRequired\r\n Required\r\nProxy-Authenticate: Basic realm=\"agentguard\"\r\n\r\n")
		return
	}

	if req.Method != http.MethodConnect {
		// Plaintext HTTP proxying cannot be SNI-verified 
		s.deny(clientPID, req.Host, "plaintext HTTP proxying not permitted")
		io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\n\r\n[SYSTEM]: plaintext HTTP egress is not permitted\r\n")
        return
	}
	host, portStr, err := net.SplitHostPort(req.Host)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	if err := s.policy.permit(host, port); err != nil {
		s.deny(clientPID, req.Host, err.Error())
		fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\n\r\n[SECURITY]: %s\r\n", s.policy.Feedback)
		return
	}

	upStream, err := upstreamDialer.Dial("tcp4", net.JoinHostPort(host, portStr))
	if err != nil {
		s.deny(clientPID, req.Host, err.Error())
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return 
	}
	defer upStream.Close()

	io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")

	if port == 443 {
		sni, err := peekSNI(br)
		if err != nil || !strings.EqualFold(strings.TrimSuffix(sni, "."), strings.TrimSuffix(host, ".")) {
			s.deny(clientPID, req.Host, fmt.Sprintf("SNI mismatch: %q vs %q (%v)", sni, host, err))
			return 
		}
	}
	conn.SetDeadline(time.Time{})		// long lived streaming responses
	go func() {
        io.Copy(upStream, br)
        if tcpConn, ok := upStream.(*net.TCPConn); ok {
            tcpConn.CloseWrite()
        }
    }()
    io.Copy(conn, upStream)
}
