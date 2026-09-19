package saferequest

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// SSRFError SSRF防御异常
type SSRFError struct {
	Message string
}

func (e *SSRFError) Error() string {
	return e.Message
}

// 配置常量
var (
	allowedProtocols   = []string{"http", "https"}
	// 如需拦截其他自定义内网网段，在此追加前缀即可
	privateIPPrefixes  = []string{"10.", "172.16.", "192.168.", "127.", "169.254."}
	errorMsg          = "Request blocked for security reasons"
	ipRegex           = regexp.MustCompile(`^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$`)
)

// resolveDomain 域名解析为IP
func resolveDomain(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", err
	}
	
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	
	return "", errors.New("no IPv4 address found")
}

// isPrivateIP 检查是否为私有IP
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	// 检查 0.0.0.0 和未指定地址
	if ip.IsUnspecified() {
		return true
	}

	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	
	// 额外检查特定前缀
	for _, prefix := range privateIPPrefixes {
		if strings.HasPrefix(ipStr, prefix) {
			return true
		}
	}
	
	return false
}

// validateURL 验证并处理URL，返回(处理后的URL, 原始域名, error)
func validateURL(rawURL string) (string, string, error) {
	// 清理特殊字符
	rawURL = strings.ReplaceAll(rawURL, "\\", "")
	rawURL = strings.ReplaceAll(rawURL, "@", "")
	
	// 解析URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", "", &SSRFError{Message: "Invalid URL"}
	}
	
	// 检查协议
	allowed := false
	for _, protocol := range allowedProtocols {
		if parsedURL.Scheme == protocol {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", "", &SSRFError{Message: "Unsupported protocol"}
	}
	
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return "", "", &SSRFError{Message: "Invalid URL"}
	}
	
	// 检查是否为IP地址
	if ipRegex.MatchString(hostname) {
		if isPrivateIP(hostname) {
			return "", "", &SSRFError{Message: "Private IP access denied"}
		}
		return rawURL, "", nil
	}
	
	// 域名解析
	ip, err := resolveDomain(hostname)
	if err != nil {
		return "", "", &SSRFError{Message: errorMsg}
	}
	
	if isPrivateIP(ip) {
		return "", "", &SSRFError{Message: "Domain resolves to private IP"}
	}
	
	// 替换域名为IP
	parsedURL.Host = ip
	if parsedURL.Port() != "" {
		parsedURL.Host = net.JoinHostPort(ip, parsedURL.Port())
	}
	
	return parsedURL.String(), hostname, nil
}

// SafeRequestOptions 安全请求选项
type SafeRequestOptions struct {
	Method          string
	Headers         map[string]string
	Body            io.Reader
	Timeout         time.Duration
	FollowRedirects bool
	VerifySSL       bool
}

// SafeRequest 安全的HTTP请求
func SafeRequest(rawURL string, options *SafeRequestOptions) (*http.Response, error) {
    if options == nil {
        options = &SafeRequestOptions{
            Method:          "GET",
            Headers:         make(map[string]string),
            Timeout:         30 * time.Second,
            FollowRedirects: true,
            VerifySSL:       false,
        }
    }

	// 禁用自动重定向
	client := &http.Client{
		Timeout: options.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
    
    currentURL := rawURL

    
    for i := 0; i <= 10; i++ { // Max 10 redirects
        // 1. Resolve & Validate IP
        // We do this manually to get the safeIP. 
        // Note: We need to parse the currentURL to get the hostname to resolve.
        // parsedURL is still needed for base.Parse(location) later, so keep it.
        _, err := url.Parse(currentURL)
        if err != nil {
            return nil, fmt.Errorf("invalid url: %v", err)
        }
        
        // hostname variable is unused as we use valid result from validateURL directly.
        
        safeUrlStr, _, err := validateURL(currentURL)
        if err != nil {
             return nil, err
        }
        
        tmpSafe, _ := url.Parse(safeUrlStr)
        targetIP := tmpSafe.Hostname() // This is the validated IP
        
        // 2. Create Custom Transport
        dialer := &net.Dialer{
            Timeout:   options.Timeout,
            KeepAlive: 30 * time.Second,
        }
        
        transport := &http.Transport{
            Proxy:                 http.ProxyFromEnvironment,
            DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                // addr is "hostname:port" (e.g. "example.com:443")
                // We overwrite the destination to our targetIP but keep the port.
                _, port, _ := net.SplitHostPort(addr)
                return dialer.DialContext(ctx, network, net.JoinHostPort(targetIP, port))
            },
            ForceAttemptHTTP2:     true,
            MaxIdleConns:          100,
            IdleConnTimeout:       90 * time.Second,
            TLSHandshakeTimeout:   10 * time.Second,
            ExpectContinueTimeout: 1 * time.Second,
        }
        
        if !options.VerifySSL {
            transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
        }
        
        client.Transport = transport
        
        // 3. Create Request with ORIGINAL URL (preserves SNI)
        req, err := http.NewRequest(options.Method, currentURL, options.Body)
        if err != nil {
            return nil, err
        }
        
        // Headers
        for key, value := range options.Headers {
            req.Header.Set(key, value)
        }
        
        // Execute
        resp, err := client.Do(req)
        if err != nil {
            return nil, err
        }
        
        // Handle Redirects
        if options.FollowRedirects && (resp.StatusCode >= 300 && resp.StatusCode < 400) {
             location := resp.Header.Get("Location")
             if location == "" {
                 return nil, errors.New("redirect without Location header")
             }
             
             // Resolve relative path
             base, _ := url.Parse(currentURL)
             next, _ := base.Parse(location)
             currentURL = next.String()
             
             resp.Body.Close()
             continue
        }
        
        return resp, nil
    }
    return nil, errors.New("too many redirects")
}

// Get 安全的GET请求
func Get(url string) (*http.Response, error) {
	return SafeRequest(url, &SafeRequestOptions{
		Method:          "GET",
		Headers:         make(map[string]string),
		Timeout:         30 * time.Second,
		FollowRedirects: true,
		VerifySSL:       false,
	})
}

// Post 安全的POST请求
func Post(url string, body io.Reader, contentType string) (*http.Response, error) {
	headers := make(map[string]string)
	if contentType != "" {
		headers["Content-Type"] = contentType
	}
	
	return SafeRequest(url, &SafeRequestOptions{
		Method:          "POST",
		Headers:         headers,
		Body:            body,
		Timeout:         30 * time.Second,
		FollowRedirects: true,
		VerifySSL:       false,
	})
}
