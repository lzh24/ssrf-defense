package saferequest

import (
	"fmt"
	"testing"
	"time"
)

func TestSafeRequest(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		shouldError bool
		description string
	}{
		{
			name:        "正常URL",
			url:         "http://httpbin.org/get",
			shouldError: false,
			description: "正常的外部HTTP请求",
		},
		{
			name:        "HTTPS请求",
			url:         "https://httpbin.org/get",
			shouldError: false,
			description: "正常的外部HTTPS请求",
		},
		{
			name:        "内网IP攻击",
			url:         "http://192.168.1.1/",
			shouldError: true,
			description: "尝试访问内网IP",
		},
		{
			name:        "本地回环攻击",
			url:         "http://127.0.0.1/",
			shouldError: true,
			description: "尝试访问本地回环地址",
		},
		{
			name:        "特殊字符绕过",
			url:         "http://example.com\\@10.0.0.1/",
			shouldError: true,
			description: "使用特殊字符尝试绕过检测",
		},
		{
			name:        "不支持的协议",
			url:         "ftp://example.com/",
			shouldError: true,
			description: "使用不支持的FTP协议",
		},
		{
			name:        "无效URL",
			url:         "not-a-url",
			shouldError: true,
			description: "无效的URL格式",
		},
	}

	fmt.Println("=== Go SSRF防御测试 ===")
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Printf("\n%s: %s\n", tt.name, tt.url)
			fmt.Printf("描述: %s\n", tt.description)
			
			options := &SafeRequestOptions{
				Method:          "GET",
				Headers:         make(map[string]string),
				Timeout:         3 * time.Second,
				FollowRedirects: true,
			}
			
			resp, err := SafeRequest(tt.url, options)
			
			if tt.shouldError {
				if err != nil {
					fmt.Printf("🛡️ 被阻止: %v\n", err)
				} else {
					t.Errorf("期望出现错误，但请求成功了")
					if resp != nil {
						resp.Body.Close()
					}
				}
			} else {
				if err != nil {
					fmt.Printf("❌ 请求失败: %v\n", err)
					// 对于网络错误，我们不认为是测试失败
					if _, ok := err.(*SSRFError); ok {
						t.Errorf("不应该被SSRF防护阻止")
					}
				} else {
					fmt.Printf("✅ 成功 - 状态码: %d\n", resp.StatusCode)
					resp.Body.Close()
				}
			}
		})
	}
}

func ExampleGet() {
	resp, err := Get("http://httpbin.org/get")
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Printf("状态码: %d\n", resp.StatusCode)
}

func ExampleSafeRequest() {
	options := &SafeRequestOptions{
		Method:          "GET",
		Headers:         map[string]string{"User-Agent": "SafeRequest/1.0"},
		Timeout:         10 * time.Second,
		FollowRedirects: true,
	}
	
	resp, err := SafeRequest("http://httpbin.org/get", options)
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Printf("状态码: %d\n", resp.StatusCode)
}
