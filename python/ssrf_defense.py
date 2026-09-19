"""
简洁版SSRF防御模块 - 保持核心功能，代码更优雅
"""

import requests
import dns.resolver
import ipaddress
import re
from urllib.parse import urlparse, urljoin
from requests.utils import requote_uri
from typing import Optional, Tuple
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SSRFError(Exception):
    """SSRF防御异常"""
    pass


# 配置常量
ALLOWED_PROTOCOLS = ['http', 'https']
# 如需拦截其他自定义内网网段，在此追加前缀即可
PRIVATE_IP_PREFIXES = ['10.', '172.16.', '192.168.', '127.', '169.254.']
ERROR_MSG = "Request blocked for security reasons"


def resolve_domain(domain: str) -> Optional[str]:
    """域名解析为IP"""
    try:
        return dns.resolver.resolve(domain, 'A')[0].to_text()
    except:
        return None


def is_private_ip(ip: str) -> bool:
    """检查是否为私有IP"""
    try:
        if ipaddress.ip_address(ip).is_private:
            return True
    except:
        pass
    return any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


def validate_url(url: str) -> Tuple[str, Optional[str]]:
    """
    验证并处理URL，返回(处理后的URL, 原始域名)
    """
    # 清理特殊字符
    url = url.replace('\\', '').replace('@', '')
    
    # 解析URL
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_PROTOCOLS:
        raise SSRFError("Unsupported protocol")
    
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("Invalid URL")
    
    # 检查是否为IP地址
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        if is_private_ip(hostname):
            raise SSRFError("Private IP access denied")
        return url, None
    
    # 域名解析
    ip = resolve_domain(hostname)
    if not ip:
        raise SSRFError(ERROR_MSG)
    
    if is_private_ip(ip):
        raise SSRFError("Domain resolves to private IP")
    
    # 替换域名为IP
    new_url = parsed._replace(netloc=ip).geturl()
    return new_url, hostname


def safe_request(url: str, follow_redirects: bool = True, verify_ssl: bool = False, **kwargs) -> requests.Response:
    """
    安全的HTTP请求
    """
    def check_redirect(response, *args, **kwargs):
        """重定向检查Hook"""
        if not response.is_redirect:
            return
        
        location = response.headers.get('location', '')
        if not location:
            return
        
        # 处理相对路径
        parsed = urlparse(location)
        if not parsed.netloc:
            location = urljoin(response.url, requote_uri(location))
        
        try:
            validate_url(location)
        except SSRFError as e:
            raise requests.exceptions.InvalidURL(f"Redirect blocked: {e}")
    
    # 验证原始URL
    try:
        safe_url, original_host = validate_url(url)
    except SSRFError as e:
        raise requests.exceptions.InvalidURL(str(e))
    
    # 设置请求头
    headers = kwargs.get('headers', {})
    if original_host:
        headers['Host'] = original_host
    kwargs['headers'] = headers
    
    # 设置重定向处理
    if follow_redirects:
        hooks = kwargs.get('hooks', {})
        response_hooks = hooks.get('response', [])
        if not isinstance(response_hooks, list):
            response_hooks = [response_hooks] if response_hooks else []
        response_hooks.append(check_redirect)
        hooks['response'] = response_hooks
        kwargs['hooks'] = hooks
        kwargs['allow_redirects'] = True
    else:
        kwargs['allow_redirects'] = False
    
    # 设置SSL验证
    kwargs['verify'] = verify_ssl
    
    return requests.get(safe_url, **kwargs)


# 测试函数
def test():
    """简单测试"""
    tests = [
        ("正常URL", "http://httpbin.org/get"),
        ("重定向", "http://httpbin.org/redirect/1"),
        ("内网攻击", "http://192.168.1.1/"),
        ("特殊字符", "http://example.com\\@10.0.0.1/")
    ]
    
    print("=== SSRF防御测试 ===")
    for name, test_url in tests:
        print(f"\n{name}: {test_url}")
        try:
            resp = safe_request(test_url, timeout=3)
            print(f"✅ 成功 - 状态码: {resp.status_code}")
        except Exception as e:
            print(f"🛡️ 被阻止: {e}")


if __name__ == "__main__":
    test()
