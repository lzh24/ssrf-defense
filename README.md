# SSRF防御方案

## 代码层

（1）去除url中的特殊字符 ('\'、'@')
（2）禁用不需要的协议，仅允许http和https请求。防止ftp、gopher、telnet、dict、file、ldap等协议引起的问题
（3）统一错误信息，避免用户可以根据错误信息来判断远端服务器的端口状态
（4）判断url中的host是否为域名，如果为域名则解析为ip，并将url中的host改为ip；如果不为域名则无需替换
（5）判断url中的host ip是否属于内网ip，限制访问内网（包括10.x.x.x等内网网段）
（6）请求的url为第（4）步中修改返回的url
（7）如果第（4）步中存在url域名修改替换ip的话，则请求修改后的url时需额外设置host header为域名
（8）不跟随30x跳转（跟随跳转需要从1开始重新检测）

其中第（1）步是为了防止利用url parse的特性造成url解析差异；第（4）步是为了防止dns rebinding；第（7）步是为了防止如果原始url为域名，替换url host为ip后，以url ip请求时，某些网站无法访问的问题；第（8）步是为了防止30x跳转绕过问题；


## 网络层

1. 或者直接使用公有云或者单向隔离网段的机器做代理，请求均使用代理请求，也可修复此类问题。比如在云平台上申请一个隔离网段的机器：
```shell
python3 -m pip install pproxy
python3 -m pproxy -l socks5://:8090/#username:password -v
```
请求测试：
```shell
curl http://example.com -x socks5://username:password@<PROXY_IP>:8090 -I
```


2. 或者网络请求模块部署到单向隔离网段（该网段机器无法访问idc，仅可访问外网）
