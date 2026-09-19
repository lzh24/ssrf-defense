const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const { URL } = require('url');
const { promisify } = require('util');

/**
 * SSRF防御异常类
 */
class SSRFError extends Error {
    constructor(message) {
        super(message);
        this.name = 'SSRFError';
    }
}

// 配置常量
const ALLOWED_PROTOCOLS = ['http:', 'https:'];
// 如需拦截其他自定义内网网段，在此追加前缀即可
const PRIVATE_IP_PREFIXES = ['10.', '172.16.', '192.168.', '127.', '169.254.'];
const ERROR_MSG = 'Request blocked for security reasons';
const IP_REGEX = /^\d+\.\d+\.\d+\.\d+$/;

/**
 * 域名解析为IP
 * @param {string} domain 域名
 * @returns {Promise<string>} IP地址
 */
async function resolveDomain(domain) {
    try {
        const addresses = await dns.resolve4(domain);
        return addresses[0];
    } catch (error) {
        throw new SSRFError(ERROR_MSG);
    }
}

/**
 * 检查是否为私有IP
 * @param {string} ip IP地址
 * @returns {boolean} 是否为私有IP
 */
function isPrivateIP(ip) {
    // 使用Node.js内置的网络工具检查
    const net = require('net');
    if (!net.isIPv4(ip)) {
        return false;
    }
    
    // 检查常见的私有IP范围
    const parts = ip.split('.').map(Number);
    
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    
    // 127.0.0.0/8 (loopback)
    if (parts[0] === 127) return true;
    
    // 169.254.0.0/16 (link-local)
    if (parts[0] === 169 && parts[1] === 254) return true;
    
    // 额外检查特定前缀
    return PRIVATE_IP_PREFIXES.some(prefix => ip.startsWith(prefix));
}

/**
 * 验证并处理URL
 * @param {string} rawURL 原始URL
 * @returns {Promise<{safeURL: string, originalHost: string|null}>} 处理结果
 */
async function validateURL(rawURL) {
    // 清理特殊字符
    rawURL = rawURL.replace(/\\/g, '').replace(/@/g, '');
    
    let parsedURL;
    try {
        parsedURL = new URL(rawURL);
    } catch (error) {
        throw new SSRFError('Invalid URL');
    }
    
    // 检查协议
    if (!ALLOWED_PROTOCOLS.includes(parsedURL.protocol)) {
        throw new SSRFError('Unsupported protocol');
    }
    
    const hostname = parsedURL.hostname;
    if (!hostname) {
        throw new SSRFError('Invalid URL');
    }
    
    // 检查是否为IP地址
    if (IP_REGEX.test(hostname)) {
        if (isPrivateIP(hostname)) {
            throw new SSRFError('Private IP access denied');
        }
        return { safeURL: rawURL, originalHost: null };
    }
    
    // 域名解析
    const ip = await resolveDomain(hostname);
    if (isPrivateIP(ip)) {
        throw new SSRFError('Domain resolves to private IP');
    }
    
    // 替换域名为IP
    const safeURL = rawURL.replace(hostname, ip);
    return { safeURL, originalHost: hostname };
}

/**
 * 安全的HTTP请求
 * @param {string} rawURL 请求URL
 * @param {Object} options 请求选项
 * @returns {Promise<Object>} 响应对象
 */
async function safeRequest(rawURL, options = {}) {
    // 默认选项
    const defaultOptions = {
        method: 'GET',
        headers: {},
        body: null,
        timeout: 30000,
        followRedirects: true,
        maxRedirects: 10,
        verifySSL: false
    };
    
    options = { ...defaultOptions, ...options };
    
    // 验证原始URL
    const { safeURL, originalHost } = await validateURL(rawURL);
    
    const parsedURL = new URL(safeURL);
    const isHttps = parsedURL.protocol === 'https:';
    const httpModule = isHttps ? https : http;
    
    // 设置请求选项
    const requestOptions = {
        hostname: parsedURL.hostname,
        port: parsedURL.port || (isHttps ? 443 : 80),
        path: parsedURL.pathname + parsedURL.search,
        method: options.method,
        headers: { ...options.headers },
        timeout: options.timeout
    };
    
    // 设置SSL验证
    if (isHttps && !options.verifySSL) {
        requestOptions.rejectUnauthorized = false;
    }
    
    // 如果原始URL是域名，设置Host头
    if (originalHost) {
        requestOptions.headers.Host = originalHost;
    }
    
    return new Promise((resolve, reject) => {
        const req = httpModule.request(requestOptions, async (res) => {
            // 处理重定向
            if (options.followRedirects && res.statusCode >= 300 && res.statusCode < 400) {
                const location = res.headers.location;
                if (location && options.maxRedirects > 0) {
                    try {
                        // 处理相对路径
                        let redirectURL = location;
                        if (!location.startsWith('http')) {
                            redirectURL = new URL(location, safeURL).toString();
                        }
                        
                        // 验证重定向URL
                        await validateURL(redirectURL);
                        
                        // 递归处理重定向
                        const redirectOptions = {
                            ...options,
                            maxRedirects: options.maxRedirects - 1
                        };
                        
                        const redirectResponse = await safeRequest(redirectURL, redirectOptions);
                        resolve(redirectResponse);
                        return;
                    } catch (error) {
                        reject(new Error(`Redirect blocked: ${error.message}`));
                        return;
                    }
                }
            }
            
            // 收集响应数据
            let data = '';
            res.setEncoding('utf8');
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: data
                });
            });
        });
        
        req.on('error', (error) => {
            reject(error);
        });
        
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
        
        // 发送请求体
        if (options.body) {
            req.write(options.body);
        }
        
        req.end();
    });
}

/**
 * 安全的GET请求
 * @param {string} url 请求URL
 * @param {Object} options 请求选项
 * @returns {Promise<Object>} 响应对象
 */
async function get(url, options = {}) {
    return safeRequest(url, { ...options, method: 'GET' });
}

/**
 * 安全的POST请求
 * @param {string} url 请求URL
 * @param {string} body 请求体
 * @param {Object} options 请求选项
 * @returns {Promise<Object>} 响应对象
 */
async function post(url, body, options = {}) {
    const headers = { ...options.headers };
    
    if (body && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }
    
    if (body && !headers['Content-Length']) {
        headers['Content-Length'] = Buffer.byteLength(body);
    }
    
    return safeRequest(url, {
        ...options,
        method: 'POST',
        headers,
        body
    });
}

module.exports = {
    safeRequest,
    get,
    post,
    SSRFError
};
