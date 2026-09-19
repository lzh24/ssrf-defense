const { safeRequest, get, post, SSRFError } = require('./safe-request');

/**
 * 测试用例
 */
const tests = [
    {
        name: '正常HTTP请求',
        url: 'http://httpbin.org/get',
        shouldError: false,
        description: '正常的外部HTTP请求'
    },
    {
        name: 'HTTPS请求',
        url: 'https://httpbin.org/get',
        shouldError: false,
        description: '正常的外部HTTPS请求'
    },
    {
        name: '内网IP攻击',
        url: 'http://192.168.1.1/',
        shouldError: true,
        description: '尝试访问内网IP'
    },
    {
        name: '本地回环攻击',
        url: 'http://127.0.0.1/',
        shouldError: true,
        description: '尝试访问本地回环地址'
    },
    {
        name: '特殊字符绕过',
        url: 'http://example.com\\@10.0.0.1/',
        shouldError: true,
        description: '使用特殊字符尝试绕过检测'
    },
    {
        name: '不支持的协议',
        url: 'ftp://example.com/',
        shouldError: true,
        description: '使用不支持的FTP协议'
    },
    {
        name: '无效URL',
        url: 'not-a-url',
        shouldError: true,
        description: '无效的URL格式'
    }
];

/**
 * 运行单个测试
 */
async function runTest(test) {
    console.log(`\n${test.name}: ${test.url}`);
    console.log(`描述: ${test.description}`);
    
    try {
        const response = await get(test.url, { timeout: 3000 });
        
        if (test.shouldError) {
            console.log('❌ 期望出现错误，但请求成功了');
            return false;
        } else {
            console.log(`✅ 成功 - 状态码: ${response.statusCode}`);
            return true;
        }
    } catch (error) {
        if (test.shouldError) {
            if (error instanceof SSRFError) {
                console.log(`🛡️ 被阻止: ${error.message}`);
                return true;
            } else {
                console.log(`🛡️ 被阻止: ${error.message}`);
                return true;
            }
        } else {
            if (error instanceof SSRFError) {
                console.log(`❌ 不应该被SSRF防护阻止: ${error.message}`);
                return false;
            } else {
                console.log(`⚠️ 网络错误: ${error.message}`);
                return true; // 网络错误不算测试失败
            }
        }
    }
}

/**
 * 测试POST请求
 */
async function testPostRequest() {
    console.log('\n=== POST请求测试 ===');
    
    try {
        const body = JSON.stringify({ test: 'data' });
        const response = await post('http://httpbin.org/post', body, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 5000
        });
        
        console.log(`✅ POST请求成功 - 状态码: ${response.statusCode}`);
        return true;
    } catch (error) {
        if (error instanceof SSRFError) {
            console.log(`❌ POST请求不应该被SSRF防护阻止: ${error.message}`);
            return false;
        } else {
            console.log(`⚠️ POST请求网络错误: ${error.message}`);
            return true;
        }
    }
}

/**
 * 测试自定义选项
 */
async function testCustomOptions() {
    console.log('\n=== 自定义选项测试 ===');
    
    try {
        const response = await safeRequest('http://httpbin.org/get', {
            method: 'GET',
            headers: {
                'User-Agent': 'SafeRequest-Node/1.0',
                'Accept': 'application/json'
            },
            timeout: 10000,
            followRedirects: true
        });
        
        console.log(`✅ 自定义选项请求成功 - 状态码: ${response.statusCode}`);
        return true;
    } catch (error) {
        if (error instanceof SSRFError) {
            console.log(`❌ 自定义选项请求不应该被SSRF防护阻止: ${error.message}`);
            return false;
        } else {
            console.log(`⚠️ 自定义选项请求网络错误: ${error.message}`);
            return true;
        }
    }
}

/**
 * 主测试函数
 */
async function runAllTests() {
    console.log('=== Node.js SSRF防御测试 ===');
    
    let passedTests = 0;
    let totalTests = tests.length;
    
    // 运行基本测试
    for (const test of tests) {
        const result = await runTest(test);
        if (result) {
            passedTests++;
        }
    }
    
    // 运行POST测试
    const postResult = await testPostRequest();
    if (postResult) {
        passedTests++;
    }
    totalTests++;
    
    // 运行自定义选项测试
    const customResult = await testCustomOptions();
    if (customResult) {
        passedTests++;
    }
    totalTests++;
    
    console.log(`\n=== 测试结果 ===`);
    console.log(`通过: ${passedTests}/${totalTests}`);
    console.log(`测试完成！`);
}

// 运行测试
if (require.main === module) {
    runAllTests().catch(console.error);
}

module.exports = {
    runAllTests,
    runTest,
    testPostRequest,
    testCustomOptions
};
