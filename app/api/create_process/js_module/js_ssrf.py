import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义SSRF漏洞检测模式
SSRF_VULNERABILITIES = {
    'javascript': [
        # 网络请求函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(fetch|XMLHttpRequest|request|axios|http\.(get|post|request)|https\.(get|post|request)|got|superagent|node-fetch|urllib|needle)$',
            'message': '网络请求函数调用'
        },
        # HTTP模块方法调用
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @module
                        property: (property_identifier) @method
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(http|https)$',
            'property_pattern': r'^(get|post|put|delete|request|createServer)$',
            'message': 'HTTP模块方法调用'
        },
        # 子进程执行命令
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @module
                        property: (property_identifier) @method
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(child_process|exec|spawn|fork|execFile)$',
            'property_pattern': r'^(exec|spawn|fork|execFile)$',
            'message': '子进程执行命令'
        },
        # URL解析相关
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(url\.parse|new\s+URL|url\.format)$',
            'message': 'URL解析函数调用'
        },
        # DNS解析
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @module
                        property: (property_identifier) @method
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(dns)$',
            'property_pattern': r'^(lookup|resolve|resolve4|resolve6)$',
            'message': 'DNS解析函数调用'
        }
    ]
}

# SSRF相关的危险模式
SSRF_DANGEROUS_PATTERNS = {
    'javascript': [
        # 内网IP地址模式
        r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})',
        r'(192\.168\.\d{1,3}\.\d{1,3})',
        r'(127\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'(localhost)',
        r'(0\.0\.0\.0)',
        # 特殊协议和端口
        r'(file://)',
        r'(gopher://)',
        r'(dict://)',
        r'(ftp://)',
        r'(:22\b)',  # SSH
        r'(:21\b)',  # FTP
        r'(:25\b)',  # SMTP
        r'(:445\b)',  # SMB
        r'(:3389\b)',  # RDP
        # AWS元数据服务
        r'(169\.254\.169\.254)',
        r'(metadata\.google\.internal)',
        # 云服务内部端点
        r'((.*\.)?internal(\.|$))',
        r'((.*\.)?local(\.|$))',
        r'((.*\.)?private(\.|$))'
    ]
}


def detect_js_ssrf_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中的SSRF漏洞

    Args:
        code: JavaScript源代码字符串
        language: 语言类型，默认为'javascript'

    Returns:
        list: 检测结果列表
    """
    if language not in LANGUAGES:
        return []

    # 初始化解析器
    parser = Parser()
    parser.set_language(LANGUAGES[language])

    # 解析代码
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    vulnerabilities = []
    network_operations = []

    # 第一步：收集所有网络相关操作
    for query_info in SSRF_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag == 'func_name' or tag == 'module':
                    name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['name'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'method':
                    method_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern', '')
                    if (not prop_pattern or
                            re.match(prop_pattern, method_name, re.IGNORECASE)):
                        current_capture['method'] = method_name

                elif tag == 'args':
                    current_capture['args_node'] = node

                elif tag in ['call'] and current_capture:
                    # 完成一个完整的捕获
                    if 'name' in current_capture:
                        # 获取参数文本
                        args_text = current_capture['args_node'].text.decode(
                            'utf8') if 'args_node' in current_capture else ''

                        network_operations.append({
                            'type': 'network_call',
                            'line': current_capture['line'],
                            'name': current_capture['name'],
                            'method': current_capture.get('method', ''),
                            'args': args_text,
                            'code_snippet': node.text.decode('utf8'),
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：分析每个网络操作的潜在风险
    for operation in network_operations:
        risk_level = '低危'
        risk_reasons = []

        # 检查参数中是否包含用户输入
        args_text = operation['args']
        if contains_user_input(args_text):
            risk_level = '中危'
            risk_reasons.append('参数包含用户输入')

        # 检查是否包含危险模式
        dangerous_patterns_found = []
        for pattern in SSRF_DANGEROUS_PATTERNS[language]:
            if re.search(pattern, args_text, re.IGNORECASE):
                dangerous_patterns_found.append(pattern)

        if dangerous_patterns_found:
            risk_level = '高危'
            risk_reasons.append(f'检测到危险模式: {", ".join(dangerous_patterns_found[:3])}')

        # 检查是否有URL验证
        if not has_url_validation(operation['node'], root, code):
            risk_reasons.append('缺少URL验证')
            if risk_level == '低危':
                risk_level = '中危'

        # 检查是否使用白名单
        if not has_whitelist_validation(operation['node'], root, code):
            risk_reasons.append('缺少白名单验证')

        # 如果是高危或中危，报告漏洞
        if risk_level in ['高危', '中危']:
            vulnerabilities.append({
                'line': operation['line'],
                'message': f'SSRF漏洞风险: {", ".join(risk_reasons)}',
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'SSRF漏洞',
                'severity': risk_level,
                'operation': f"{operation['name']}{'.' + operation['method'] if operation['method'] else ''}"
            })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_user_input(text):
    """
    检查文本中是否包含用户输入的模式

    Args:
        text: 要检查的文本

    Returns:
        bool: 是否包含用户输入
    """
    user_input_patterns = [
        r'req\.(query|params|body|headers)',
        r'request\.(query|params|body|headers)',
        r'params\[',
        r'query\[',
        r'body\[',
        r'headers\[',
        r'process\.argv',
        r'process\.env',
        r'window\.location',
        r'document\.URL',
        r'localStorage\.getItem',
        r'sessionStorage\.getItem',
        r'cookie',
        r'formData',
        r'input',
        r'userInput',
        r'userInput'
    ]

    for pattern in user_input_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def has_url_validation(node, root, code):
    """
    检查节点附近是否有URL验证逻辑

    Args:
        node: 当前节点
        root: AST根节点
        code: 源代码

    Returns:
        bool: 是否有URL验证
    """
    # 获取节点周围的代码
    start_line = max(0, node.start_point[0] - 10)
    end_line = node.end_point[0] + 10

    lines = code.split('\n')
    context_code = '\n'.join(lines[start_line:end_line])

    # 检查常见的URL验证模式
    validation_patterns = [
        r'new\s+URL\(',
        r'url\.parse\(',
        r'\.startsWith\([\'"](https?|ftp)',
        r'\.match\([^)]*https?',
        r'\.test\([^)]*https?',
        r'\.indexOf\([\'"]https?',
        r'\.includes\([\'"]https?',
        r'\.search\([^)]*https?',
        r'\.replace\([^)]*https?',
        r'\.split\([^)]*https?',
        r'\.substring\([^)]*https?',
        r'\.substr\([^)]*https?',
        r'\.slice\([^)]*https?',
        r'whitelist',
        r'allowedDomains',
        r'allowedUrls',
        r'validUrl',
        r'isValidUrl',
        r'validateUrl',
        r'checkUrl'
    ]

    for pattern in validation_patterns:
        if re.search(pattern, context_code, re.IGNORECASE):
            return True

    return False


def has_whitelist_validation(node, root, code):
    """
    检查节点附近是否有白名单验证逻辑

    Args:
        node: 当前节点
        root: AST根节点
        code: 源代码

    Returns:
        bool: 是否有白名单验证
    """
    # 获取节点周围的代码
    start_line = max(0, node.start_point[0] - 15)
    end_line = node.end_point[0] + 15

    lines = code.split('\n')
    context_code = '\n'.join(lines[start_line:end_line])

    # 检查白名单验证模式
    whitelist_patterns = [
        r'whitelist',
        r'whiteList',
        r'allowed',
        r'permitted',
        r'valid',
        r'trusted',
        r'safelist',
        r'approved',
        r'\.includes\([^)]*(\.com|\.org|\.net)',
        r'\.indexOf\([^)]*(\.com|\.org|\.net)',
        r'\.match\([^)]*(\.com|\.org|\.net)',
        r'\.test\([^)]*(\.com|\.org|\.net)',
        r'\.search\([^)]*(\.com|\.org|\.net)'
    ]

    for pattern in whitelist_patterns:
        if re.search(pattern, context_code, re.IGNORECASE):
            return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的SSRF漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_ssrf_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 高危SSRF示例
const userInput = req.query.url;
fetch(userInput);  // 直接使用用户输入

// 内网地址访问
fetch('http://192.168.1.1/admin');
axios.get('http://10.0.0.1:8080/api');

// 文件协议访问
const maliciousUrl = 'file:///etc/passwd';
request(maliciousUrl);

// AWS元数据服务
fetch('http://169.254.169.254/latest/meta-data/');

// 中危示例 - 部分验证但仍有风险
const url = req.body.url;
if (url.startsWith('http')) {
    fetch(url);  // 只有协议验证，没有域名验证
}

// 使用child_process执行命令
const childProcess = require('child_process');
const command = req.query.cmd;
childProcess.exec(command);

// DNS解析用户输入
const dns = require('dns');
dns.lookup(req.query.hostname, (err, address) => {
    console.log(address);
});

// 相对安全的示例 - 有白名单验证
const allowedDomains = ['example.com', 'api.trusted.com'];
function safeFetch(url) {
    const domain = new URL(url).hostname;
    if (allowedDomains.includes(domain)) {
        return fetch(url);
    }
    throw new Error('Domain not allowed');
}

// 使用HTTP模块
const http = require('http');
http.get(req.query.url, (res) => {
    // 处理响应
});

// 危险的URL拼接
const baseUrl = 'http://internal-api/';
const endpoint = req.params.endpoint;
fetch(baseUrl + endpoint);

// 使用环境变量但仍然危险
const configUrl = process.env.API_URL || 'http://localhost:3000';
fetch(configUrl + '/data');
"""

    print("=" * 60)
    print("JavaScript SSRF漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在SSRF漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   操作: {vuln['operation']}")
            print(f"   代码片段: {vuln['code_snippet'][:80]}...")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   类型: {vuln['vulnerability_type']}")
    else:
        print("未检测到SSRF漏洞")