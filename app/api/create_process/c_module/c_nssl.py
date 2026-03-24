import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 增强的Cookie安全漏洞模式
COOKIE_SECURITY_VULNERABILITIES = {
    'c': [
        # 检测cURL库函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(curl_easy_setopt|curl_easy_getinfo)$',
            'message': 'cURL库函数调用'
        },
        # 检测HTTP头设置函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(sprintf|snprintf|strcpy|strncpy|memcpy|strcat|strncat)$',
            'message': '字符串操作函数可能用于构造HTTP头'
        },
        # 检测网络发送函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(send|sendto|write|fwrite)$',
            'message': '网络数据发送函数'
        },
        # 检测HTTP客户端函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(http_|https?_|request_|socket_|tcp_)',
            'message': 'HTTP/网络相关函数'
        },
        # 检测字符串字面量中的Cookie和URL模式
        {
            'query': '''
                (string_literal) @string_lit
            ''',
            'message': '字符串字面量可能包含Cookie或URL模式'
        },
        # 检测变量声明和赋值
        {
            'query': '''
                (declaration
                    declarator: (init_declarator
                        declarator: (_) @var_name
                        value: (_) @value
                    )
                ) @decl
            ''',
            'message': '变量声明和赋值'
        },
        # 检测赋值表达式
        {
            'query': '''
                (assignment_expression
                    left: (_) @left
                    right: (_) @right
                ) @assign
            ''',
            'message': '赋值表达式'
        }
    ]
}

# 增强的HTTP和Cookie模式
HTTP_PATTERNS = {
    'protocols': {
        'http': r'http://',
        'https': r'https://'
    },
    'cookie_keywords': [
        r'cookie', r'set-cookie', r'setcookie', r'cookiefile', r'cookiejar',
        r'session', r'sessionid', r'session_id', r'auth', r'authentication',
        r'token', r'bearer', r'jwt', r'oauth'
    ],
    'cookie_functions': [
        r'curl_easy_setopt', r'curl_easy_getinfo', r'setcookie', r'getcookie',
        r'addcookie', r'removecookie'
    ],
    'security_flags': [
        r'secure', r'httponly', r'samesite', r'strict', r'lax', r'none'
    ],
    'http_headers': [
        r'cookie:', r'set-cookie:', r'authorization:', r'x-auth-token:'
    ]
}


def detect_c_cookie_security(code, language='c'):
    """
    检测C代码中Cookie安全漏洞：不通过SSL发送Cookie
    """
    if language not in LANGUAGES:
        return []

    parser = Parser()
    parser.set_language(LANGUAGES[language])
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    vulnerabilities = []

    # 收集所有相关信息
    http_urls = find_http_urls(root)
    cookie_operations = find_cookie_operations(root)
    network_calls = find_network_calls(root)
    string_operations = find_string_operations(root)

    # 分析漏洞模式
    vulnerabilities.extend(analyze_http_cookie_combinations(http_urls, cookie_operations))
    vulnerabilities.extend(analyze_network_cookie_combinations(network_calls, cookie_operations))
    vulnerabilities.extend(analyze_string_based_cookies(string_operations))
    vulnerabilities.extend(analyze_curl_operations(root))

    return sorted(vulnerabilities, key=lambda x: x['line'])


def find_http_urls(root):
    """查找所有HTTP URL"""
    urls = []
    try:
        query = LANGUAGES['c'].query('(string_literal) @string_lit')
        captures = query.captures(root)

        for node, tag in captures:
            content = node.text.decode('utf8')
            # 查找HTTP URL
            if re.search(HTTP_PATTERNS['protocols']['http'], content, re.IGNORECASE):
                url_info = {
                    'node': node,
                    'content': content,
                    'line': node.start_point[0] + 1,
                    'is_secure': False,
                    'type': 'http_url'
                }
                # 检查是否同时包含HTTPS（混合情况）
                if re.search(HTTP_PATTERNS['protocols']['https'], content, re.IGNORECASE):
                    url_info['is_secure'] = True
                urls.append(url_info)

    except Exception as e:
        print(f"查找HTTP URL错误: {e}")

    return urls


def find_cookie_operations(root):
    """查找所有Cookie相关操作"""
    cookie_ops = []

    # 查找字符串中的Cookie关键词
    try:
        query = LANGUAGES['c'].query('(string_literal) @string_lit')
        captures = query.captures(root)

        for node, tag in captures:
            content = node.text.decode('utf8').lower()
            for keyword in HTTP_PATTERNS['cookie_keywords']:
                if re.search(keyword, content, re.IGNORECASE):
                    cookie_ops.append({
                        'node': node,
                        'content': content,
                        'line': node.start_point[0] + 1,
                        'type': 'cookie_string',
                        'keyword': keyword,
                        'has_security_flags': check_security_flags(content)
                    })
                    break

    except Exception as e:
        print(f"查找Cookie字符串错误: {e}")

    # 查找Cookie相关函数调用
    try:
        query = LANGUAGES['c'].query('''
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list) @args
            ) @call
        ''')
        captures = query.captures(root)

        current_call = {}
        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in HTTP_PATTERNS['cookie_functions']:
                    if re.search(pattern, func_name, re.IGNORECASE):
                        current_call['func_name'] = func_name
                        current_call['func_node'] = node
            elif tag == 'call' and current_call:
                cookie_ops.append({
                    'node': node,
                    'func_name': current_call['func_name'],
                    'line': node.start_point[0] + 1,
                    'type': 'cookie_function',
                    'code_snippet': node.text.decode('utf8')
                })
                current_call = {}

    except Exception as e:
        print(f"查找Cookie函数错误: {e}")

    return cookie_ops


def find_network_calls(root):
    """查找网络相关函数调用"""
    network_calls = []
    network_patterns = [
        r'^send', r'^recv', r'^write', r'^read', r'^connect',
        r'^curl_', r'^http_', r'^https?_', r'^socket'
    ]

    try:
        query = LANGUAGES['c'].query('''
            (call_expression
                function: (identifier) @func_name
            ) @call
        ''')
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in network_patterns:
                    if re.search(pattern, func_name, re.IGNORECASE):
                        network_calls.append({
                            'node': node.parent,
                            'func_name': func_name,
                            'line': node.start_point[0] + 1,
                            'code_snippet': node.parent.text.decode('utf8')
                        })
                        break

    except Exception as e:
        print(f"查找网络调用错误: {e}")

    return network_calls


def find_string_operations(root):
    """查找字符串操作"""
    string_ops = []

    try:
        # 查找字符串连接和格式化操作
        query = LANGUAGES['c'].query('''
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list) @args
            ) @call
        ''')
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                if re.match(r'^(sprintf|snprintf|strcat|strncat|strcpy|strncpy)$', func_name, re.IGNORECASE):
                    string_ops.append({
                        'node': node.parent,
                        'func_name': func_name,
                        'line': node.start_point[0] + 1,
                        'code_snippet': node.parent.text.decode('utf8'),
                        'arguments': get_function_arguments(node.parent)
                    })

    except Exception as e:
        print(f"查找字符串操作错误: {e}")

    return string_ops


def analyze_http_cookie_combinations(http_urls, cookie_operations):
    """分析HTTP URL和Cookie操作的组合"""
    vulnerabilities = []

    for url in http_urls:
        if url['is_secure']:  # 跳过HTTPS
            continue

        # 查找附近的Cookie操作
        for cookie_op in cookie_operations:
            if abs(url['line'] - cookie_op['line']) <= 10:  # 在10行范围内
                vulnerabilities.append({
                    'line': url['line'],
                    'code_snippet': url['content'][:100],
                    'vulnerability_type': 'Cookie安全：不通过SSL发送Cookie',
                    'severity': '高危',
                    'message': f"不安全的HTTP URL附近发现Cookie操作: {url['content'][:50]}...",
                    'related_line': cookie_op['line']
                })
                break

    return vulnerabilities


def analyze_network_cookie_combinations(network_calls, cookie_operations):
    """分析网络调用和Cookie操作的组合"""
    vulnerabilities = []

    for net_call in network_calls:
        # 检查网络调用是否使用HTTP
        if contains_http_url(net_call['code_snippet']):
            # 查找附近的Cookie操作
            for cookie_op in cookie_operations:
                if abs(net_call['line'] - cookie_op['line']) <= 5:
                    vulnerabilities.append({
                        'line': net_call['line'],
                        'code_snippet': net_call['code_snippet'][:100],
                        'vulnerability_type': 'Cookie安全：不通过SSL发送Cookie',
                        'severity': '高危',
                        'message': f"网络调用使用HTTP协议传输Cookie数据: {net_call['func_name']}",
                        'related_line': cookie_op['line']
                    })
                    break

    return vulnerabilities


def analyze_string_based_cookies(string_operations):
    """分析基于字符串的Cookie操作"""
    vulnerabilities = []

    for op in string_operations:
        code = op['code_snippet'].lower()

        # 检查是否包含Cookie关键词和HTTP URL
        has_cookie = any(keyword in code for keyword in HTTP_PATTERNS['cookie_keywords'])
        has_http = HTTP_PATTERNS['protocols']['http'] in code
        has_https = HTTP_PATTERNS['protocols']['https'] in code

        if has_cookie and has_http and not has_https:
            vulnerabilities.append({
                'line': op['line'],
                'code_snippet': op['code_snippet'][:100],
                'vulnerability_type': 'Cookie安全：不通过SSL发送Cookie',
                'severity': '中危',
                'message': f"字符串操作构造不安全的HTTP Cookie: {op['func_name']}"
            })

    return vulnerabilities


def analyze_curl_operations(root):
    """分析cURL操作"""
    vulnerabilities = []

    try:
        query = LANGUAGES['c'].query('''
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list (_)* @args)
            ) @call
        ''')
        captures = query.captures(root)

        current_call = {}
        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                if func_name.lower() == 'curl_easy_setopt':
                    current_call['func_name'] = func_name
                    current_call['line'] = node.start_point[0] + 1
            elif tag == 'args' and current_call:
                args_text = node.text.decode('utf8').lower()
                # 检查是否设置Cookie相关选项
                if any(opt in args_text for opt in ['cookiefile', 'cookiejar', 'cookie']):
                    # 检查是否使用HTTP URL
                    if has_http_url_in_context(node):
                        vulnerabilities.append({
                            'line': current_call['line'],
                            'code_snippet': node.parent.text.decode('utf8')[:100],
                            'vulnerability_type': 'Cookie安全：不通过SSL发送Cookie',
                            'severity': '高危',
                            'message': "cURL设置Cookie但使用不安全的HTTP连接"
                        })
                current_call = {}

    except Exception as e:
        print(f"分析cURL操作错误: {e}")

    return vulnerabilities


def check_security_flags(text):
    """检查是否包含安全标志"""
    return any(flag in text.lower() for flag in HTTP_PATTERNS['security_flags'])


def contains_http_url(text):
    """检查文本是否包含HTTP URL"""
    return (HTTP_PATTERNS['protocols']['http'] in text.lower() and
            HTTP_PATTERNS['protocols']['https'] not in text.lower())


def has_http_url_in_context(node):
    """检查节点上下文中是否有HTTP URL"""
    # 向上遍历父节点
    current = node
    while current:
        if current.type == 'string_literal':
            content = current.text.decode('utf8')
            if contains_http_url(content):
                return True
        current = current.parent
    return False


def get_function_arguments(call_node):
    """获取函数调用的参数"""
    arguments = []
    for child in call_node.children:
        if child.type == 'argument_list':
            for arg in child.children:
                if arg.type not in ['(', ')', ',']:
                    arguments.append(arg.text.decode('utf8'))
    return arguments


def analyze_c_cookie_security(code_string):
    """分析C代码字符串中的Cookie安全漏洞"""
    return detect_c_cookie_security(code_string, 'c')


# 测试代码
if __name__ == "__main__":
    test_c_code = """
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

void insecure_examples() {
    // 不安全的Cookie操作
    CURL *curl = curl_easy_init();

    // 漏洞1: 使用HTTP传输Cookie
    curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/login");
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "cookies.txt");

    // 漏洞2: 手动构造不安全的Cookie头
    char header[256];
    sprintf(header, "Cookie: session=abc123");  // 缺少Secure标志

    // 漏洞3: 使用HTTP发送敏感数据
    char request[512];
    strcpy(request, "POST http://api.example.com/data HTTP/1.1\\r\\n");
    strcat(request, "Cookie: token=secret123\\r\\n");

    // 漏洞4: 不安全的字符串操作
    char url[100];
    strcpy(url, "http://example.com/dashboard");
    // send(socket, url, strlen(url), 0);
}

void secure_examples() {
    // 安全的Cookie操作
    CURL *curl = curl_easy_init();

    // 使用HTTPS
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/login");
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "cookies.txt");

    // 安全的Cookie头
    char secure_header[256];
    sprintf(secure_header, "Set-Cookie: session=abc123; Secure; HttpOnly");
}

int main() {
    insecure_examples();
    secure_examples();
    return 0;
}
"""

    print("=" * 60)
    print("C语言Cookie安全漏洞检测")
    print("=" * 60)

    results = analyze_c_cookie_security(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在Cookie安全漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            if 'related_line' in vuln:
                print(f"   关联行号: {vuln['related_line']}")
    else:
        print("未检测到Cookie安全漏洞")