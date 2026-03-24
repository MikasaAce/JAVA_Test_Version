import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义Cookie安全漏洞模式
COOKIE_SECURITY_VULNERABILITIES = {
    'cpp': [
        # 检测字符串中的Cookie设置
        {
            'query': '''
                (string_literal) @cookie_string
            ''',
            'string_pattern': r'Set-Cookie',
            'message': '字符串中的Cookie设置'
        },
        # 检测cout输出操作
        {
            'query': '''
                (call_expression
                    function: (field_expression
                        field: (identifier) @field_name
                    )
                ) @call
            ''',
            'field_pattern': r'^operator<<$',
            'message': 'cout输出操作'
        },
        # 检测printf类函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf)$',
            'message': '格式化输出函数'
        }
    ]
}

# HTTPS/SSL相关函数模式
SSL_SECURE_FUNCTIONS = {
    'query': '''
        (call_expression
            function: [
                (identifier) @func_name
                (field_expression
                    field: (identifier) @field_name
                )
            ]
        ) @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(SSL_|TLS_|DTLS_|curl_|https?_|CURLOPT_)',
            'message': 'SSL/TLS相关函数'
        },
        {
            'field_pattern': r'^(setOpt|easy_setopt|operator<<)$',
            'message': 'HTTPS相关操作'
        }
    ]
}


def detect_cpp_cookie_security(code, language='cpp'):
    """
    检测C++代码中Cookie安全漏洞

    Args:
        code: C++源代码字符串
        language: 语言类型，默认为'cpp'

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
    cookie_operations = []  # 存储所有Cookie操作
    ssl_operations = []  # 存储SSL相关操作

    # 第一步：收集所有Cookie相关操作
    for query_info in COOKIE_SECURITY_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                text = node.text.decode('utf8').strip('"\'')

                if tag == 'cookie_string':
                    string_pattern = query_info.get('string_pattern', '')
                    if string_pattern and re.search(string_pattern, text, re.IGNORECASE):
                        # 检查是否包含Set-Cookie
                        cookie_operations.append({
                            'type': 'cookie_string',
                            'line': node.start_point[0] + 1,
                            'string': text,
                            'code_snippet': get_code_snippet(node.parent, 100),
                            'node': node
                        })

                elif tag == 'field_name':
                    field_pattern = query_info.get('field_pattern', '')
                    if field_pattern and re.search(field_pattern, text, re.IGNORECASE):
                        # 检查是否是cout输出操作
                        parent = node.parent
                        if parent and parent.type == 'field_expression':
                            call_expr = parent.parent
                            if call_expr and call_expr.type == 'call_expression':
                                # 检查参数中是否包含Set-Cookie
                                args_text = get_code_snippet(call_expr, 200)
                                if 'Set-Cookie' in args_text:
                                    cookie_operations.append({
                                        'type': 'cout_operation',
                                        'line': node.start_point[0] + 1,
                                        'field': text,
                                        'code_snippet': args_text,
                                        'node': call_expr
                                    })

                elif tag == 'func_name':
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.search(func_pattern, text, re.IGNORECASE):
                        # 检查参数中是否包含Set-Cookie
                        call_expr = node.parent
                        if call_expr and call_expr.type == 'call_expression':
                            args_text = get_code_snippet(call_expr, 200)
                            if 'Set-Cookie' in args_text:
                                cookie_operations.append({
                                    'type': 'printf_operation',
                                    'line': node.start_point[0] + 1,
                                    'function': text,
                                    'code_snippet': args_text,
                                    'node': call_expr
                                })

        except Exception as e:
            print(f"Cookie安全查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有SSL相关操作
    try:
        query = LANGUAGES[language].query(SSL_SECURE_FUNCTIONS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            text = node.text.decode('utf8')

            if tag == 'func_name':
                for pattern_info in SSL_SECURE_FUNCTIONS['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    if func_pattern and re.search(func_pattern, text, re.IGNORECASE):
                        ssl_operations.append({
                            'type': 'ssl_func',
                            'line': node.start_point[0] + 1,
                            'function': text,
                            'code_snippet': get_code_snippet(node.parent, 100),
                            'node': node.parent
                        })

            elif tag == 'field_name':
                for pattern_info in SSL_SECURE_FUNCTIONS['patterns']:
                    field_pattern = pattern_info.get('field_pattern', '')
                    if field_pattern and re.search(field_pattern, text, re.IGNORECASE):
                        ssl_operations.append({
                            'type': 'ssl_field',
                            'line': node.start_point[0] + 1,
                            'field': text,
                            'code_snippet': get_code_snippet(node.parent.parent, 100),
                            'node': node.parent.parent
                        })

    except Exception as e:
        print(f"SSL操作查询错误: {e}")

    # 第三步：分析Cookie安全漏洞
    for cookie_op in cookie_operations:
        # 检查代码片段中是否包含Secure标志
        code_snippet = cookie_op['code_snippet']
        if re.search(r'\bSecure\b', code_snippet, re.IGNORECASE):
            continue  # 如果有Secure标志，跳过

        vulnerability_details = {
            'line': cookie_op['line'],
            'code_snippet': cookie_op['code_snippet'],
            'vulnerability_type': 'Cookie安全',
            'severity': '中危',
            'message': ''
        }

        # 根据类型设置消息
        if cookie_op['type'] == 'cookie_string':
            vulnerability_details['message'] = f"字符串中的Cookie设置未使用Secure标志"
        elif cookie_op['type'] == 'cout_operation':
            vulnerability_details['message'] = f"cout输出操作可能设置不安全的Cookie"
        elif cookie_op['type'] == 'printf_operation':
            vulnerability_details['message'] = f"格式化输出函数 '{cookie_op['function']}' 可能设置不安全的Cookie"

        # 检查是否在安全上下文中设置Cookie
        if not is_in_secure_context(cookie_op['node'], ssl_operations, root):
            vulnerability_details['severity'] = '高危'
            vulnerability_details['message'] += " (在非安全上下文中)"

        vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def get_code_snippet(node, max_length=100):
    """获取代码片段"""
    try:
        if node is None:
            return "无法获取节点"
        snippet = node.text.decode('utf8')
        if len(snippet) > max_length:
            return snippet[:max_length] + '...'
        return snippet
    except:
        return "无法获取代码片段"


def is_in_secure_context(node, ssl_operations, root_node):
    """
    检查节点是否在安全上下文（SSL/TLS连接）中
    """
    if not node:
        return False

    # 获取当前节点的位置
    node_line = node.start_point[0] + 1

    # 检查附近是否有SSL操作
    for ssl_op in ssl_operations:
        ssl_line = ssl_op['line']
        # 如果SSL操作在同一函数或相近范围内
        if abs(ssl_line - node_line) < 30:
            return True

    # 检查代码片段中是否包含HTTPS或安全相关关键词
    code_text = get_code_snippet(node, 200)
    secure_keywords = ['https://', 'ssl', 'tls', 'secure', 'encrypt', 'CURLOPT_SSL']
    if any(keyword in code_text.lower() for keyword in secure_keywords):
        return True

    return False


def analyze_cpp_code(code_string):
    """
    分析C++代码字符串中的Cookie安全漏洞
    """
    return detect_cpp_cookie_security(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <string>
#include <curl/curl.h>

void set_insecure_cookies() {
    // 不安全的Cookie设置 - 未使用Secure标志
    std::cout << "Set-Cookie: sessionid=abc123; Path=/" << std::endl;

    // 不安全的Cookie设置 - 缺少Secure标志
    std::string cookie = "user=john; HttpOnly";
    std::cout << "Set-Cookie: " << cookie << std::endl;

    // 直接使用Set-Cookie头
    printf("Set-Cookie: test=value\\n");
}

void set_secure_cookies() {
    // 安全的Cookie设置 - 使用Secure标志
    std::cout << "Set-Cookie: sessionid=def456; Secure; HttpOnly; Path=/" << std::endl;
}

void http_client() {
    CURL *curl = curl_easy_init();
    if(curl) {
        // 不安全的CURL操作 - 未启用SSL验证
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/login");
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

        // 执行请求...
        curl_easy_cleanup(curl);
    }
}

void https_client() {
    CURL *curl = curl_easy_init();
    if(curl) {
        // 安全的CURL操作 - 使用HTTPS并启用SSL验证
        curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/login");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");

        // 执行请求...
        curl_easy_cleanup(curl);
    }
}

int main() {
    set_insecure_cookies();
    set_secure_cookies();
    http_client();
    https_client();
    return 0;
}
"""

    print("=" * 60)
    print("C++ Cookie安全漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Cookie安全漏洞")