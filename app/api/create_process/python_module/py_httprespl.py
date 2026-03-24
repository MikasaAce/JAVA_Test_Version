import os
import re
from tree_sitter import Language, Parser

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义HTTP响应拆分漏洞模式（简化版）
HTTP_RESPONSE_SPLITTING_VULNERABILITIES = {
    'python': [
        # 检测响应头设置
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @response_obj
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list 
                        (string) @header_name
                        (_) @header_value
                    )
                ) @call
            ''',
            'response_pattern': r'^(response|resp|headers)$',
            'method_pattern': r'^(add_header|__setitem__|set_header|set)$',
            'message': '响应头设置',
            'severity': '高危',
            'risk_type': 'header_setting'
        },
        # 检测重定向函数调用
        {
            'query': '''
                (call
                    function: (identifier) @redirect_func
                    arguments: (argument_list (_) @redirect_url)
                ) @call
            ''',
            'redirect_pattern': r'^(redirect|Redirect|redirect_to|HttpResponseRedirect)$',
            'message': '重定向函数调用',
            'severity': '高危',
            'risk_type': 'redirect_function'
        },
        # 检测响应内容写入
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @response_obj
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list (_) @content)
                ) @call
            ''',
            'response_pattern': r'^(response|resp)$',
            'method_pattern': r'^(write|data|set_data)$',
            'message': '响应内容写入',
            'severity': '中危',
            'risk_type': 'response_write'
        },
        # 检测直接的头赋值
        {
            'query': '''
                (assignment
                    left: (attribute
                        object: (identifier) @response_obj
                        attribute: (string) @header_name
                    )
                    right: (_) @header_value
                ) @assignment
            ''',
            'response_pattern': r'^(response|resp|headers)$',
            'message': '直接头赋值',
            'severity': '高危',
            'risk_type': 'direct_header_assignment'
        }
    ]
}

# HTTP响应拆分危险字符
RESPONSE_SPLITTING_CHARS = {
    'crlf_sequences': [
        r'\\r\\n', r'\\n\\r', r'\\r', r'\\n',
        r'\r\n', r'\n\r', r'\r', r'\n',
        r'%0d%0a', r'%0a%0d', r'%0d', r'%0a'
    ],
    'header_injection_patterns': [
        r'[\r\n]',  # 包含换行符
        r':\s*',  # 包含冒号（可能注入新头）
        r'HTTP/\d\.\d'  # 包含HTTP版本
    ]
}

# 用户输入相关关键词
USER_INPUT_KEYWORDS = [
    'request', 'args', 'form', 'input', 'user_input',
    'data', 'content', 'url', 'header', 'cookie',
    'get', 'post', 'query', 'param', 'value'
]


def detect_http_response_splitting(code, language='python'):
    """
    检测Python代码中HTTP响应拆分漏洞（简化版）
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
    response_operations = []  # 存储所有响应操作

    # 第一步：收集所有响应操作
    for query_info in HTTP_RESPONSE_SPLITTING_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['response_obj', 'method_name', 'redirect_func']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['header_name', 'header_value', 'redirect_url', 'content']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['call', 'assignment'] and current_capture:
                    # 检查是否匹配模式
                    if is_response_operation(current_capture, query_info):
                        code_snippet = node.text.decode('utf8')

                        operation = {
                            'type': 'response_operation',
                            'line': current_capture['line'],
                            'response_obj': current_capture.get('response_obj', ''),
                            'method_name': current_capture.get('method_name', ''),
                            'header_name': current_capture.get('header_name', ''),
                            'header_value': current_capture.get('header_value', ''),
                            'redirect_url': current_capture.get('redirect_url', ''),
                            'content': current_capture.get('content', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'severity': query_info.get('severity', '中危'),
                            'risk_type': query_info.get('risk_type', 'unknown'),
                            'original_message': query_info.get('message', ''),
                            'query_info': query_info
                        }
                        response_operations.append(operation)

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：分析HTTP响应拆分漏洞
    for operation in response_operations:
        vulnerability_details = analyze_response_splitting_vulnerability(operation, code)
        if vulnerability_details:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_response_operation(capture, query_info):
    """
    检查是否是响应操作
    """
    risk_type = query_info.get('risk_type', '')

    if risk_type in ['header_setting', 'direct_header_assignment']:
        response_obj = capture.get('response_obj', '')
        method_name = capture.get('method_name', '')
        response_pattern = query_info.get('response_pattern', '')
        method_pattern = query_info.get('method_pattern', '')

        return (re.match(response_pattern, response_obj, re.IGNORECASE) and
                (not method_pattern or re.match(method_pattern, method_name, re.IGNORECASE)))

    elif risk_type == 'redirect_function':
        redirect_func = capture.get('redirect_func', '')
        redirect_pattern = query_info.get('redirect_pattern', '')
        return bool(re.match(redirect_pattern, redirect_func, re.IGNORECASE))

    elif risk_type == 'response_write':
        response_obj = capture.get('response_obj', '')
        method_name = capture.get('method_name', '')
        response_pattern = query_info.get('response_pattern', '')
        method_pattern = query_info.get('method_pattern', '')

        return (re.match(response_pattern, response_obj, re.IGNORECASE) and
                re.match(method_pattern, method_name, re.IGNORECASE))

    return False


def analyze_response_splitting_vulnerability(operation, code):
    """
    分析HTTP响应拆分漏洞
    """
    risk_type = operation['risk_type']

    # 根据风险类型进行分析
    if risk_type in ['header_setting', 'direct_header_assignment']:
        return analyze_header_setting_vulnerability(operation, code)
    elif risk_type == 'redirect_function':
        return analyze_redirect_vulnerability(operation, code)
    elif risk_type == 'response_write':
        return analyze_response_write_vulnerability(operation, code)

    return None


def analyze_header_setting_vulnerability(operation, code):
    """
    分析响应头设置漏洞
    """
    header_name = operation.get('header_name', '')
    header_value = operation.get('header_value', '')

    # 检查是否是敏感头
    sensitive_headers = ['Location', 'Set-Cookie', 'Content-Type', 'Content-Length']
    header_name_clean = header_name.strip('"\'')
    is_sensitive = any(h.lower() == header_name_clean.lower() for h in sensitive_headers)

    # 检查头值是否可能包含用户输入
    if may_contain_user_input(header_value) or is_sensitive:
        # 检查是否包含危险字符
        if contains_response_splitting_chars(header_value):
            vulnerability_details = {
                'line': operation['line'],
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'HTTP响应拆分',
                'severity': '高危',
                'risk_type': operation['risk_type'],
                'header_name': header_name_clean,
                'message': f"响应头 '{header_name_clean}' 可能包含CRLF字符 - 可能遭受响应拆分攻击"
            }

            # 检查是否缺少验证
            if not has_input_validation(operation, code):
                vulnerability_details['message'] += " (缺少输入验证)"

            return vulnerability_details
        elif is_sensitive and may_contain_user_input(header_value):
            # 敏感头包含用户输入但未发现CRLF字符，仍报告为警告
            vulnerability_details = {
                'line': operation['line'],
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'HTTP响应拆分',
                'severity': '中危',
                'risk_type': operation['risk_type'],
                'header_name': header_name_clean,
                'message': f"敏感响应头 '{header_name_clean}' 包含用户输入 - 需要CRLF字符验证"
            }
            return vulnerability_details

    return None


def analyze_redirect_vulnerability(operation, code):
    """
    分析重定向漏洞
    """
    redirect_url = operation.get('redirect_url', '')

    # 检查重定向URL是否可能包含用户输入
    if may_contain_user_input(redirect_url):
        # 检查是否包含危险字符
        if contains_response_splitting_chars(redirect_url):
            vulnerability_details = {
                'line': operation['line'],
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'HTTP响应拆分',
                'severity': '高危',
                'risk_type': operation['risk_type'],
                'message': "重定向URL可能包含CRLF字符 - 可能遭受响应拆分攻击"
            }

            # 检查是否缺少验证
            if not has_input_validation(operation, code):
                vulnerability_details['message'] += " (缺少输入验证)"

            return vulnerability_details
        else:
            # 重定向包含用户输入但未发现CRLF字符，报告为警告
            vulnerability_details = {
                'line': operation['line'],
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'HTTP响应拆分',
                'severity': '中危',
                'risk_type': operation['risk_type'],
                'message': "重定向URL包含用户输入 - 需要CRLF字符验证"
            }
            return vulnerability_details

    return None


def analyze_response_write_vulnerability(operation, code):
    """
    分析响应内容写入漏洞
    """
    content = operation.get('content', '')

    # 检查响应内容是否可能包含用户输入
    if may_contain_user_input(content):
        # 检查是否包含危险字符
        if contains_response_splitting_chars(content):
            vulnerability_details = {
                'line': operation['line'],
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'HTTP响应拆分',
                'severity': '中危',
                'risk_type': operation['risk_type'],
                'message': "响应内容可能包含CRLF字符 - 可能遭受响应拆分攻击"
            }
            return vulnerability_details

    return None


def may_contain_user_input(text):
    """
    检查文本是否可能包含用户输入
    """
    if not text:
        return False

    clean_text = text.strip('"\'')

    # 如果是字面量字符串且不包含变量，不太可能是用户输入
    if re.match(r'^[\'\"][^\'\"]*[\'\"]$', clean_text) and not any(
            keyword in clean_text for keyword in USER_INPUT_KEYWORDS):
        return False

    # 包含用户输入相关关键词
    for keyword in USER_INPUT_KEYWORDS:
        if re.search(rf'\b{keyword}\b', clean_text, re.IGNORECASE):
            return True

    # 包含变量或函数调用
    if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*', clean_text):
        return True

    return False


def contains_response_splitting_chars(text):
    """
    检查文本是否包含响应拆分危险字符
    """
    if not text:
        return False

    clean_text = text.strip('"\'')

    # 检查CRLF序列
    for pattern in RESPONSE_SPLITTING_CHARS['crlf_sequences']:
        if re.search(pattern, clean_text, re.IGNORECASE):
            return True

    # 检查头注入模式
    for pattern in RESPONSE_SPLITTING_CHARS['header_injection_patterns']:
        if re.search(pattern, clean_text, re.IGNORECASE):
            return True

    return False


def has_input_validation(operation, code):
    """
    检查是否有输入验证
    """
    line = operation['line']

    # 在附近代码中查找验证函数
    validation_indicators = [
        're.escape', 'html.escape', 'cgi.escape', 'urllib.parse.quote',
        'validate', 'sanitize', 'clean', 'check', 'is_valid',
        'replace', 'strip', 'encode', 'decode', 'sub', 'escape',
        'quote', 'urlencode'
    ]

    lines = code.split('\n')
    start_line = max(0, line - 5)
    end_line = min(len(lines), line + 5)

    for i in range(start_line, end_line):
        line_content = lines[i].lower()
        for indicator in validation_indicators:
            if indicator in line_content:
                return True

    return False


def analyze_python_http_response_splitting(code_string):
    """
    分析Python代码字符串中的HTTP响应拆分漏洞
    """
    return detect_http_response_splitting(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = '''
from flask import Flask, redirect, make_response, request
from django.http import HttpResponse, HttpResponseRedirect
import urllib.parse

app = Flask(__name__)

# 易受HTTP响应拆分攻击的示例
@app.route('/vulnerable_redirect')
def vulnerable_redirect():
    # 1. 重定向URL包含用户输入 - 高危
    next_url = request.args.get('next', '/')
    return redirect(next_url)

@app.route('/vulnerable_header')
def vulnerable_header():
    response = make_response("Vulnerable")

    # 2. 响应头包含用户输入 - 高危
    user_agent = request.headers.get('User-Agent', '')
    response.headers['X-User-Agent'] = user_agent

    # 3. Location头包含用户输入 - 高危
    redirect_path = request.args.get('path', '/')
    response.headers['Location'] = redirect_path

    # 4. Set-Cookie头包含用户输入 - 高危
    user_data = request.args.get('data', '')
    response.headers['Set-Cookie'] = f'session={user_data}'

    # 5. 直接头赋值
    response.headers['Custom-Header'] = request.args.get('custom', '')

    return response

@app.route('/vulnerable_content')
def vulnerable_content():
    response = make_response()

    # 6. 响应内容包含用户输入 - 中危
    user_content = request.args.get('content', '')
    response.data = user_content

    return response

# 具体的响应拆分攻击示例
@app.route('/crsf_example')
def crsf_example():
    # 攻击者可以注入完整的HTTP响应
    malicious_input = "http://evil.com\\r\\n\\r\\nHTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n\\r\\n<h1>Hacked</h1>"

    response = make_response()
    response.headers['Location'] = malicious_input
    return response

@app.route('/cookie_injection')
def cookie_injection():
    # Cookie注入攻击
    malicious_cookie = "session=123; Path=/\\r\\nSet-Cookie: admin=true; Path=/"

    response = make_response()
    response.headers['Set-Cookie'] = malicious_cookie
    return response

# 相对安全的示例
@app.route('/secure_redirect')
def secure_redirect():
    # 1. 安全的URL验证
    next_url = request.args.get('next', '/')

    # 验证URL格式
    if not next_url.startswith('/') and not next_url.startswith('http://localhost'):
        next_url = '/'

    # 使用安全的重定向
    return redirect(next_url)

@app.route('/secure_header')
def secure_header():
    response = make_response("Secure")

    # 2. 安全的头设置
    user_agent = request.headers.get('User-Agent', '')

    # 清理用户输入
    safe_user_agent = user_agent.replace('\\r', '').replace('\\n', '')
    safe_user_agent = safe_user_agent[:100]  # 限制长度

    response.headers['X-User-Agent'] = safe_user_agent

    # 3. 安全的Location头
    redirect_path = request.args.get('path', '/')
    safe_path = urllib.parse.quote(redirect_path, safe='')  # URL编码
    response.headers['Location'] = safe_path

    return response

@app.route('/secure_cookie')
def secure_cookie():
    response = make_response("Secure cookie")

    # 4. 安全的Cookie设置
    user_data = request.args.get('data', '')

    # 清理Cookie值
    safe_data = re.sub(r'[\\r\\n]', '', user_data)
    safe_data = safe_data[:50]  # 限制长度

    response.set_cookie('session', safe_data, httponly=True, secure=True)

    return response

# Django示例
def django_views(request):
    # 不安全的Django示例
    next_url = request.GET.get('next', '/')
    response = HttpResponseRedirect(next_url)

    # 安全的Django示例
    safe_url = request.GET.get('url', '/')
    safe_url = safe_url.replace('\\r', '').replace('\\n', '')
    safe_response = HttpResponseRedirect(safe_url)

    return response

if __name__ == '__main__':
    app.run(debug=True)
'''

    print("=" * 70)
    print("Python HTTP响应拆分漏洞检测（简化版）")
    print("=" * 70)

    results = analyze_python_http_response_splitting(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个HTTP响应拆分漏洞:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   风险类型: {vuln['risk_type']}")
            print(f"   严重程度: {vuln['severity']}")
            if vuln.get('header_name'):
                print(f"   涉及头: {vuln.get('header_name')}")
            print("-" * 50)
    else:
        print("未检测到HTTP响应拆分漏洞")