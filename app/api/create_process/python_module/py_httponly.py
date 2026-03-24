import os
import re
from tree_sitter import Language, Parser

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义Cookie安全漏洞模式
COOKIE_SECURITY_VULNERABILITIES = {
    'python': [
        # 主要检测模式 - 覆盖所有set_cookie调用
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @response_obj
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list 
                        (string) @cookie_name
                        (_) @cookie_value
                        (_)* @other_args
                    )
                ) @call
            ''',
            'method_pattern': r'^(set_cookie|set_cookie)$',
            'message': 'set_cookie调用',
            'severity': '中危',
            'risk_type': 'set_cookie_main'
        }
    ]
}

# Cookie安全属性
COOKIE_SECURITY_ATTRIBUTES = {
    'secure_attributes': [
        'httponly', 'secure', 'samesite', 'max_age', 'expires', 'domain', 'path'
    ],
    'sensitive_cookies': [
        'session', 'sessionid', 'token', 'auth', 'authentication',
        'csrf', 'csrftoken', 'jwt', 'access_token', 'refresh_token',
        'user', 'username', 'userid', 'login', 'account'
    ]
}


def detect_cookie_security_issues(code, language='python'):
    """
    检测Python代码中Cookie安全漏洞（修复重复检测问题）
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
    cookie_set_calls = []  # 存储所有set_cookie调用
    processed_locations = set()  # 用于去重，使用位置信息而不是节点对象

    # 第一步：收集所有set_cookie调用（使用单一查询避免重复）
    for query_info in COOKIE_SECURITY_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['response_obj', 'method_name']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['cookie_name', 'cookie_value']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag == 'call' and current_capture:
                    # 检查是否匹配模式
                    if is_cookie_set_call(current_capture, query_info):
                        # 使用位置信息进行去重
                        line = current_capture['line']
                        cookie_name = current_capture.get('cookie_name', '')
                        location_key = f"{line}:{cookie_name}"

                        if location_key not in processed_locations:
                            processed_locations.add(location_key)

                            code_snippet = node.text.decode('utf8')

                            cookie_call = {
                                'type': 'cookie_set',
                                'line': line,
                                'response_obj': current_capture.get('response_obj', ''),
                                'method_name': current_capture.get('method_name', ''),
                                'cookie_name': cookie_name,
                                'cookie_value': current_capture.get('cookie_value', ''),
                                'code_snippet': code_snippet,
                                'node': node,
                                'severity': query_info.get('severity', '中危'),
                                'risk_type': query_info.get('risk_type', 'unknown'),
                                'original_message': query_info.get('message', ''),
                                'query_info': query_info
                            }
                            cookie_set_calls.append(cookie_call)

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：分析Cookie安全漏洞
    for call in cookie_set_calls:
        vulnerability_details = analyze_cookie_security_vulnerability(call, code)
        if vulnerability_details:
            # 检查最终结果是否重复
            vuln_key = f"{vulnerability_details['line']}:{vulnerability_details.get('cookie_name', '')}"
            if not any(v['line'] == vulnerability_details['line'] and
                       v.get('cookie_name') == vulnerability_details.get('cookie_name')
                       for v in vulnerabilities):
                vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_cookie_set_call(capture, query_info):
    """
    检查是否是cookie设置调用
    """
    risk_type = query_info.get('risk_type', '')

    if risk_type == 'set_cookie_main':
        method_name = capture.get('method_name', '')
        method_pattern = query_info.get('method_pattern', '')
        return bool(re.match(method_pattern, method_name, re.IGNORECASE))

    return False


def analyze_cookie_security_vulnerability(call, code):
    """
    分析Cookie安全漏洞
    """
    cookie_name = call.get('cookie_name', '')
    code_snippet = call['code_snippet']
    line = call['line']

    # 检查HttpOnly设置
    httponly_status = check_httponly_setting(code_snippet, line, code)
    secure_status = check_secure_setting(code_snippet, line, code)
    samesite_status = check_samesite_setting(code_snippet, line, code)

    # 如果没有安全问题，直接返回
    if (httponly_status == 'true' and
            secure_status == 'true' and
            samesite_status in ['lax', 'strict'] and
            not is_sensitive_cookie(cookie_name)):
        return None

    vulnerability_details = {
        'line': line,
        'code_snippet': code_snippet,
        'vulnerability_type': 'Cookie安全',
        'severity': call['severity'],
        'risk_type': call['risk_type'],
        'cookie_name': cookie_name.strip('"\'')
    }

    # 构建漏洞消息
    issues = []

    if httponly_status == 'missing':
        issues.append("HttpOnly未设置")
        vulnerability_details['severity'] = '高危'
    elif httponly_status == 'false':
        issues.append("HttpOnly显式禁用")
        vulnerability_details['severity'] = '严重'

    if secure_status == 'missing':
        issues.append("Secure未设置")
        if vulnerability_details['severity'] != '严重':
            vulnerability_details['severity'] = '高危'
    elif secure_status == 'false':
        issues.append("Secure显式禁用")
        vulnerability_details['severity'] = '严重'

    if samesite_status == 'missing':
        issues.append("SameSite未设置")
    elif samesite_status == 'none':
        issues.append("SameSite=None（可能不安全）")

    # 检查是否是敏感Cookie
    if is_sensitive_cookie(cookie_name):
        issues.append("敏感Cookie")
        vulnerability_details['severity'] = elevate_severity(vulnerability_details['severity'])
        
        return vulnerability_details

    return None


def check_httponly_setting(code_snippet, line, full_code):
    """
    检查HttpOnly设置
    """
    # 在代码片段中查找
    if re.search(r'httponly\s*=\s*True', code_snippet, re.IGNORECASE):
        return 'true'
    elif re.search(r'httponly\s*=\s*False', code_snippet, re.IGNORECASE):
        return 'false'
    elif re.search(r'httponly\s*=\s*None', code_snippet, re.IGNORECASE):
        return 'false'

    # 在附近代码中查找
    lines = full_code.split('\n')
    start_line = max(0, line - 3)
    end_line = min(len(lines), line + 3)

    for i in range(start_line, end_line):
        line_content = lines[i]
        if re.search(r'httponly\s*=\s*True', line_content, re.IGNORECASE):
            return 'true'
        elif re.search(r'httponly\s*=\s*False', line_content, re.IGNORECASE):
            return 'false'
        elif re.search(r'httponly\s*=\s*None', line_content, re.IGNORECASE):
            return 'false'

    return 'missing'


def check_secure_setting(code_snippet, line, full_code):
    """
    检查Secure设置
    """
    # 在代码片段中查找
    if re.search(r'secure\s*=\s*True', code_snippet, re.IGNORECASE):
        return 'true'
    elif re.search(r'secure\s*=\s*False', code_snippet, re.IGNORECASE):
        return 'false'
    elif re.search(r'secure\s*=\s*None', code_snippet, re.IGNORECASE):
        return 'false'

    # 在附近代码中查找
    lines = full_code.split('\n')
    start_line = max(0, line - 3)
    end_line = min(len(lines), line + 3)

    for i in range(start_line, end_line):
        line_content = lines[i]
        if re.search(r'secure\s*=\s*True', line_content, re.IGNORECASE):
            return 'true'
        elif re.search(r'secure\s*=\s*False', line_content, re.IGNORECASE):
            return 'false'
        elif re.search(r'secure\s*=\s*None', line_content, re.IGNORECASE):
            return 'false'

    return 'missing'


def check_samesite_setting(code_snippet, line, full_code):
    """
    检查SameSite设置
    """
    # 在代码片段中查找
    if re.search(r'samesite\s*=\s*[\'"]Lax[\'"]', code_snippet, re.IGNORECASE):
        return 'lax'
    elif re.search(r'samesite\s*=\s*[\'"]Strict[\'"]', code_snippet, re.IGNORECASE):
        return 'strict'
    elif re.search(r'samesite\s*=\s*[\'"]None[\'"]', code_snippet, re.IGNORECASE):
        return 'none'

    # 在附近代码中查找
    lines = full_code.split('\n')
    start_line = max(0, line - 3)
    end_line = min(len(lines), line + 3)

    for i in range(start_line, end_line):
        line_content = lines[i]
        if re.search(r'samesite\s*=\s*[\'"]Lax[\'"]', line_content, re.IGNORECASE):
            return 'lax'
        elif re.search(r'samesite\s*=\s*[\'"]Strict[\'"]', line_content, re.IGNORECASE):
            return 'strict'
        elif re.search(r'samesite\s*=\s*[\'"]None[\'"]', line_content, re.IGNORECASE):
            return 'none'

    return 'missing'


def is_sensitive_cookie(cookie_name):
    """
    检查是否是敏感Cookie
    """
    if not cookie_name:
        return False

    clean_name = cookie_name.strip('"\'')

    for pattern in COOKIE_SECURITY_ATTRIBUTES['sensitive_cookies']:
        if re.match(pattern, clean_name, re.IGNORECASE):
            return True

    return False


def elevate_severity(current_severity):
    """
    提升严重程度等级
    """
    severity_levels = {'低危': '中危', '中危': '高危', '高危': '严重'}
    return severity_levels.get(current_severity, current_severity)


def analyze_python_cookie_security(code_string):
    """
    分析Python代码字符串中的Cookie安全漏洞
    """
    return detect_cookie_security_issues(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = '''
from flask import Flask, make_response, request, session
from django.http import HttpResponse, JsonResponse

app = Flask(__name__)

# 不安全的Cookie设置示例
@app.route('/insecure')
def insecure_cookies():
    response = make_response("Insecure cookies")

    # 1. HttpOnly未设置 - 高危
    response.set_cookie('session_id', 'abc123')

    # 2. 敏感Cookie未设置HttpOnly - 严重
    response.set_cookie('auth_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')

    # 3. HttpOnly显式设置为False - 严重
    response.set_cookie('user_data', 'user123', httponly=False)

    # 4. 缺少Secure标志（在HTTPS环境中）
    response.set_cookie('preferences', 'theme=dark', secure=False)

    # 5. SameSite未设置
    response.set_cookie('cart_id', 'cart123')

    # 6. 多个安全问题
    response.set_cookie('csrf_token', 'csrf123', httponly=False, secure=False)

    return response

# 相对安全的Cookie设置示例
@app.route('/secure')
def secure_cookies():
    response = make_response("Secure cookies")

    # 1. 设置HttpOnly和Secure
    response.set_cookie('session_id', 'abc123', httponly=True, secure=True)

    # 2. 设置SameSite
    response.set_cookie('auth_token', 'secure_token', 
                       httponly=True, secure=True, samesite='Lax')

    # 3. 完整的安全设置
    response.set_cookie('user_prefs', 'pref_data',
                       httponly=True, secure=True, 
                       samesite='Strict', max_age=3600)

    # 4. 敏感Cookie额外保护
    response.set_cookie('admin_session', 'admin123',
                       httponly=True, secure=True,
                       samesite='Strict', path='/admin')

    return response

# Django示例
def django_views(request):
    # 不安全的Django Cookie设置
    response = HttpResponse("Django insecure")
    response.set_cookie('sessionid', 'django_session', httponly=False)
    response.set_cookie('csrftoken', 'csrf_token_value')

    # 安全的Django Cookie设置
    secure_response = JsonResponse({"status": "ok"})
    secure_response.set_cookie('sessionid', 'secure_session', 
                              httponly=True, secure=True, samesite='Lax')

    return response

# Flask直接response设置
@app.route('/flask_direct')
def flask_direct():
    resp = make_response("Flask direct")

    # 不安全的设置
    resp.set_cookie('unsafe_cookie', 'value123')

    # 安全的设置
    resp.set_cookie('safe_cookie', 'value456', 
                   httponly=True, secure=True, samesite='Lax')

    return resp

# 条件性安全设置（可能不安全）
@app.route('/conditional')
def conditional_cookies():
    response = make_response("Conditional")

    # 条件性设置HttpOnly（可能被绕过）
    use_httponly = request.args.get('secure', 'false') == 'true'
    response.set_cookie('conditional_cookie', 'value123', 
                       httponly=use_httponly)

    return response

# 生产环境最佳实践
def set_secure_cookie(response, name, value, max_age=None):
    """安全设置Cookie的辅助函数"""
    response.set_cookie(
        name,
        value,
        httponly=True,
        secure=True,  # 在生产环境中应为True
        samesite='Lax',
        max_age=max_age or 3600,
        path='/'
    )

@app.route('/best_practice')
def best_practice():
    response = make_response("Best practice")
    set_secure_cookie(response, 'session_id', 'secure_session_value')
    set_secure_cookie(response, 'user_token', 'user_token_value', max_age=7200)
    return response

if __name__ == '__main__':
    app.run(debug=True)
'''

    print("=" * 70)
    print("Python Cookie安全漏洞检测（修复重复检测问题）")
    print("=" * 70)

    results = analyze_python_cookie_security(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个Cookie安全问题:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   风险类型: {vuln['risk_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   Cookie名称: {vuln.get('cookie_name', 'N/A')}")
            print("-" * 50)
    else:
        print("未检测到Cookie安全问题")