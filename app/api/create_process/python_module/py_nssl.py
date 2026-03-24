import os
import re
import sys
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
        # 检测不安全的Cookie设置 - 缺少secure标志
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @response_obj
                        attribute: (identifier) @set_cookie_method
                    )
                    arguments: (argument_list 
                        (string) @cookie_name
                        (string) @cookie_value
                    )
                ) @call
            ''',
            'method_pattern': r'^(set_cookie|set_cookie)$',
            'secure_required': True,
            'message': 'Cookie设置缺少secure标志'
        },
        # 检测set_cookie调用 - 检查关键字参数
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @response_obj
                        attribute: (identifier) @set_cookie_method
                    )
                    arguments: (argument_list 
                        (string) @cookie_name
                        (string) @cookie_value
                        (keyword_argument)* @kwargs
                    )
                ) @call
            ''',
            'method_pattern': r'^(set_cookie|set_cookie)$',
            'secure_required': True,
            'message': 'Cookie设置可能缺少secure标志'
        },
        # 检测HttpOnly标志缺失
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @response_obj
                        attribute: (identifier) @set_cookie_method
                    )
                    arguments: (argument_list 
                        (_)* @args
                        (keyword_argument)* @kwargs
                    )
                ) @call
            ''',
            'method_pattern': r'^(set_cookie|set_cookie)$',
            'httponly_required': True,
            'message': 'Cookie设置可能缺少httponly标志'
        },
        # 检测Flask的set_cookie方法
        {
            'query': '''
                (call
                    function: (attribute
                        object: (call
                            function: (identifier) @make_response_func
                        ) @response_obj
                        attribute: (identifier) @set_cookie_method
                    )
                    arguments: (argument_list 
                        (_)* @args
                        (keyword_argument)* @kwargs
                    )
                ) @call
            ''',
            'make_response_pattern': r'^(make_response|response)$',
            'method_pattern': r'^(set_cookie)$',
            'secure_required': True,
            'httponly_required': True,
            'message': 'Flask Cookie设置安全配置问题'
        },
        # 检测Django的set_cookie方法
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @http_response_obj
                        attribute: (identifier) @set_cookie_method
                    )
                    arguments: (argument_list 
                        (_)* @args
                        (keyword_argument)* @kwargs
                    )
                ) @call
            ''',
            'response_pattern': r'^(HttpResponse|JsonResponse|HttpResponseRedirect)$',
            'method_pattern': r'^(set_cookie|set_cookie)$',
            'secure_required': True,
            'httponly_required': True,
            'message': 'Django Cookie设置安全配置问题'
        },
        # 检测session配置安全问题
        {
            'query': '''
                (assignment
                    left: (attribute
                        object: (identifier) @app_obj
                        attribute: (identifier) @session_config
                    )
                    right: (_) @config_value
                ) @assignment
            ''',
            'app_pattern': r'^(app|application)$',
            'config_pattern': r'^(session_cookie_secure|session_cookie_httponly|session_cookie_samesite)$',
            'message': 'Session Cookie安全配置问题'
        },
        # 检测Cookie的samesite标志设置
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @response_obj
                        attribute: (identifier) @set_cookie_method
                    )
                    arguments: (argument_list 
                        (_)* @args
                        (keyword_argument)* @kwargs
                    )
                ) @call
            ''',
            'method_pattern': r'^(set_cookie|set_cookie)$',
            'samesite_required': True,
            'message': 'Cookie设置可能缺少samesite标志'
        }
    ]
}

# Web框架响应对象模式
WEB_FRAMEWORK_RESPONSES = {
    'query': '''
        [
            (call
                function: (identifier) @response_func
                arguments: (argument_list) @args
            )
            (assignment
                left: (identifier) @response_var
                right: (call
                    function: (identifier) @response_func
                    arguments: (argument_list) @args
                )
            )
        ] @response_creation
    ''',
    'patterns': [
        {
            'func_pattern': r'^(make_response|Response|HttpResponse|JsonResponse|HttpResponseRedirect|redirect)$',
            'message': 'Web框架响应对象创建'
        }
    ]
}

# Cookie相关配置模式
COOKIE_CONFIGURATIONS = {
    'query': '''
        [
            (assignment
                left: (attribute
                    object: (identifier) @app_obj
                    attribute: (identifier) @config_name
                )
                right: (_) @config_value
            )
            (call
                function: (attribute
                    object: (identifier) @app_obj
                    attribute: (identifier) @config_method
                )
                arguments: (argument_list 
                    (string) @config_key
                    (_) @config_value
                )
            )
        ] @config_assignment
    ''',
    'patterns': [
        {
            'app_pattern': r'^(app|application|flask_app|django_app)$',
            'config_pattern': r'^(SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|SESSION_COOKIE_SAMESITE|'
                            r'session_cookie_secure|session_cookie_httponly|session_cookie_samesite)$',
            'message': 'Session Cookie全局配置'
        }
    ]
}

# 不安全的值模式
INSECURE_VALUES = {
    'false_values': ['False', 'false', '0', 'None', '""', "''"],
    'insecure_samesite': ['None', '"None"', "'None'", 'Lax', '"Lax"', "'Lax'"],
    'secure_samesite': ['Strict', '"Strict"', "'Strict'", 'Strict; Secure', '"Strict; Secure"']
}


def detect_cookie_security_issues(code, language='python'):
    """
    检测Python代码中Cookie安全配置问题

    Args:
        code: Python源代码字符串
        language: 语言类型，默认为'python'

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
    cookie_operations = []  # 存储Cookie操作
    response_creations = []  # 存储响应对象创建
    config_assignments = []  # 存储配置赋值

    # 第一步：收集所有Cookie设置操作
    for query_info in COOKIE_SECURITY_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['set_cookie_method', 'response_obj', 'make_response_func', 
                          'http_response_obj', 'app_obj', 'session_config']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['cookie_name', 'cookie_value', 'config_value']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['kwargs', 'args']:
                    current_capture[tag] = node.text.decode('utf8')

                elif tag in ['call', 'assignment'] and current_capture:
                    # 检查方法名和对象是否匹配模式
                    method_pattern = query_info.get('method_pattern', '')
                    make_response_pattern = query_info.get('make_response_pattern', '')
                    response_pattern = query_info.get('response_pattern', '')
                    app_pattern = query_info.get('app_pattern', '')
                    config_pattern = query_info.get('config_pattern', '')

                    method_match = True
                    make_response_match = True
                    response_match = True
                    app_match = True
                    config_match = True

                    if method_pattern and 'set_cookie_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['set_cookie_method'], re.IGNORECASE)

                    if make_response_pattern and 'make_response_func' in current_capture:
                        make_response_match = re.match(make_response_pattern, current_capture['make_response_func'], re.IGNORECASE)

                    if response_pattern and 'http_response_obj' in current_capture:
                        response_match = re.match(response_pattern, current_capture['http_response_obj'], re.IGNORECASE)

                    if app_pattern and 'app_obj' in current_capture:
                        app_match = re.match(app_pattern, current_capture['app_obj'], re.IGNORECASE)

                    if config_pattern and 'session_config' in current_capture:
                        config_match = re.match(config_pattern, current_capture['session_config'], re.IGNORECASE)

                    if method_match and make_response_match and response_match and app_match and config_match:
                        code_snippet = node.text.decode('utf8')

                        cookie_operations.append({
                            'type': 'cookie_operation',
                            'line': current_capture['line'],
                            'method': current_capture.get('set_cookie_method', ''),
                            'response_object': current_capture.get('response_obj', ''),
                            'app_object': current_capture.get('app_obj', ''),
                            'config_name': current_capture.get('session_config', ''),
                            'cookie_name': current_capture.get('cookie_name', ''),
                            'cookie_value': current_capture.get('cookie_value', ''),
                            'keyword_arguments': current_capture.get('kwargs', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'secure_required': query_info.get('secure_required', False),
                            'httponly_required': query_info.get('httponly_required', False),
                            'samesite_required': query_info.get('samesite_required', False),
                            'vulnerability_type': query_info.get('message', 'Cookie安全配置问题')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"Cookie安全查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集响应对象创建
    try:
        query = LANGUAGES[language].query(WEB_FRAMEWORK_RESPONSES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['response_func', 'response_var']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'response_creation' and current_capture:
                # 检查是否匹配响应创建模式
                for pattern_info in WEB_FRAMEWORK_RESPONSES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')

                    if 'response_func' in current_capture and re.match(func_pattern, current_capture['response_func'], re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        response_creations.append({
                            'type': 'response_creation',
                            'line': current_capture['line'],
                            'function': current_capture['response_func'],
                            'variable': current_capture.get('response_var', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"响应对象创建查询错误: {e}")

    # 第三步：收集配置赋值
    try:
        query = LANGUAGES[language].query(COOKIE_CONFIGURATIONS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['app_obj', 'config_name', 'config_method', 'config_key']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['config_value']:
                current_capture[tag] = node.text.decode('utf8')

            elif tag == 'config_assignment' and current_capture:
                # 检查是否匹配配置模式
                for pattern_info in COOKIE_CONFIGURATIONS['patterns']:
                    app_pattern = pattern_info.get('app_pattern', '')
                    config_pattern = pattern_info.get('config_pattern', '')

                    app_match = False
                    config_match = False

                    if app_pattern and 'app_obj' in current_capture:
                        app_match = re.match(app_pattern, current_capture['app_obj'], re.IGNORECASE)

                    if config_pattern and 'config_name' in current_capture:
                        config_match = re.match(config_pattern, current_capture['config_name'], re.IGNORECASE)
                    elif config_pattern and 'config_key' in current_capture:
                        config_match = re.match(config_pattern, current_capture['config_key'], re.IGNORECASE)

                    if app_match and config_match:
                        code_snippet = node.text.decode('utf8')
                        config_assignments.append({
                            'type': 'config_assignment',
                            'line': current_capture['line'],
                            'app_object': current_capture['app_obj'],
                            'config_name': current_capture.get('config_name', '') or current_capture.get('config_key', ''),
                            'config_value': current_capture.get('config_value', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"配置赋值查询错误: {e}")

    # 第四步：分析Cookie安全漏洞
    for cookie_op in cookie_operations:
        vulnerability_details = analyze_cookie_operation(cookie_op)
        if vulnerability_details:
            vulnerabilities.append(vulnerability_details)

    # 第五步：分析配置安全问题
    for config in config_assignments:
        vulnerability_details = analyze_config_assignment(config)
        if vulnerability_details:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_cookie_operation(cookie_op):
    """
    分析单个Cookie操作的安全问题
    """
    vulnerabilities = []
    code_snippet = cookie_op['code_snippet']
    line = cookie_op['line']

    # 检查secure标志
    if cookie_op['secure_required'] and not has_secure_flag(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Cookie安全配置',
            'severity': '高危',
            'message': f"{cookie_op['method']} 调用缺少secure标志 - Cookie将通过非SSL连接发送"
        })

    # 检查httponly标志
    if cookie_op['httponly_required'] and not has_httponly_flag(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Cookie安全配置',
            'severity': '中危',
            'message': f"{cookie_op['method']} 调用缺少httponly标志 - Cookie可能被客户端JavaScript访问"
        })

    # 检查samesite标志
    if cookie_op['samesite_required'] and not has_samesite_flag(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Cookie安全配置',
            'severity': '中危',
            'message': f"{cookie_op['method']} 调用缺少samesite标志 - 存在CSRF风险"
        })

    # 检查不安全的samesite值
    if has_insecure_samesite_value(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Cookie安全配置',
            'severity': '中危',
            'message': f"{cookie_op['method']} 使用不安全的samesite值"
        })

    return vulnerabilities[0] if vulnerabilities else None


def analyze_config_assignment(config):
    """
    分析配置赋值的安全问题
    """
    config_name = config['config_name'].lower()
    config_value = config['config_value'].lower()

    # 检查SESSION_COOKIE_SECURE设置为False
    if 'secure' in config_name and is_false_value(config_value):
        return {
            'line': config['line'],
            'code_snippet': config['code_snippet'],
            'vulnerability_type': 'Session Cookie配置',
            'severity': '高危',
            'message': f"{config['config_name']} 设置为False - Session Cookie将通过非SSL连接发送"
        }

    # 检查SESSION_COOKIE_HTTPONLY设置为False
    if 'httponly' in config_name and is_false_value(config_value):
        return {
            'line': config['line'],
            'code_snippet': config['code_snippet'],
            'vulnerability_type': 'Session Cookie配置',
            'severity': '中危',
            'message': f"{config['config_name']} 设置为False - Session Cookie可能被客户端JavaScript访问"
        }

    # 检查不安全的samesite配置
    if 'samesite' in config_name and is_insecure_samesite(config_value):
        return {
            'line': config['line'],
            'code_snippet': config['code_snippet'],
            'vulnerability_type': 'Session Cookie配置',
            'severity': '中危',
            'message': f"{config['config_name']} 使用不安全的配置值"
        }

    return None


def has_secure_flag(code_snippet):
    """检查代码片段是否包含secure标志"""
    secure_patterns = [
        r'secure\s*=\s*True',
        r'secure\s*=\s*1',
        r'secure=True',
        r'"secure"\s*:\s*true',
        r"'secure'\s*:\s*true"
    ]
    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in secure_patterns)


def has_httponly_flag(code_snippet):
    """检查代码片段是否包含httponly标志"""
    httponly_patterns = [
        r'httponly\s*=\s*True',
        r'httponly\s*=\s*1',
        r'httponly=True',
        r'http_only\s*=\s*True',
        r'"httponly"\s*:\s*true',
        r"'httponly'\s*:\s*true"
    ]
    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in httponly_patterns)


def has_samesite_flag(code_snippet):
    """检查代码片段是否包含samesite标志"""
    samesite_patterns = [
        r'samesite\s*=',
        r'same_site\s*=',
        r'"samesite"\s*:',
        r"'samesite'\s*:"
    ]
    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in samesite_patterns)


def has_insecure_samesite_value(code_snippet):
    """检查是否使用不安全的samesite值"""
    insecure_samesite_patterns = [
        r'samesite\s*=\s*[\'"]?None[\'"]?',
        r'samesite\s*=\s*[\'"]?Lax[\'"]?',
        r'same_site\s*=\s*[\'"]?None[\'"]?'
    ]
    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in insecure_samesite_patterns)


def is_false_value(config_value):
    """检查配置值是否为False"""
    false_values = ['false', 'False', '0', 'none', 'None', '""', "''"]
    return any(false_val in config_value for false_val in false_values)


def is_insecure_samesite(config_value):
    """检查是否使用不安全的samesite值"""
    insecure_values = ['none', 'None', '"none"', "'none'", 'lax', 'Lax', '"lax"', "'lax'"]
    return any(insecure_val in config_value for insecure_val in insecure_values)


def detect_cookie_security_issues_main(code_string):
    """
    主函数：分析Python代码字符串中的Cookie安全问题
    """
    return detect_cookie_security_issues(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
from flask import Flask, make_response, request, session
from django.http import HttpResponse, JsonResponse
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# 不安全的Cookie配置
def insecure_cookie_examples():
    # 不安全的Cookie设置 - 缺少secure标志
    response = make_response("Hello World")
    response.set_cookie('user_id', '12345')  # 缺少secure和httponly
    
    # 不安全的Flask session配置
    app.config['SESSION_COOKIE_SECURE'] = False  # 高危
    app.config['SESSION_COOKIE_HTTPONLY'] = False  # 中危
    
    # 不安全的samesite配置
    app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # 中危
    
    # 不安全的set_cookie调用
    response.set_cookie('auth_token', 'abc123', secure=False)  # 显式设置为False
    
    # 缺少samesite标志
    response.set_cookie('preferences', 'dark_mode', secure=True, httponly=True)  # 缺少samesite
    
    # 使用不安全的samesite值
    response.set_cookie('csrftoken', 'token123', samesite='Lax')  # 应该使用Strict
    
    return response

# 安全的Cookie配置
def secure_cookie_examples():
    # 安全的Cookie设置
    response = make_response("Hello World")
    response.set_cookie('user_id', '12345', secure=True, httponly=True, samesite='Strict')
    
    # 安全的Flask session配置
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    
    # 安全的Django Cookie设置
    django_response = HttpResponse()
    django_response.set_cookie('sessionid', 'secure_session', secure=True, httponly=True, samesite='Strict')
    
    # 安全的JsonResponse
    json_response = JsonResponse({'status': 'ok'})
    json_response.set_cookie('preferences', '{"theme":"dark"}', secure=True, httponly=True, samesite='Strict')
    
    return response

# 混合配置
def mixed_configuration():
    # 部分安全配置
    response = make_response("Test")
    
    # 只有secure，缺少httponly
    response.set_cookie('cookie1', 'value1', secure=True)  # 中危
    
    # 只有httponly，缺少secure  
    response.set_cookie('cookie2', 'value2', httponly=True)  # 高危
    
    # 使用相对安全的samesite
    response.set_cookie('cookie3', 'value3', secure=True, httponly=True, samesite='Lax')  # 低危
    
    # 环境变量配置
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_SECURE', False)  # 可能不安全
    
    return response

if __name__ == "__main__":
    insecure_cookie_examples()
    secure_cookie_examples() 
    mixed_configuration()
"""

    print("=" * 60)
    print("Python Cookie安全配置检测")
    print("=" * 60)

    results = detect_cookie_security_issues_main(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个Cookie安全问题:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Cookie安全问题")