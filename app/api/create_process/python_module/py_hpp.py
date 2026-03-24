import os
import re
from tree_sitter import Language, Parser

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义HTTP参数污染漏洞模式（修复版）
HTTP_PARAMETER_POLLUTION_VULNERABILITIES = {
    'python': [
        # 检测Web框架中的参数获取 - 修复语法
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @request_obj
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list (string) @param_name)
                ) @call
            ''',
            'request_pattern': r'^(request|req)$',
            'method_pattern': r'^(args|form|values|get|post)$',
            'message': 'Web框架参数获取',
            'severity': '中危',
            'risk_type': 'web_framework_param'
        },
        # 检测Flask请求参数 - 修复语法
        {
            'query': '''
                (call
                    function: (attribute
                        object: (attribute
                            object: (identifier) @flask_obj
                            attribute: (identifier) @request_attr
                        )
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list (string) @param_name)
                ) @call
            ''',
            'flask_pattern': r'^(flask)$',
            'request_pattern': r'^(request)$',
            'method_pattern': r'^(args|form|values|get_json|get_data)$',
            'message': 'Flask请求参数获取',
            'severity': '中危',
            'risk_type': 'flask_param'
        },
        # 检测Django请求参数
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @request_obj
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list (string) @param_name)
                ) @call
            ''',
            'request_pattern': r'^(request|req)$',
            'method_pattern': r'^(GET|POST)$',
            'message': 'Django请求参数获取',
            'severity': '中危',
            'risk_type': 'django_param'
        },
        # 检测直接访问请求字典 - 修复语法
        {
            'query': '''
                (subscript
                    value: (attribute
                        object: (identifier) @request_obj
                        attribute: (identifier) @method_name
                    )
                    index: (string) @param_name
                ) @subscript
            ''',
            'request_pattern': r'^(request|req)$',
            'method_pattern': r'^(args|form|values|GET|POST)$',
            'message': '直接字典方式参数获取',
            'severity': '中危',
            'risk_type': 'direct_dict_param'
        },
        # 检测参数直接用于敏感操作 - 简化查询
        {
            'query': '''
                (call
                    function: (identifier) @sensitive_func
                    arguments: (argument_list 
                        (call) @param_call
                    )
                ) @sensitive_call
            ''',
            'sensitive_pattern': r'^(execute|query|eval|exec|system|popen|call|run|connect|login|authenticate)$',
            'message': '参数直接用于敏感操作',
            'severity': '高危',
            'risk_type': 'direct_sensitive_use'
        },
        # 检测参数用于SQL查询 - 简化查询
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @db_obj
                        attribute: (identifier) @sql_method
                    )
                    arguments: (argument_list 
                        (string) @sql_string
                    )
                ) @sql_call
            ''',
            'db_pattern': r'^(cursor|db|connection|sql)$',
            'sql_pattern': r'^(execute|executemany|query)$',
            'message': 'SQL查询调用',
            'severity': '高危',
            'risk_type': 'sql_query'
        },
        # 检测参数用于文件操作 - 简化查询
        {
            'query': '''
                (call
                    function: (identifier) @file_func
                    arguments: (argument_list 
                        (call) @param_call
                    )
                ) @file_call
            ''',
            'file_pattern': r'^(open|file|remove|unlink|rmdir|chmod|chown)$',
            'message': '文件操作调用',
            'severity': '高危',
            'risk_type': 'file_operation'
        },
        # 检测参数用于重定向 - 简化查询
        {
            'query': '''
                (call
                    function: (identifier) @redirect_func
                    arguments: (argument_list 
                        (call) @param_call
                    )
                ) @redirect_call
            ''',
            'redirect_pattern': r'^(redirect|Redirect)$',
            'message': '重定向调用',
            'severity': '中危',
            'risk_type': 'redirect_operation'
        },
        # 新增：检测请求参数赋值
        {
            'query': '''
                (assignment
                    left: (identifier) @var_name
                    right: (call
                        function: (attribute
                            object: (identifier) @request_obj
                            attribute: (identifier) @method_name
                        )
                        arguments: (argument_list (string) @param_name)
                    )
                ) @assignment
            ''',
            'request_pattern': r'^(request|req)$',
            'method_pattern': r'^(args|form|values|get|post|GET|POST)$',
            'message': '请求参数赋值',
            'severity': '中危',
            'risk_type': 'param_assignment'
        }
    ]
}

# 参数污染敏感参数
SENSITIVE_PARAMETERS = {
    'authentication_params': [
        'username', 'user', 'email', 'login', 'account',
        'password', 'pass', 'pwd', 'secret', 'token',
        'session', 'cookie', 'auth', 'credential', 'key'
    ],
    'security_params': [
        'role', 'permission', 'admin', 'superuser', 'privilege',
        'access', 'level', 'rights', 'authority'
    ],
    'system_params': [
        'url', 'redirect', 'return', 'next', 'target',
        'file', 'path', 'filename', 'dir', 'directory',
        'cmd', 'command', 'exec', 'query', 'sql'
    ],
    'business_params': [
        'id', 'user_id', 'account_id', 'order_id', 'transaction_id',
        'amount', 'price', 'total', 'balance', 'limit'
    ]
}


def detect_http_parameter_pollution(code, language='python'):
    """
    检测Python代码中HTTP参数污染漏洞（修复版）
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
    param_usage_locations = []  # 存储参数使用位置

    # 收集所有参数使用位置
    for query_info in HTTP_PARAMETER_POLLUTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                # 收集节点信息
                if tag in ['request_obj', 'flask_obj', 'request_attr', 'db_obj',
                           'method_name', 'sql_method', 'sensitive_func',
                           'file_func', 'redirect_func', 'var_name']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['param_name', 'sql_string']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['call', 'subscript', 'sensitive_call', 'sql_call',
                             'file_call', 'redirect_call', 'assignment'] and current_capture:
                    # 检查是否匹配模式
                    if is_parameter_usage(current_capture, query_info):
                        code_snippet = node.text.decode('utf8')

                        usage_info = {
                            'type': 'parameter_usage',
                            'line': current_capture['line'],
                            'request_obj': current_capture.get('request_obj', ''),
                            'method_name': current_capture.get('method_name', ''),
                            'param_name': current_capture.get('param_name', ''),
                            'var_name': current_capture.get('var_name', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'severity': query_info.get('severity', '中危'),
                            'risk_type': query_info.get('risk_type', 'unknown'),
                            'original_message': query_info.get('message', ''),
                            'query_info': query_info
                        }
                        param_usage_locations.append(usage_info)

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 分析参数污染漏洞
    for usage in param_usage_locations:
        vulnerability_details = analyze_parameter_pollution_vulnerability(usage, root, code)
        if vulnerability_details:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_parameter_usage(capture, query_info):
    """
    检查是否是参数使用
    """
    risk_type = query_info.get('risk_type', '')

    if risk_type in ['web_framework_param', 'flask_param', 'django_param', 'direct_dict_param', 'param_assignment']:
        request_obj = capture.get('request_obj', '')
        method_name = capture.get('method_name', '')
        request_pattern = query_info.get('request_pattern', '')
        method_pattern = query_info.get('method_pattern', '')

        return (re.match(request_pattern, request_obj, re.IGNORECASE) and
                re.match(method_pattern, method_name, re.IGNORECASE))

    elif risk_type == 'direct_sensitive_use':
        sensitive_func = capture.get('sensitive_func', '')
        sensitive_pattern = query_info.get('sensitive_pattern', '')
        return bool(re.match(sensitive_pattern, sensitive_func, re.IGNORECASE))

    elif risk_type == 'sql_query':
        db_obj = capture.get('db_obj', '')
        sql_method = capture.get('sql_method', '')
        db_pattern = query_info.get('db_pattern', '')
        sql_pattern = query_info.get('sql_pattern', '')

        return (re.match(db_pattern, db_obj, re.IGNORECASE) and
                re.match(sql_pattern, sql_method, re.IGNORECASE))

    elif risk_type == 'file_operation':
        file_func = capture.get('file_func', '')
        file_pattern = query_info.get('file_pattern', '')
        return bool(re.match(file_pattern, file_func, re.IGNORECASE))

    elif risk_type == 'redirect_operation':
        redirect_func = capture.get('redirect_func', '')
        redirect_pattern = query_info.get('redirect_pattern', '')
        return bool(re.match(redirect_pattern, redirect_func, re.IGNORECASE))

    return False


def analyze_parameter_pollution_vulnerability(usage, root, code):
    """
    分析参数污染漏洞
    """
    risk_type = usage['risk_type']
    param_name = usage.get('param_name', '')
    var_name = usage.get('var_name', '')

    vulnerability_details = {
        'line': usage['line'],
        'code_snippet': usage['code_snippet'],
        'vulnerability_type': 'HTTP参数污染',
        'severity': usage['severity'],
        'risk_type': risk_type
    }

    # 根据风险类型设置具体消息
    if risk_type in ['web_framework_param', 'flask_param', 'django_param', 'direct_dict_param', 'param_assignment']:
        param_value = param_name if param_name else var_name
        clean_param = param_value.strip('"\'') if param_value else ''

        if is_sensitive_parameter(clean_param):
            vulnerability_details['message'] = (
                f"敏感参数 '{clean_param}' 直接获取 - 可能受到参数污染攻击"
            )
            vulnerability_details['severity'] = '高危'
            vulnerability_details['parameter'] = clean_param
        else:
            vulnerability_details['message'] = (
                f"参数 '{clean_param}' 直接获取 - 需要验证和清理"
            )
            vulnerability_details['parameter'] = clean_param

    elif risk_type == 'direct_sensitive_use':
        vulnerability_details['message'] = (
            f"请求参数直接用于敏感操作 - 可能受到参数污染攻击"
        )

    elif risk_type == 'sql_query':
        vulnerability_details['message'] = (
            f"请求参数用于SQL查询 - 需要检查SQL注入和参数污染风险"
        )
        vulnerability_details['severity'] = '高危'

    elif risk_type == 'file_operation':
        vulnerability_details['message'] = (
            f"请求参数用于文件操作 - 可能受到路径遍历和参数污染攻击"
        )
        vulnerability_details['severity'] = '高危'

    elif risk_type == 'redirect_operation':
        vulnerability_details['message'] = (
            f"请求参数用于重定向 - 可能受到开放重定向和参数污染攻击"
        )

    # 检查是否缺少验证
    if not has_parameter_validation(usage, root, code):
        vulnerability_details['message'] += " (缺少参数验证)"
        if vulnerability_details['severity'] != '高危':
            vulnerability_details['severity'] = '中危'

    # 检查是否是多值参数使用
    if is_multi_value_parameter_usage(usage):
        vulnerability_details['message'] += " (多值参数处理)"
        vulnerability_details['severity'] = elevate_severity(vulnerability_details['severity'])

    return vulnerability_details


def is_sensitive_parameter(param_name):
    """
    检查是否是敏感参数
    """
    if not param_name:
        return False

    clean_param = param_name.strip('"\'')

    # 检查认证参数
    for pattern in SENSITIVE_PARAMETERS['authentication_params']:
        if re.match(pattern, clean_param, re.IGNORECASE):
            return True

    # 检查安全参数
    for pattern in SENSITIVE_PARAMETERS['security_params']:
        if re.match(pattern, clean_param, re.IGNORECASE):
            return True

    # 检查系统参数
    for pattern in SENSITIVE_PARAMETERS['system_params']:
        if re.match(pattern, clean_param, re.IGNORECASE):
            return True

    # 检查业务参数
    for pattern in SENSITIVE_PARAMETERS['business_params']:
        if re.match(pattern, clean_param, re.IGNORECASE):
            return True

    return False


def has_parameter_validation(usage, root, code):
    """
    检查参数是否有验证
    """
    line = usage['line']

    # 简单的检查：在参数使用附近是否有验证逻辑
    validation_indicators = [
        'validate', 'check', 'sanitize', 'clean', 'verify', 'filter',
        'is_valid', 'escape', 'quote', 'encode', 'int(', 'str(', 'float(',
        'isdigit', 'isalpha', 'isalnum', 'if.*:', 'assert'
    ]

    code_snippet = usage['code_snippet'].lower()
    for indicator in validation_indicators:
        if indicator in code_snippet:
            return True

    # 检查附近代码行
    lines = code.split('\n')
    start_line = max(0, line - 5)
    end_line = min(len(lines), line + 5)

    for i in range(start_line, end_line):
        line_content = lines[i].lower()
        for indicator in validation_indicators:
            if indicator in line_content:
                return True

    return False


def is_multi_value_parameter_usage(usage):
    """
    检查是否是多值参数使用
    """
    risk_type = usage['risk_type']

    # 对于某些框架，特定方法可能返回多值
    method_name = usage.get('method_name', '').lower()

    multi_value_methods = ['values', 'getlist', 'getall']
    if method_name in multi_value_methods:
        return True

    # 检查是否使用get()方法，这可能处理多值不同
    if 'get' in method_name and risk_type in ['web_framework_param', 'flask_param', 'django_param']:
        return True

    return False


def elevate_severity(current_severity):
    """
    提升严重程度等级
    """
    severity_levels = {'低危': '中危', '中危': '高危', '高危': '严重'}
    return severity_levels.get(current_severity, current_severity)


def analyze_python_http_parameter_pollution(code_string):
    """
    分析Python代码字符串中的HTTP参数污染漏洞
    """
    return detect_http_parameter_pollution(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = '''
from flask import Flask, request, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

# 易受参数污染攻击的示例
@app.route('/vulnerable')
def vulnerable_examples():
    # 1. 直接获取参数用于敏感操作
    username = request.args.get('username')
    password = request.args.get('password')

    # 认证逻辑 - 可能受到参数污染
    if authenticate_user(username, password):
        return "Login successful"

    # 2. 参数用于SQL查询
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

    # 3. 参数用于文件操作
    filename = request.args.get('file')
    with open(filename, 'r') as f:  # 路径遍历 + 参数污染
        content = f.read()

    # 4. 参数用于重定向
    next_url = request.args.get('next')
    return redirect(next_url)  # 开放重定向 + 参数污染

    # 5. 多值参数处理不当
    roles = request.args.get('role')  # 可能只获取第一个值
    if roles == 'admin':
        grant_admin_access()

    return "Vulnerable endpoint"

# 参数污染特定示例
@app.route('/pollution')
def parameter_pollution_examples():
    # 参数污染攻击场景

    # 场景1: 认证绕过
    # 攻击者发送: ?username=user&username=admin
    username = request.args.get('username')
    # 某些框架可能返回 'user', 某些返回 'admin'

    # 场景2: 权限提升  
    # 攻击者发送: ?role=user&role=admin
    role = request.form.get('role')
    if role == 'admin':
        grant_admin_privileges()

    # 场景3: 业务逻辑绕过
    # 攻击者发送: ?price=100&price=1
    price = request.values.get('price')
    total = calculate_total(price)  # 可能使用错误的价格

    # 场景4: SQL注入增强
    # 攻击者发送: ?id=1&id=1 UNION SELECT * FROM passwords
    user_id = request.args.get('id')

    return "Parameter pollution test"

# 相对安全的示例
@app.route('/safe')
def safe_examples():
    # 1. 参数验证和清理
    username = request.args.get('username', '')
    if not validate_username(username):
        return "Invalid username"

    # 2. 使用参数化查询
    user_id = request.args.get('id', '')
    try:
        user_id_int = int(user_id)  # 类型转换
    except ValueError:
        return "Invalid ID"

    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id_int,))

    # 3. 安全的文件操作
    filename = request.args.get('file', '')
    safe_filename = os.path.basename(filename)  # 路径清理
    if not safe_filename.endswith('.txt'):
        return "Invalid file type"

    # 4. 安全的重定向
    next_url = request.args.get('next', '')
    if not next_url.startswith('/') and not next_url.startswith(url_for('index')):
        return "Invalid redirect URL"
    return redirect(next_url)

    # 5. 明确处理多值参数
    roles = request.args.getlist('role')  # 明确获取列表
    if 'admin' in roles:
        # 明确处理多值情况
        pass

    return "Safe endpoint"

# Django示例
def django_views(request):
    # Django中的参数获取
    username = request.GET.get('username')
    password = request.POST.get('password')

    # 直接字典访问
    user_id = request.GET['id']  # 可能抛出KeyError

    # 多值参数
    categories = request.GET.getlist('category')

    return "Django view"

# 辅助函数
def authenticate_user(username, password):
    # 简单的认证逻辑
    return username == "admin" and password == "password"

def grant_admin_access():
    pass

def grant_admin_privileges():
    pass

def calculate_total(price):
    return float(price) * 1.1

def validate_username(username):
    return bool(username) and len(username) > 3

if __name__ == '__main__':
    app.run(debug=True)
'''

    print("=" * 70)
    print("Python HTTP参数污染漏洞检测（修复版）")
    print("=" * 70)

    results = analyze_python_http_parameter_pollution(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个潜在参数污染漏洞:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   风险类型: {vuln['risk_type']}")
            print(f"   严重程度: {vuln['severity']}")
            if vuln.get('parameter'):
                print(f"   涉及参数: {vuln.get('parameter')}")
            print("-" * 50)
    else:
        print("未检测到HTTP参数污染漏洞")