import os
import re
import json
from tree_sitter import Language, Parser

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义JSON注入漏洞模式
JSON_INJECTION_VULNERABILITIES = {
    'python': [
        # 检测json.dumps调用
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @module
                        attribute: (identifier) @func_name
                    )
                    arguments: (argument_list (_) @data_arg)
                ) @call
            ''',
            'module_pattern': r'^(json|simplejson|ujson|rapidjson)$',
            'func_pattern': r'^(dumps|dump|encode)$',
            'message': 'JSON序列化调用',
            'severity': '中危',
            'risk_type': 'json_serialization'
        },
        # 检测字符串拼接构建JSON
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (binary_expression
                            left: (string) @left_str
                            operator: "+"
                            right: (_) @right_expr
                        ) @concat_expr
                    )
                ) @call
            ''',
            'func_pattern': r'^(json\.dumps|json\.dump|json\.encode)$',
            'message': 'JSON字符串拼接',
            'severity': '高危',
            'risk_type': 'json_string_concat'
        },
        # 检测格式化字符串构建JSON
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string) @format_string
                    )
                ) @call
            ''',
            'func_pattern': r'^(json\.dumps|json\.dump|json\.encode)$',
            'message': 'JSON格式化字符串',
            'severity': '高危',
            'risk_type': 'json_format_string'
        },
        # 检测eval执行JSON
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @json_string)
                ) @call
            ''',
            'func_pattern': r'^(eval|exec)$',
            'message': 'eval执行JSON',
            'severity': '严重',
            'risk_type': 'eval_json'
        },
        # 检测JavaScript代码注入
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @module
                        attribute: (identifier) @func_name
                    )
                    arguments: (argument_list (_) @data_arg)
                ) @call
            ''',
            'module_pattern': r'^(json)$',
            'func_pattern': r'^(dumps|dump)$',
            'message': 'JSON序列化调用',
            'severity': '中危',
            'risk_type': 'json_js_injection'
        }
    ]
}

# JSON注入危险模式
JSON_INJECTION_PATTERNS = {
    'javascript_injection': [
        r'</script', r'<script', r'javascript:', r'onload=', r'onerror=',
        r'onclick=', r'onmouseover=', r'eval\s*\(', r'alert\s*\(',
        r'document\.', r'window\.', r'location\.', r'XMLHttpRequest',
        r'fetch\s*\(', r'setTimeout', r'setInterval'
    ],
    'html_injection': [
        r'</?[a-z][\s\S]*>', r'&[a-z]+;', r'&#x?[0-9a-f]+;',
        r'on\w+\s*=', r'href\s*=\s*[\'"]javascript:',
        r'src\s*=\s*[\'"]javascript:'
    ],
    'json_breaking': [
        r'[{}[\],]',  # JSON结构字符
        r'"[^"]*"\s*:',  # JSON键
        r'true|false|null',  # JSON字面量
        r'-?\d+(\.\d+)?([eE][+-]?\d+)?'  # JSON数字
    ]
}

# 安全JSON处理模式
SAFE_JSON_PATTERNS = {
    'safe_functions': [
        r'^json\.dumps$', r'^json\.dump$', r'^json\.encode$',
        r'^html\.escape$', r'^cgi\.escape$', r'^re\.escape$'
    ],
    'safe_parameters': [
        r'ensure_ascii\s*=\s*True',
        r'escape_forward_slashes\s*=\s*True',
        r'sort_keys\s*=\s*True',
        r'separators\s*=\s*\([\'\"],\s*[\'\"]:[\'\"]\)'
    ]
}


def detect_json_injection(code, language='python'):
    """
    检测Python代码中JSON注入漏洞
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
    json_operations = []  # 存储所有JSON操作

    # 第一步：收集所有JSON操作
    for query_info in JSON_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['module', 'func_name']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['data_arg', 'json_string', 'left_str', 'right_expr', 'format_string']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['call', 'concat_expr'] and current_capture:
                    # 检查是否匹配模式
                    if is_json_operation(current_capture, query_info):
                        code_snippet = node.text.decode('utf8')

                        operation = {
                            'type': 'json_operation',
                            'line': current_capture['line'],
                            'module': current_capture.get('module', ''),
                            'function': current_capture.get('func_name', ''),
                            'data_arg': current_capture.get('data_arg', ''),
                            'json_string': current_capture.get('json_string', ''),
                            'left_str': current_capture.get('left_str', ''),
                            'right_expr': current_capture.get('right_expr', ''),
                            'format_string': current_capture.get('format_string', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'severity': query_info.get('severity', '中危'),
                            'risk_type': query_info.get('risk_type', 'unknown'),
                            'original_message': query_info.get('message', ''),
                            'query_info': query_info
                        }
                        json_operations.append(operation)

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：分析JSON注入漏洞
    for operation in json_operations:
        vulnerability_details = analyze_json_injection_vulnerability(operation, code)
        if vulnerability_details:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_json_operation(capture, query_info):
    """
    检查是否是JSON操作
    """
    risk_type = query_info.get('risk_type', '')

    if risk_type in ['json_serialization', 'json_js_injection']:
        module = capture.get('module', '')
        func_name = capture.get('func_name', '')
        module_pattern = query_info.get('module_pattern', '')
        func_pattern = query_info.get('func_pattern', '')

        return (re.match(module_pattern, module, re.IGNORECASE) and
                re.match(func_pattern, func_name, re.IGNORECASE))

    elif risk_type == 'json_string_concat':
        func_name = capture.get('func_name', '')
        func_pattern = query_info.get('func_pattern', '')
        return bool(re.match(func_pattern, func_name, re.IGNORECASE))

    elif risk_type == 'json_format_string':
        func_name = capture.get('func_name', '')
        func_pattern = query_info.get('func_pattern', '')
        return bool(re.match(func_pattern, func_name, re.IGNORECASE))

    elif risk_type == 'eval_json':
        func_name = capture.get('func_name', '')
        func_pattern = query_info.get('func_pattern', '')
        return bool(re.match(func_pattern, func_name, re.IGNORECASE))

    return False


def analyze_json_injection_vulnerability(operation, code):
    """
    分析JSON注入漏洞
    """
    risk_type = operation['risk_type']

    vulnerability_details = {
        'line': operation['line'],
        'code_snippet': operation['code_snippet'],
        'vulnerability_type': 'JSON注入',
        'severity': operation['severity'],
        'risk_type': risk_type
    }

    # 根据风险类型进行分析
    if risk_type in ['json_serialization', 'json_js_injection']:
        return analyze_json_serialization_vulnerability(operation, code)
    elif risk_type == 'json_string_concat':
        return analyze_json_string_concat_vulnerability(operation, code)
    elif risk_type == 'json_format_string':
        return analyze_json_format_string_vulnerability(operation, code)
    elif risk_type == 'eval_json':
        return analyze_eval_json_vulnerability(operation, code)

    return None


def analyze_json_serialization_vulnerability(operation, code):
    """
    分析JSON序列化漏洞
    """
    data_arg = operation.get('data_arg', '')

    # 检查数据参数是否可能包含用户输入
    if may_contain_user_input(data_arg):
        # 检查是否缺少安全参数
        if not has_safe_json_parameters(operation, code):
            vulnerability_details = {
                'line': operation['line'],
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'JSON注入',
                'severity': operation['severity'],
                'risk_type': operation['risk_type'],
                'message': f"JSON序列化调用可能包含用户输入 - 需要适当的转义和验证"
            }

            # 检查是否可能包含JavaScript代码
            if may_contain_javascript(data_arg):
                vulnerability_details['message'] += " (可能包含JavaScript代码)"
                vulnerability_details['severity'] = '高危'

            return vulnerability_details

    return None


def analyze_json_string_concat_vulnerability(operation, code):
    """
    分析JSON字符串拼接漏洞
    """
    left_str = operation.get('left_str', '')
    right_expr = operation.get('right_expr', '')

    # 检查右侧表达式是否可能包含用户输入
    if may_contain_user_input(right_expr):
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': 'JSON注入',
            'severity': '高危',
            'risk_type': operation['risk_type'],
            'message': "JSON字符串拼接可能包含用户输入 - 容易遭受注入攻击"
        }

        # 检查左侧字符串是否是JSON结构
        if is_json_structure(left_str):
            vulnerability_details['message'] += " (拼接JSON结构)"

        return vulnerability_details

    return None


def analyze_json_format_string_vulnerability(operation, code):
    """
    分析JSON格式化字符串漏洞
    """
    format_string = operation.get('format_string', '')

    # 检查格式化字符串是否包含占位符
    if contains_format_placeholders(format_string):
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': 'JSON注入',
            'severity': '高危',
            'risk_type': operation['risk_type'],
            'message': "JSON格式化字符串可能包含用户输入 - 容易遭受注入攻击"
        }

        return vulnerability_details

    return None


def analyze_eval_json_vulnerability(operation, code):
    """
    分析eval执行JSON漏洞
    """
    json_string = operation.get('json_string', '')

    # 检查是否可能包含用户输入
    if may_contain_user_input(json_string):
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': 'JSON注入',
            'severity': '严重',
            'risk_type': operation['risk_type'],
            'message': "使用eval执行JSON字符串 - 严重安全风险，可能执行任意代码"
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

    # 用户输入相关关键词
    user_input_keywords = [
        'request', 'args', 'form', 'input', 'user_input',
        'data', 'content', 'query', 'param', 'value',
        'get', 'post', 'cookies', 'headers', 'json'
    ]

    # 检查是否包含用户输入关键词
    for keyword in user_input_keywords:
        if re.search(rf'\b{keyword}\b', clean_text, re.IGNORECASE):
            return True

    # 检查是否包含变量（非字面量）
    if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*', clean_text) and not re.match(r'^[\'\"][^\'\"]*[\'\"]$', clean_text):
        return True

    return False


def may_contain_javascript(text):
    """
    检查文本是否可能包含JavaScript代码
    """
    if not text:
        return False

    clean_text = text.strip('"\'')

    # 检查JavaScript注入模式
    for pattern in JSON_INJECTION_PATTERNS['javascript_injection']:
        if re.search(pattern, clean_text, re.IGNORECASE):
            return True

    # 检查HTML注入模式
    for pattern in JSON_INJECTION_PATTERNS['html_injection']:
        if re.search(pattern, clean_text, re.IGNORECASE):
            return True

    return False


def is_json_structure(text):
    """
    检查文本是否是JSON结构
    """
    if not text:
        return False

    clean_text = text.strip('"\'')

    # 检查JSON结构特征
    for pattern in JSON_INJECTION_PATTERNS['json_breaking']:
        if re.search(pattern, clean_text):
            return True

    return False


def contains_format_placeholders(text):
    """
    检查文本是否包含格式化占位符
    """
    if not text:
        return False

    clean_text = text.strip('"\'')

    # 检查各种格式化占位符
    format_patterns = [
        r'\{.*?\}',  # {} 占位符
        r'%[sdf]',  # %s, %d, %f
        r'\{[0-9]+\}',  # {0}, {1}
        r'%\([^)]+\)s'  # %(name)s
    ]

    for pattern in format_patterns:
        if re.search(pattern, clean_text):
            return True

    return False


def has_safe_json_parameters(operation, code):
    """
    检查是否有安全的JSON参数
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    # 检查代码片段中的安全参数
    for pattern in SAFE_JSON_PATTERNS['safe_parameters']:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True

    # 在附近代码中查找安全函数
    safe_functions = [
        'html.escape', 'cgi.escape', 're.escape', 'json.dumps',
        'validate', 'sanitize', 'clean'
    ]

    lines = code.split('\n')
    start_line = max(0, line - 5)
    end_line = min(len(lines), line + 5)

    for i in range(start_line, end_line):
        line_content = lines[i].lower()
        for func in safe_functions:
            if func in line_content:
                return True

    return False


def analyze_python_json_injection(code_string):
    """
    分析Python代码字符串中的JSON注入漏洞
    """
    return detect_json_injection(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = '''
import json
import simplejson
from flask import request, jsonify

app = Flask(__name__)

# 易受JSON注入攻击的示例
@app.route('/vulnerable_json')
def vulnerable_json():
    # 1. 直接序列化用户输入 - 中危
    user_data = request.json
    json_output = json.dumps(user_data)  # 可能包含恶意JavaScript

    # 2. 字符串拼接构建JSON - 高危
    user_input = request.args.get('input', '')
    malicious_json = '{"data": "' + user_input + '"}'  # JSON注入
    result = json.dumps(malicious_json)

    # 3. 格式化字符串构建JSON - 高危
    username = request.args.get('username', '')
    user_json = '{"user": "%s"}' % username  # 格式化注入
    json.dumps(user_json)

    # 4. eval执行JSON - 严重
    json_string = request.args.get('json', '{}')
    data = eval(json_string)  # 严重漏洞，可能执行任意代码

    # 5. 直接返回用户JSON
    return jsonify(request.json)  # 可能包含恶意数据

# 具体的JSON注入攻击示例
@app.route('/xss_via_json')
def xss_via_json():
    # 攻击者可以注入JavaScript代码
    malicious_data = {
        "message": "</script><script>alert('XSS')</script>",
        "html": "<img src=x onerror=alert(1)>",
        "url": "javascript:alert('XSS')"
    }

    # 直接返回可能在前端执行恶意代码
    return json.dumps(malicious_data)

@app.route('/json_breaking')
def json_breaking():
    # JSON结构破坏攻击
    user_input = request.args.get('input', '')

    # 攻击者输入: {"key": "value"}} {"injected": "data"}
    malicious_json = '{"data": "' + user_input + '"}'
    # 结果: {"data": "value"}} {"injected": "data"}

    return json.dumps(malicious_json)

@app.route('/object_injection')
def object_injection():
    # 对象注入攻击
    user_class = request.args.get('class', '')

    # 攻击者输入: {"__class__": "os.system", "__init__": {"__globals__": ...}}
    user_data = json.loads(request.data)
    # 可能通过特殊属性访问系统资源

    return "Processed"

# 相对安全的示例
@app.route('/secure_json')
def secure_json():
    # 1. 安全的JSON序列化
    user_data = request.json

    # 验证和清理数据
    if not is_safe_data(user_data):
        return json.dumps({"error": "Invalid data"})

    # 使用安全的序列化参数
    safe_output = json.dumps(user_data, ensure_ascii=True, separators=(',', ':'))

    # 2. 安全的字符串处理
    user_input = request.args.get('input', '')

    # 清理用户输入
    safe_input = html.escape(user_input)
    safe_json = json.dumps({"data": safe_input})

    # 3. 使用安全的JSON解析
    json_string = request.args.get('json', '{}')
    try:
        data = json.loads(json_string)  # 使用json.loads而不是eval
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON"})

    return safe_output

@app.route('/content_type_safe')
def content_type_safe():
    # 设置正确的内容类型
    response = jsonify({"data": "safe"})
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response

# 辅助函数
def is_safe_data(data):
    """检查数据是否安全"""
    if not isinstance(data, (dict, list, str, int, float, bool, type(None))):
        return False

    # 递归检查嵌套数据
    if isinstance(data, dict):
        for key, value in data.items():
            if not is_safe_data(value):
                return False
    elif isinstance(data, list):
        for item in data:
            if not is_safe_data(item):
                return False
    elif isinstance(data, str):
        # 检查字符串是否包含危险内容
        if may_contain_javascript(data):
            return False

    return True

def safe_json_serialize(data):
    """安全的JSON序列化函数"""
    # 深度清理数据
    cleaned_data = deep_clean_data(data)

    # 使用安全参数序列化
    return json.dumps(
        cleaned_data,
        ensure_ascii=True,
        separators=(',', ':'),
        default=str  # 处理无法序列化的对象
    )

def deep_clean_data(data):
    """深度清理数据"""
    if isinstance(data, dict):
        return {k: deep_clean_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [deep_clean_data(item) for item in data]
    elif isinstance(data, str):
        # 移除危险字符和标签
        cleaned = re.sub(r'[<>]', '', data)
        cleaned = re.sub(r'javascript:', '', cleaned, flags=re.IGNORECASE)
        return cleaned
    else:
        return data

if __name__ == '__main__':
    app.run(debug=True)
'''

    print("=" * 70)
    print("Python JSON注入漏洞检测")
    print("=" * 70)

    results = analyze_python_json_injection(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个JSON注入漏洞:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   风险类型: {vuln['risk_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print("-" * 50)
    else:
        print("未检测到JSON注入漏洞")