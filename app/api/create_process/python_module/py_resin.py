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

# 定义资源注入漏洞模式
RESOURCE_INJECTION_VULNERABILITIES = {
    'python': [
        # 检测URL资源操作 - 直接用户输入
        {
            'query': '''
                (call
                    function: (identifier) @url_func
                    arguments: (argument_list 
                        (_) @url_param
                    )
                ) @call
            ''',
            'func_pattern': r'^(urlopen|urlretrieve|Request|build_opener|install_opener)$',
            'message': 'URL资源操作'
        },
        # 检测requests库调用
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @requests_obj
                        attribute: (identifier) @http_method
                    )
                    arguments: (argument_list 
                        (_) @url_param
                    )
                ) @call
            ''',
            'obj_pattern': r'^(requests|session|req)$',
            'method_pattern': r'^(get|post|put|delete|head|options|request)$',
            'message': 'HTTP请求操作'
        },
        # 检测网络连接操作
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @socket_obj
                        attribute: (identifier) @connect_method
                    )
                    arguments: (argument_list 
                        (_) @host_param
                        (_) @port_param
                    )
                ) @call
            ''',
            'obj_pattern': r'^(socket)$',
            'method_pattern': r'^(connect|bind|listen)$',
            'message': '网络连接操作'
        },
        # 检测数据库连接操作
        {
            'query': '''
                (call
                    function: (identifier) @db_connect_func
                    arguments: (argument_list 
                        (_)* @connection_params
                    )
                ) @call
            ''',
            'func_pattern': r'^(connect|Connection|create_connection|create_engine)$',
            'message': '数据库连接操作'
        },
        # 检测文件流操作
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @stream_obj
                        attribute: (identifier) @stream_method
                    )
                    arguments: (argument_list 
                        (_) @stream_param
                    )
                ) @call
            ''',
            'method_pattern': r'^(open|read|write|load|dump|parse)$',
            'message': '流资源操作'
        },
        # 检测外部命令执行（可能涉及资源）
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @module_obj
                        attribute: (identifier) @exec_method
                    )
                    arguments: (argument_list 
                        (_) @command_param
                    )
                ) @call
            ''',
            'module_pattern': r'^(subprocess|os)$',
            'method_pattern': r'^(run|call|Popen|system|popen|exec|execv)$',
            'message': '外部命令执行'
        },
        # 检测配置资源加载
        {
            'query': '''
                (call
                    function: (identifier) @config_func
                    arguments: (argument_list 
                        (_) @config_param
                    )
                ) @call
            ''',
            'func_pattern': r'^(load|loads|yaml\.safe_load|yaml\.load|json\.load|json\.loads|pickle\.load|pickle\.loads)$',
            'message': '配置资源加载'
        },
        # 检测模板渲染操作
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @template_obj
                        attribute: (identifier) @render_method
                    )
                    arguments: (argument_list 
                        (_)* @template_params
                    )
                ) @call
            ''',
            'method_pattern': r'^(render|render_template|render_string)$',
            'message': '模板渲染操作'
        },
        # 检测字符串拼接的资源操作
        {
            'query': '''
                (call
                    function: (identifier) @resource_func
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @left_part
                            operator: "+"
                            right: (_) @right_part
                        ) @concat_expr
                    )
                ) @call
            ''',
            'func_pattern': r'^(urlopen|get|post|put|connect|load|render)$',
            'message': '字符串拼接的资源操作'
        }
    ]
}

# 用户输入源模式（资源注入相关）
RESOURCE_USER_INPUT_SOURCES = {
    'query': '''
        [
            (call
                function: (identifier) @func_name
                arguments: (argument_list) @args
            )
            (call
                function: (attribute
                    object: (_) @obj
                    attribute: (identifier) @attr
                )
                arguments: (argument_list) @args
            )
        ] @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(input|raw_input)$',
            'message': '标准输入'
        },
        {
            'obj_pattern': r'^(flask|django|bottle|tornado)\.request$',
            'attr_pattern': r'^(args|form|values|data|json|files|get|post|cookies|headers)$',
            'message': 'Web请求参数'
        },
        {
            'obj_pattern': r'^request$',
            'attr_pattern': r'^(args|form|values|data|json|files|get|post|cookies|headers)$',
            'message': '请求对象参数'
        },
        {
            'obj_pattern': r'^(sys)$',
            'attr_pattern': r'^(argv)$',
            'message': '命令行参数'
        },
        {
            'obj_pattern': r'^os\.environ$',
            'attr_pattern': r'^(get|__getitem__)$',
            'message': '环境变量'
        },
        {
            'obj_pattern': r'^(config|settings|app\.config)$',
            'attr_pattern': r'^(get)$',
            'message': '配置参数'
        }
    ]
}

# 资源构建模式
RESOURCE_BUILDING_PATTERNS = {
    'query': '''
        [
            (assignment
                left: (identifier) @var_name
                right: (binary_expression
                    left: (_) @left_expr
                    operator: "+"
                    right: (_) @right_expr
                ) @concat_expr
            )
            (assignment
                left: (identifier) @var_name
                right: (interpolation) @fstring_expr
            )
            (assignment
                left: (identifier) @var_name
                right: (call
                    function: (attribute
                        object: (string) @base_string
                        attribute: (identifier) @format_method
                    )
                    arguments: (argument_list (_)* @format_args)
                ) @format_call
            )
        ] @assignment
    ''',
    'patterns': [
        {
            'var_pattern': r'^(url|endpoint|api_url|service_url|db_url|connection_string|dsn|host|port|command|query|template|config_file)$',
            'message': '资源URL构建'
        },
        {
            'base_string_pattern': r'^(https?://|ftp://|file://|tcp://|postgresql://|mysql://|sqlite://)',
            'message': '资源协议字符串构建'
        }
    ]
}

# 危险资源模式
DANGEROUS_RESOURCE_PATTERNS = {
    'dangerous_protocols': [
        'file://',
        'ftp://',
        'gopher://',
        'jar://',
        'mailto:',
        'telnet://',
    ],
    'internal_resources': [
        'localhost',
        '127.0.0.1',
        '::1',
        '0.0.0.0',
        'internal.',
        '.internal',
        '.local',
        '169.254.',
        '10.',
        '172.16.',
        '172.31.',
        '192.168.',
    ],
    'sensitive_endpoints': [
        '/etc/passwd',
        '/etc/shadow',
        '/proc/',
        '/sys/',
        'file:///etc/',
        'file:///c:/windows/',
        'admin',
        'debug',
        'console',
        'phpmyadmin',
    ]
}

def analyze_resource_injection(code, language='python'):
    """
    检测Python代码中资源注入漏洞

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
    resource_operations = []  # 存储资源操作
    user_input_sources = []  # 存储用户输入源
    resource_buildings = []  # 存储资源构建操作

    # 第一步：收集所有资源操作
    for query_info in RESOURCE_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['url_func', 'requests_obj', 'http_method', 'socket_obj', 
                          'connect_method', 'db_connect_func', 'stream_obj', 
                          'stream_method', 'module_obj', 'exec_method', 'config_func',
                          'template_obj', 'render_method', 'resource_func']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['url_param', 'host_param', 'port_param', 'command_param', 
                           'config_param', 'stream_param', 'left_part', 'right_part']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['connection_params', 'template_params']:
                    current_capture[tag] = node.text.decode('utf8')

                elif tag == 'call' and current_capture:
                    # 检查函数名是否匹配模式
                    func_pattern = query_info.get('func_pattern', '')
                    obj_pattern = query_info.get('obj_pattern', '')
                    method_pattern = query_info.get('method_pattern', '')
                    module_pattern = query_info.get('module_pattern', '')

                    func_match = True
                    obj_match = True
                    method_match = True
                    module_match = True

                    if func_pattern and 'url_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['url_func'], re.IGNORECASE)
                    elif func_pattern and 'db_connect_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['db_connect_func'], re.IGNORECASE)
                    elif func_pattern and 'config_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['config_func'], re.IGNORECASE)
                    elif func_pattern and 'resource_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['resource_func'], re.IGNORECASE)

                    if obj_pattern and 'requests_obj' in current_capture:
                        obj_match = re.match(obj_pattern, current_capture['requests_obj'], re.IGNORECASE)
                    elif obj_pattern and 'socket_obj' in current_capture:
                        obj_match = re.match(obj_pattern, current_capture['socket_obj'], re.IGNORECASE)
                    elif obj_pattern and 'stream_obj' in current_capture:
                        obj_match = re.match(obj_pattern, current_capture['stream_obj'], re.IGNORECASE)

                    if method_pattern and 'http_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['http_method'], re.IGNORECASE)
                    elif method_pattern and 'connect_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['connect_method'], re.IGNORECASE)
                    elif method_pattern and 'stream_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['stream_method'], re.IGNORECASE)
                    elif method_pattern and 'exec_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['exec_method'], re.IGNORECASE)
                    elif method_pattern and 'render_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['render_method'], re.IGNORECASE)

                    if module_pattern and 'module_obj' in current_capture:
                        module_match = re.match(module_pattern, current_capture['module_obj'], re.IGNORECASE)

                    if func_match and obj_match and method_match and module_match:
                        code_snippet = node.text.decode('utf8')

                        resource_operations.append({
                            'type': 'resource_operation',
                            'line': current_capture['line'],
                            'function': current_capture.get('url_func', '') or 
                                       current_capture.get('http_method', '') or
                                       current_capture.get('connect_method', '') or
                                       current_capture.get('db_connect_func', '') or
                                       current_capture.get('stream_method', '') or
                                       current_capture.get('exec_method', '') or
                                       current_capture.get('config_func', '') or
                                       current_capture.get('render_method', '') or
                                       current_capture.get('resource_func', ''),
                            'object': current_capture.get('requests_obj', '') or 
                                     current_capture.get('socket_obj', '') or
                                     current_capture.get('stream_obj', '') or
                                     current_capture.get('module_obj', '') or
                                     current_capture.get('template_obj', ''),
                            'resource_param': current_capture.get('url_param', '') or 
                                            current_capture.get('host_param', '') or
                                            current_capture.get('command_param', '') or
                                            current_capture.get('config_param', '') or
                                            current_capture.get('stream_param', '') or
                                            current_capture.get('left_part', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'vulnerability_type': query_info.get('message', '资源注入风险')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"资源注入查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(RESOURCE_USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'obj', 'attr']:
                name = node.text.decode('utf8')
                current_capture[tag] = name
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'call' and current_capture:
                # 检查是否匹配用户输入模式
                for pattern_info in RESOURCE_USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    obj_pattern = pattern_info.get('obj_pattern', '')
                    attr_pattern = pattern_info.get('attr_pattern', '')

                    match = False
                    if func_pattern and 'func_name' in current_capture:
                        if re.match(func_pattern, current_capture['func_name'], re.IGNORECASE):
                            match = True
                    elif obj_pattern and attr_pattern and 'obj' in current_capture and 'attr' in current_capture:
                        if (re.match(obj_pattern, current_capture['obj'], re.IGNORECASE) and
                                re.match(attr_pattern, current_capture['attr'], re.IGNORECASE)):
                            match = True

                    if match:
                        code_snippet = node.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': current_capture['line'],
                            'function': current_capture.get('func_name', ''),
                            'object': current_capture.get('obj', ''),
                            'attribute': current_capture.get('attr', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：收集资源构建操作
    try:
        query = LANGUAGES[language].query(RESOURCE_BUILDING_PATTERNS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['var_name', 'format_method']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['base_string', 'left_expr', 'right_expr', 'fstring_expr']:
                current_capture[tag] = node.text.decode('utf8')

            elif tag == 'assignment' and current_capture:
                # 检查是否匹配资源构建模式
                for pattern_info in RESOURCE_BUILDING_PATTERNS['patterns']:
                    var_pattern = pattern_info.get('var_pattern', '')
                    base_string_pattern = pattern_info.get('base_string_pattern', '')

                    var_match = False
                    base_match = True  # 如果没有base_string_pattern，默认为True

                    if var_pattern and 'var_name' in current_capture:
                        var_match = re.match(var_pattern, current_capture['var_name'], re.IGNORECASE)

                    if base_string_pattern and 'base_string' in current_capture:
                        base_match = re.match(base_string_pattern, current_capture['base_string'], re.IGNORECASE)

                    if var_match and base_match:
                        code_snippet = node.text.decode('utf8')
                        resource_buildings.append({
                            'type': 'resource_building',
                            'line': current_capture['line'],
                            'variable': current_capture.get('var_name', ''),
                            'base_string': current_capture.get('base_string', ''),
                            'expression': current_capture.get('left_expr', '') + ' + ' + current_capture.get('right_expr', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"资源构建查询错误: {e}")

    # 第四步：分析资源注入漏洞
    for resource_op in resource_operations:
        vulnerability_details = analyze_resource_operation(resource_op, user_input_sources, resource_buildings)
        if vulnerability_details:
            vulnerabilities.extend(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_resource_operation(resource_op, user_input_sources, resource_buildings):
    """
    分析单个资源操作的安全问题
    """
    vulnerabilities = []
    code_snippet = resource_op['code_snippet']
    line = resource_op['line']
    function_name = resource_op['function']
    resource_param = resource_op['resource_param']

    # 检查直接用户输入
    if is_direct_user_input(resource_op, user_input_sources):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '资源注入',
            'severity': '高危',
            'message': f"{function_name} 函数直接使用用户输入作为资源参数"
        })

    # 检查字符串拼接
    elif is_string_concatenation(resource_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '资源注入',
            'severity': '高危',
            'message': f"{function_name} 函数使用字符串拼接构建资源参数"
        })

    # 检查危险协议
    elif contains_dangerous_protocols(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '资源注入',
            'severity': '高危',
            'message': f"{function_name} 函数可能使用危险协议访问资源"
        })

    # 检查内部资源访问
    elif accesses_internal_resources(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '资源注入',
            'severity': '中危',
            'message': f"{function_name} 函数可能访问内部系统资源"
        })

    # 检查敏感端点
    elif accesses_sensitive_endpoints(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '资源注入',
            'severity': '严重',
            'message': f"{function_name} 函数可能访问敏感系统端点"
        })

    # 检查资源验证缺失
    elif not has_resource_validation(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '资源注入',
            'severity': '中危',
            'message': f"{function_name} 函数缺少资源验证逻辑"
        })

    return vulnerabilities


def is_direct_user_input(resource_op, user_input_sources):
    """
    检查资源参数是否直接来自用户输入
    """
    resource_param = resource_op['resource_param']
    
    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'request', 'args', 'form', 'get', 
                      'post', 'url', 'endpoint', 'host', 'port', 'command', 'query']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', resource_param, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == resource_op['node'] or is_child_node(resource_op['node'], source['node']):
            return True

    return False


def is_string_concatenation(resource_op):
    """
    检查是否使用字符串拼接构建资源参数
    """
    code_snippet = resource_op['code_snippet']
    return '+' in code_snippet and any(keyword in code_snippet for keyword in 
                                     ['urlopen', 'get', 'post', 'connect', 'load', 'render', 'system'])


def contains_dangerous_protocols(code_snippet):
    """
    检查是否包含危险协议
    """
    for protocol in DANGEROUS_RESOURCE_PATTERNS['dangerous_protocols']:
        if protocol in code_snippet:
            return True
    return False


def accesses_internal_resources(code_snippet):
    """
    检查是否可能访问内部资源
    """
    for internal_resource in DANGEROUS_RESOURCE_PATTERNS['internal_resources']:
        if internal_resource in code_snippet:
            return True
    return False


def accesses_sensitive_endpoints(code_snippet):
    """
    检查是否可能访问敏感端点
    """
    for endpoint in DANGEROUS_RESOURCE_PATTERNS['sensitive_endpoints']:
        if endpoint in code_snippet:
            return True
    return False


def has_resource_validation(code_snippet):
    """
    检查代码片段是否包含资源验证逻辑
    """
    validation_patterns = [
        r'whitelist',
        r'allowed_hosts',
        r'allowed_domains',
        r'validate_url',
        r'is_safe_url',
        r'urlparse',
        r'startswith\([\'"]https?://[\'"]\)',
        r'allowed_protocols',
        r'sanitize.*url',
        r'check.*host',
        r'verify.*domain'
    ]
    
    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in validation_patterns)


def is_child_node(child, parent):
    """
    检查一个节点是否是另一个节点的子节点
    """
    node = child
    while node:
        if node == parent:
            return True
        node = node.parent
    return False


def analyze_resource_injection_main(code_string):
    """
    主函数：分析Python代码字符串中的资源注入漏洞
    """
    return analyze_resource_injection(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import urllib.request
import requests
import socket
import subprocess
import yaml
import json
import pickle
from flask import request, render_template_string
import sqlite3
import os

# 不安全的资源注入示例
def insecure_resource_examples():
    # URL资源注入 - 高危
    user_url = request.args.get('url')
    response = urllib.request.urlopen(user_url)  # 高危: URL资源注入
    
    # requests库注入 - 高危
    api_endpoint = request.form.get('endpoint')
    result = requests.get(api_endpoint)  # 高危
    
    # 字符串拼接URL - 高危
    base_api = "https://api.example.com/v1/"
    user_path = request.json.get('path')
    full_url = base_api + user_path  # 高危
    requests.post(full_url, data={})
    
    # 网络连接注入 - 高危
    user_host = request.args.get('host')
    user_port = int(request.args.get('port', 80))
    sock = socket.socket()
    sock.connect((user_host, user_port))  # 高危
    
    # 数据库连接注入 - 高危
    db_host = request.form.get('db_host')
    conn = sqlite3.connect(db_host)  # 高危
    
    # 命令执行中的资源注入 - 严重
    user_command = request.args.get('command')
    subprocess.run(user_command, shell=True)  # 严重: 命令注入
    
    # 不安全的反序列化 - 高危
    user_data = request.files['data'].read()
    obj = pickle.loads(user_data)  # 高危: 反序列化注入
    
    # 模板注入 - 高危
    user_template = request.args.get('template')
    render_template_string(user_template)  # 高危: SSTI

# 相对安全的资源操作示例
def safe_resource_examples():
    # 硬编码资源 - 安全
    response = requests.get('https://api.example.com/data')  # 安全
    
    # 经过验证的URL - 安全
    user_url = request.args.get('url')
    if user_url and user_url.startswith('https://trusted.com/'):
        urllib.request.urlopen(user_url)  # 安全: URL验证
    
    # 白名单验证 - 安全
    allowed_endpoints = ['/api/v1/users', '/api/v1/products']
    endpoint = request.args.get('endpoint')
    if endpoint in allowed_endpoints:
        requests.get(f'https://api.example.com{endpoint}')  # 安全
    
    # 使用urlparse验证 - 安全
    from urllib.parse import urlparse
    user_url = request.form.get('url')
    parsed = urlparse(user_url)
    if parsed.netloc in ['example.com', 'trusted.org']:
        requests.get(user_url)  # 安全
    
    # 安全的数据库连接 - 安全
    conn = sqlite3.connect('/var/lib/app.db')  # 安全: 硬编码路径
    
    # 安全的反序列化 - 安全
    user_data = request.files['data'].read()
    data = json.loads(user_data)  # 相对安全: JSON反序列化
    
    # 安全的模板渲染 - 安全
    template = '<h1>Hello {{ name }}</h1>'
    name = request.args.get('name', 'World')
    render_template_string(template, name=name)  # 安全: 模板硬编码

# 配置加载示例
def config_loading_examples():
    # 不安全的配置加载 - 高危
    config_file = request.args.get('config')
    with open(config_file, 'r') as f:
        config = yaml.load(f)  # 高危: YAML注入
    
    # 相对安全的配置加载
    config_file = 'app_config.yaml'
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)  # 安全: 使用safe_load
    
    # 环境变量配置 - 相对安全
    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith('postgresql://'):
        # 连接数据库  # 相对安全
        pass

# 混合示例
def mixed_examples():
    # 部分验证
    user_host = request.args.get('host')
    if user_host:  # 验证不充分
        socket.gethostbyname(user_host)  # 高危
    
    # 使用内置安全函数
    from urllib.parse import urlparse
    user_url = request.form.get('url')
    parsed = urlparse(user_url)
    if parsed.scheme in ['http', 'https']:  # 协议验证
        requests.get(user_url)  # 相对安全
    
    # 直接内部资源访问
    internal_url = request.args.get('internal_url')
    if internal_url:
        # 可能访问内部服务
        requests.get(f"http://internal-service/{internal_url}")  # 中危

# 资源验证辅助函数
def is_safe_url(url):
    \"\"\"检查URL是否安全\"\"\"
    from urllib.parse import urlparse
    
    if not url:
        return False
        
    parsed = urlparse(url)
    
    # 只允许HTTP/HTTPS协议
    if parsed.scheme not in ['http', 'https']:
        return False
        
    # 白名单域名检查
    allowed_domains = ['example.com', 'trusted.org', 'api.safe.com']
    return parsed.hostname in allowed_domains

def validate_hostname(hostname):
    \"\"\"验证主机名是否安全\"\"\"
    # 不允许内部IP地址
    internal_patterns = [
        r'^localhost$',
        r'^127\.\d+\.\d+\.\d+$',
        r'^10\.\d+\.\d+\.\d+$',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$',
        r'^192\.168\.\d+\.\d+$'
    ]
    
    for pattern in internal_patterns:
        if re.match(pattern, hostname):
            return False
            
    return True

if __name__ == "__main__":
    insecure_resource_examples()
    safe_resource_examples()
    config_loading_examples()
    mixed_examples()
"""

    print("=" * 60)
    print("Python 资源注入漏洞检测")
    print("=" * 60)

    results = analyze_resource_injection_main(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个资源注入漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到资源注入漏洞")