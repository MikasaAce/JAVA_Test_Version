import os
import re
import sys
from tree_sitter import Language, Parser
from urllib.parse import urlparse

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义SSRF漏洞模式
SSRF_VULNERABILITIES = {
    'python': [
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
        # 检测urllib请求
        {
            'query': '''
                (call
                    function: (identifier) @url_func
                    arguments: (argument_list 
                        (_) @url_param
                    )
                ) @call
            ''',
            'func_pattern': r'^(urlopen|urlretrieve|Request)$',
            'message': 'urllib请求操作'
        },
        # 检测httpx库调用
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @httpx_obj
                        attribute: (identifier) @http_method
                    )
                    arguments: (argument_list 
                        (_) @url_param
                    )
                ) @call
            ''',
            'obj_pattern': r'^(httpx|client)$',
            'method_pattern': r'^(get|post|put|delete|head|options|request)$',
            'message': 'httpx请求操作'
        },
        # 检测aiohttp库调用
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @aiohttp_obj
                        attribute: (identifier) @http_method
                    )
                    arguments: (argument_list 
                        (_) @url_param
                    )
                ) @call
            ''',
            'obj_pattern': r'^(aiohttp|session)$',
            'method_pattern': r'^(get|post|put|delete|head|options)$',
            'message': 'aiohttp请求操作'
        },
        # 检测字符串拼接的URL
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @http_obj
                        attribute: (identifier) @http_method
                    )
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @url_left
                            operator: "+"
                            right: (_) @url_right
                        ) @concat_url
                    )
                ) @call
            ''',
            'method_pattern': r'^(get|post|put|delete|urlopen|request)$',
            'message': '字符串拼接的URL请求'
        },
        # 检测format格式化的URL
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @http_obj
                        attribute: (identifier) @http_method
                    )
                    arguments: (argument_list 
                        (call
                            function: (attribute
                                object: (string) @base_url
                                attribute: (identifier) @format_method
                            )
                            arguments: (argument_list (_)* @format_args)
                        ) @format_call
                    )
                ) @call
            ''',
            'method_pattern': r'^(get|post|put|delete|urlopen|request)$',
            'message': 'format格式化的URL请求'
        },
        # 检测f-string URL
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @http_obj
                        attribute: (identifier) @http_method
                    )
                    arguments: (argument_list 
                        (interpolation) @fstring_url
                    )
                ) @call
            ''',
            'method_pattern': r'^(get|post|put|delete|urlopen|request)$',
            'message': 'f-string URL请求'
        },
        # 检测socket连接
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
            'message': 'socket连接操作'
        },
        # 检测文件协议请求
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @http_obj
                        attribute: (identifier) @http_method
                    )
                    arguments: (argument_list 
                        (string) @file_url
                    )
                ) @call
            ''',
            'method_pattern': r'^(get|post|put|delete|urlopen|request)$',
            'url_pattern': r'^file://',
            'message': '文件协议请求'
        }
    ]
}

# 用户输入源模式（SSRF相关）
SSRF_USER_INPUT_SOURCES = {
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

# URL构建模式
URL_BUILDING_PATTERNS = {
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
            'var_pattern': r'^(url|endpoint|api_url|service_url|webhook|callback|redirect|target|destination)$',
            'message': 'URL构建'
        },
        {
            'base_string_pattern': r'^(https?://|ftp://|file://|gopher://|dict://)',
            'message': '协议字符串构建'
        }
    ]
}

# 危险URL模式
DANGEROUS_URL_PATTERNS = {
    'dangerous_protocols': [
        'file://',
        'ftp://',
        'gopher://',
        'dict://',
        'sftp://',
        'tftp://',
        'ldap://',
        'ldaps://',
        'jar://',
    ],
    'internal_networks': [
        'localhost',
        '127.0.0.1',
        '::1',
        '0.0.0.0',
        'internal.',
        '.internal',
        '.local',
        '.localdomain',
        '169.254.',
        '10.',
        '172.16.',
        '172.17.',
        '172.18.',
        '172.19.',
        '172.20.',
        '172.21.',
        '172.22.',
        '172.23.',
        '172.24.',
        '172.25.',
        '172.26.',
        '172.27.',
        '172.28.',
        '172.29.',
        '172.30.',
        '172.31.',
        '192.168.',
        'fc00::/7',
        'fe80::/10'
    ],
    'metadata_services': [
        '169.254.169.254',  # AWS metadata
        '100.100.100.200',  # Alibaba Cloud metadata
        'metadata.google.internal',  # GCP metadata
        '169.254.169.250',  # Azure metadata
        'metadata.tencentyun.com',  # Tencent Cloud metadata
    ],
    'admin_interfaces': [
        ':22',    # SSH
        ':23',    # Telnet
        ':80',    # HTTP
        ':443',   # HTTPS
        ':8000',  # Common admin port
        ':8080',  # Common admin port
        ':8888',  # Common admin port
        ':9000',  # Common admin port
        ':2375',  # Docker
        ':2376',  # Docker
        ':3306',  # MySQL
        ':5432',  # PostgreSQL
        ':6379',  # Redis
        ':27017', # MongoDB
    ]
}

def analyze_ssrf(code, language='python'):
    """
    检测Python代码中SSRF漏洞

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
    http_operations = []  # 存储HTTP操作
    user_input_sources = []  # 存储用户输入源
    url_buildings = []  # 存储URL构建操作

    # 第一步：收集所有HTTP操作
    for query_info in SSRF_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['http_method', 'requests_obj', 'url_func', 'httpx_obj', 
                          'aiohttp_obj', 'socket_obj', 'connect_method']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['url_param', 'url_left', 'url_right', 'file_url', 
                           'host_param', 'port_param', 'base_url', 'fstring_url']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['format_method', 'format_call']:
                    current_capture[tag] = node.text.decode('utf8')

                elif tag == 'call' and current_capture:
                    # 检查方法名是否匹配模式
                    method_pattern = query_info.get('method_pattern', '')
                    obj_pattern = query_info.get('obj_pattern', '')
                    func_pattern = query_info.get('func_pattern', '')
                    url_pattern = query_info.get('url_pattern', '')

                    method_match = True
                    obj_match = True
                    func_match = True
                    url_match = True

                    if method_pattern and 'http_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['http_method'], re.IGNORECASE)
                    elif method_pattern and 'connect_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['connect_method'], re.IGNORECASE)

                    if obj_pattern and 'requests_obj' in current_capture:
                        obj_match = re.match(obj_pattern, current_capture['requests_obj'], re.IGNORECASE)
                    elif obj_pattern and 'httpx_obj' in current_capture:
                        obj_match = re.match(obj_pattern, current_capture['httpx_obj'], re.IGNORECASE)
                    elif obj_pattern and 'aiohttp_obj' in current_capture:
                        obj_match = re.match(obj_pattern, current_capture['aiohttp_obj'], re.IGNORECASE)
                    elif obj_pattern and 'socket_obj' in current_capture:
                        obj_match = re.match(obj_pattern, current_capture['socket_obj'], re.IGNORECASE)

                    if func_pattern and 'url_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['url_func'], re.IGNORECASE)

                    if url_pattern and 'file_url' in current_capture:
                        url_match = re.search(url_pattern, current_capture['file_url'], re.IGNORECASE)

                    if method_match and obj_match and func_match and url_match:
                        code_snippet = node.text.decode('utf8')

                        http_operations.append({
                            'type': 'http_operation',
                            'line': current_capture['line'],
                            'method': current_capture.get('http_method', '') or 
                                    current_capture.get('url_func', '') or
                                    current_capture.get('connect_method', ''),
                            'object': current_capture.get('requests_obj', '') or 
                                     current_capture.get('httpx_obj', '') or
                                     current_capture.get('aiohttp_obj', '') or
                                     current_capture.get('socket_obj', ''),
                            'url_param': current_capture.get('url_param', '') or 
                                        current_capture.get('url_left', '') or
                                        current_capture.get('file_url', '') or
                                        current_capture.get('fstring_url', ''),
                            'host_param': current_capture.get('host_param', ''),
                            'port_param': current_capture.get('port_param', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'vulnerability_type': query_info.get('message', 'SSRF风险')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"SSRF查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(SSRF_USER_INPUT_SOURCES['query'])
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
                for pattern_info in SSRF_USER_INPUT_SOURCES['patterns']:
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

    # 第三步：收集URL构建操作
    try:
        query = LANGUAGES[language].query(URL_BUILDING_PATTERNS['query'])
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
                # 检查是否匹配URL构建模式
                for pattern_info in URL_BUILDING_PATTERNS['patterns']:
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
                        url_buildings.append({
                            'type': 'url_building',
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
        print(f"URL构建查询错误: {e}")

    # 第四步：分析SSRF漏洞
    for http_op in http_operations:
        vulnerability_details = analyze_http_operation(http_op, user_input_sources, url_buildings)
        if vulnerability_details:
            vulnerabilities.extend(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_http_operation(http_op, user_input_sources, url_buildings):
    """
    分析单个HTTP操作的安全问题
    """
    vulnerabilities = []
    code_snippet = http_op['code_snippet']
    line = http_op['line']
    method_name = http_op['method']
    url_param = http_op['url_param']
    host_param = http_op['host_param']

    # 检查直接用户输入
    if is_direct_user_input(http_op, user_input_sources):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSRF',
            'severity': '高危',
            'message': f"{method_name} 操作直接使用用户输入作为URL参数"
        })

    # 检查字符串拼接
    elif is_string_concatenation(http_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSRF',
            'severity': '高危',
            'message': f"{method_name} 操作使用字符串拼接构建URL"
        })

    # 检查危险协议
    elif contains_dangerous_protocols(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSRF',
            'severity': '高危',
            'message': f"{method_name} 操作可能使用危险协议访问内部资源"
        })

    # 检查内部网络访问
    elif accesses_internal_networks(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSRF',
            'severity': '高危',
            'message': f"{method_name} 操作可能访问内部网络资源"
        })

    # 检查元数据服务访问
    elif accesses_metadata_services(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSRF',
            'severity': '严重',
            'message': f"{method_name} 操作可能访问云服务元数据接口"
        })

    # 检查管理接口访问
    elif accesses_admin_interfaces(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSRF',
            'severity': '高危',
            'message': f"{method_name} 操作可能访问管理接口"
        })

    # 检查URL验证缺失
    elif not has_url_validation(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSRF',
            'severity': '中危',
            'message': f"{method_name} 操作缺少URL验证逻辑"
        })

    return vulnerabilities


def is_direct_user_input(http_op, user_input_sources):
    """
    检查URL参数是否直接来自用户输入
    """
    url_param = http_op['url_param']
    host_param = http_op['host_param']
    
    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'request', 'args', 'form', 'get', 
                      'post', 'url', 'endpoint', 'host', 'port', 'webhook', 'callback']
    
    param_text = (url_param or '') + (host_param or '')
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', param_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == http_op['node'] or is_child_node(http_op['node'], source['node']):
            return True

    return False


def is_string_concatenation(http_op):
    """
    检查是否使用字符串拼接构建URL
    """
    code_snippet = http_op['code_snippet']
    return '+' in code_snippet and any(keyword in code_snippet for keyword in 
                                     ['get', 'post', 'urlopen', 'request', 'connect'])


def contains_dangerous_protocols(code_snippet):
    """
    检查是否包含危险协议
    """
    for protocol in DANGEROUS_URL_PATTERNS['dangerous_protocols']:
        if protocol in code_snippet:
            return True
    return False


def accesses_internal_networks(code_snippet):
    """
    检查是否可能访问内部网络
    """
    for internal_net in DANGEROUS_URL_PATTERNS['internal_networks']:
        if internal_net in code_snippet:
            return True
    return False


def accesses_metadata_services(code_snippet):
    """
    检查是否可能访问元数据服务
    """
    for metadata_service in DANGEROUS_URL_PATTERNS['metadata_services']:
        if metadata_service in code_snippet:
            return True
    return False


def accesses_admin_interfaces(code_snippet):
    """
    检查是否可能访问管理接口
    """
    for admin_interface in DANGEROUS_URL_PATTERNS['admin_interfaces']:
        if admin_interface in code_snippet:
            return True
    return False


def has_url_validation(code_snippet):
    """
    检查代码片段是否包含URL验证逻辑
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
        r'verify.*domain',
        r'block_internal_ips',
        r'allow_redirects=False'
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


def analyze_ssrf_main(code_string):
    """
    主函数：分析Python代码字符串中的SSRF漏洞
    """
    return analyze_ssrf(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import requests
import urllib.request
import httpx
import aiohttp
import socket
from flask import request
import os

# 不安全的SSRF示例
def insecure_ssrf_examples():
    # 直接用户输入URL - 高危
    user_url = request.args.get('url')
    response = requests.get(user_url)  # 高危: SSRF
    
    # 字符串拼接URL - 高危
    base_api = "http://api.example.com/v1/"
    user_endpoint = request.form.get('endpoint')
    full_url = base_api + user_endpoint  # 高危
    requests.post(full_url, data={})
    
    # format格式化URL - 高危
    service_name = request.json.get('service')
    url = "http://{}.internal.example.com/data".format(service_name)  # 高危
    urllib.request.urlopen(url)
    
    # f-string URL - 高危
    instance_id = request.args.get('instance')
    metadata_url = f"http://169.254.169.254/latest/meta-data/{instance_id}"  # 严重
    requests.get(metadata_url)
    
    # 危险协议访问 - 高危
    file_path = request.form.get('file')
    file_url = f"file://{file_path}"  # 高危
    urllib.request.urlopen(file_url)
    
    # socket连接内部服务 - 高危
    internal_host = request.args.get('host', 'localhost')
    internal_port = int(request.args.get('port', 22))
    sock = socket.socket()
    sock.connect((internal_host, internal_port))  # 高危
    
    # httpx库SSRF - 高危
    webhook_url = request.json.get('webhook')
    async with httpx.AsyncClient() as client:
        response = await client.post(webhook_url)  # 高危
    
    # aiohttp库SSRF - 高危
    callback_url = request.args.get('callback')
    async with aiohttp.ClientSession() as session:
        async with session.get(callback_url) as response:  # 高危
            pass

# 相对安全的HTTP操作示例
def safe_http_examples():
    # 硬编码URL - 安全
    response = requests.get('https://api.example.com/data')  # 安全
    
    # 经过验证的URL - 安全
    user_url = request.args.get('url')
    if user_url and is_safe_url(user_url):
        requests.get(user_url)  # 安全: URL验证
    
    # 白名单验证 - 安全
    allowed_domains = ['api.example.com', 'cdn.example.org']
    user_url = request.form.get('url')
    if is_url_in_whitelist(user_url, allowed_domains):
        requests.get(user_url)  # 安全
    
    # 使用urlparse验证 - 安全
    from urllib.parse import urlparse
    user_url = request.form.get('url')
    parsed = urlparse(user_url)
    if parsed.netloc in ['example.com', 'trusted.org']:
        requests.get(user_url)  # 安全
    
    # 禁用重定向 - 相对安全
    user_url = request.args.get('url')
    requests.get(user_url, allow_redirects=False)  # 相对安全
    
    # 限制协议 - 安全
    if user_url.startswith('https://'):
        requests.get(user_url)  # 相对安全

# 云服务相关示例
def cloud_service_examples():
    # 不安全的元数据访问 - 严重
    metadata_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    requests.get(metadata_url)  # 严重: 云元数据泄露
    
    # AWS元数据访问 - 严重
    role_name = request.args.get('role')
    aws_metadata = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
    urllib.request.urlopen(aws_metadata)  # 严重
    
    # GCP元数据访问 - 严重
    gcp_metadata = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    requests.get(gcp_metadata, headers={'Metadata-Flavor': 'Google'})  # 严重

# 混合示例
def mixed_examples():
    # 部分验证
    user_url = request.args.get('url')
    if user_url:  # 验证不充分
        requests.get(user_url)  # 高危
    
    # 使用内置安全函数
    from urllib.parse import urlparse
    user_url = request.form.get('url')
    parsed = urlparse(user_url)
    if parsed.scheme in ['http', 'https']:  # 协议验证
        requests.get(user_url)  # 相对安全
    
    # 直接内部服务访问
    internal_service = request.args.get('service')
    if internal_service:
        # 可能访问内部服务
        requests.get(f"http://internal-{internal_service}.corp/api")  # 高危

# URL验证辅助函数
def is_safe_url(url):
    \"\"\"检查URL是否安全\"\"\"
    from urllib.parse import urlparse
    
    if not url:
        return False
        
    parsed = urlparse(url)
    
    # 只允许HTTP/HTTPS协议
    if parsed.scheme not in ['http', 'https']:
        return False
        
    # 阻止内部IP地址
    internal_ips = ['127.0.0.1', 'localhost', '::1', '0.0.0.0']
    if parsed.hostname in internal_ips:
        return False
        
    # 阻止私有网络
    if parsed.hostname and is_private_ip(parsed.hostname):
        return False
        
    # 白名单域名检查
    allowed_domains = ['example.com', 'api.example.com', 'cdn.example.org']
    return parsed.hostname in allowed_domains

def is_private_ip(ip):
    \"\"\"检查IP是否为私有IP\"\"\"
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

def is_url_in_whitelist(url, whitelist):
    \"\"\"检查URL是否在白名单中\"\"\"
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        for allowed_domain in whitelist:
            if hostname == allowed_domain or hostname.endswith('.' + allowed_domain):
                return True
        return False
    except:
        return False

if __name__ == "__main__":
    insecure_ssrf_examples()
    safe_http_examples()
    cloud_service_examples()
    mixed_examples()
"""

    print("=" * 60)
    print("Python SSRF漏洞检测")
    print("=" * 60)

    results = analyze_ssrf_main(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个SSRF漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SSRF漏洞")