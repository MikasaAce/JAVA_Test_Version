import os
import re
from tree_sitter import Language, Parser

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义拒绝服务漏洞模式（改进版）
DENIAL_OF_SERVICE_VULNERABILITIES = {
    'python': [
        # 检测正则表达式拒绝服务 (ReDoS) - 改进：只关注用户输入
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @module
                        attribute: (identifier) @func_name
                    )
                    arguments: (argument_list (_) @pattern (_)? @flags)
                ) @call
            ''',
            'module_pattern': r'^(re|regex)$',
            'func_pattern': r'^(search|match|findall|finditer|sub|subn|split|compile|fullmatch)$',
            'message': '正则表达式函数调用',
            'severity': '中危',
            'risk_type': 'redos',
            'require_user_input': True
        },
        # 检测XML解析拒绝服务 - 改进：只关注用户输入
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @module
                        attribute: (identifier) @func_name
                    )
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'module_pattern': r'^(xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax|xml\.parsers\.expat)$',
            'func_pattern': r'^(parse|fromstring|parseString)$',
            'message': 'XML解析函数调用',
            'severity': '中危',
            'risk_type': 'xml_dos',
            'require_user_input': True
        },
        # 检测JSON解析拒绝服务 - 改进：只关注用户输入
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @module
                        attribute: (identifier) @func_name
                    )
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'module_pattern': r'^(json|simplejson|ujson|rapidjson)$',
            'func_pattern': r'^(loads|load)$',
            'message': 'JSON解析函数调用',
            'severity': '低危',
            'risk_type': 'json_dos',
            'require_user_input': True
        },
        # 检测大文件读取 - 改进：检查文件路径是否来自用户输入
        {
            'query': '''
                (call
                    function: (attribute
                        object: (call
                            function: (identifier) @open_func
                            arguments: (argument_list (_) @filename)
                        ) @open_call
                        attribute: (identifier) @read_method
                    )
                    arguments: (argument_list) @read_args
                ) @call
            ''',
            'open_func_pattern': r'^(open|file)$',
            'read_method_pattern': r'^(read|readlines)$',
            'message': '大文件读取操作',
            'severity': '中危',
            'risk_type': 'file_dos',
            'require_user_input': True
        },
        # 检测无限循环或高复杂度循环 - 改进：只检测明显的无限循环
        {
            'query': '''
                [
                    (while_statement
                        condition: (_) @condition
                    ) @while_loop
                ]
            ''',
            'message': 'while循环语句',
            'severity': '中危',
            'risk_type': 'loop_dos',
            'check_infinite_only': True
        },
        # 检测递归函数 - 改进：只检测深度递归风险
        {
            'query': '''
                (function_definition
                    name: (identifier) @func_name
                    body: (block (_)* @body)
                ) @func_def
            ''',
            'message': '函数定义',
            'severity': '低危',
            'risk_type': 'recursion_dos',
            'check_deep_recursion_only': True
        },
        # 检测大列表/字典操作 - 改进：只关注可能的大数据量操作
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(sorted|list|dict|set|max|min|sum|all|any)$',
            'message': '大集合操作函数',
            'severity': '低危',
            'risk_type': 'collection_dos',
            'require_large_data': True
        },
        # 检测网络请求超时设置 - 改进：只关注缺少超时的情况
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @module
                        attribute: (identifier) @func_name
                    )
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'module_pattern': r'^(requests|urllib|urllib2|urllib3|http\.client|aiohttp|socket)$',
            'func_pattern': r'^(get|post|put|delete|request|urlopen|connect|recv|send)$',
            'message': '网络请求函数',
            'severity': '中危',
            'risk_type': 'network_dos',
            'check_missing_timeout': True
        },
        # 检测进程创建 - 改进：只关注可能大量创建进程的情况
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @module
                        attribute: (identifier) @func_name
                    )
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'module_pattern': r'^(os|subprocess|multiprocessing)$',
            'func_pattern': r'^(system|popen|call|run|Popen|spawn|fork)$',
            'message': '进程创建函数',
            'severity': '中危',
            'risk_type': 'process_dos',
            'require_mass_creation': True
        },
        # 检测内存密集型操作 - 改进：只关注真正的大数据操作
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(zip|map|filter|iter|range|xrange|enumerate)$',
            'message': '内存密集型操作',
            'severity': '低危',
            'risk_type': 'memory_dos',
            'require_large_scale': True
        }
    ]
}

# 用户输入源模式
USER_INPUT_SOURCES = {
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
            'message': '标准输入函数'
        },
        {
            'obj_pattern': r'^(sys\.stdin|stdin)$',
            'attr_pattern': r'^(read|readline|readlines)$',
            'message': '标准输入读取'
        },
        {
            'obj_pattern': r'^(sys)$',
            'attr_pattern': r'^(argv)$',
            'message': '命令行参数'
        },
        {
            'obj_pattern': r'^(requests|urllib|urllib2|urllib3|http\.client|aiohttp)$',
            'attr_pattern': r'^(get|post|put|delete|request|urlopen)$',
            'message': '网络输入'
        },
        {
            'obj_pattern': r'^(flask|django|bottle|tornado|fastapi|sanic)\.request$',
            'attr_pattern': r'^(args|form|values|data|json|files|headers|cookies|get_json|get_data)$',
            'message': 'Web框架输入'
        },
        {
            'obj_pattern': r'^(socket)$',
            'attr_pattern': r'^(recv|recvfrom|recvmsg)$',
            'message': '网络套接字输入'
        }
    ]
}

# 危险的正则表达式模式（改进版）
DANGEROUS_REGEX_PATTERNS = {
    'query': '''
        (string) @regex_string
    ''',
    'dangerous_patterns': [
        # 真正的指数复杂度正则
        (r'\([^)]*\+[^)]*\)\+', '嵌套加号量词'),
        (r'\([^)]*\*[^)]*\)\*', '嵌套星号量词'),
        (r'\([^)]*\{[^}]*,\}[^)]*\)[\*\+]', '嵌套可变重复'),
        (r'\(\.\*\)\{2,\}', '多重通配符重复'),
        (r'\(\?:\w+\|\.\)\*', '交替通配符星号'),
        (r'\^\(\.\*\)\?\.\*\$', '嵌套可选通配符'),
        (r'\(\?=\.\*\)\.\*', '前向断言通配符'),
        (r'\(\?<=\.\*\)\.\*', '后向断言通配符'),
    ]
}

# 资源限制检查
RESOURCE_LIMIT_PATTERNS = {
    'query': '''
        [
            (call
                function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @func_name
                )
                arguments: (argument_list (_)* @args)
            ) @call
            (keyword_argument
                name: (identifier) @kw_name
                value: (_) @kw_value
            ) @kw_arg
        ]
    ''',
    'timeout_patterns': [
        {
            'module_pattern': r'^(requests|urllib|urllib3|aiohttp|socket)$',
            'kw_pattern': r'^(timeout|connect_timeout|read_timeout)$',
            'message': '超时设置'
        }
    ]
}


def detect_denial_of_service(code, language='python'):
    """
    检测Python代码中拒绝服务漏洞（改进版）
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

    # 收集各种信息
    user_input_sources = collect_user_input_sources(root, language)
    resource_limits = collect_resource_limits(root, language)
    dangerous_regexes = collect_dangerous_regexes(root, language)

    # 收集DoS相关调用
    for query_info in DENIAL_OF_SERVICE_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'module', 'open_func', 'read_method']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['arg', 'pattern', 'filename', 'condition']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['call', 'while_loop', 'func_def', 'open_call'] and current_capture:
                    if should_collect_call(current_capture, query_info):
                        code_snippet = node.text.decode('utf8')

                        dos_call = {
                            'type': 'dos_call',
                            'line': current_capture['line'],
                            'module': current_capture.get('module', ''),
                            'function': current_capture.get('func_name', ''),
                            'pattern': current_capture.get('pattern', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'filename': current_capture.get('filename', ''),
                            'filename_node': current_capture.get('filename_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'severity': query_info.get('severity', '低危'),
                            'risk_type': query_info.get('risk_type', 'unknown'),
                            'original_message': query_info.get('message', ''),
                            'query_info': query_info
                        }

                        # 立即分析这个调用，而不是先收集再分析
                        vulnerability_details = analyze_dos_vulnerability_improved(
                            dos_call, dangerous_regexes, resource_limits, user_input_sources, root
                        )

                        if vulnerability_details:
                            vulnerabilities.append(vulnerability_details)

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def should_collect_call(current_capture, query_info):
    """
    判断是否应该收集这个调用（减少误报）
    """
    # 对于集合操作，检查参数是否可能包含大数据
    if query_info.get('require_large_data'):
        arg = current_capture.get('arg', '')
        # 如果参数是小的字面量，不收集
        if is_small_literal(arg):
            return False

    # 对于内存密集型操作，检查规模
    if query_info.get('require_large_scale'):
        arg = current_capture.get('arg', '')
        # 如果参数是小的范围或字面量，不收集
        if is_small_scale_operation(arg):
            return False

    return True


def is_small_literal(arg):
    """
    检查参数是否是小字面量
    """
    if not arg:
        return False

    # 小的数字字面量
    if re.match(r'^\s*\d+\s*$', arg) and int(arg) < 1000:
        return True

    # 小的列表/范围
    if re.match(r'^\s*range\s*\(\s*\d+\s*\)\s*$', arg):
        match = re.search(r'range\s*\(\s*(\d+)\s*\)', arg)
        if match and int(match.group(1)) < 1000:
            return True

    # 字面量字符串
    if re.match(r'^[\'\"][^\'\"]{0,50}[\'\"]$', arg):
        return True

    return False


def is_small_scale_operation(arg):
    """
    检查操作是否是小规模的
    """
    if not arg:
        return False

    # 小的range操作
    if 'range' in arg:
        matches = re.findall(r'range\s*\(\s*(\d+)\s*\)', arg)
        for match in matches:
            if int(match) > 10000:  # 只有大于10000的range才认为是大规模的
                return False
        return True

    # 其他情况默认不认为是小规模
    return False


def collect_user_input_sources(root, language):
    """
    收集用户输入源
    """
    user_input_sources = []
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'obj', 'attr']:
                name = node.text.decode('utf8')
                current_capture[tag] = name
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'call' and current_capture:
                for pattern_info in USER_INPUT_SOURCES['patterns']:
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

    return user_input_sources


def collect_resource_limits(root, language):
    """
    收集资源限制设置
    """
    resource_limits = []
    try:
        query = LANGUAGES[language].query(RESOURCE_LIMIT_PATTERNS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['module', 'func_name', 'kw_name']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['call', 'kw_arg'] and current_capture:
                for pattern_info in RESOURCE_LIMIT_PATTERNS['timeout_patterns']:
                    module_pattern = pattern_info.get('module_pattern', '')
                    kw_pattern = pattern_info.get('kw_pattern', '')

                    if ('module' in current_capture and 'kw_name' in current_capture and
                            re.match(module_pattern, current_capture['module'], re.IGNORECASE) and
                            re.match(kw_pattern, current_capture['kw_name'], re.IGNORECASE)):
                        resource_limits.append({
                            'line': current_capture['line'],
                            'type': 'timeout_setting',
                            'module': current_capture['module'],
                            'keyword': current_capture['kw_name'],
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })

                current_capture = {}
    except Exception as e:
        print(f"资源限制查询错误: {e}")

    return resource_limits


def collect_dangerous_regexes(root, language):
    """
    收集危险正则表达式
    """
    dangerous_regexes = []
    try:
        query = LANGUAGES[language].query(DANGEROUS_REGEX_PATTERNS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'regex_string':
                regex_text = node.text.decode('utf8').strip('"\'')

                for pattern, description in DANGEROUS_REGEX_PATTERNS['dangerous_patterns']:
                    if re.search(pattern, regex_text):
                        dangerous_regexes.append({
                            'line': node.start_point[0] + 1,
                            'pattern': regex_text,
                            'dangerous_pattern': pattern,
                            'description': description,
                            'code_snippet': node.text.decode('utf8'),
                            'node': node
                        })
                        break
    except Exception as e:
        print(f"危险正则表达式查询错误: {e}")

    return dangerous_regexes


def analyze_dos_vulnerability_improved(call, dangerous_regexes, resource_limits, user_input_sources, root):
    """
    改进的DoS漏洞分析（减少误报）
    """
    query_info = call.get('query_info', {})
    risk_type = call['risk_type']

    # 检查是否需要用户输入但不存在
    if query_info.get('require_user_input'):
        has_user_input = False

        # 检查参数节点
        if call.get('arg_node'):
            has_user_input = is_user_input_related(call['arg_node'], user_input_sources, root)

        # 检查文件名节点
        if not has_user_input and call.get('filename_node'):
            has_user_input = is_user_input_related(call['filename_node'], user_input_sources, root)

        # 如果没有用户输入，直接返回
        if not has_user_input:
            return None

    # 根据风险类型进行精确分析
    if risk_type == 'redos':
        return analyze_redos_vulnerability(call, dangerous_regexes)
    elif risk_type == 'collection_dos':
        return analyze_collection_dos_vulnerability(call)
    elif risk_type == 'memory_dos':
        return analyze_memory_dos_vulnerability(call)
    elif risk_type == 'network_dos':
        return analyze_network_dos_vulnerability(call, resource_limits)
    elif risk_type == 'loop_dos':
        return analyze_loop_dos_vulnerability(call)
    elif risk_type == 'file_dos':
        return analyze_file_dos_vulnerability(call)
    elif risk_type == 'xml_dos':
        return analyze_xml_dos_vulnerability(call)
    elif risk_type == 'json_dos':
        return analyze_json_dos_vulnerability(call)
    elif risk_type == 'process_dos':
        return analyze_process_dos_vulnerability(call)
    elif risk_type == 'recursion_dos':
        return analyze_recursion_dos_vulnerability(call)

    return None


def is_user_input_related(node, user_input_sources, root_node):
    """
    检查节点是否与用户输入相关
    """
    if not node:
        return False

    arg_text = node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'data', 'request', 'response',
                       'body', 'content', 'payload', 'param', 'form', 'file',
                       'query', 'args', 'json', 'xml']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == node or is_child_node(node, source['node']):
            return True

    return False


def analyze_redos_vulnerability(call, dangerous_regexes):
    """分析ReDoS漏洞"""
    if call['pattern'] and is_dangerous_regex(call['pattern'], dangerous_regexes):
        return {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '拒绝服务',
            'severity': '高危',
            'risk_type': 'redos',
            'message': f"危险正则表达式模式: {call['module']}.{call['function']} - 可能造成ReDoS攻击"
        }
    return None


def analyze_collection_dos_vulnerability(call):
    """分析集合操作DoS漏洞"""
    # 只有在大数据量操作时才报告
    arg = call.get('argument', '')
    if not is_large_data_operation(arg):
        return None

    return {
        'line': call['line'],
        'code_snippet': call['code_snippet'],
        'vulnerability_type': '拒绝服务',
        'severity': '低危',
        'risk_type': 'collection_dos',
        'message': f"大集合操作: {call['function']} - 处理大量数据可能导致内存耗尽"
    }


def analyze_memory_dos_vulnerability(call):
    """分析内存DoS漏洞"""
    # 只有在大规模操作时才报告
    arg = call.get('argument', '')
    if not is_large_scale_operation(arg):
        return None

    return {
        'line': call['line'],
        'code_snippet': call['code_snippet'],
        'vulnerability_type': '拒绝服务',
        'severity': '低危',
        'risk_type': 'memory_dos',
        'message': f"内存密集型操作: {call['function']} - 可能消耗大量内存"
    }


def analyze_network_dos_vulnerability(call, resource_limits):
    """分析网络DoS漏洞"""
    # 检查是否缺少超时设置
    if not has_timeout_setting(call, resource_limits):
        return {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '拒绝服务',
            'severity': '中危',
            'risk_type': 'network_dos',
            'message': f"网络请求缺少超时设置: {call['module']}.{call['function']} - 可能遭受慢速连接攻击"
        }
    return None


def analyze_loop_dos_vulnerability(call):
    """分析循环DoS漏洞"""
    # 只检测明显的无限循环
    if is_infinite_loop(call):
        return {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '拒绝服务',
            'severity': '中危',
            'risk_type': 'loop_dos',
            'message': "潜在无限循环 - 可能导致CPU耗尽"
        }
    return None


def analyze_file_dos_vulnerability(call):
    """分析文件DoS漏洞"""
    return {
        'line': call['line'],
        'code_snippet': call['code_snippet'],
        'vulnerability_type': '拒绝服务',
        'severity': '中危',
        'risk_type': 'file_dos',
        'message': "文件读取操作 - 用户可能指定大文件导致内存耗尽"
    }


def analyze_xml_dos_vulnerability(call):
    """分析XML DoS漏洞"""
    return {
        'line': call['line'],
        'code_snippet': call['code_snippet'],
        'vulnerability_type': '拒绝服务',
        'severity': '中危',
        'risk_type': 'xml_dos',
        'message': f"XML解析: {call['module']}.{call['function']} - 可能遭受XML炸弹攻击"
    }


def analyze_json_dos_vulnerability(call):
    """分析JSON DoS漏洞"""
    return {
        'line': call['line'],
        'code_snippet': call['code_snippet'],
        'vulnerability_type': '拒绝服务',
        'severity': '低危',
        'risk_type': 'json_dos',
        'message': f"JSON解析: {call['module']}.{call['function']} - 可能遭受深度嵌套JSON攻击"
    }


def analyze_process_dos_vulnerability(call):
    """分析进程DoS漏洞"""
    # 检查是否在循环中创建进程
    if is_in_mass_creation_context(call):
        return {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '拒绝服务',
            'severity': '中危',
            'risk_type': 'process_dos',
            'message': f"进程创建: {call['module']}.{call['function']} - 可能创建过多进程导致资源耗尽"
        }
    return None


def analyze_recursion_dos_vulnerability(call):
    """分析递归DoS漏洞"""
    # 检查是否是深度递归
    if is_deep_recursion(call):
        return {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '拒绝服务',
            'severity': '低危',
            'risk_type': 'recursion_dos',
            'message': "深度递归函数 - 可能导致栈溢出"
        }
    return None


# 辅助函数（改进版）
def is_dangerous_regex(pattern, dangerous_regexes):
    """检查正则表达式是否危险"""
    pattern_text = pattern.strip('"\'')
    for dangerous_regex in dangerous_regexes:
        if dangerous_regex['pattern'] == pattern_text:
            return True
    return False


def is_large_data_operation(arg):
    """检查是否是大数据量操作"""
    if not arg:
        return False

    # 大的数字
    if re.match(r'^\s*\d+\s*$', arg) and int(arg) > 10000:
        return True

    # 大的range操作
    if 'range' in arg:
        matches = re.findall(r'range\s*\(\s*(\d+)\s*\)', arg)
        for match in matches:
            if int(match) > 10000:
                return True

    return False


def is_large_scale_operation(arg):
    """检查是否是大规模操作"""
    if not arg:
        return False

    # 非常大的range操作
    if 'range' in arg:
        matches = re.findall(r'range\s*\(\s*(\d+)\s*\)', arg)
        for match in matches:
            if int(match) > 1000000:  # 100万以上才认为是大规模
                return True

    return False


def has_timeout_setting(call, resource_limits):
    """检查是否有超时设置"""
    for limit in resource_limits:
        if (limit['type'] == 'timeout_setting' and
                abs(limit['line'] - call['line']) <= 10):
            return True
    return False


def is_infinite_loop(call):
    """检查是否是无限循环"""
    code_snippet = call['code_snippet'].lower()
    infinite_indicators = [
        r'while\s+True:',
        r'while\s+1:',
        r'while\s+\(True\):',
        r'while\s+\(1\):'
    ]
    for indicator in infinite_indicators:
        if re.search(indicator, code_snippet):
            return True
    return False


def is_in_mass_creation_context(call):
    """检查是否在大量创建上下文中"""
    # 简单的检查：是否在循环中
    code_snippet = call['code_snippet']
    if 'for ' in code_snippet or 'while ' in code_snippet:
        return True
    return False


def is_deep_recursion(call):
    """检查是否是深度递归"""
    # 简单的检查：函数是否调用自身多次
    code_snippet = call['code_snippet']
    func_name = call.get('function', '')
    if func_name and code_snippet.count(func_name) > 2:
        return True
    return False


def is_child_node(child, parent):
    """检查一个节点是否是另一个节点的子节点"""
    node = child
    while node:
        if node == parent:
            return True
        node = node.parent
    return False


def analyze_python_dos_vulnerabilities(code_string):
    """分析Python代码字符串中的拒绝服务漏洞"""
    return detect_denial_of_service(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import re
import xml.etree.ElementTree as ET
import json
import requests
import os
from flask import request

def vulnerable_dos_patterns():
    # 1. 危险正则表达式 - ReDoS
    user_input = request.args.get('pattern')
    text = request.args.get('text')
    # 危险的正则模式
    result = re.search(r'(a+)+b', text)  # 指数复杂度

    # 2. XML炸弹攻击
    xml_data = request.files['xml_file'].read()
    root = ET.fromstring(xml_data)  # 可能遭受XML炸弹

    # 3. 大文件读取（用户控制文件名）
    filename = request.args.get('file')
    with open(filename, 'r') as f:
        content = f.read()

    # 4. 无限循环
    while True:  # 明显的无限循环
        process_data()

    # 5. 缺少超时的网络请求
    response = requests.get('http://example.com')  # 缺少超时设置

    # 6. 大量进程创建
    for i in range(10000):
        os.system(f'echo {i}')

def safe_patterns():
    # 1. 小规模操作 - 不应报告
    small_list = list(range(100))  # 小范围，不应报告
    small_range = range(50)  # 小范围，不应报告

    # 2. 带超时的网络请求
    response = requests.get('http://example.com', timeout=5.0)

    # 3. 安全的正则表达式
    result = re.search(r'^[a-z]+$', 'test')

    # 4. 硬编码文件读取
    with open('config.txt', 'r') as f:
        content = f.read()

    # 5. 有界循环
    for i in range(1000):
        process_data(i)

def process_data():
    pass

if __name__ == "__main__":
    vulnerable_dos_patterns()
    safe_patterns()
"""

    print("=" * 70)
    print("Python拒绝服务漏洞检测（改进版）")
    print("=" * 70)

    results = analyze_python_dos_vulnerabilities(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:80]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   风险类型: {vuln['risk_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print("-" * 50)
    else:
        print("未检测到拒绝服务漏洞")