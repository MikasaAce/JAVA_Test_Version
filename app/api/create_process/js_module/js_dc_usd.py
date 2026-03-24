import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JavaScript反序列化漏洞模式
DESERIALIZATION_VULNERABILITIES = {
    'javascript': [
        # 检测eval函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(eval|Function|setTimeout|setInterval)$',
            'message': '动态代码执行函数调用发现'
        },
        # 检测new Function调用
        {
            'query': '''
                (new_expression
                    constructor: (identifier) @constructor
                    arguments: (arguments) @args
                ) @new
            ''',
            'pattern': r'^Function$',
            'message': 'Function构造函数调用发现'
        },
        # 检测JSON.parse调用
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(JSON)$',
            'property_pattern': r'^(parse)$',
            'message': 'JSON反序列化调用发现'
        },
        # 检测反序列化相关的第三方库调用
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (call_expression
                            function: (identifier) @module_name
                        )
                        property: (property_identifier) @method_name
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(require|import)$',
            'method_pattern': r'^(parse|deserialize|load|decode)$',
            'message': '第三方反序列化库调用发现'
        },
        # 检测不安全的对象复制/合并操作
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(Object)$',
            'property_pattern': r'^(assign|create|defineProperties)$',
            'message': '潜在不安全的对象操作发现'
        },
        # 检测原型污染相关操作
        {
            'query': '''
                (assignment_expression
                    left: (member_expression
                        object: (member_expression
                            object: (identifier) @proto_obj
                            property: (property_identifier) @proto_prop
                        )
                        property: (property_identifier) @target_prop
                    )
                    right: (_) @value
                ) @assignment
            ''',
            'pattern': r'^(__proto__|prototype|constructor)$',
            'message': '原型污染操作发现'
        }
    ]
}

# 已知的危险反序列化库
DANGEROUS_DESERIALIZATION_LIBS = {
    'serialize-javascript', 'node-serialize', 'serialize', 'deserialize',
    'js-yaml', 'yaml', 'xml2js', 'fast-xml-parser', 'xml-parser',
    'cookie', 'express-session', 'body-parser'
}


def detect_js_deserialization_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中不安全的反序列化操作

    Args:
        code: JavaScript源代码字符串
        language: 语言类型，默认为'javascript'

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

    # 检测所有反序列化相关操作
    for query_info in DESERIALIZATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'constructor', 'object', 'module_name', 'proto_obj']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture[tag] = name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['property', 'method_name', 'proto_prop']:
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern') or query_info.get('method_pattern', '')
                    if not prop_pattern or re.match(prop_pattern, prop_name, re.IGNORECASE):
                        current_capture[tag] = prop_name

                elif tag in ['call', 'new', 'assignment'] and current_capture:
                    # 完成一个完整的捕获
                    if validate_deserialization_pattern(current_capture, query_info):
                        # 获取完整的代码片段
                        code_snippet = node.text.decode('utf8')

                        # 分析参数是否来自不可信来源
                        args_node = None
                        for child in node.children:
                            if child.type == 'arguments':
                                args_node = child
                                break

                        is_untrusted_source = False
                        if args_node:
                            args_text = args_node.text.decode('utf8')
                            is_untrusted_source = check_untrusted_source(args_text, code)

                        vulnerabilities.append({
                            'line': current_capture['line'],
                            'message': query_info['message'],
                            'code_snippet': code_snippet,
                            'vulnerability_type': '不安全的反序列化',
                            'severity': '高危' if is_untrusted_source else '中危',
                            'details': {
                                'function': current_capture.get('func_name') or
                                            current_capture.get('constructor') or
                                            current_capture.get('property') or
                                            current_capture.get('method_name'),
                                'untrusted_source': is_untrusted_source
                            }
                        })

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def validate_deserialization_pattern(capture, query_info):
    """验证捕获的模式是否符合反序列化漏洞条件"""
    # 检查eval相关调用
    if 'func_name' in capture and capture.get('func_name') in ['eval', 'Function']:
        return True

    # 检查JSON.parse
    if (capture.get('object') == 'JSON' and capture.get('property') == 'parse'):
        return True

    # 检查第三方库调用
    if (capture.get('module_name') == 'require' and
            capture.get('method_name') and
            any(lib in capture.get('method_name', '').lower() for lib in DANGEROUS_DESERIALIZATION_LIBS)):
        return True

    # 检查原型污染
    if (capture.get('proto_prop') in ['__proto__', 'prototype', 'constructor']):
        return True

    # 检查其他模式
    pattern = query_info.get('pattern', '')
    if pattern and any(key in capture for key in ['func_name', 'constructor', 'object']):
        for key in ['func_name', 'constructor', 'object']:
            if key in capture and re.match(pattern, capture[key], re.IGNORECASE):
                return True

    return False


def check_untrusted_source(args_text, full_code):
    """
    检查函数参数是否来自不可信来源

    Args:
        args_text: 参数字符串
        full_code: 完整代码

    Returns:
        bool: 是否来自不可信来源
    """
    # 检查是否包含用户输入相关变量
    user_input_indicators = [
        r'req\.', r'request\.', r'query\.', r'params\.', r'body\.',
        r'localStorage\.', r'sessionStorage\.', r'cookie',
        r'window\.', r'document\.', r'location\.', r'navigator\.',
        r'XMLHttpRequest', r'fetch', r'axios'
    ]

    for indicator in user_input_indicators:
        if re.search(indicator, args_text, re.IGNORECASE):
            return True

    # 检查是否包含URL参数
    if re.search(r'window\.location|document\.URL|URLSearchParams', args_text, re.IGNORECASE):
        return True

    # 检查是否包含外部数据源
    external_sources = [
        r'localStorage', r'sessionStorage', r'indexedDB',
        r'FileReader', r'Blob', r'FormData'
    ]

    for source in external_sources:
        if re.search(source, args_text, re.IGNORECASE):
            return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的反序列化漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_deserialization_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 不安全的eval使用
const userInput = req.body.data;
eval(userInput);  // 高危：直接执行用户输入

// 不安全的Function构造函数
const dynamicCode = req.query.code;
const func = new Function(dynamicCode);  // 高危
func();

// JSON.parse可能安全，但需要上下文分析
const jsonData = '{"name": "test"}';
const obj = JSON.parse(jsonData);  // 相对安全

// 来自用户输入的JSON.parse
const userJson = req.body.json;
const userObj = JSON.parse(userJson);  // 中危：可能包含恶意数据

// 使用危险的第三方库
const serialize = require('node-serialize');
const serializedData = req.cookies.data;
const data = serialize.unserialize(serializedData);  // 高危：已知漏洞库

// 原型污染漏洞
const maliciousData = JSON.parse('{"__proto__": {"isAdmin": true}}');
Object.assign({}, maliciousData);  // 高危：原型污染

// setTimeout/setInterval可能被滥用
const userCode = req.query.callback;
setTimeout(userCode, 100);  // 高危：执行用户代码

// 不安全的对象操作
const config = req.body.config;
Object.assign(global, config);  // 高危：污染全局对象

// YAML解析可能执行代码
const yaml = require('js-yaml');
const yamlData = req.body.yaml;
const result = yaml.load(yamlData);  // 高危：YAML可能包含代码

// XML解析可能有问题
const xml2js = require('xml2js');
const xmlData = req.body.xml;
xml2js.parseString(xmlData, (err, result) => {});  // 中危：XML外部实体

// Cookie反序列化
const cookie = require('cookie');
const cookies = cookie.parse(req.headers.cookie);  // 中危：需要检查内容
"""

    print("=" * 60)
    print("JavaScript反序列化漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   函数/方法: {vuln['details']['function']}")
            print(f"   不可信来源: {'是' if vuln['details']['untrusted_source'] else '否'}")
    else:
        print("未检测到反序列化漏洞")