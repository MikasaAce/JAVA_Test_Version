import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义XStream反序列化漏洞模式
XSTREAM_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (_) @arg)
                ) @call
            ''',
            'object_pattern': r'^(xstream|XStream|xstreamInstance)$',
            'property_pattern': r'^(fromXML|unmarshal|fromJson|deserialize)$',
            'message': 'XStream反序列化调用发现'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (_) @arg)
                ) @call
            ''',
            'pattern': r'^(fromXML|unmarshal|fromJson|deserialize)$',
            'message': '反序列化函数调用发现'
        },
        {
            'query': '''
                (new_expression
                    constructor: (identifier) @constructor
                ) @new
            ''',
            'pattern': r'^(XStream)$',
            'message': 'XStream对象实例化'
        },
        {
            'query': '''
                (variable_declarator
                    name: (identifier) @var_name
                    value: (new_expression
                        constructor: (identifier) @constructor
                    )
                ) @var_decl
            ''',
            'pattern': r'^(XStream)$',
            'message': 'XStream变量声明'
        },
        {
            'query': '''
                (assignment_expression
                    left: (identifier) @var_name
                    right: (new_expression
                        constructor: (identifier) @constructor
                    )
                ) @assignment
            ''',
            'pattern': r'^(XStream)$',
            'message': 'XStream赋值实例化'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (call_expression
                            function: (identifier) @require_func
                            arguments: (arguments (string) @module_name)
                        )
                        property: (property_identifier) @property
                    )
                    arguments: (arguments) @args
                ) @require_call
            ''',
            'require_pattern': r'^(require)$',
            'module_pattern': r'^(xstream)$',
            'message': 'XStream模块导入'
        }
    ]
}


def detect_xstream_deserialization_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中不安全的XStream反序列化漏洞

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
    xstream_instances = set()  # 存储XStream实例名称
    xstream_imports = set()  # 存储导入的XStream模块
    deserialization_calls = []  # 存储反序列化调用

    # 第一步：收集所有XStream实例和导入
    for query_info in XSTREAM_VULNERABILITIES[language][2:]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag == 'constructor':
                    constructor_name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, constructor_name, re.IGNORECASE):
                        # 获取变量名
                        parent = node.parent
                        if parent and parent.type == 'new_expression':
                            grand_parent = parent.parent
                            if grand_parent and grand_parent.type == 'variable_declarator':
                                var_name_node = grand_parent.child_by_field_name('name')
                                if var_name_node:
                                    xstream_instances.add(var_name_node.text.decode('utf8'))
                            elif grand_parent and grand_parent.type == 'assignment_expression':
                                var_name_node = grand_parent.child_by_field_name('left')
                                if var_name_node:
                                    xstream_instances.add(var_name_node.text.decode('utf8'))

                elif tag == 'var_name':
                    var_name = node.text.decode('utf8')
                    xstream_instances.add(var_name)

                elif tag == 'module_name':
                    module_name = node.text.decode('utf8').strip('"\'')
                    pattern = query_info.get('module_pattern', '')
                    if pattern and re.match(pattern, module_name, re.IGNORECASE):
                        xstream_imports.add(module_name)

        except Exception as e:
            print(f"XStream实例收集错误: {e}")
            continue

    # 第二步：收集所有反序列化调用
    for query_info in XSTREAM_VULNERABILITIES[language][:2]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['object', 'func_name']:
                    name = node.text.decode('utf8')

                    if tag == 'object':
                        pattern = query_info.get('object_pattern', '')
                        if pattern and re.match(pattern, name, re.IGNORECASE):
                            current_capture['object'] = name
                            current_capture['line'] = node.start_point[0] + 1
                            current_capture['node'] = node

                    elif tag == 'func_name':
                        pattern = query_info.get('pattern', '')
                        if pattern and re.match(pattern, name, re.IGNORECASE):
                            current_capture['function'] = name
                            current_capture['line'] = node.start_point[0] + 1
                            current_capture['node'] = node

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern', '')
                    if prop_pattern and re.match(prop_pattern, prop_name, re.IGNORECASE):
                        current_capture['property'] = prop_name

                elif tag == 'arg':
                    current_capture['argument'] = node.text.decode('utf8')
                    current_capture['argument_node'] = node

                elif tag in ['call'] and current_capture:
                    # 检查是否匹配XStream反序列化模式
                    is_xstream_call = False
                    call_details = {}

                    # 检查对象方法调用
                    if 'object' in current_capture and 'property' in current_capture:
                        obj_name = current_capture['object']
                        if (obj_name in xstream_instances or
                                re.match(r'^(xstream|XStream)$', obj_name, re.IGNORECASE)):
                            is_xstream_call = True
                            call_details['type'] = 'method_call'
                            call_details['object'] = obj_name
                            call_details['method'] = current_capture['property']

                    # 检查函数调用
                    elif 'function' in current_capture:
                        func_name = current_capture['function']
                        if re.match(r'^(fromXML|unmarshal|fromJson|deserialize)$', func_name, re.IGNORECASE):
                            is_xstream_call = True
                            call_details['type'] = 'function_call'
                            call_details['function'] = func_name

                    if is_xstream_call:
                        # 获取完整的代码片段
                        code_snippet = get_code_snippet(current_capture['node'], code)

                        deserialization_calls.append({
                            'line': current_capture['line'],
                            'code_snippet': code_snippet,
                            'argument': current_capture.get('argument', ''),
                            'argument_node': current_capture.get('argument_node'),
                            'node': current_capture['node'],
                            'details': call_details
                        })

                    current_capture = {}

        except Exception as e:
            print(f"反序列化调用查询错误: {e}")
            continue

    # 第三步：分析漏洞
    for call in deserialization_calls:
        # 检查参数是否可能来自不可信源
        argument = call['argument']
        is_vulnerable = is_untrusted_source(argument, code)

        if is_vulnerable:
            source_type = get_argument_source(argument)

            vulnerabilities.append({
                'line': call['line'],
                'message': 'XStream Security: Unsafe deserialization detected',
                'code_snippet': call['code_snippet'],
                'vul_type': 'XStream反序列化漏洞',
                'severity': '高危',
                'details': f'参数来自不可信源: {source_type}',
                'call_type': call['details']['type'],
                'method': call['details'].get('method', call['details'].get('function', 'unknown'))
            })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def get_code_snippet(node, code, context_lines=2):
    """
    获取代码片段，包含上下文

    Args:
        node: AST节点
        code: 源代码
        context_lines: 上下文行数

    Returns:
        str: 代码片段
    """
    lines = code.split('\n')
    start_line = max(0, node.start_point[0] - context_lines)
    end_line = min(len(lines), node.end_point[0] + context_lines + 1)

    snippet_lines = []
    for i in range(start_line, end_line):
        line_content = lines[i]
        if node.start_point[0] <= i <= node.end_point[0]:
            # 高亮当前行
            snippet_lines.append(f"➡️ {i + 1:3d}: {line_content}")
        else:
            snippet_lines.append(f"   {i + 1:3d}: {line_content}")

    return '\n'.join(snippet_lines)


def get_argument_source(argument):
    """
    获取参数来源的简要描述

    Args:
        argument: 参数字符串

    Returns:
        str: 来源描述
    """
    if not argument:
        return "空参数"

    cleaned_arg = argument.lower().strip()

    # 识别常见的不可信源模式
    sources = [
        (r'req\.', 'HTTP请求'),
        (r'request\.', 'HTTP请求'),
        (r'\.body', '请求体'),
        (r'\.param', '请求参数'),
        (r'\.query', '查询参数'),
        (r'\.headers', '请求头'),
        (r'\.cookie', 'Cookie'),
        (r'\.data', '响应数据'),
        (r'\.text\(\)', '响应文本'),
        (r'\.content', '内容'),
        (r'\.input', '输入'),
        (r'window\.location', 'URL参数'),
        (r'document\.', 'DOM内容'),
        (r'fs\.read', '文件系统'),
        (r'process\.env', '环境变量'),
        (r'process\.argv', '命令行参数'),
        (r'localStorage\.', '本地存储'),
        (r'sessionStorage\.', '会话存储'),
        (r'fetch\(', '网络请求'),
        (r'XMLHttpRequest', 'XHR请求'),
        (r'axios\(', 'Axios请求'),
        (r'\.then\(', 'Promise回调'),
        (r'\.catch\(', 'Promise错误处理'),
        (r'user', '用户输入'),
        (r'input', '输入数据'),
    ]

    for pattern, description in sources:
        if re.search(pattern, cleaned_arg, re.IGNORECASE):
            return f"{description}"

    # 如果是变量但不是明确可信的
    if re.search(r'[a-zA-Z_$][a-zA-Z0-9_$]*', cleaned_arg):
        return f"变量引用"

    return f"未知来源"


def is_untrusted_source(argument, code):
    """
    检查参数是否可能来自不可信源

    Args:
        argument: 参数字符串
        code: 完整源代码

    Returns:
        bool: 是否可能来自不可信源
    """
    if not argument:
        return True

    cleaned_arg = argument.lower().strip()

    # 可信的来源模式（字面量等）
    trusted_patterns = [
        r'^".*"$',  # 字符串字面量
        r'^\'.*\'$',  # 字符串字面量
        r'^\d+$',  # 数字字面量
        r'^\[.*\]$',  # 数组字面量
        r'^\{.*\}$',  # 对象字面量
        r'^JSON\.stringify\(',  # JSON序列化
        r'^crypto\.',  # 加密相关
    ]

    # 不可信的模式
    untrusted_patterns = [
        r'req\.', r'request\.', r'\.body', r'\.param', r'\.query',
        r'\.headers', r'\.cookie', r'\.data', r'\.text\(\)', r'\.content',
        r'\.input', r'window\.location', r'document\.', r'fs\.read',
        r'process\.env', r'process\.argv', r'localStorage\.', r'sessionStorage\.',
        r'fetch\(', r'XMLHttpRequest', r'axios\(', r'\.then\(', r'\.catch\(',
        r'user', r'input'
    ]

    # 检查是否为可信源
    for pattern in trusted_patterns:
        if re.search(pattern, cleaned_arg, re.IGNORECASE):
            return False

    # 检查是否为不可信源
    for pattern in untrusted_patterns:
        if re.search(pattern, cleaned_arg, re.IGNORECASE):
            return True

    # 默认情况下，如果有变量但不是明确可信的，认为是不可信的
    if re.search(r'[a-zA-Z_$][a-zA-Z0-9_$]*', cleaned_arg):
        return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的XStream反序列化漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_xstream_deserialization_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 安全的XStream使用
const xstream1 = new XStream();
const safeData = xstream1.fromXML('<safe><data>test</data></safe>');  // 字面量，安全

// 不安全的XStream使用 - 来自请求体
const xstream2 = new XStream();
app.post('/process', (req, res) => {
    const userData = xstream2.fromXML(req.body);  // 不安全：来自请求体
    // 处理数据
});

// 不安全的函数调用
function processUserInput(input) {
    const result = fromXML(input);  // 不安全：来自函数参数
    return result;
}

// 来自URL参数的不安全使用
const xstream3 = new XStream();
const urlParams = new URLSearchParams(window.location.search);
const xmlData = urlParams.get('data');
const parsed = xstream3.fromXML(xmlData);  // 不安全：来自URL参数

// 来自文件的不安全使用
const fs = require('fs');
const fileData = fs.readFileSync('user_input.xml', 'utf8');
const xstream4 = new XStream();
const result = xstream4.fromXML(fileData);  // 不安全：来自文件

// 使用fetch获取的不安全数据
fetch('/api/data')
    .then(response => response.text())
    .then(xml => {
        const xstream5 = new XStream();
        const data = xstream5.fromXML(xml);  // 不安全：来自网络请求
    });

// 使用其他反序列化方法
const xstream6 = new XStream();
const dataFromJson = xstream6.fromJson(req.query.json);  // 不安全：来自查询参数

// 使用unmarshal方法
const xstream7 = new XStream();
const unmarshalled = xstream7.unmarshal(req.body.content);  // 不安全：来自请求内容

// 间接的不安全使用
function getData() {
    return document.getElementById('user-input').value;
}
const xstream8 = new XStream();
const indirectData = xstream8.fromXML(getData());  // 不安全：来自DOM输入

// 模块导入方式
const XStream = require('xstream');
const xstream9 = new XStream();
const moduleData = xstream9.fromXML(req.body.data);  // 不安全：来自请求体

// 赋值实例化
let xstream10;
xstream10 = new XStream();
const assignedData = xstream10.fromXML(req.params.xml);  // 不安全：来自URL参数

// 安全的变量使用
const trustedData = '<config><setting>value</setting></config>';
const xstream11 = new XStream();
const safeResult = xstream11.fromXML(trustedData);  // 安全：来自可信变量
"""

    print("=" * 60)
    print("JavaScript XStream反序列化漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   调用类型: {vuln['call_type']} - {vuln['method']}")
            print(f"   代码片段:\n{vuln['code_snippet']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   详情: {vuln['details']}")
    else:
        print("未检测到XStream反序列化漏洞")