import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JavaScript的不安全JSON反序列化漏洞模式
JSON_DESERIALIZATION_VULNERABILITIES = {
    'javascript': [
        # 1. 直接使用eval进行JSON解析
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (string) @json_string)
                ) @call
            ''',
            'pattern': r'^(eval|Function|setTimeout|setInterval)$',
            'message': '直接使用eval解析JSON字符串',
            'severity': '高危'
        },
        # 2. 使用new Function构造器
        {
            'query': '''
                (new_expression
                    constructor: (identifier) @constructor
                    arguments: (arguments (string) @code_string)
                ) @new_expr
            ''',
            'pattern': r'^(Function)$',
            'message': '使用Function构造器动态执行代码',
            'severity': '高危'
        },
        # 3. 字符串拼接后使用eval
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments 
                        (template_string) @template_str
                    )
                ) @call
            ''',
            'pattern': r'^(eval|Function)$',
            'message': '使用模板字符串拼接后执行eval',
            'severity': '高危'
        },
        # 4. 使用setTimeout/setInterval执行字符串代码
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments 
                        (string) @code_string
                        (_)*
                    )
                ) @call
            ''',
            'pattern': r'^(setTimeout|setInterval|setImmediate)$',
            'message': '使用定时器执行字符串代码',
            'severity': '中危'
        },
        # 5. 使用JSON.parse的reviver函数中的危险操作
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments 
                        (_) @json_arg
                        (function) @reviver_func
                    )
                ) @call
            ''',
            'pattern': r'^(JSON)$',
            'property_pattern': r'^(parse)$',
            'message': 'JSON.parse使用reviver函数，可能存在风险',
            'severity': '低危'
        },
        # 6. 使用不安全的第三方库进行JSON解析
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments 
                        (string) @json_string
                    )
                ) @call
            ''',
            'pattern': r'^(jQuery|$|_|window|globalThis|JSON|Object)$',
            'property_pattern': r'^(parseJSON|parse|evalJSON|deserialize|fromJSON)$',
            'message': '使用可能不安全的JSON解析方法',
            'severity': '中危'
        },
        # 7. 动态import() 可能用于执行代码
        {
            'query': '''
                (call_expression
                    function: (import)
                    arguments: (arguments 
                        (string) @import_string
                    )
                ) @call
            ''',
            'message': '动态import可能用于代码执行',
            'severity': '低危'
        },
        # 8. 使用with语句可能导致的代码注入
        {
            'query': '''
                (with_statement
                    object: (_) @with_object
                    body: (_) @with_body
                ) @with_stmt
            ''',
            'message': '使用with语句，可能存在安全风险',
            'severity': '低危'
        },
        # 9. 使用innerHTML/innerText/textContent等可能执行脚本
        {
            'query': '''
                (assignment_expression
                    left: (member_expression
                        object: (_) @object
                        property: (property_identifier) @property
                    )
                    right: (_) @value
                ) @assignment
            ''',
            'pattern': r'^(document|element|el|div|span|body|head|html|window)$',
            'property_pattern': r'^(innerHTML|innerText|textContent|outerHTML|insertAdjacentHTML|write|writeln)$',
            'message': '直接设置HTML内容，可能执行恶意脚本',
            'severity': '中危'
        }
    ]
}


def detect_js_json_deserialization_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中不安全的JSON反序列化漏洞

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

    # 检测所有定义的漏洞模式
    for vuln_info in JSON_DESERIALIZATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(vuln_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'constructor', 'object']:
                    name = node.text.decode('utf8')
                    pattern = vuln_info.get('pattern', '')
                    if not pattern or re.match(pattern, name, re.IGNORECASE):
                        current_capture[tag] = name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = vuln_info.get('property_pattern', '')
                    if not prop_pattern or re.match(prop_pattern, prop_name, re.IGNORECASE):
                        current_capture[tag] = prop_name

                elif tag in ['call', 'new_expr', 'assignment', 'with_stmt'] and current_capture:
                    # 获取代码片段
                    code_snippet = node.text.decode('utf8')

                    # 检查是否包含JSON相关字符串
                    json_indicators = ['JSON', 'parse', 'eval', 'Function', 'setTimeout']
                    if any(indicator in code_snippet for indicator in json_indicators):
                        vulnerabilities.append({
                            'line': current_capture['line'],
                            'message': vuln_info['message'],
                            'code_snippet': code_snippet[:200] + '...' if len(code_snippet) > 200 else code_snippet,
                            'vulnerability_type': '不安全的JSON反序列化',
                            'severity': vuln_info.get('severity', '中危'),
                            'pattern_type': vuln_info.get('pattern', '通用')
                        })

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {vuln_info.get('message')}: {e}")
            continue

    # 额外的启发式检测：查找字符串拼接后的eval调用
    vulnerabilities.extend(detect_string_concat_eval(root, code, language))

    return sorted(vulnerabilities, key=lambda x: x['line'])


def detect_string_concat_eval(root, code, language):
    """
    检测字符串拼接后执行eval的情况

    Args:
        root: AST根节点
        code: 源代码
        language: 语言类型

    Returns:
        list: 检测结果列表
    """
    vulnerabilities = []

    try:
        # 查找变量声明和赋值
        query = LANGUAGES[language].query('''
            (variable_declarator
                name: (identifier) @var_name
                value: (call_expression
                    function: (member_expression
                        object: (_) @concat_object
                        property: (property_identifier) @concat_method
                    )
                    arguments: (arguments) @concat_args
                )
            ) @var_decl
        ''')

        concat_vars = {}
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'var_name':
                var_name = node.text.decode('utf8')
                concat_vars[var_name] = {
                    'line': node.start_point[0] + 1,
                    'node': node
                }

        # 查找这些变量是否被用于eval
        eval_query = LANGUAGES[language].query('''
            (call_expression
                function: (identifier) @func_name
                arguments: (arguments (identifier) @arg_name)
            ) @call
        ''')

        eval_captures = eval_query.captures(root)
        current_eval = {}

        for node, tag in eval_captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                if func_name in ['eval', 'Function']:
                    current_eval['func'] = func_name
                    current_eval['line'] = node.start_point[0] + 1
            elif tag == 'arg_name' and current_eval:
                arg_name = node.text.decode('utf8')
                if arg_name in concat_vars:
                    code_snippet = node.parent.text.decode('utf8')
                    vulnerabilities.append({
                        'line': current_eval['line'],
                        'message': '字符串拼接后用于eval执行',
                        'code_snippet': code_snippet[:200] + '...' if len(code_snippet) > 200 else code_snippet,
                        'vulnerability_type': '不安全的JSON反序列化',
                        'severity': '高危',
                        'pattern_type': '字符串拼接eval'
                    })
                current_eval = {}

    except Exception as e:
        print(f"字符串拼接检测错误: {e}")

    return vulnerabilities


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的不安全JSON反序列化漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_json_deserialization_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码 - 包含各种不安全的JSON反序列化模式
    test_js_code = """
// 1. 直接使用eval解析JSON
const data1 = '{"name": "John", "age": 30}';
const obj1 = eval('(' + data1 + ')');  // 高危漏洞

// 2. 使用Function构造器
const data2 = '{"name": "Jane", "age": 25}';
const obj2 = new Function('return ' + data2)();  // 高危漏洞

// 3. 模板字符串拼接eval
const partialData = '{"name": "Bob"';
const obj3 = eval(`(${partialData}, "age": 35})`);  // 高危漏洞

// 4. setTimeout执行字符串代码
setTimeout('console.log("Executed code")', 1000);  // 中危漏洞

// 5. JSON.parse with reviver函数（可能安全，但需要检查）
const data5 = '{"name": "Alice", "age": 28}';
const obj5 = JSON.parse(data5, (key, value) => {
    if (key === 'dangerous') {
        eval(value);  // 在reviver中执行eval - 高危
    }
    return value;
});

// 6. 使用jQuery的parseJSON（可能不安全）
const data6 = '{"name": "Charlie"}';
const obj6 = jQuery.parseJSON(data6);  // 中危漏洞

// 7. 动态import
const moduleName = './malicious-module.js';
import(moduleName).then(module => {  // 低危漏洞
    module.execute();
});

// 8. with语句
const config = {debug: true};
with (config) {
    if (debug) {
        eval('console.log("Debug mode")');  // 结合with和eval
    }
}

// 9. 设置innerHTML可能执行脚本
document.getElementById('content').innerHTML = '<script>alert("XSS")</script>';

// 10. 间接的字符串拼接eval
const userInput = getUserInput(); // 假设来自用户
const jsonStr = '{"data": ' + userInput + '}';
const result = eval('(' + jsonStr + ')');

// 11. 使用setInterval执行字符串
setInterval('updateData()', 5000);

// 12. 使用Object构造函数
const data12 = '{"name": "David"}';
const obj12 = Object.assign({}, eval('(' + data12 + ')'));

// 安全的使用方式
const safeData = '{"name": "Safe"}';
const safeObj = JSON.parse(safeData);  // 安全

// 使用安全的reviver函数
const safeObj2 = JSON.parse(safeData, (key, value) => {
    // 只是转换数据，不执行代码
    return typeof value === 'string' ? value.trim() : value;
});

function getUserInput() {
    return '"malicious"; alert("hacked")';
}
"""

    print("=" * 80)
    print("JavaScript不安全JSON反序列化漏洞检测")
    print("=" * 80)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   检测模式: {vuln.get('pattern_type', '未知')}")
    else:
        print("未检测到不安全的JSON反序列化漏洞")

    print("\n" + "=" * 80)
    print("检测完成")
    print("=" * 80)