import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JSON注入漏洞检测模式 - 增强版
JSON_INJECTION_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (_) @arg)
                ) @call
            ''',
            'pattern': r'^(JSON\.parse|parseJSON|eval|Function)$',
            'message': 'JSON解析或代码执行函数调用'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @obj
                        property: (property_identifier) @method
                    )
                    arguments: (arguments (_) @arg)
                ) @call
            ''',
            'pattern': r'^(JSON)$',
            'method_pattern': r'^(parse|stringify)$',
            'message': 'JSON方法调用'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (template_string) @template_arg)
                ) @call
            ''',
            'pattern': r'^(JSON\.parse|parseJSON|eval|Function)$',
            'message': '使用模板字符串的JSON操作'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (binary_expression) @binary_arg)
                ) @call
            ''',
            'pattern': r'^(JSON\.parse|parseJSON|eval|Function)$',
            'message': '使用拼接字符串的JSON操作'
        }
    ]
}

# 定义用户输入源模式 - 增强版
USER_INPUT_SOURCES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (_) @obj
                        property: (property_identifier) @method
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(document|window|location|navigator|history|localStorage|sessionStorage|req|request|res|response)$',
            'method_pattern': r'^(cookie|URL|search|hash|href|referrer|getItem|querySelector|getElementById|body|query|params|param)$',
            'message': '用户输入源方法调用'
        },
        {
            'query': '''
                (identifier) @input_id
            ''',
            'pattern': r'^(userInput|input|data|formData|jsonData|payload|content|body|query|params|req|request|res|response)$',
            'message': '用户输入标识符'
        }
    ]
}


def detect_js_json_injection(code, language='javascript'):
    """
    检测JavaScript代码中的JSON注入漏洞

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
    json_operations = []  # 存储所有JSON操作
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集所有JSON操作
    for query_info in JSON_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'obj', 'method']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    method_pattern = query_info.get('method_pattern', '')

                    if (pattern and re.match(pattern, name, re.IGNORECASE)) or \
                            (tag == 'method' and method_pattern and re.match(method_pattern, name, re.IGNORECASE)):
                        current_capture[tag] = name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['arg', 'template_arg', 'binary_arg'] and current_capture:
                    # 获取参数
                    text = node.text.decode('utf8')
                    current_capture['argument'] = text
                    current_capture['argument_node'] = node
                    current_capture['argument_type'] = tag

                elif tag in ['call'] and current_capture:
                    # 完成一个完整的捕获
                    if 'func_name' in current_capture or ('obj' in current_capture and 'method' in current_capture):
                        # 获取完整的代码片段
                        code_snippet = node.text.decode('utf8')

                        json_operations.append({
                            'type': 'json_operation',
                            'line': current_capture['line'],
                            'function': current_capture.get('func_name', ''),
                            'object': current_capture.get('obj', ''),
                            'method': current_capture.get('method', ''),
                            'argument': current_capture.get('argument', ''),
                            'argument_type': current_capture.get('argument_type', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"JSON操作查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    for query_info in USER_INPUT_SOURCES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['obj', 'method', 'input_id']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    method_pattern = query_info.get('method_pattern', '')

                    if (pattern and re.match(pattern, name, re.IGNORECASE)) or \
                            (tag == 'method' and method_pattern and re.match(method_pattern, name, re.IGNORECASE)) or \
                            (tag == 'input_id' and pattern and re.match(pattern, name, re.IGNORECASE)):
                        # 获取完整的代码片段
                        code_snippet = node.text.decode('utf8')

                        user_input_sources.append({
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'name': name,
                            'code_snippet': code_snippet,
                            'node': node
                        })

                elif tag in ['call']:
                    # 处理调用表达式
                    code_snippet = node.text.decode('utf8')

                    # 检查是否包含用户输入模式
                    if any(re.match(pattern, code_snippet, re.IGNORECASE) for pattern in
                           [r'\.cookie', r'\.body', r'\.query', r'\.params', r'\.getElement', r'\.querySelector']):
                        user_input_sources.append({
                            'type': 'user_input_call',
                            'line': node.start_point[0] + 1,
                            'code_snippet': code_snippet,
                            'node': node
                        })

        except Exception as e:
            print(f"用户输入源查询错误 {query_info.get('message')}: {e}")
            continue

    # 第三步：分析漏洞
    for json_op in json_operations:
        json_line = json_op['line']
        json_code = json_op['code_snippet']

        # 检查1: 参数是否为变量（非字面量）
        if is_variable_argument(json_op):
            vulnerabilities.append({
                'line': json_line,
                'message': '潜在的JSON注入漏洞: 使用变量作为JSON解析参数',
                'code_snippet': json_code,
                'vulnerability_type': 'JSON注入',
                'severity': '中危'
            })
            continue

        # 检查2: 参数是否为模板字符串或拼接字符串
        if json_op['argument_type'] in ['template_arg', 'binary_arg']:
            vulnerabilities.append({
                'line': json_line,
                'message': '潜在的JSON注入漏洞: 使用模板字符串或拼接字符串作为JSON参数',
                'code_snippet': json_code,
                'vulnerability_type': 'JSON注入',
                'severity': '高危'
            })
            continue

        # 检查3: 检查JSON操作是否包含可能的用户输入
        for user_input in user_input_sources:
            input_line = user_input['line']

            # 检查用户输入是否在JSON操作之前或附近
            if input_line <= json_line:
                # 检查用户输入是否被用于JSON操作
                if is_user_input_used_in_json(json_op, user_input, code):
                    vulnerabilities.append({
                        'line': json_line,
                        'message': f'潜在的JSON注入漏洞: 使用未经验证的输入进行JSON操作',
                        'code_snippet': json_code,
                        'vulnerability_type': 'JSON注入',
                        'severity': '高危',
                        'input_source': user_input
                    })
                    break

        # 检查4: 是否直接使用eval处理JSON
        if json_op['function'].lower() in ['eval', 'function'] and 'json' in json_code.lower():
            vulnerabilities.append({
                'line': json_line,
                'message': '高危JSON注入漏洞: 使用eval处理JSON数据',
                'code_snippet': json_code,
                'vulnerability_type': 'JSON注入',
                'severity': '高危'
            })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_variable_argument(json_op):
    """
    检查JSON操作的参数是否为变量

    Args:
        json_op: JSON操作信息

    Returns:
        bool: 参数是否为变量
    """
    if 'argument' not in json_op:
        return False

    argument = json_op['argument']

    # 检查是否为字面量字符串
    if (argument.startswith('"') and argument.endswith('"')) or \
            (argument.startswith("'") and argument.endswith("'")):
        return False

    # 检查是否为模板字符串
    if argument.startswith('`') and argument.endswith('`'):
        return True

    # 检查是否为变量名（标识符）
    if re.match(r'^[a-zA-Z_$][a-zA-Z_$0-9]*$', argument):
        return True

    # 检查是否为复杂表达式（包含运算符）
    if any(op in argument for op in ['+', '-', '*', '/', '%', '?', ':']):
        return True

    return False


def is_user_input_used_in_json(json_op, user_input, full_code):
    """
    检查用户输入是否被用于JSON操作

    Args:
        json_op: JSON操作信息
        user_input: 用户输入信息
        full_code: 完整代码

    Returns:
        bool: 用户输入是否被用于JSON操作
    """
    # 简单检查：用户输入名称是否出现在JSON操作代码中
    if 'name' in user_input and user_input['name'].lower() in json_op['code_snippet'].lower():
        return True

    # 检查输入代码片段是否出现在JSON操作中
    if user_input['code_snippet'] in json_op['code_snippet']:
        return True

    # 检查是否为同一行或相邻行
    json_line = json_op['line']
    input_line = user_input['line']

    if abs(json_line - input_line) <= 3:
        # 提取代码行进行分析
        lines = full_code.split('\n')
        start_line = max(0, input_line - 1)
        end_line = min(len(lines), json_line + 1)

        relevant_code = '\n'.join(lines[start_line:end_line])

        # 检查是否有赋值关系
        if re.search(rf'{re.escape(user_input["name"])}\s*=[^=]', relevant_code) and \
                re.search(rf'{re.escape(user_input["name"])}', json_op['code_snippet']):
            return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的JSON注入漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_json_injection(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 存在JSON注入漏洞的代码示例
const userInput = document.getElementById('userInput').value;
const userData = JSON.parse(userInput);  // 直接解析用户输入

// 从URL参数获取数据并解析
const urlParams = new URLSearchParams(window.location.search);
const data = urlParams.get('data');
const parsedData = JSON.parse(data);  // 直接解析URL参数

// 使用字符串拼接构造JSON
const userInput2 = document.cookie;
const jsonString = '{"data": "' + userInput2 + '"}';  // 不安全拼接
const parsedJson = JSON.parse(jsonString);

// 使用eval执行JSON
const userJson = localStorage.getItem('userData');
eval('var obj = ' + userJson);  // 使用eval解析JSON

// 使用模板字符串
const templateJson = `{"user": "${userInput}"}`;
JSON.parse(templateJson);

// 看似安全但实际上不安全的操作
function processUserData(input) {
    // 没有充分验证输入
    if (input && typeof input === 'string') {
        return JSON.parse(input);  // 仍然可能被注入
    }
}

// 安全的JSON操作示例
const safeData = JSON.parse('{"fixed": "data"}');  // 解析固定字符串
const safeStringify = JSON.stringify({key: 'value'});  // 序列化固定对象

// 使用try-catch但不充分验证
try {
    const data = JSON.parse(userInput);
} catch (e) {
    console.error('解析错误');
}

// 从请求体获取数据并解析
app.post('/api/data', (req, res) => {
    const userData = req.body;
    const parsed = JSON.parse(userData.json);  // 从请求体解析
});

// 使用Function构造函数
const dynamicFunc = new Function('return ' + userInput);
const result = dynamicFunc();
"""

    print("=" * 60)
    print("JavaScript JSON注入漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            if 'input_source' in vuln:
                print(f"   输入源: {vuln['input_source'].get('name', '未知')} (行 {vuln['input_source']['line']})")
    else:
        print("未检测到JSON注入漏洞")