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

# 定义Python命令注入漏洞模式
COMMAND_INJECTION_VULNERABILITIES = {
    'python': [
        # 检测os.system函数调用
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
            'module_pattern': r'^(os|subprocess)$',
            'func_pattern': r'^(system|popen|call|run|Popen)$',
            'message': '系统命令执行函数调用'
        },
        # 检测直接导入的函数调用
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(system|popen|call|run)$',
            'message': '直接命令执行函数调用'
        },
        # 检测subprocess模块调用
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
            'module_pattern': r'^subprocess$',
            'func_pattern': r'^(call|run|Popen|check_output|check_call)$',
            'message': 'subprocess模块命令执行'
        },
        # 检测字符串拼接后传递给危险函数
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @module
                        attribute: (identifier) @func_name
                    )
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @left
                            operator: "+"
                            right: (_) @right
                        ) @concat_arg
                    )
                ) @call
            ''',
            'module_pattern': r'^(os|subprocess)$',
            'func_pattern': r'^(system|popen|call|run|Popen)$',
            'message': '字符串拼接后的命令执行'
        },
        # 检测shell=True的subprocess调用
        {
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
                            value: (true) @shell_true
                        ) @shell_kw
                    )
                ) @call
            ''',
            'module_pattern': r'^subprocess$',
            'func_pattern': r'^(run|call|Popen|check_output|check_call)$',
            'message': '使用shell=True的subprocess调用'
        },
        # 检测eval和exec函数
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(eval|exec|execfile|compile)$',
            'message': '代码执行函数调用'
        }
    ]
}

# Python用户输入源模式
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
            'obj_pattern': r'^(flask|django)\.request$',
            'attr_pattern': r'^(args|form|values|data|json|files|headers|cookies)$',
            'message': 'Web框架输入'
        }
    ]
}

# 危险字符串操作模式
DANGEROUS_STRING_OPERATIONS = {
    'query': '''
        [
            (call
                function: (identifier) @func_name
                arguments: (argument_list (_)* @args)
            )
            (call
                function: (attribute
                    object: (_) @obj
                    attribute: (identifier) @attr
                )
                arguments: (argument_list (_)* @args)
            )
        ] @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(str\.format|format)$',
            'message': '字符串格式化'
        },
        {
            'func_pattern': r'^\%$',  # % 操作符
            'message': '字符串格式化操作符'
        },
        {
            'func_pattern': r'^(replace|join|strip|lstrip|rstrip)$',
            'message': '字符串操作'
        },
        {
            'func_pattern': r'^(encode|decode)$',
            'message': '编码解码操作'
        }
    ]
}


def detect_python_command_injection(code, language='python'):
    """
    检测Python代码中命令注入漏洞

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
    dangerous_calls = []  # 存储所有危险函数调用
    user_input_sources = []  # 存储用户输入源
    dangerous_string_ops = []  # 存储危险字符串操作

    # 第一步：收集所有危险函数调用
    for query_info in COMMAND_INJECTION_VULNERABILITIES[language]:
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

                elif tag in ['arg', 'concat_arg', 'shell_kw']:
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

                        dangerous_calls.append({
                            'type': 'dangerous_call',
                            'line': current_capture['line'],
                            'module': current_capture.get('module', ''),
                            'function': current_capture.get('func_name', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'shell_true': 'shell_kw' in current_capture,
                            'code_snippet': code_snippet,
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有用户输入源
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
                # 检查是否匹配任何用户输入模式
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

    # 第三步：收集危险字符串操作
    try:
        query = LANGUAGES[language].query(DANGEROUS_STRING_OPERATIONS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'obj', 'attr']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'call' and current_capture:
                # 检查是否匹配危险字符串操作模式
                for pattern_info in DANGEROUS_STRING_OPERATIONS['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')

                    if 'func_name' in current_capture and re.match(func_pattern, current_capture['func_name'],
                                                                   re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        dangerous_string_ops.append({
                            'line': current_capture['line'],
                            'function': current_capture['func_name'],
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"危险字符串操作查询错误: {e}")

    # 第四步：分析漏洞
    for call in dangerous_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '命令注入',
            'severity': '高危'
        }

        # 情况1: 直接使用字符串字面量
        if call['argument'] and is_direct_command(call['argument']):
            vulnerability_details['message'] = f"直接命令执行: {call['function']} 调用包含可能危险的命令"
            is_vulnerable = True

        # 情况2: shell=True 的subprocess调用
        elif call['shell_true']:
            vulnerability_details['message'] = f"使用shell=True的subprocess调用: {call['function']}"
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True

        # 情况3: 检查参数是否来自用户输入
        elif call['arg_node'] and is_user_input_related(call['arg_node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入直接传递给危险函数: {call['function']}"
            is_vulnerable = True

        # 情况4: 检查参数是否经过危险字符串操作
        elif call['arg_node'] and is_dangerous_string_operation(call['arg_node'], dangerous_string_ops, root):
            vulnerability_details['message'] = f"经过危险字符串操作后传递给命令执行函数: {call['function']}"
            is_vulnerable = True

        # 情况5: eval/exec函数调用
        elif call['function'] in ['eval', 'exec', 'execfile']:
            vulnerability_details['message'] = f"代码执行函数调用: {call['function']}"
            vulnerability_details['severity'] = '严重'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_direct_command(argument):
    """
    检查参数是否看起来像直接命令
    """
    command_patterns = [
        r'^\s*(rm\s+-|del\s+|ls\s*$|dir\s*$|cat\s+|echo\s+|ping\s+|curl\s+|wget\s+)',
        r'^\s*(\w+\.(exe|bat|cmd|ps1|sh|py)\b)',
        r'[;&|`]\s*\w',
        r'^\s*cmd\.exe\s+/c',
        r'^\s*/bin/(bash|sh)\s+-c',
        r'\$\{?[^\}]+\}?',  # 类似 ${VAR} 的变量
    ]

    for pattern in command_patterns:
        if re.search(pattern, argument, re.IGNORECASE):
            return True

    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'input', 'user_input', 'data', 'cmd', 'command',
                       'param', 'args', 'kwargs', 'request', 'query', 'form']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_dangerous_string_operation(arg_node, dangerous_string_ops, root_node):
    """
    检查参数是否经过危险字符串操作
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查是否直接使用了危险字符串函数的缓冲区
    for op in dangerous_string_ops:
        # 简单的文本匹配（实际应用中需要更精确的数据流分析）
        if op['function'] in arg_text:
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


def analyze_python_code(code_string):
    """
    分析Python代码字符串中的命令注入漏洞
    """
    return detect_python_command_injection(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import os
import subprocess
import sys
from flask import request

def vulnerable_function():
    # 直接命令执行 - 高危
    os.system("ls -la")

    # 用户输入直接传递给命令 - 高危
    user_input = input("Enter command: ")
    os.system(user_input)  # 命令注入漏洞

    # 命令行参数直接使用
    if len(sys.argv) > 1:
        subprocess.call(sys.argv[1], shell=True)  # 高危

    # 环境变量直接使用
    path = os.getenv("PATH")
    os.system(f"echo {path}")  # 危险的环境变量使用

    # 字符串拼接后执行 - 高危
    command = "echo "
    user_data = input("Enter data: ")
    command += user_data
    os.system(command)  # 命令注入

    # subprocess with shell=True
    subprocess.run("ls -la", shell=True)  # 高危

    # eval函数 - 严重漏洞
    user_code = input("Enter code: ")
    eval(user_code)  # 代码注入

    # Web框架输入
    def web_handler():
        cmd = request.args.get('command')
        os.system(cmd)  # 命令注入

    # 相对安全的做法
    subprocess.run(["ls", "-la"])  # 相对安全
    subprocess.call(["echo", "hello"])  # 相对安全

def safe_function():
    # 安全的硬编码命令
    os.system("echo Hello World")

    # 安全的参数化执行
    subprocess.run(["ls", "-l"])

    # 安全的列表形式调用
    subprocess.Popen(["echo", "safe"])

if __name__ == "__main__":
    vulnerable_function()
    safe_function()
"""

    print("=" * 60)
    print("Python命令注入漏洞检测")
    print("=" * 60)

    results = analyze_python_code(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到命令注入漏洞")