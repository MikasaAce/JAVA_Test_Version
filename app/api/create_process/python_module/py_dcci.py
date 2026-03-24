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

# 定义代码注入漏洞模式
CODE_INJECTION_VULNERABILITIES = {
    'python': [
        # 检测eval函数调用
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(eval)$',
            'message': 'eval函数调用',
            'severity': '严重',
            'risk_type': 'eval_injection'
        },
        # 检测exec函数调用
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(exec|execfile)$',
            'message': 'exec函数调用',
            'severity': '严重',
            'risk_type': 'exec_injection'
        },
        # 检测compile函数调用
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_)+ @args)
                ) @call
            ''',
            'func_pattern': r'^(compile)$',
            'message': 'compile函数调用',
            'severity': '高危',
            'risk_type': 'compile_injection'
        },
        # 检测__import__函数调用
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(__import__)$',
            'message': '__import__函数调用',
            'severity': '高危',
            'risk_type': 'import_injection'
        },
        # 检测动态导入（importlib）
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
            'module_pattern': r'^(importlib)$',
            'func_pattern': r'^(import_module)$',
            'message': '动态模块导入',
            'severity': '中危',
            'risk_type': 'dynamic_import'
        },
        # 检测getattr/setattr动态属性访问
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_)+ @args)
                ) @call
            ''',
            'func_pattern': r'^(getattr|setattr|delattr|hasattr)$',
            'message': '动态属性访问',
            'severity': '中危',
            'risk_type': 'dynamic_attr'
        },
        # 检测globals/locals函数
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(globals|locals|vars)$',
            'message': '命名空间访问函数',
            'severity': '中危',
            'risk_type': 'namespace_access'
        },
        # 检测字符串格式化后执行
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @left
                            operator: "+"
                            right: (_) @right
                        ) @concat_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(eval|exec)$',
            'message': '字符串拼接后执行代码',
            'severity': '严重',
            'risk_type': 'concat_execution'
        },
        # 检测格式化字符串后执行
        {
            'query': '''
                (call
                    function: (call
                        function: (string) @format_string
                        arguments: (argument_list) @format_args
                    ) @format_call
                    arguments: (argument_list) @exec_args
                ) @call
                (#match? @format_string ".*format.*")
            ''',
            'message': '格式化字符串后执行代码',
            'severity': '高危',
            'risk_type': 'format_execution'
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
        },
        {
            'obj_pattern': r'^(sqlite3|mysql|psycopg2|pymongo)$',
            'attr_pattern': r'^(execute|executemany|find|find_one|aggregate)$',
            'message': '数据库输入'
        },
        {
            'obj_pattern': r'^(re)$',
            'attr_pattern': r'^(search|match|findall|finditer|sub|subn)$',
            'message': '正则表达式输入'
        }
    ]
}

# 动态代码构造模式
DYNAMIC_CODE_PATTERNS = {
    'query': '''
        [
            (call
                function: (identifier) @func_name
                arguments: (argument_list (_)* @args)
            ) @call
            (binary_expression
                left: (_) @left
                operator: "+" @op
                right: (_) @right
            ) @binary_expr
            (call
                function: (attribute
                    object: (_) @str_obj
                    attribute: (identifier) @str_method
                )
                arguments: (argument_list (_)* @str_args)
            ) @str_call
        ]
    ''',
    'patterns': [
        {
            'func_pattern': r'^(str|bytes|format)$',
            'message': '字符串转换函数'
        },
        {
            'str_method_pattern': r'^(format|replace|join|encode|decode)$',
            'message': '字符串操作方法'
        },
        {
            'binary_pattern': r'^\+$',
            'message': '字符串拼接操作'
        }
    ]
}

# 危险的内置函数和属性
DANGEROUS_BUILTINS = {
    'query': '''
        [
            (identifier) @builtin_name
            (attribute
                object: (_) @obj
                attribute: (identifier) @attr_name
            ) @attr
        ]
    ''',
    'dangerous_builtins': [
        '__import__', '__builtins__', '__globals__', '__locals__',
        '__code__', '__func__', '__self__', '__class__', '__bases__',
        '__subclasses__', '__mro__', '__getattribute__', '__getattr__',
        '__setattr__', '__delattr__', '__getitem__', '__setitem__',
        '__delitem__', '__call__', '__new__', '__init__', '__del__',
        '__repr__', '__str__', '__format__', '__bytes__'
    ],
    'dangerous_attributes': [
        'func_globals', 'func_code', 'gi_frame', 'f_back', 'f_locals',
        'f_globals', 'f_builtins', 'f_code', 'co_code', 'co_names',
        'co_consts', 'co_filename', 'co_firstlineno', 'co_lnotab',
        'co_freevars', 'co_cellvars', 'co_flags', 'co_stacksize',
        'co_argcount', 'co_kwonlyargcount', 'co_nlocals', 'co_varnames'
    ]
}


def detect_code_injection(code, language='python'):
    """
    检测Python代码中代码注入漏洞

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
    code_execution_calls = []  # 存储代码执行调用
    user_input_sources = []  # 存储用户输入源
    dynamic_code_constructions = []  # 存储动态代码构造
    dangerous_references = []  # 存储危险的内置引用

    # 第一步：收集所有代码执行调用
    for query_info in CODE_INJECTION_VULNERABILITIES[language]:
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

                elif tag in ['arg', 'concat_arg', 'format_string']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['call', 'format_call'] and current_capture:
                    # 检查函数名是否匹配模式
                    func_pattern = query_info.get('func_pattern', '')
                    module_pattern = query_info.get('module_pattern', '')

                    func_match = True
                    module_match = True

                    if func_pattern and 'func_name' in current_capture:
                        func_match = bool(re.match(func_pattern, current_capture['func_name'], re.IGNORECASE))

                    if module_pattern and 'module' in current_capture:
                        module_match = bool(re.match(module_pattern, current_capture['module'], re.IGNORECASE))

                    if func_match and module_match:
                        code_snippet = node.text.decode('utf8')

                        execution_call = {
                            'type': 'code_execution',
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
                        code_execution_calls.append(execution_call)
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

    # 第三步：收集动态代码构造
    try:
        query = LANGUAGES[language].query(DYNAMIC_CODE_PATTERNS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'str_method', 'op']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['call', 'binary_expr', 'str_call'] and current_capture:
                # 检查是否匹配动态代码构造模式
                for pattern_info in DYNAMIC_CODE_PATTERNS['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    str_method_pattern = pattern_info.get('str_method_pattern', '')
                    binary_pattern = pattern_info.get('binary_pattern', '')

                    match = False

                    if func_pattern and 'func_name' in current_capture:
                        if re.match(func_pattern, current_capture['func_name'], re.IGNORECASE):
                            match = True
                    elif str_method_pattern and 'str_method' in current_capture:
                        if re.match(str_method_pattern, current_capture['str_method'], re.IGNORECASE):
                            match = True
                    elif binary_pattern and 'op' in current_capture:
                        if re.match(binary_pattern, current_capture['op'], re.IGNORECASE):
                            match = True

                    if match:
                        code_snippet = node.text.decode('utf8')
                        dynamic_code_constructions.append({
                            'line': current_capture['line'],
                            'type': tag,
                            'operation': current_capture.get('func_name') or current_capture.get(
                                'str_method') or current_capture.get('op'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': pattern_info.get('message', '')
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"动态代码构造查询错误: {e}")

    # 第四步：收集危险的内置引用
    try:
        query = LANGUAGES[language].query(DANGEROUS_BUILTINS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'builtin_name':
                name = node.text.decode('utf8')
                if name in DANGEROUS_BUILTINS['dangerous_builtins']:
                    dangerous_references.append({
                        'line': node.start_point[0] + 1,
                        'type': 'dangerous_builtin',
                        'name': name,
                        'code_snippet': node.text.decode('utf8'),
                        'node': node,
                        'message': f'危险内置函数/变量: {name}'
                    })
            elif tag == 'attr_name':
                name = node.text.decode('utf8')
                if name in DANGEROUS_BUILTINS['dangerous_attributes']:
                    dangerous_references.append({
                        'line': node.start_point[0] + 1,
                        'type': 'dangerous_attribute',
                        'name': name,
                        'code_snippet': node.parent.text.decode('utf8'),
                        'node': node.parent,
                        'message': f'危险属性访问: {name}'
                    })

    except Exception as e:
        print(f"危险内置引用查询错误: {e}")

    # 第五步：分析漏洞
    for call in code_execution_calls:
        vulnerability_details = analyze_code_injection_vulnerability(
            call, user_input_sources, dynamic_code_constructions, dangerous_references, root
        )

        if vulnerability_details:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_code_injection_vulnerability(call, user_input_sources, dynamic_code_constructions, dangerous_references,
                                         root):
    """
    分析单个代码执行调用的漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': call['line'],
        'code_snippet': call['code_snippet'],
        'vulnerability_type': '代码注入',
        'severity': call['severity'],
        'function': call['function'],
        'risk_type': call['risk_type']
    }

    # 情况1: eval/exec直接调用
    if call['risk_type'] in ['eval_injection', 'exec_injection']:
        vulnerability_details['message'] = (
            f"代码执行函数: {call['function']} - "
            f"可能执行任意Python代码"
        )
        is_vulnerable = True

    # 情况2: compile函数调用
    elif call['risk_type'] == 'compile_injection':
        vulnerability_details['message'] = (
            f"代码编译函数: {call['function']} - "
            f"可能编译并执行任意代码"
        )
        is_vulnerable = True

    # 情况3: 动态导入
    elif call['risk_type'] in ['import_injection', 'dynamic_import']:
        vulnerability_details['message'] = (
            f"动态导入: {call['function']} - "
            f"可能导入恶意模块"
        )
        is_vulnerable = True

    # 情况4: 动态属性访问
    elif call['risk_type'] == 'dynamic_attr':
        vulnerability_details['message'] = (
            f"动态属性访问: {call['function']} - "
            f"可能访问或修改敏感属性"
        )
        is_vulnerable = True

    # 情况5: 参数来自用户输入
    if call['arg_node'] and is_user_input_related(call['arg_node'], user_input_sources, root):
        vulnerability_details['message'] += " (数据来自用户输入)"
        vulnerability_details['severity'] = elevate_severity(vulnerability_details['severity'])
        is_vulnerable = True

    # 情况6: 动态代码构造
    if has_dynamic_construction(call, dynamic_code_constructions):
        vulnerability_details['message'] += " (使用动态代码构造)"
        vulnerability_details['severity'] = elevate_severity(vulnerability_details['severity'])
        is_vulnerable = True

    # 情况7: 包含危险内置引用
    if has_dangerous_references(call, dangerous_references):
        vulnerability_details['message'] += " (引用危险内置对象)"
        is_vulnerable = True

    # 情况8: 检查参数内容
    if call['argument'] and contains_dangerous_patterns(call['argument']):
        vulnerability_details['message'] += " (参数包含危险模式)"
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'data', 'code', 'command',
                       'script', 'expression', 'query', 'request', 'response',
                       'body', 'content', 'payload', 'param', 'form', 'file']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def has_dynamic_construction(call, dynamic_code_constructions):
    """
    检查是否有动态代码构造
    """
    for construction in dynamic_code_constructions:
        if abs(construction['line'] - call['line']) <= 10:  # 10行范围内
            return True
    return False


def has_dangerous_references(call, dangerous_references):
    """
    检查是否有危险的内置引用
    """
    call_text = call['code_snippet'].lower()

    for ref in dangerous_references:
        if ref['name'].lower() in call_text:
            return True

    return False


def contains_dangerous_patterns(argument):
    """
    检查参数是否包含危险模式
    """
    dangerous_patterns = [
        # Python内置危险函数
        r'__import__', r'__builtins__', r'__globals__', r'__locals__',
        r'__code__', r'__class__', r'__bases__', r'__subclasses__',
        r'__getattribute__', r'__getattr__', r'__setattr__',
        r'__getitem__', r'__setitem__', r'__call__', r'__new__',

        # 系统命令执行
        r'os\.system', r'os\.popen', r'subprocess', r'commands',
        r'popen2', r'popen3', r'popen4',

        # 文件操作
        r'open\(', r'file\(', r'__file__',

        # 网络操作
        r'urllib', r'requests', r'socket',

        # 序列化
        r'pickle', r'marshal', r'yaml', r'json',

        # 其他危险模式
        r'import\s+\w+', r'from\s+\w+\s+import',
        r'def\s+\w+', r'class\s+\w+', r'lambda\s',
        r'print', r'assert', r'del\s', r'global\s',
        r'nonlocal\s', r'raise\s', r'try:', r'except\s',
        r'finally:', r'with\s', r'while\s', r'for\s',
        r'if\s', r'else:', r'elif\s'
    ]

    for pattern in dangerous_patterns:
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


def analyze_python_code_injection(code_string):
    """
    分析Python代码字符串中的代码注入漏洞
    """
    return detect_code_injection(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import os
import subprocess
from flask import request
import importlib

def vulnerable_code_injection():
    # 1. eval直接执行用户输入 - 严重
    user_code = input("Enter Python code: ")
    result = eval(user_code)  # 严重漏洞 - 代码注入

    # 2. exec执行用户输入
    malicious_script = request.args.get('script')
    exec(malicious_script)  # 严重漏洞

    # 3. 字符串拼接后执行
    base_code = "print('"
    user_input = request.form.get('message')
    full_code = base_code + user_input + "')"
    eval(full_code)  # 严重漏洞

    # 4. 格式化字符串后执行
    template = "{} + {}"
    a = request.json.get('a')
    b = request.json.get('b')
    expression = template.format(a, b)
    result = eval(expression)  # 高危漏洞

    # 5. compile动态编译
    user_source = request.files['source'].read().decode()
    code_obj = compile(user_source, '<string>', 'exec')
    exec(code_obj)  # 严重漏洞

    # 6. 动态导入
    module_name = request.cookies.get('module')
    malicious_module = __import__(module_name)  # 高危漏洞

    # 7. importlib动态导入
    plugin_name = input("Enter plugin name: ")
    plugin = importlib.import_module(plugin_name)  # 中危漏洞

    # 8. 动态属性访问
    obj = some_object
    attr_name = request.args.get('attribute')
    value = getattr(obj, attr_name)  # 中危漏洞

    # 9. 访问危险内置属性
    class_obj = object.__class__
    subclasses = class_obj.__subclasses__()  # 危险操作

    # 10. 使用globals/locals
    namespace = globals()
    user_var = request.args.get('var')
    if user_var in namespace:
        del namespace[user_var]  # 危险操作

def safe_usage():
    # 1. 硬编码的eval
    result = eval("2 + 2")  # 相对安全

    # 2. 受限的执行环境
    safe_builtins = {'__builtins__': None}
    user_input = "1 + 1"
    result = eval(user_input, safe_builtins)  # 相对安全

    # 3. 白名单验证
    user_code = input("Enter simple expression: ")
    if is_safe_expression(user_code):
        result = eval(user_code)  # 带有验证

    # 4. 静态导入
    import math
    result = math.sqrt(16)  # 安全

def is_safe_expression(expr):
    '''简单的表达式安全检查'''
    # 只允许简单的数学表达式
    safe_pattern = r'^[0-9+\-*/().\\s]+$'
    return bool(re.match(safe_pattern, expr))

def advanced_injection_techniques():
    # 利用__builtins__
    code = "__import__('os').system('rm -rf /')"
    eval(code)  # 严重漏洞

    # 利用__globals__
    def test_function():
        return "test"

    user_code = "test_function.__globals__"
    result = eval(user_code)  # 高危漏洞

    # 类属性遍历
    user_class = object.__class__
    user_subclasses = user_class.__subclasses__()
    # 进一步利用...

if __name__ == "__main__":
    vulnerable_code_injection()
    safe_usage()
    advanced_injection_techniques()
"""

    print("=" * 70)
    print("Python代码注入漏洞检测")
    print("=" * 70)

    results = analyze_python_code_injection(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:80]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   风险类型: {vuln['risk_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   函数调用: {vuln.get('function', '')}")
            print("-" * 50)
    else:
        print("未检测到代码注入漏洞")