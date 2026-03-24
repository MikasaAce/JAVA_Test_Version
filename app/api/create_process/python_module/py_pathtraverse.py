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

# 定义路径遍历漏洞模式
PATH_TRAVERSAL_VULNERABILITIES = {
    'python': [
        # 检测文件打开操作 - 直接用户输入
        {
            'query': '''
                (call
                    function: (identifier) @file_func
                    arguments: (argument_list 
                        (_) @file_path
                    )
                ) @call
            ''',
            'func_pattern': r'^(open|file)$',
            'message': '文件打开操作'
        },
        # 检测文件操作函数 - 属性访问
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @module_obj
                        attribute: (identifier) @file_func
                    )
                    arguments: (argument_list 
                        (_) @file_path
                    )
                ) @call
            ''',
            'module_pattern': r'^(os|shutil|pathlib|Path)$',
            'func_pattern': r'^(open|remove|unlink|rename|chmod|chown|stat|lstat|listdir|walk|scandir|mkdir|makedirs|rmdir|removedirs)$',
            'message': '文件系统操作'
        },
        # 检测路径拼接操作
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @module_obj
                        attribute: (identifier) @path_func
                    )
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @path_left
                            operator: "+"
                            right: (_) @path_right
                        ) @concat_path
                    )
                ) @call
            ''',
            'module_pattern': r'^(os|os\.path)$',
            'func_pattern': r'^(path\.join|join)$',
            'message': '路径拼接操作'
        },
        # 检测os.path.join调用
        {
            'query': '''
                (call
                    function: (attribute
                        object: (attribute
                            object: (identifier) @os_module
                            attribute: (identifier) @path_module
                        )
                        attribute: (identifier) @join_func
                    )
                    arguments: (argument_list (_)* @join_args)
                ) @call
            ''',
            'os_pattern': r'^os$',
            'path_pattern': r'^path$',
            'func_pattern': r'^(join|abspath|normpath|realpath)$',
            'message': 'os.path路径操作'
        },
        # 检测字符串拼接的文件路径
        {
            'query': '''
                (call
                    function: (identifier) @file_func
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @path_left
                            operator: "+"
                            right: (_) @path_right
                        ) @concat_path
                    )
                ) @call
            ''',
            'func_pattern': r'^(open|file)$',
            'message': '字符串拼接的文件路径'
        },
        # 检测format格式化的文件路径
        {
            'query': '''
                (call
                    function: (identifier) @file_func
                    arguments: (argument_list 
                        (call
                            function: (attribute
                                object: (string) @base_path
                                attribute: (identifier) @format_method
                            )
                            arguments: (argument_list (_)* @format_args)
                        ) @format_call
                    )
                ) @call
            ''',
            'func_pattern': r'^(open|file)$',
            'message': 'format格式化的文件路径'
        },
        # 检测f-string文件路径
        {
            'query': '''
                (call
                    function: (identifier) @file_func
                    arguments: (argument_list 
                        (interpolation) @fstring_path
                    )
                ) @call
            ''',
            'func_pattern': r'^(open|file)$',
            'message': 'f-string文件路径'
        },
        # 检测文件读取操作
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @file_obj
                        attribute: (identifier) @read_method
                    )
                    arguments: (argument_list) @args
                ) @call
            ''',
            'method_pattern': r'^(read|readline|readlines|write|writelines)$',
            'message': '文件读写操作'
        },
        # 检测with语句中的文件操作
        {
            'query': '''
                (with_statement
                    body: (block) @with_body
                    (with_clause
                        (with_item
                            value: (call
                                function: (identifier) @file_func
                                arguments: (argument_list (_) @file_path)
                            ) @file_call
                        ) @with_item
                    ) @with_clause
                ) @with_stmt
            ''',
            'func_pattern': r'^(open)$',
            'message': 'with语句文件操作'
        }
    ]
}

# 用户输入源模式（路径遍历相关）
PATH_USER_INPUT_SOURCES = {
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
            'obj_pattern': r'^(flask|django)\.request$',
            'attr_pattern': r'^(args|form|values|data|json|files|get|post)$',
            'message': 'Web请求参数'
        },
        {
            'obj_pattern': r'^request$',
            'attr_pattern': r'^(args|form|values|data|json|files|get|post)$',
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
        }
    ]
}

# 路径构建模式
PATH_BUILDING_PATTERNS = {
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
            (assignment
                left: (identifier) @var_name
                right: (call
                    function: (attribute
                        object: (identifier) @module_obj
                        attribute: (identifier) @path_func
                    )
                    arguments: (argument_list (_)* @path_args)
                ) @path_call
            )
        ] @assignment
    ''',
    'patterns': [
        {
            'var_pattern': r'^(path|file_path|filename|file_name|filepath|file|dir|directory|upload_path|download_path)$',
            'message': '文件路径构建'
        },
        {
            'base_string_pattern': r'^(/|\./|\.\./|\\|\.\\|\.\\.\\)',
            'message': '路径字符串构建'
        },
        {
            'module_pattern': r'^(os\.path|pathlib|Path)$',
            'func_pattern': r'^(join|abspath|normpath|realpath)$',
            'message': '路径处理函数调用'
        }
    ]
}

# 危险路径模式
DANGEROUS_PATH_PATTERNS = {
    'traversal_patterns': [
        r'\.\./',
        r'\.\.\\',
        r'/\.\./',
        r'\\\.\.\\',
        r'~/',
        r'%2e%2e%2f',  # URL编码的../
        r'%2e%2e/',     # 部分编码的../
        r'..%2f',       # 部分编码的../
        r'%2e%2e%5c',   # URL编码的..\
        r'..%5c',       # 部分编码的..\
        r'\.\.%00',     # 空字节注入
    ],
    'sensitive_directories': [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/etc/group',
        '/etc/sudoers',
        '/var/log',
        '/root',
        '/home',
        '/proc/',
        '/sys/',
        'C:\\Windows\\System32',
        'C:\\Windows\\SysWOW64',
        'C:\\boot.ini',
        'C:\\Windows\\win.ini'
    ]
}

def analyze_path_traversal(code, language='python'):
    """
    检测Python代码中路径遍历漏洞

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
    file_operations = []  # 存储文件操作
    user_input_sources = []  # 存储用户输入源
    path_buildings = []  # 存储路径构建操作

    # 第一步：收集所有文件操作
    for query_info in PATH_TRAVERSAL_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['file_func', 'module_obj', 'path_func', 'join_func', 'read_method', 'file_obj']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['file_path', 'path_left', 'path_right', 'base_path', 'fstring_path']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['format_method', 'format_call', 'os_module', 'path_module']:
                    current_capture[tag] = node.text.decode('utf8')

                elif tag in ['call', 'with_stmt'] and current_capture:
                    # 检查函数名是否匹配模式
                    func_pattern = query_info.get('func_pattern', '')
                    module_pattern = query_info.get('module_pattern', '')
                    os_pattern = query_info.get('os_pattern', '')
                    path_pattern = query_info.get('path_pattern', '')
                    method_pattern = query_info.get('method_pattern', '')

                    func_match = True
                    module_match = True
                    os_match = True
                    path_match = True
                    method_match = True

                    if func_pattern and 'file_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['file_func'], re.IGNORECASE)
                    elif func_pattern and 'path_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['path_func'], re.IGNORECASE)
                    elif func_pattern and 'join_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['join_func'], re.IGNORECASE)

                    if method_pattern and 'read_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['read_method'], re.IGNORECASE)

                    if module_pattern and 'module_obj' in current_capture:
                        module_match = re.match(module_pattern, current_capture['module_obj'], re.IGNORECASE)

                    if os_pattern and 'os_module' in current_capture:
                        os_match = re.match(os_pattern, current_capture['os_module'], re.IGNORECASE)

                    if path_pattern and 'path_module' in current_capture:
                        path_match = re.match(path_pattern, current_capture['path_module'], re.IGNORECASE)

                    if func_match and module_match and os_match and path_match and method_match:
                        code_snippet = node.text.decode('utf8')

                        file_operations.append({
                            'type': 'file_operation',
                            'line': current_capture['line'],
                            'function': current_capture.get('file_func', '') or 
                                      current_capture.get('path_func', '') or
                                      current_capture.get('join_func', '') or
                                      current_capture.get('read_method', ''),
                            'module': current_capture.get('module_obj', ''),
                            'file_path': current_capture.get('file_path', '') or 
                                       current_capture.get('path_left', '') or
                                       current_capture.get('fstring_path', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'vulnerability_type': query_info.get('message', '路径遍历风险')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"路径遍历查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(PATH_USER_INPUT_SOURCES['query'])
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
                for pattern_info in PATH_USER_INPUT_SOURCES['patterns']:
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

    # 第三步：收集路径构建操作
    try:
        query = LANGUAGES[language].query(PATH_BUILDING_PATTERNS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['var_name', 'format_method', 'module_obj', 'path_func']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['base_string', 'left_expr', 'right_expr', 'fstring_expr']:
                current_capture[tag] = node.text.decode('utf8')

            elif tag == 'assignment' and current_capture:
                # 检查是否匹配路径构建模式
                for pattern_info in PATH_BUILDING_PATTERNS['patterns']:
                    var_pattern = pattern_info.get('var_pattern', '')
                    base_string_pattern = pattern_info.get('base_string_pattern', '')
                    module_pattern = pattern_info.get('module_pattern', '')
                    func_pattern = pattern_info.get('func_pattern', '')

                    var_match = False
                    base_match = True
                    module_match = True
                    func_match = True

                    if var_pattern and 'var_name' in current_capture:
                        var_match = re.match(var_pattern, current_capture['var_name'], re.IGNORECASE)

                    if base_string_pattern and 'base_string' in current_capture:
                        base_match = re.match(base_string_pattern, current_capture['base_string'], re.IGNORECASE)

                    if module_pattern and 'module_obj' in current_capture:
                        module_match = re.match(module_pattern, current_capture['module_obj'], re.IGNORECASE)

                    if func_pattern and 'path_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['path_func'], re.IGNORECASE)

                    if var_match and base_match and module_match and func_match:
                        code_snippet = node.text.decode('utf8')
                        path_buildings.append({
                            'type': 'path_building',
                            'line': current_capture['line'],
                            'variable': current_capture.get('var_name', ''),
                            'base_string': current_capture.get('base_string', ''),
                            'expression': current_capture.get('left_expr', '') + ' + ' + current_capture.get('right_expr', ''),
                            'function': current_capture.get('path_func', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"路径构建查询错误: {e}")

    # 第四步：分析路径遍历漏洞
    for file_op in file_operations:
        vulnerability_details = analyze_file_operation(file_op, user_input_sources, path_buildings)
        if vulnerability_details:
            vulnerabilities.extend(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_file_operation(file_op, user_input_sources, path_buildings):
    """
    分析单个文件操作的安全问题
    """
    vulnerabilities = []
    code_snippet = file_op['code_snippet']
    line = file_op['line']
    function_name = file_op['function']
    file_path = file_op['file_path']

    # 检查直接用户输入
    if is_direct_user_input(file_op, user_input_sources):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '路径遍历',
            'severity': '高危',
            'message': f"{function_name} 函数直接使用用户输入作为文件路径"
        })

    # 检查字符串拼接
    elif is_string_concatenation(file_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '路径遍历',
            'severity': '高危',
            'message': f"{function_name} 函数使用字符串拼接构建文件路径"
        })

    # 检查format格式化
    elif is_format_operation(file_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '路径遍历',
            'severity': '高危',
            'message': f"{function_name} 函数使用format方法构建文件路径"
        })

    # 检查f-string格式化
    elif is_fstring_operation(file_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '路径遍历',
            'severity': '高危',
            'message': f"{function_name} 函数使用f-string构建文件路径"
        })

    # 检查危险路径模式
    elif contains_dangerous_patterns(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '路径遍历',
            'severity': '高危',
            'message': f"{function_name} 函数包含危险的路径遍历模式"
        })

    # 检查敏感文件访问
    elif accesses_sensitive_files(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '路径遍历',
            'severity': '严重',
            'message': f"{function_name} 函数可能访问敏感系统文件"
        })

    # 检查路径验证缺失
    elif not has_path_validation(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '路径遍历',
            'severity': '中危',
            'message': f"{function_name} 函数缺少路径验证逻辑"
        })

    return vulnerabilities


def is_direct_user_input(file_op, user_input_sources):
    """
    检查文件路径是否直接来自用户输入
    """
    file_path = file_op['file_path']
    
    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'request', 'args', 'form', 'get', 
                      'post', 'filename', 'file_name', 'filepath', 'path', 'dir']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', file_path, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == file_op['node'] or is_child_node(file_op['node'], source['node']):
            return True

    return False


def is_string_concatenation(file_op):
    """
    检查是否使用字符串拼接构建路径
    """
    code_snippet = file_op['code_snippet']
    return '+' in code_snippet and ('open' in code_snippet or 'file' in code_snippet or 'os.' in code_snippet)


def is_format_operation(file_op):
    """
    检查是否使用format方法构建路径
    """
    return 'format' in file_op.get('format_method', '')


def is_fstring_operation(file_op):
    """
    检查是否使用f-string构建路径
    """
    return 'fstring_path' in file_op


def contains_dangerous_patterns(code_snippet):
    """
    检查是否包含危险的路径遍历模式
    """
    for pattern in DANGEROUS_PATH_PATTERNS['traversal_patterns']:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True
    return False


def accesses_sensitive_files(code_snippet):
    """
    检查是否可能访问敏感文件
    """
    for sensitive_file in DANGEROUS_PATH_PATTERNS['sensitive_directories']:
        if sensitive_file in code_snippet:
            return True
    return False


def has_path_validation(code_snippet):
    """
    检查代码片段是否包含路径验证逻辑
    """
    validation_patterns = [
        r'os\.path\.abspath',
        r'os\.path\.normpath',
        r'os\.path\.realpath',
        r'startswith\([\'"]/safe/path[\'"]\)',
        r'basename',
        r'secure_filename',
        r'whitelist',
        r'allowed_paths',
        r'validate_path',
        r'sanitize.*path',
        r'path\.is_absolute',
        r'Path\.resolve'
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


def analyze_path_traversal_main(code_string):
    """
    主函数：分析Python代码字符串中的路径遍历漏洞
    """
    return analyze_path_traversal(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import os
import shutil
from flask import request
from pathlib import Path
import sys

# 不安全的路径遍历示例
def insecure_path_examples():
    # 直接用户输入文件路径 - 高危
    filename = request.args.get('file')
    with open(filename, 'r') as f:  # 高危: 路径遍历
        content = f.read()
    
    # 字符串拼接路径 - 高危
    base_dir = "/var/www/uploads/"
    user_file = request.form.get('user_file')
    file_path = base_dir + user_file  # 高危
    os.remove(file_path)
    
    # format格式化路径 - 高危
    user_id = request.json.get('user_id')
    log_path = "/var/log/user_{}.log".format(user_id)  # 高危
    open(log_path, 'w')
    
    # f-string路径 - 高危
    username = request.args.get('username')
    config_path = f"/etc/{username}/config.conf"  # 高危
    shutil.copy(config_path, '/tmp/')
    
    # 直接路径遍历 - 严重
    malicious_path = "../../../etc/passwd"
    open(malicious_path, 'r')  # 严重: 敏感文件访问
    
    # os.path.join不安全使用 - 高危
    user_input = request.files['file'].filename
    full_path = os.path.join('/uploads', user_input)  # 高危: 如果user_input包含../
    os.rename(full_path, '/tmp/file')
    
    # 没有验证的文件操作 - 中危
    file_to_read = request.args.get('file', 'default.txt')
    return open(file_to_read).read()  # 中危: 缺少验证

# 相对安全的文件操作示例
def safe_path_examples():
    # 硬编码路径 - 安全
    with open('/etc/secure_config.conf', 'r') as f:  # 安全: 硬编码
        config = f.read()
    
    # 经过验证的路径 - 安全
    user_file = request.args.get('file')
    if user_file and user_file.endswith('.txt'):
        safe_path = os.path.join('/safe_dir', user_file)  # 相对安全
        open(safe_path, 'r')
    
    # 使用basename - 安全
    filename = os.path.basename(request.files['file'].filename)
    safe_path = os.path.join('/uploads', filename)  # 安全: 使用basename
    shutil.move(safe_path, '/processed/')
    
    # 路径规范化 - 安全
    user_path = request.form.get('path')
    normalized_path = os.path.normpath(user_path)  # 安全: 规范化
    if normalized_path.startswith('/allowed'):
        open(normalized_path, 'r')
    
    # 白名单验证 - 安全
    allowed_files = ['file1.txt', 'file2.txt', 'file3.txt']
    file_to_open = request.args.get('file')
    if file_to_open in allowed_files:
        open(f'/data/{file_to_open}', 'r')  # 安全: 白名单
    
    # 使用pathlib安全操作 - 安全
    user_input = request.args.get('dir')
    base_path = Path('/safe/base')
    target_path = base_path / user_input  # 相对安全
    if base_path in target_path.parents:  # 安全: 路径检查
        target_path.read_text()

# 文件上传相关示例
def file_upload_examples():
    # 不安全的文件上传
    uploaded_file = request.files['file']
    filename = uploaded_file.filename
    file_path = os.path.join('/uploads', filename)  # 高危
    uploaded_file.save(file_path)
    
    # 相对安全的文件上传
    from werkzeug.utils import secure_filename
    uploaded_file = request.files['file']
    safe_filename = secure_filename(uploaded_file.filename)  # 安全: 使用secure_filename
    file_path = os.path.join('/uploads', safe_filename)
    uploaded_file.save(file_path)
    
    # 自定义安全验证
    filename = request.files['file'].filename
    if is_safe_filename(filename):
        file_path = os.path.join('/uploads', filename)
        uploaded_file.save(file_path)

# 路径处理函数示例
def path_handling_examples():
    # 不安全的路径处理
    user_path = request.args.get('path', '.')
    absolute_path = os.path.abspath(user_path)  # 高危: 可能逃逸
    files = os.listdir(absolute_path)
    
    # 安全的路径处理
    user_path = request.args.get('path')
    base_dir = '/allowed/base'
    full_path = os.path.join(base_dir, user_path)
    normalized = os.path.normpath(full_path)
    if normalized.startswith(base_dir):  # 安全: 路径检查
        os.listdir(normalized)

# 辅助函数
def is_safe_filename(filename):
    \"\"\"检查文件名是否安全\"\"\"
    if not filename:
        return False
        
    # 检查路径遍历字符
    if '..' in filename or '/' in filename or '\\\\' in filename:
        return False
        
    # 检查文件扩展名
    allowed_extensions = ['.txt', '.pdf', '.jpg', '.png']
    return any(filename.lower().endswith(ext) for ext in allowed_extensions)

# 混合示例
def mixed_examples():
    # 部分验证
    user_file = request.args.get('file')
    if user_file:  # 验证不充分
        open(user_file, 'r')  # 高危
    
    # 使用内置安全函数
    from werkzeug.utils import secure_filename
    filename = secure_filename(request.files['file'].filename)
    open(f'/uploads/{filename}', 'wb')  # 安全
    
    # 直接系统命令中的路径遍历
    user_input = request.args.get('cmd')
    os.system(f"cat /var/log/{user_input}")  # 高危: 命令注入+路径遍历

if __name__ == "__main__":
    insecure_path_examples()
    safe_path_examples()
    file_upload_examples()
    path_handling_examples()
    mixed_examples()
"""

    print("=" * 60)
    print("Python 路径遍历漏洞检测")
    print("=" * 60)

    results = analyze_path_traversal_main(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个路径遍历漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到路径遍历漏洞")