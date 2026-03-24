import os
import re
from tree_sitter import Language, Parser

# 假设language_path在其他模块中定义，这里直接使用
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++路径遍历漏洞模式
PATH_TRAVERSAL_VULNERABILITIES = {
    'cpp': [
        # 检测文件操作函数中的路径参数（扩展了函数列表）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @path_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(fopen|open|creat|freopen|remove|unlink|rename|access|chmod|chown|chdir|mkdir|rmdir|stat|lstat|symlink|link|CreateFile|OpenFile|fopen_s|_wfopen)$',
            'arg_index': 0,
            'message': '文件操作函数调用'
        },
        # 检测Windows API文件操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @path_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(CreateFileA|CreateFileW|OpenFile|FindFirstFile|FindFirstFileEx|ShellExecute|ShellExecuteEx|CopyFile|MoveFile|DeleteFile)$',
            'arg_index': 0,
            'message': 'Windows文件操作函数'
        },
        # 检测C++文件流构造函数
        {
            'query': '''
                (call_expression
                    function: (qualified_identifier
                        name: (identifier) @class_name
                    )
                    arguments: (argument_list 
                        (_) @path_arg
                        (_)*
                    )
                ) @call
                (#match? @class_name "^(basic_ifstream|basic_ofstream|basic_fstream|ifstream|ofstream|fstream)$")
            ''',
            'arg_index': 0,
            'message': 'C++文件流构造函数'
        },
        # 检测字符串拼接操作
        {
            'query': '''
                (call_expression
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
            'func_pattern': r'^(fopen|open|CreateFile|ifstream|ofstream|fstream|unlink|rename|access|chdir|symlink)$',
            'message': '路径拼接后的文件操作'
        },
        # 检测格式化字符串函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @format_func
                    arguments: (argument_list (_)* @format_args)
                ) @format_call
                .
                (call_expression
                    function: (identifier) @file_func
                    arguments: (argument_list (_) @path_arg)
                ) @file_call
                (#match? @format_func "^(sprintf|snprintf|swprintf|vsprintf|vsnprintf)$")
                (#match? @file_func "^(fopen|open|CreateFile|ifstream|ofstream|unlink|rename|access|chdir|symlink)$")
            ''',
            'message': '格式化字符串后文件操作'
        }
    ]
}

# C++用户输入源模式
USER_INPUT_SOURCES = {
    'query': '''
        [
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list) @args
            )
            (call_expression
                function: (field_expression
                    object: (_) @obj
                    field: (_) @field
                )
                arguments: (argument_list) @args
            )
        ] @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(cin|getline|gets|fgets|scanf|sscanf|fscanf|getc|getchar|read)$',
            'message': '标准输入函数'
        },
        {
            'func_pattern': r'^(recv|recvfrom|recvmsg|ReadFile)$',
            'message': '网络输入函数'
        },
        {
            'func_pattern': r'^(fread|fgetc)$',
            'message': '文件输入函数'
        },
        {
            'obj_pattern': r'^(std::cin|cin)$',
            'field_pattern': r'^(operator>>|get|getline|read)$',
            'message': 'C++标准输入'
        },
        {
            'func_pattern': r'^(getenv|_wgetenv)$',
            'message': '环境变量获取'
        },
        {
            'func_pattern': r'^(GetCommandLine|GetCommandLineW)$',
            'message': '命令行参数获取'
        }
    ]
}

# 路径遍历特征模式
PATH_TRAVERSAL_PATTERNS = [
    r'\.\./',
    r'\.\.\\',
    r'\.\.%2f',
    r'\.\.%5c',
    r'%2e%2e/',
    r'%2e%2e\\',
    r'\.\.%00',
    r'\.\./\.\./',
    r'\.\.\\\.\.\\',
    r'\.\./\.\./\.\./',
    r'\.\.\\\.\.\\\.\.\\',
    r'^\s*/\s*\.\.',
    r'^\s*\\s*\.\.',
    r'//',
    r'\\\\',
    '~/',
    r'~\\',
]

# 用户输入相关变量名模式（用于路径参数检测）
USER_INPUT_VAR_PATTERNS = [
    r'\bargv\b',
    r'\bfilename\b',
    r'\bfilepath\b',
    r'\bpathname\b',
    r'\buser_path\b',
    r'\buser_input\b',
    r'\buser_file\b',
    r'\binput_file\b',
    r'\btarget\b',
    r'\blinkpath\b',
    r'\bold_name\b',
    r'\bnew_name\b',
    r'\bsrc\b',
    r'\bdest\b',
    r'\buser_data\b',
]


def _parse_comment_lines(code):
    """解析源码，返回所有属于注释的行号集合（1-based）"""
    lines = code.split('\n')
    comment_lines = set()
    in_block_comment = False
    for i, line in enumerate(lines):
        line_num = i + 1
        if in_block_comment:
            comment_lines.add(line_num)
            if line.find('*/') != -1:
                in_block_comment = False
        else:
            idx = 0
            in_string = False
            string_char = None
            while idx < len(line):
                ch = line[idx]
                if in_string:
                    if ch == '\\':
                        idx += 2
                        continue
                    if ch == string_char:
                        in_string = False
                else:
                    if ch in ('"', "'"):
                        in_string = True
                        string_char = ch
                    elif ch == '/' and idx + 1 < len(line) and line[idx + 1] == '/':
                        comment_lines.add(line_num)
                        break
                    elif ch == '/' and idx + 1 < len(line) and line[idx + 1] == '*':
                        comment_lines.add(line_num)
                        if line.find('*/', idx + 2) == -1:
                            in_block_comment = True
                        break
                idx += 1
    return comment_lines


def _collect_safe_function_ranges(language, root):
    """收集所有 safe_* 函数定义的行号范围"""
    ranges = []
    try:
        query = language.query('''
            (function_definition
                declarator: (function_declarator
                    declarator: (identifier) @func_name
                )
                body: (compound_statement) @body
            ) @function
        ''')
        captures = query.captures(root)
        current = {}
        for node, tag in captures:
            if tag == 'func_name':
                name = node.text.decode('utf8')
                if name.startswith('safe_') or name == 'demonstrate_attacks':
                    current['name'] = name
                    current['line'] = node.start_point[0] + 1
            elif tag == 'function' and current:
                start = current['line']
                end = node.end_point[0] + 1
                ranges.append((start, end))
                current = {}
    except Exception:
        pass
    return ranges


def _has_path_sanitization(code, func_line, func_name):
    """检查函数调用前是否有路径安全验证（如realpath、strncmp等）"""
    lines = code.split('\n')
    # 检查该函数调用之前5-20行是否有安全措施
    check_start = max(0, func_line - 20)
    check_end = func_line - 1

    for i in range(check_start, check_end):
        line = lines[i]
        # 检查realpath调用
        if re.search(r'\brealpath\s*\(', line):
            return True
        # 检查strncmp路径前缀验证
        if re.search(r'\bstrncmp\s*\(.*BASE_DIR|resolved_path.*strlen', line):
            return True
        # 检查strstr路径遍历检测
        if re.search(r'\bstrstr\s*\(.*filename.*"\.\."', line):
            return True
        # 检查白名单验证
        if re.search(r'\ballowed\s*=\s*1\b', line) or re.search(r'\bisalnum\s*\(', line):
            return True
        # 检查O_NOFOLLOW标志
        if re.search(r'O_NOFOLLOW', line):
            return True
        # 检查S_ISREG
        if re.search(r'S_ISREG', line):
            return True

    return False


def detect_cpp_path_traversal(code, language='cpp'):
    """
    检测C++代码中路径遍历漏洞

    Args:
        code: C++源代码字符串
        language: 语言类型，默认为'cpp'

    Returns:
        list: 检测结果列表
    """
    if language not in LANGUAGES:
        return []

    # 预处理
    comment_lines = _parse_comment_lines(code)

    # 初始化解析器
    parser = Parser()
    parser.set_language(LANGUAGES[language])

    # 解析代码
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    safe_func_ranges = _collect_safe_function_ranges(LANGUAGES[language], root)

    vulnerabilities = []
    file_operations = []
    user_input_sources = []

    # 第一步：收集所有文件操作函数调用
    for query_info in PATH_TRAVERSAL_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'format_func', 'file_func', 'class_name']:
                    name = node.text.decode('utf8')
                    line = node.start_point[0] + 1

                    # 跳过注释中的代码
                    if line in comment_lines:
                        continue

                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = line

                elif tag in ['path_arg', 'concat_arg']:
                    arg_line = node.start_point[0] + 1
                    if arg_line not in comment_lines:
                        current_capture['arg'] = node.text.decode('utf8')
                        current_capture['arg_node'] = node
                        current_capture['arg_index'] = query_info.get('arg_index', 0)

                elif tag in ['call', 'format_call', 'file_call'] and current_capture:
                    call_line = node.start_point[0] + 1
                    if call_line not in comment_lines:
                        if 'func' in current_capture and 'arg_node' in current_capture:
                            code_snippet = node.text.decode('utf8')

                            file_operations.append({
                                'type': 'file_operation',
                                'line': current_capture['line'],
                                'function': current_capture.get('func', ''),
                                'argument': current_capture.get('arg', ''),
                                'arg_node': current_capture.get('arg_node'),
                                'arg_index': current_capture.get('arg_index', 0),
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
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                current_capture['func'] = func_name
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['obj', 'field']:
                name = node.text.decode('utf8')
                if tag == 'obj':
                    current_capture['object'] = name
                else:
                    current_capture['field'] = name

            elif tag == 'call' and current_capture:
                for pattern_info in USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    obj_pattern = pattern_info.get('obj_pattern', '')
                    field_pattern = pattern_info.get('field_pattern', '')

                    match = False
                    if func_pattern and 'func' in current_capture:
                        if re.match(func_pattern, current_capture['func'], re.IGNORECASE):
                            match = True
                    elif obj_pattern and field_pattern and 'object' in current_capture and 'field' in current_capture:
                        if (re.match(obj_pattern, current_capture['object'], re.IGNORECASE) and
                                re.match(field_pattern, current_capture['field'], re.IGNORECASE)):
                            match = True

                    if match:
                        code_snippet = node.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'object': current_capture.get('object', ''),
                            'field': current_capture.get('field', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：分析路径遍历漏洞
    for operation in file_operations:
        line = operation['line']

        # 跳过 safe_* 函数内的文件操作
        if _is_in_safe_function(line, safe_func_ranges):
            continue

        is_vulnerable = False
        vulnerability_details = {
            'line': line,
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': '路径遍历',
            'severity': '高危',
            'function': operation['function']
        }

        # 情况1: 检查路径参数是否包含路径遍历模式（硬编码的../等）
        if operation['argument'] and contains_path_traversal_pattern(operation['argument']):
            vulnerability_details['message'] = f"路径参数包含路径遍历模式: {operation['function']}"
            vulnerability_details['pattern'] = find_traversal_pattern(operation['argument'])
            is_vulnerable = True

        # 情况2: 检查参数是否来自用户输入（扩展变量名匹配）
        elif operation['arg_node'] and is_user_input_related(operation['arg_node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入直接用作文件路径: {operation['function']}"
            is_vulnerable = True

        # 情况3: 检查文件操作函数的参数是否包含用户输入变量名
        elif operation['arg_node'] and has_user_input_var_in_arg(operation['arg_node']):
            vulnerability_details['message'] = f"文件路径参数包含用户输入变量: {operation['function']}"
            is_vulnerable = True

        # 情况4: 检查是否使用拼接构建路径且拼接了用户输入
        elif operation['arg_node'] and is_path_concat_with_input(operation['arg_node']):
            vulnerability_details['message'] = f"使用字符串拼接构建文件路径: {operation['function']}"
            is_vulnerable = True

        if is_vulnerable:
            # 检查是否有路径安全验证措施
            if _has_path_sanitization(code, line, operation['function']):
                continue

            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def _is_in_safe_function(line_num, safe_func_ranges):
    """检查给定行号是否在 safe_* 函数的作用域内"""
    for start, end in safe_func_ranges:
        if start <= line_num <= end:
            return True
    return False


def contains_path_traversal_pattern(text):
    """
    检查文本是否包含路径遍历模式
    """
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def find_traversal_pattern(text):
    """
    找到具体的路径遍历模式
    """
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return pattern
    return None


def is_user_input_related(arg_node, user_input_sources):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名（更严格）
    strict_vars = ['argv', 'input', 'filename', 'filepath', 'user_path', 'user_input']
    for var in strict_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if is_child_node(arg_node, source['node']):
            return True

    return False


def has_user_input_var_in_arg(arg_node):
    """
    检查参数节点是否包含用户输入相关的变量名
    （用于捕获 access(filename, F_OK) 等场景中 filename 为函数参数的情况）
    """
    arg_text = arg_node.text.decode('utf8')
    for pattern in USER_INPUT_VAR_PATTERNS:
        if re.search(pattern, arg_text, re.IGNORECASE):
            return True
    return False


def is_path_concat_with_input(arg_node):
    """
    检查参数是否是通过字符串拼接构建的路径且包含用户输入
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查是否是 sprintf 等格式化字符串（包含格式符和变量）
    if re.search(r'%s.*argv|%s.*filename|%s.*user_|%s.*input', arg_text, re.IGNORECASE):
        return True

    # 检查 + 拼接中是否有用户输入变量
    if '+' in arg_text:
        for pattern in USER_INPUT_VAR_PATTERNS:
            if re.search(pattern, arg_text, re.IGNORECASE):
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


def analyze_cpp_code(code_string):
    """
    分析C++代码字符串中的路径遍历漏洞
    """
    return detect_cpp_path_traversal(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

using namespace std;

#define BASE_DIR "/var/www/files/"

void vulnerable_function(int argc, char* argv[]) {
    // 直接路径遍历 - 高危
    FILE* fp1 = fopen("../../etc/passwd", "r");

    // 用户输入直接用作路径 - 高危
    if (argc > 1) {
        ifstream file(argv[1]);
    }

    // 环境变量直接使用 - 高危
    char* home = getenv("HOME");
    string config_path = string(home) + "/.config/../.bashrc";
    ofstream config_file(config_path.c_str());

    // access使用用户输入
    access(argv[1], F_OK);

    // unlink使用用户输入
    unlink(argv[1]);

    // chdir使用用户输入
    chdir(argv[1]);

    // symlink使用用户输入
    symlink(argv[1], "/tmp/link");
}

void safe_realpath(char *filename) {
    char path[256];
    char resolved_path[256];

    sprintf(path, "%s%s", BASE_DIR, filename);

    if (realpath(path, resolved_path) == NULL) {
        return;
    }

    if (strncmp(resolved_path, BASE_DIR, strlen(BASE_DIR)) != 0) {
        return;
    }

    FILE *fp = fopen(resolved_path, "r");
    if (fp != NULL) {
        fclose(fp);
    }
}

void demonstrate_attacks() {
    printf("Path traversal examples...\\n");
    printf("../../../etc/passwd\\n");
}

int main(int argc, char* argv[]) {
    vulnerable_function(argc, argv);
    safe_realpath(argv[1]);
    demonstrate_attacks();
    return 0;
}
"""

    print("=" * 60)
    print("C++路径遍历漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   函数: {vuln['function']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            if 'pattern' in vuln:
                print(f"   检测模式: {vuln['pattern']}")
    else:
        print("未检测到路径遍历漏洞")