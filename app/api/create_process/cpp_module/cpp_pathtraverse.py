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
        # 检测文件操作函数中的路径参数
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
            'func_pattern': r'^(fopen|open|creat|freopen|fstream|ifstream|ofstream|remove|rename|stat|access|chmod|chown|mkdir|rmdir|CreateFile|OpenFile|fopen_s|_wfopen)$',
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
            'func_pattern': r'^(fopen|open|CreateFile|ifstream|ofstream|fstream)$',
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
                (#match? @file_func "^(fopen|open|CreateFile|ifstream|ofstream)$")
            ''',
            'message': '格式化字符串后文件操作'
        }
    ]
}

# C++用户输入源模式（与命令注入相同）
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
            'func_pattern': r'^(fread|fgetc|fgets|getline)$',
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
    r'~/',
    r'~\\',
]


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

    # 初始化解析器
    parser = Parser()
    parser.set_language(LANGUAGES[language])

    # 解析代码
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    vulnerabilities = []
    file_operations = []  # 存储文件操作函数调用
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集所有文件操作函数调用
    for query_info in PATH_TRAVERSAL_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'format_func', 'file_func', 'class_name']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['path_arg', 'concat_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node
                    current_capture['arg_index'] = query_info.get('arg_index', 0)

                elif tag in ['call', 'format_call', 'file_call'] and current_capture:
                    # 完成一个完整的捕获
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
                # 检查是否匹配任何用户输入模式
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
        is_vulnerable = False
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': '路径遍历',
            'severity': '高危',
            'function': operation['function']
        }

        # 情况1: 检查路径参数是否包含路径遍历模式
        if operation['argument'] and contains_path_traversal_pattern(operation['argument']):
            vulnerability_details['message'] = f"路径参数包含路径遍历模式: {operation['function']}"
            vulnerability_details['pattern'] = find_traversal_pattern(operation['argument'])
            is_vulnerable = True

        # 情况2: 检查参数是否来自用户输入
        elif operation['arg_node'] and is_user_input_related(operation['arg_node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入直接用作文件路径: {operation['function']}"
            is_vulnerable = True

        # 情况3: 检查是否使用相对路径
        elif operation['argument'] and is_relative_path(operation['argument']):
            vulnerability_details['message'] = f"使用相对路径可能导致的路径遍历: {operation['function']}"
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


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

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'input', 'filename', 'path', 'file', 'url', 'param', 'user', 'name']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if is_child_node(arg_node, source['node']):
            return True

    return False


def is_relative_path(text):
    """
    检查是否为相对路径
    """
    # 相对路径特征
    relative_patterns = [
        r'^[^/\\]',  # 不以/或\开头
        r'^\./',  # 以./开头
        r'^\.\\',  # 以.\开头
        r'^\w:',  # Windows驱动器相对路径 (C:filename)
    ]

    for pattern in relative_patterns:
        if re.search(pattern, text, re.IGNORECASE):
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

using namespace std;

void vulnerable_function(int argc, char* argv[]) {
    // 直接路径遍历 - 高危
    FILE* fp1 = fopen("../../etc/passwd", "r"); // 明显的路径遍历

    // 用户输入直接用作路径 - 高危
    if (argc > 1) {
        ifstream file(argv[1]); // 路径注入漏洞
    }

    // 环境变量直接使用 - 高危
    char* home = getenv("HOME");
    string config_path = string(home) + "/.config/../.bashrc";
    ofstream config_file(config_path.c_str()); // 路径遍历

    // 字符串拼接路径遍历
    string base_path = "/var/www/";
    string user_input;
    cin >> user_input;
    string full_path = base_path + user_input; // 可能包含../../
    fopen(full_path.c_str(), "r");

    // 格式化字符串路径遍历
    char buffer[100];
    sprintf(buffer, "/home/%s/../.ssh/id_rsa", argv[1]);
    fopen(buffer, "r"); // 路径遍历

    // URL编码路径遍历
    fopen("..%2f..%2fetc%2fpasswd", "r"); // URL编码的路径遍历

    // Windows路径遍历
    CreateFileA("..\\..\\Windows\\System32\\cmd.exe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
}

void safe_function() {
    // 安全的硬编码路径
    ifstream file("/var/log/app.log");

    // 安全的相对路径（无遍历）
    fopen("config/settings.ini", "r");

    // 路径规范化后使用
    string safe_path = normalize_path(user_input);
    fopen(safe_path.c_str(), "r");
}

int main(int argc, char* argv[]) {
    vulnerable_function(argc, argv);
    safe_function();
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