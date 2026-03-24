import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++ OPEN重定向漏洞模式
OPEN_REDIRECTION_VULNERABILITIES = {
    'cpp': [
        # 检测文件打开函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @file_arg)
                ) @call
            ''',
            'func_pattern': r'^(fopen|open|_open|_wopen|CreateFile|CreateFileA|CreateFileW)$',
            'message': '文件打开函数调用'
        },
        # 检测文件流构造函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @file_arg)
                ) @call
            ''',
            'func_pattern': r'^(ifstream|ofstream|fstream)$',
            'message': '文件流构造函数调用'
        },
        # 检测Windows API文件操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @file_arg)
                ) @call
            ''',
            'func_pattern': r'^(OpenFile|_lopen|_lcreat)$',
            'message': 'Windows API文件操作函数'
        },
        # 检测字符串拼接后的文件路径
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
            'func_pattern': r'^(fopen|open|_open|_wopen|CreateFile|CreateFileA|CreateFileW)$',
            'message': '字符串拼接后的文件路径'
        }
    ]
}

# 简化的用户输入源模式
USER_INPUT_SOURCES = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    ''',
    'patterns': [
        r'^(cin|getline|gets|fgets|scanf|sscanf|fscanf|getc|getchar|read)$',
        r'^(recv|recvfrom|recvmsg|ReadFile)$',
        r'^(fread|fgetc|fgets|getline)$',
        r'^(getenv|_wgetenv)$',
        r'^(GetCommandLine|GetCommandLineW)$'
    ]
}

# 危险字符串函数模式
DANGEROUS_STRING_FUNCTIONS = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list (_)* @args)
        ) @call
    ''',
    'patterns': [
        r'^strcat$',
        r'^strcpy$',
        r'^wcscat$',
        r'^wcscpy$',
        r'^sprintf$',
        r'^swprintf$',
        r'^vsprintf$',
        r'^vswprintf$'
    ]
}

# 危险路径模式
DANGEROUS_PATH_PATTERNS = [
    r'\.\./',  # 目录遍历
    r'\.\.\\',  # Windows目录遍历
    r'^/',  # 绝对路径（Unix）
    r'^[A-Za-z]:\\',  # 绝对路径（Windows）
    r'^\\\\',  # UNC路径
    r'~/',  # 用户主目录
    r'/dev/',  # 设备文件
    r'/proc/',  # 进程文件系统
    r'/sys/',  # 系统文件系统
    r'^(COM|LPT)\d+',  # Windows设备文件
    r'\.\.$',  # 父目录引用
]


def detect_cpp_open_redirection(code, language='cpp'):
    """
    检测C++代码中OPEN重定向漏洞

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
    file_open_calls = []  # 存储文件打开函数调用
    user_input_sources = []  # 存储用户输入源
    dangerous_string_ops = []  # 存储危险字符串操作

    # 第一步：收集所有文件打开函数调用
    for query_info in OPEN_REDIRECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag == 'func_name':
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['file_arg', 'concat_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag == 'call' and current_capture:
                    # 完成一个完整的捕获
                    if 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')

                        file_open_calls.append({
                            'type': 'file_open_call',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有用户输入源（简化版本）
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in USER_INPUT_SOURCES['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：收集危险字符串操作
    try:
        query = LANGUAGES[language].query(DANGEROUS_STRING_FUNCTIONS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in DANGEROUS_STRING_FUNCTIONS['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        dangerous_string_ops.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break

    except Exception as e:
        print(f"危险字符串函数查询错误: {e}")

    # 第四步：分析OPEN重定向漏洞
    for call in file_open_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': 'OPEN重定向',
            'severity': '中危'
        }

        # 情况1: 检查路径是否包含危险模式
        if call['argument'] and is_dangerous_path(call['argument']):
            vulnerability_details['message'] = f"文件路径包含危险模式: {call['function']} 调用可能被利用进行路径遍历"
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True

        # 情况2: 检查参数是否来自用户输入
        elif call['arg_node'] and is_user_input_related(call['arg_node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入直接传递给文件打开函数: {call['function']}"
            is_vulnerable = True

        # 情况3: 检查参数是否经过危险字符串操作
        elif call['arg_node'] and is_dangerous_string_operation(call['arg_node'], dangerous_string_ops, root):
            vulnerability_details['message'] = f"经过危险字符串操作后传递给文件打开函数: {call['function']}"
            is_vulnerable = True

        # 情况4: 检查是否使用argv参数
        elif call['argument'] and re.search(r'\bargv\b', call['argument'], re.IGNORECASE):
            vulnerability_details['message'] = f"命令行参数直接传递给文件打开函数: {call['function']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_dangerous_path(file_path):
    """
    检查文件路径是否包含危险模式
    """
    # 移除字符串引号
    clean_path = re.sub(r'^[\'"]|[\'"]$', '', file_path)

    for pattern in DANGEROUS_PATH_PATTERNS:
        if re.search(pattern, clean_path, re.IGNORECASE):
            return True

    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'env', 'input', 'filename', 'path', 'file', 'param', 'user', 'data']
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


def analyze_cpp_code(code_string):
    """
    分析C++代码字符串中的OPEN重定向漏洞
    """
    return detect_cpp_open_redirection(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>
#include <windows.h>

using namespace std;

void vulnerable_function(int argc, char* argv[]) {
    char buffer[100];

    // 直接路径遍历 - 高危
    FILE* fp1 = fopen("../../../etc/passwd", "r");

    // 用户输入直接传递给文件打开 - 高危
    if (argc > 1) {
        FILE* fp2 = fopen(argv[1], "r");
    }

    // 环境变量直接使用
    char* home = getenv("HOME");
    string config_path = string(home) + "/.config/sensitive.conf";
    ifstream config_file(config_path.c_str());

    // 字符串拼接后打开文件
    string base_path = "/var/www/uploads/";
    string user_file;
    cin >> user_file;
    string full_path = base_path + user_file;
    ofstream output_file(full_path.c_str());

    // Windows API危险调用
    HANDLE hFile = CreateFileA("C:\\\\Windows\\\\System32\\\\config\\\\SAM", 
                              GENERIC_READ, 0, NULL, OPEN_EXISTING, 
                              FILE_ATTRIBUTE_NORMAL, NULL);

    // 危险字符串操作后打开文件
    sprintf(buffer, "/tmp/%s", argv[1]);
    FILE* fp3 = fopen(buffer, "w");

    // UNC路径漏洞 (Windows)
    char* unc_path = "\\\\192.168.1.100\\share\\malicious.exe";
    HANDLE hFile2 = CreateFileA(unc_path, GENERIC_READ, 0, NULL, 
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // 相对安全的做法
    string safe_path = "data.txt";
    ifstream safe_file(safe_path.c_str());
}

int main(int argc, char* argv[]) {
    vulnerable_function(argc, argv);
    return 0;
}
"""

    print("=" * 60)
    print("C++ OPEN重定向漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到OPEN重定向漏洞")