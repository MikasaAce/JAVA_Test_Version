import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在config_path中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++资源注入漏洞模式
RESOURCE_INJECTION_VULNERABILITIES = {
    'cpp': [
        # 检测文件操作函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(fopen|open|creat|_open|_wopen|freopen|tmpfile)$',
            'message': '文件操作函数调用'
        },
        # 检测文件流操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
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
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(CreateFile|CreateFileA|CreateFileW|OpenFile|_lopen|_lcreat|FindFirstFile|FindFirstFileA|FindFirstFileW)$',
            'message': 'Windows API文件操作函数'
        },
        # 检测目录操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(mkdir|_mkdir|rmdir|_rmdir|chdir|_chdir|GetCurrentDirectory|SetCurrentDirectory|RemoveDirectory|CreateDirectory)$',
            'message': '目录操作函数调用'
        },
        # 检测网络资源操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(socket|connect|bind|listen|accept|URLDownloadToFile|InternetOpenUrl|InternetReadFile|HttpOpenRequest|HttpSendRequest)$',
            'message': '网络资源操作函数调用'
        },
        # 检测数据库操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(sqlite3_open|mysql_real_connect|PQconnectdb|OCILogon|SQLConnect|SQLDriverConnect)$',
            'message': '数据库连接函数调用'
        },
        # 检测字符串拼接后传递给资源操作函数
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
            'func_pattern': r'^(fopen|open|CreateFile|CreateFileA|CreateFileW|mkdir|_mkdir|sqlite3_open|mysql_real_connect)$',
            'message': '字符串拼接后的资源操作'
        },
        # 检测路径遍历模式
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string_literal) @path_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(fopen|open|CreateFile|CreateFileA|CreateFileW|mkdir|_mkdir)$',
            'path_pattern': r'\.\.(/|\\\\)',
            'message': '路径遍历漏洞'
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
        {
            'func_pattern': r'^(cin|getline|gets|fgets|scanf|sscanf|fscanf|getc|getchar|read|recv|recvfrom|recvmsg|ReadFile|fread|fgetc|getenv|_wgetenv|GetCommandLine|GetCommandLineW)$',
            'message': '输入函数'
        }
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

# 路径遍历检测模式
PATH_TRAVERSAL_PATTERNS = [
    r'\.\.(/|\\\\)',  # 相对路径遍历
    r'^/',  # 绝对路径（Unix）
    r'^[a-zA-Z]:\\',  # 绝对路径（Windows）
    r'^(\\\\|//)',  # 网络路径
    r'~(/|\\\\)',  # 用户主目录
]

# 常见用户输入变量名
USER_INPUT_VARIABLES = [
    'argv', 'env', 'input', 'buffer', 'path', 'file', 'url', 'dir',
    'filename', 'param', 'cmd', 'command', 'data', 'user', 'name'
]


def detect_cpp_resource_injection(code, language='cpp'):
    """
    检测C++代码中资源注入漏洞

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
    resource_calls = []  # 存储所有资源操作函数调用
    user_input_sources = []  # 存储用户输入源
    dangerous_string_ops = []  # 存储危险字符串操作

    # 第一步：收集所有资源操作函数调用
    for query_info in RESOURCE_INJECTION_VULNERABILITIES[language]:
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

                elif tag in ['arg', 'concat_arg', 'path_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag == 'call' and current_capture:
                    # 检查路径遍历模式
                    path_pattern = query_info.get('path_pattern', '')
                    if path_pattern and 'arg' in current_capture:
                        if re.search(path_pattern, current_capture['arg'], re.IGNORECASE):
                            code_snippet = node.text.decode('utf8')
                            resource_calls.append({
                                'type': 'path_traversal',
                                'line': current_capture['line'],
                                'function': current_capture.get('func', ''),
                                'argument': current_capture.get('arg', ''),
                                'arg_node': current_capture.get('arg_node'),
                                'code_snippet': code_snippet,
                                'node': node
                            })
                    elif 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')
                        resource_calls.append({
                            'type': 'resource_call',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"资源操作查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有用户输入源（简化版本）
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern_info in USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        code_snippet = node.parent.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': code_snippet,
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

    # 第四步：分析漏洞
    for call in resource_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '资源注入',
            'severity': '高危'
        }

        # 情况1: 路径遍历检测
        if call['type'] == 'path_traversal':
            vulnerability_details['message'] = f"路径遍历漏洞: {call['function']} 调用包含路径遍历模式"
            is_vulnerable = True

        # 情况2: 检查参数是否来自用户输入
        elif call['arg_node'] and is_user_input_related(call['arg_node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入直接传递给资源操作函数: {call['function']}"
            is_vulnerable = True

        # 情况3: 检查参数是否经过危险字符串操作
        elif call['arg_node'] and is_dangerous_string_operation(call['arg_node'], dangerous_string_ops, root):
            vulnerability_details['message'] = f"经过危险字符串操作后传递给资源操作函数: {call['function']}"
            is_vulnerable = True

        # 情况4: 检查参数是否包含路径遍历模式
        elif call['argument'] and contains_path_traversal(call['argument']):
            vulnerability_details['message'] = f"资源路径包含路径遍历模式: {call['function']}"
            is_vulnerable = True

        # 情况5: 检查参数是否包含常见用户输入变量名
        elif call['argument'] and contains_user_input_variable(call['argument']):
            vulnerability_details['message'] = f"资源路径可能包含用户输入: {call['function']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_path_traversal(argument):
    """
    检查参数是否包含路径遍历模式
    """
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, argument, re.IGNORECASE):
            return True
    return False


def contains_user_input_variable(argument):
    """
    检查参数是否包含常见的用户输入变量名
    """
    for var in USER_INPUT_VARIABLES:
        if re.search(rf'\b{var}\b', argument, re.IGNORECASE):
            return True
    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    if contains_user_input_variable(arg_text):
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
    分析C++代码字符串中的资源注入漏洞
    """
    return detect_cpp_resource_injection(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>

using namespace std;

void vulnerable_function(int argc, char* argv[]) {
    // 路径遍历漏洞 - 高危
    FILE* fp = fopen("../../etc/passwd", "r"); // 路径遍历

    // 用户输入直接传递给文件操作 - 高危
    if (argc > 1) {
        ofstream file(argv[1]); // 资源注入漏洞
        file << "some data";
        file.close();
    }

    // 环境变量直接使用 - 高危
    char* home = getenv("HOME");
    string config_path = home;
    config_path += "/.config/data";
    ifstream config_file(config_path.c_str()); // 潜在资源注入

    // 字符串拼接后操作文件 - 高危
    string userInput = "/tmp/";
    string userData;
    cin >> userData;
    userInput += userData;
    fopen(userInput.c_str(), "w"); // 资源注入

    // Windows API危险调用
    CreateFileA("C:\\\\Windows\\\\System32\\\\config\\\\SAM", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); // 敏感文件访问

    // 危险字符串操作后操作文件
    char buffer[100];
    sprintf(buffer, "/tmp/%s", argv[1]);
    fopen(buffer, "w"); // 资源注入

    // 网络资源操作
    URLDownloadToFile(NULL, "http://example.com/userfile.txt", "local_file.txt", 0, NULL); // 潜在危险下载
}

void safe_function() {
    // 安全的硬编码路径
    FILE* fp = fopen("/tmp/static_file.txt", "r");

    // 安全的文件操作
    ofstream file("safe_file.txt");
    file << "safe data";
    file.close();
}

int main(int argc, char* argv[]) {
    vulnerable_function(argc, argv);
    safe_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++资源注入漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到资源注入漏洞")