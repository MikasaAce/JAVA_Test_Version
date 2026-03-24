import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++命令注入漏洞模式
COMMAND_INJECTION_VULNERABILITIES = {
    'cpp': [
        # 检测system函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(system|popen|execl|execlp|execle|execv|execvp|execvpe|exec|_exec|_spawn|_wsystem)$',
            'message': '系统命令执行函数调用'
        },
        # 检测Windows API危险函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(WinExec|ShellExecute|ShellExecuteEx|CreateProcess|_wsystem)$',
            'message': 'Windows API命令执行函数'
        },
        # 检测通过指针或引用传递的命令参数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @arg1
                        (_)? @arg2
                    )
                ) @call
            ''',
            'func_pattern': r'^(execl|execlp|execle|execv|execvp|execvpe|CreateProcess)$',
            'arg_index': 0,  # 检查第一个参数
            'message': '进程执行函数调用'
        },
        # 检测字符串拼接后传递给危险函数
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
            'func_pattern': r'^(system|popen|WinExec|ShellExecute)$',
            'message': '字符串拼接后的命令执行'
        },
        # 检测sprintf/strcat等危险字符串操作后传递给system
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
                (#match? @func_name "^(sprintf|strcat|strcpy|wcscat|wcscpy)$")
                .
                (call_expression
                    function: (identifier) @sys_func
                    arguments: (argument_list (_) @cmd_arg)
                ) @sys_call
                (#match? @sys_func "^(system|popen)$")
            ''',
            'message': '字符串操作后执行命令'
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


def detect_cpp_command_injection(code, language='cpp'):
    """
    检测C++代码中命令注入漏洞

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
                if tag in ['func_name', 'sys_func']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['arg', 'concat_arg', 'cmd_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag in ['call', 'sys_call'] and current_capture:
                    # 完成一个完整的捕获
                    if 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')

                        dangerous_calls.append({
                            'type': 'dangerous_call',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'arg_index': query_info.get('arg_index', None)
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

        # 情况2: 检查参数是否来自用户输入
        elif call['arg_node'] and is_user_input_related(call['arg_node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入直接传递给危险函数: {call['function']}"
            is_vulnerable = True

        # 情况3: 检查参数是否经过危险字符串操作
        elif call['arg_node'] and is_dangerous_string_operation(call['arg_node'], dangerous_string_ops, root):
            vulnerability_details['message'] = f"经过危险字符串操作后传递给命令执行函数: {call['function']}"
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
        r'^\s*(\w+\.(exe|bat|cmd|ps1|sh)\b)',
        r'[;&|`]\s*\w',
        r'^\s*cmd\.exe\s+/c',
        r'^\s*/bin/(bash|sh)\s+-c',
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
    user_input_vars = ['argv', 'env', 'input', 'buffer', 'cmd', 'command', 'param']
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


def analyze_cpp_code(code_string):
    """
    分析C++代码字符串中的命令注入漏洞
    """
    return detect_cpp_command_injection(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace std;

void vulnerable_function(int argc, char* argv[]) {
    // 直接命令执行 - 高危
    system("ls -la");

    // 用户输入直接传递给命令 - 高危
    if (argc > 1) {
        system(argv[1]); // 命令注入漏洞
    }

    // 环境变量直接使用 - 高危
    char* path = getenv("PATH");
    system(path); // 危险的环境变量使用

    // 字符串拼接后执行 - 高危
    string userInput = "echo ";
    string userData;
    cin >> userData;
    userInput += userData;
    system(userInput.c_str()); // 命令注入

    // Windows API危险调用
    WinExec("calc.exe", SW_SHOW); // 直接执行计算器

    // 危险字符串操作后执行命令
    char buffer[100];
    sprintf(buffer, "echo %s", argv[1]);
    system(buffer); // 命令注入

    // 相对安全的做法 - 使用参数化执行
    const char* safeArgs[] = {"ls", "-la", nullptr};
    execvp("ls", safeArgs); // 相对安全

    // 使用popen
    FILE* fp = popen("ls -la", "r"); // 仍然危险如果命令来自用户输入
    if (fp) {
        pclose(fp);
    }
}

void safe_function() {
    // 安全的硬编码命令
    system("echo Hello World");

    // 安全的参数化执行
    const char* args[] = {"ls", "-l", nullptr};
    execvp("ls", args);
}

int main(int argc, char* argv[]) {
    vulnerable_function(argc, argv);
    safe_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++命令注入漏洞检测")
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
        print("未检测到命令注入漏洞")