import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++格式字符串漏洞模式
FORMAT_STRING_VULNERABILITIES = {
    'cpp': [
        # 检测printf系列函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @format_arg
                        (_)* @other_args
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|sprintf|snprintf|fprintf|vprintf|vsprintf|vsnprintf|vfprintf)$',
            'message': 'printf系列函数调用'
        },
        # 检测scanf系列函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @format_arg
                        (_)* @other_args
                    )
                ) @call
            ''',
            'func_pattern': r'^(scanf|sscanf|fscanf|vscanf|vsscanf|vfscanf)$',
            'message': 'scanf系列函数调用'
        },
        # 检测syslog函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @priority_arg
                        (_) @format_arg
                        (_)* @other_args
                    )
                ) @call
            ''',
            'func_pattern': r'^syslog$',
            'message': 'syslog函数调用'
        },
        # 检测setproctitle函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @format_arg
                        (_)* @other_args
                    )
                ) @call
            ''',
            'func_pattern': r'^setproctitle$',
            'message': 'setproctitle函数调用'
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


def detect_cpp_format_string_vulnerabilities(code, language='cpp'):
    """
    检测C++代码中格式字符串漏洞

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
    format_function_calls = []  # 存储所有格式函数调用
    user_input_sources = []  # 存储用户输入源
    dangerous_string_ops = []  # 存储危险字符串操作

    # 第一步：收集所有格式函数调用
    for query_info in FORMAT_STRING_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['format_arg']:
                    current_capture['format_arg'] = node
                    current_capture['format_text'] = node.text.decode('utf8')

                elif tag == 'call' and current_capture:
                    # 完成一个完整的捕获
                    if 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')

                        format_function_calls.append({
                            'type': 'format_function',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'format_arg': current_capture.get('format_arg'),
                            'format_text': current_capture.get('format_text', ''),
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

    # 第四步：分析格式字符串漏洞
    for call in format_function_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '格式字符串漏洞',
            'severity': '高危'
        }

        # 情况1: 格式字符串包含用户可控的%字符
        if call['format_arg'] and has_user_controlled_format_specifiers(call['format_arg'], user_input_sources, root):
            vulnerability_details['message'] = f"用户控制的格式字符串: {call['function']} 调用包含用户控制的格式说明符"
            is_vulnerable = True

        # 情况2: 格式字符串直接来自用户输入
        elif call['format_arg'] and is_user_input_related(call['format_arg'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入直接作为格式字符串: {call['function']}"
            is_vulnerable = True

        # 情况3: 格式字符串经过危险字符串操作
        elif call['format_arg'] and is_dangerous_string_operation(call['format_arg'], dangerous_string_ops, root):
            vulnerability_details['message'] = f"经过危险字符串操作后的格式字符串: {call['function']}"
            is_vulnerable = True

        # 情况4: 检查格式字符串是否包含危险的格式说明符
        elif call['format_text'] and has_dangerous_format_specifiers(call['format_text']):
            vulnerability_details['message'] = f"格式字符串包含危险格式说明符: {call['function']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def has_dangerous_format_specifiers(format_string):
    """
    检查格式字符串是否包含危险的格式说明符
    """
    # 危险的格式说明符模式
    dangerous_patterns = [
        r'%[0-9]*n',  # %n 系列 - 可以写入内存
        r'%[0-9]*s',  # %s 系列 - 可能导致信息泄露或读取越界
        r'%.\*',  # %.*  - 动态精度/宽度
        r'%\*',  # %*   - 动态宽度
    ]

    # 检查是否有用户输入的格式说明符迹象
    user_controlled_patterns = [
        r'%[^%]*%[^%]*\$\$',  # 位置参数（可能被利用）
        r'%\d+\$',  # 位置参数（可能被利用）
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, format_string):
            return True

    return False


def has_user_controlled_format_specifiers(format_node, user_input_sources, root_node):
    """
    检查格式字符串节点是否包含用户控制的格式说明符
    """
    format_text = format_node.text.decode('utf8')

    # 检查格式字符串中是否有明显的用户输入迹象
    user_input_indicators = [
        r'%s',  # 字符串格式说明符
        r'%.\*',  # 动态精度
        r'%\*',  # 动态宽度
    ]

    for pattern in user_input_indicators:
        if re.search(pattern, format_text):
            # 进一步检查这个格式字符串是否与用户输入相关
            if is_user_input_related(format_node, user_input_sources, root_node):
                return True

    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'env', 'input', 'buffer', 'user', 'data', 'param']
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
    分析C++代码字符串中的格式字符串漏洞
    """
    return detect_cpp_format_string_vulnerabilities(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdio>
#include <cstring>
#include <string>

using namespace std;

void vulnerable_function(int argc, char* argv[]) {
    char buffer[100];

    // 直接使用用户输入作为格式字符串 - 高危
    printf(argv[1]); // 格式字符串漏洞

    // sprintf使用用户输入作为格式字符串 - 高危
    sprintf(buffer, argv[1]); // 格式字符串漏洞

    // 用户输入拼接进格式字符串 - 高危
    char format[100] = "Result: ";
    strcat(format, argv[1]);
    printf(format); // 格式字符串漏洞

    // 使用scanf系列函数 - 可能高危
    char input[100];
    scanf("%s", input); // 如果输入包含格式说明符可能有问题
    printf(input); // 格式字符串漏洞

    // syslog使用用户输入 - 高危
    syslog(LOG_INFO, argv[1]); // 格式字符串漏洞
}

void safe_function() {
    // 安全的硬编码格式字符串
    printf("Hello, World!\\n");

    // 安全的参数化格式字符串
    const char* name = "Alice";
    printf("Hello, %s\\n", name);

    // 安全的scanf使用
    int value;
    scanf("%d", &value); // 格式字符串固定
}

int main(int argc, char* argv[]) {
    vulnerable_function(argc, argv);
    safe_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++格式字符串漏洞检测")
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
        print("未检测到格式字符串漏洞")