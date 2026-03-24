import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在配置中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++日志伪造漏洞模式
LOG_FORGERY_VULNERABILITIES = {
    'cpp': [
        # 检测标准输出函数调用
        {
            'query': '''
                (call_expression
                    function: [
                        (identifier) @func_name
                        (field_expression) @field_func
                    ]
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|wprintf|fwprintf|swprintf|vswprintf)$',
            'message': '标准输出函数调用'
        },
        # 检测C++流输出操作
        {
            'query': '''
                (binary_expression
                    left: (_) @left
                    operator: "<<"
                    right: (_) @right
                ) @stream_op
            ''',
            'message': 'C++流输出操作'
        },
        # 检测日志库函数调用
        {
            'query': '''
                (call_expression
                    function: [
                        (identifier) @func_name
                        (field_expression) @field_func
                    ]
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(spdlog|boost::log|glog|LOG|log4cxx|log4cpp|Poco::Logger)',
            'message': '日志库函数调用'
        },
        # 检测Windows日志函数
        {
            'query': '''
                (call_expression
                    function: [
                        (identifier) @func_name
                        (field_expression) @field_func
                    ]
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(OutputDebugString|EventWrite|ReportEvent|WriteFileLog)$',
            'message': 'Windows日志函数调用'
        }
    ]
}

# C++用户输入源模式（修正版）
USER_INPUT_SOURCES = {
    'query': '''
        [
            (call_expression
                function: [
                    (identifier) @func_name
                    (field_expression) @field_func
                ]
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
            'func_pattern': r'^(getenv|_wgetenv)$',
            'message': '环境变量获取'
        },
        {
            'func_pattern': r'^(GetCommandLine|GetCommandLineW)$',
            'message': '命令行参数获取'
        },
        {
            'func_pattern': r'^(std::cin|cin)$',
            'message': 'C++标准输入对象'
        }
    ]
}

# 格式化字符串敏感字符模式
FORMAT_STRING_SENSITIVE_PATTERNS = [
    r'%n',  # %n格式化符（可能导致内存写入）
    r'%\d*\*',  # 动态宽度/精度指定
    r'%[^aAfFgGeEsSpcdiouxXhlLjztL]',  # 无效格式化符
]

# 敏感日志内容模式
SENSITIVE_LOG_PATTERNS = [
    r'(password|passwd|pwd|secret|token|key|credential|auth)',
    r'(ssn|social\.security|credit\.card|bank\.account)',
    r'(admin|root|superuser|privileged)',
    r'(\d{3}-\d{2}-\d{4})',  # SSN模式
    r'(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})',  # 信用卡号
]


def detect_cpp_log_forgery(code, language='cpp'):
    """
    检测C++代码中日志伪造漏洞

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
    log_calls = []  # 存储所有日志/输出函数调用
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集所有日志/输出函数调用
    for query_info in LOG_FORGERY_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'field_func']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['args'] = []

                elif tag in ['left', 'right']:
                    # 处理流操作符 << 的参数
                    if 'args' not in current_capture:
                        current_capture['args'] = []
                    arg_text = node.text.decode('utf8')
                    current_capture['args'].append({
                        'text': arg_text,
                        'node': node
                    })

                elif tag in ['call', 'stream_op'] and current_capture:
                    # 完成一个完整的捕获
                    if 'func' in current_capture or tag == 'stream_op':
                        code_snippet = node.text.decode('utf8')

                        if tag == 'stream_op':
                            function_name = 'operator<<'
                        else:
                            function_name = current_capture.get('func', 'unknown')

                        log_calls.append({
                            'type': 'log_call',
                            'line': current_capture.get('line', node.start_point[0] + 1),
                            'function': function_name,
                            'arguments': current_capture.get('args', []),
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
            if tag in ['func_name', 'field_func']:
                func_name = node.text.decode('utf8')
                current_capture['func'] = func_name
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'call' and current_capture:
                # 检查是否匹配任何用户输入模式
                for pattern_info in USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')

                    if func_pattern and 'func' in current_capture:
                        if re.match(func_pattern, current_capture['func'], re.IGNORECASE):
                            code_snippet = node.text.decode('utf8')
                            user_input_sources.append({
                                'type': 'user_input',
                                'line': current_capture['line'],
                                'function': current_capture.get('func', ''),
                                'code_snippet': code_snippet,
                                'node': node
                            })
                            break

                current_capture = {}

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：分析日志伪造漏洞
    for call in log_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'function': call['function'],
            'vulnerability_type': '日志伪造',
            'severity': '中危'
        }

        # 分析每个参数
        for arg in call['arguments']:
            arg_text = arg['text']
            arg_node = arg['node']

            # 情况1: 检查是否包含用户输入
            if is_user_input_related(arg_node, user_input_sources, root):
                vulnerability_details['message'] = f"用户输入直接用于日志输出: {call['function']}"
                vulnerability_details['severity'] = '高危'
                is_vulnerable = True
                break

            # 情况2: 检查格式化字符串漏洞
            if contains_format_string_vulnerability(arg_text, call['function']):
                vulnerability_details['message'] = f"潜在的格式化字符串漏洞: {call['function']}"
                vulnerability_details['severity'] = '高危'
                is_vulnerable = True
                break

            # 情况3: 检查敏感信息泄露
            if contains_sensitive_information(arg_text):
                vulnerability_details['message'] = f"敏感信息可能被记录: {call['function']}"
                is_vulnerable = True
                break

            # 情况4: 检查日志注入模式（换行符等）
            if contains_log_injection_patterns(arg_text):
                vulnerability_details['message'] = f"潜在的日志注入: {call['function']}"
                is_vulnerable = True
                break

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_format_string_vulnerability(text, function_name):
    """
    检查文本是否包含潜在的格式化字符串漏洞
    """
    # 对于printf系列函数，检查格式化字符串
    printf_functions = ['printf', 'fprintf', 'sprintf', 'snprintf',
                        'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
                        'wprintf', 'fwprintf', 'swprintf', 'vswprintf']

    if any(func in function_name for func in printf_functions):
        for pattern in FORMAT_STRING_SENSITIVE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True

    return False


def contains_sensitive_information(text):
    """
    检查文本是否包含敏感信息模式
    """
    for pattern in SENSITIVE_LOG_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def contains_log_injection_patterns(text):
    """
    检查文本是否包含日志注入模式
    """
    injection_patterns = [
        r'\\n', r'\\r', r'\\t',  # 转义字符
        r'\r', r'\n', r'\t',  # 实际换行符
        r'%.*?%',  # 双重百分号
    ]

    for pattern in injection_patterns:
        if re.search(pattern, text):
            return True
    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'env', 'input', 'buffer', 'user', 'data',
                       'param', 'request', 'response', 'query', 'form']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
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


def analyze_cpp_log_forgery(code_string):
    """
    分析C++代码字符串中的日志伪造漏洞
    """
    return detect_cpp_log_forgery(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdio>
#include <cstring>
#include <string>

using namespace std;

void vulnerable_logging(int argc, char* argv[]) {
    char buffer[100];
    string userInput;

    // 用户输入直接用于日志 - 高危
    printf("User input: %s\\n", argv[1]); // 日志伪造漏洞

    // 格式化字符串漏洞 - 高危
    sprintf(buffer, "Data: %s", argv[1]);
    printf(buffer); // 格式化字符串漏洞

    // 敏感信息记录 - 中危
    string password = "secret123";
    cout << "Password: " << password << endl; // 敏感信息泄露

    // 日志注入 - 中危
    cin >> userInput;
    cout << "Log: " << userInput << endl; // 可能包含恶意内容

    // 环境变量记录
    char* path = getenv("PATH");
    fprintf(stderr, "PATH: %s\\n", path); // 可能包含敏感信息

    // 相对安全的做法 - 输入验证
    if (true) {
        printf("Valid input: %s\\n", argv[1]);
    }
}

void safe_logging() {
    // 安全的硬编码日志
    printf("Application started\\n");
    cout << "Info: System initialized" << endl;

    // 安全的格式化
    int value = 42;
    printf("Value: %d\\n", value);
}

int main(int argc, char* argv[]) {
    vulnerable_logging(argc, argv);
    safe_logging();
    return 0;
}
"""

    print("=" * 60)
    print("C++日志伪造漏洞检测")
    print("=" * 60)

    results = analyze_cpp_log_forgery(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   函数: {vuln['function']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到日志伪造漏洞")