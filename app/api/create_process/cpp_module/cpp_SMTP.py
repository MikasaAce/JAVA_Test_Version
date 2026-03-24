import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义SMTP标头操纵漏洞模式
SMTP_HEADER_INJECTION_VULNERABILITIES = {
    'cpp': [
        # 检测SMTP数据发送函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @arg1
                        (_)? @arg2
                        (_)? @arg3
                    )
                ) @call
            ''',
            'func_pattern': r'^(send|write|printf|fprintf|sprintf|snprintf|swprintf|vsprintf|vsnprintf|vswprintf)$',
            'message': '数据发送函数调用'
        },
        # 检测标头设置函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @header_name
                        (_) @header_value
                    )
                ) @call
            ''',
            'func_pattern': r'^(SetHeader|AddHeader|AppendHeader|setHeader|addHeader|appendHeader|set_header|add_header|append_header)$',
            'message': '标头设置函数调用'
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
            'func_pattern': r'^(send|write|printf|fprintf|sprintf|SetHeader|AddHeader)$',
            'message': '字符串拼接操作'
        }
    ]
}

# 修正的用户输入源模式
USER_INPUT_SOURCES = {
    'query': '''
        [
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list) @args
            )
            (call_expression
                function: (field_expression
                    field: (identifier) @field_name
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

# SMTP相关标头字段模式
SMTP_HEADER_PATTERNS = [
    r'^(To|From|Subject|Cc|Bcc|Reply-To|Return-Path|Date|Message-ID)$',
    r'Content-Type',
    r'Content-Transfer-Encoding',
    r'MIME-Version',
]

# SMTP注入危险字符模式
SMTP_INJECTION_PATTERNS = [
    r'\\r\\n\\.\\r\\n',  # SMTP数据结束符
    r'\\r\\n\\s*\\.',  # 数据结束符变种
    r'^\\s*\\.',  # 行首的点
    r'\\r\\n\\r\\n',  # 标头结束符
    r'\\r\\n\\s*\\w+:',  # 新标头开始
    r'\\n\\s*\\w+:',  # 新标头开始(LF)
]


def detect_cpp_smtp_header_injection(code, language='cpp'):
    """
    检测C++代码中SMTP标头操纵漏洞
    """
    if language not in LANGUAGES:
        return []

    parser = Parser()
    parser.set_language(LANGUAGES[language])
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    vulnerabilities = []
    smtp_calls = []
    user_input_sources = []
    dangerous_string_ops = []

    # 第一步：收集SMTP相关函数调用
    for query_info in SMTP_HEADER_INJECTION_VULNERABILITIES[language]:
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

                elif tag in ['arg1', 'arg2', 'arg3', 'concat_arg', 'header_value']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag == 'header_name':
                    current_capture['header_name'] = node.text.decode('utf8')

                elif tag == 'call' and current_capture:
                    if 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')
                        smtp_calls.append({
                            'type': 'smtp_call',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'header_name': current_capture.get('header_name', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"SMTP查询错误: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag == 'func_name':
                current_capture['func'] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'field_name':
                current_capture['field'] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'call' and current_capture:
                for pattern_info in USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')

                    if 'func' in current_capture and func_pattern:
                        if re.match(func_pattern, current_capture['func'], re.IGNORECASE):
                            user_input_sources.append({
                                'type': 'user_input',
                                'line': current_capture['line'],
                                'function': current_capture['func'],
                                'code_snippet': node.text.decode('utf8'),
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
    for call in smtp_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': 'SMTP标头操纵',
            'severity': '中危'
        }

        # 检查是否包含注入模式
        if call['argument'] and contains_smtp_injection_patterns(call['argument']):
            vulnerability_details['message'] = f"SMTP数据包含注入危险字符: {call['function']}"
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True

        # 检查是否来自用户输入
        elif call['arg_node'] and is_user_input_related(call['arg_node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入直接用于SMTP数据: {call['function']}"
            is_vulnerable = True

        # 检查是否经过危险字符串操作
        elif call['arg_node'] and is_dangerous_string_operation(call['arg_node'], dangerous_string_ops, root):
            vulnerability_details['message'] = f"危险字符串操作后用于SMTP数据: {call['function']}"
            is_vulnerable = True

        # 检查标头字段
        elif call['header_name'] and is_smtp_header_field(call['header_name']):
            if call['argument'] and is_suspicious_header_value(call['argument']):
                vulnerability_details['message'] = f"可疑标头值: {call['header_name']}"
                is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return vulnerabilities


def contains_smtp_injection_patterns(text):
    """检查是否包含SMTP注入模式"""
    text_str = text if isinstance(text, str) else text.decode('utf8')

    patterns = [
        r'\\r\\n',  # CRLF
        r'\\n',  # LF
        r'%0d%0a',  # URL编码的CRLF
        r'%0a',  # URL编码的LF
        r'%0d',  # URL编码的CR
        r'\\s*\\.\\s*',  # 点字符
        r':\\s*\\w+',  # 冒号后跟字符（新标头）
    ]

    for pattern in patterns:
        if re.search(pattern, text_str, re.IGNORECASE):
            return True
    return False


def is_smtp_header_field(header_name):
    """检查是否是SMTP标头字段"""
    header_str = header_name if isinstance(header_name, str) else header_name.decode('utf8')

    patterns = [
        r'^(to|from|subject|cc|bcc|reply-to|return-path)$',
        r'content-type',
        r'content-transfer-encoding',
        r'mime-version',
    ]

    for pattern in patterns:
        if re.match(pattern, header_str, re.IGNORECASE):
            return True
    return False


def is_suspicious_header_value(text):
    """检查标头值是否可疑"""
    text_str = text if isinstance(text, str) else text.decode('utf8')
    return contains_smtp_injection_patterns(text_str)


def is_user_input_related(arg_node, user_input_sources, root_node):
    """检查参数是否与用户输入相关"""
    arg_text = arg_node.text.decode('utf8')

    # 检查常见用户输入变量名
    user_input_vars = ['argv', 'input', 'user', 'data', 'param', 'buffer', 'cmd']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否来自已知输入源
    for source in user_input_sources:
        if is_child_node(arg_node, source['node']):
            return True

    return False


def is_dangerous_string_operation(arg_node, dangerous_string_ops, root_node):
    """检查是否经过危险字符串操作"""
    arg_text = arg_node.text.decode('utf8')

    for op in dangerous_string_ops:
        if op['function'].lower() in arg_text.lower():
            return True

    return False


def is_child_node(child, parent):
    """检查节点关系"""
    node = child
    while node:
        if node == parent:
            return True
        node = node.parent
    return False


def analyze_cpp_smtp_code(code_string):
    """分析C++代码中的SMTP标头操纵漏洞"""
    return detect_cpp_smtp_header_injection(code_string, 'cpp')


# 测试代码
if __name__ == "__main__":
    test_cpp_code = """
#include <iostream>
#include <string>
#include <cstring>

using namespace std;

void vulnerable_function() {
    char buffer[100];
    string userInput;

    // 直接用户输入
    cout << "Enter email: ";
    cin >> userInput;

    // 危险：直接拼接
    string header = "From: " + userInput + "\\r\\n";
    send(socket_fd, header.c_str(), header.length(), 0);

    // 危险：sprintf使用
    sprintf(buffer, "To: %s\\r\\n", userInput.c_str());
    send(socket_fd, buffer, strlen(buffer), 0);

    // 包含注入的输入
    string malicious = "test@example.com\\r\\nBcc: attacker@example.com\\r\\n";
    string badHeader = "From: " + malicious;
    send(socket_fd, badHeader.c_str(), badHeader.length(), 0);
}

void safe_function() {
    // 安全：硬编码
    const char* safeHeader = "From: safe@example.com\\r\\n";
    send(socket_fd, safeHeader, strlen(safeHeader), 0);

    // 安全：输入清理
    string userInput;
    cin >> userInput;

    // 移除危险字符
    size_t pos;
    while ((pos = userInput.find("\\r")) != string::npos) {
        userInput.erase(pos, 2);
    }
    while ((pos = userInput.find("\\n")) != string::npos) {
        userInput.erase(pos, 2);
    }

    string safeHeader2 = "From: " + userInput + "\\r\\n";
    send(socket_fd, safeHeader2.c_str(), safeHeader2.length(), 0);
}

int main() {
    vulnerable_function();
    safe_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++ SMTP标头操纵漏洞检测")
    print("=" * 60)

    results = analyze_cpp_smtp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SMTP标头操纵漏洞")