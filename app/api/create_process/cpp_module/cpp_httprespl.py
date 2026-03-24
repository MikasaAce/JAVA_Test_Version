import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义HTTP响应拆分漏洞模式
HTTP_RESPONSE_SPLITTING_VULNERABILITIES = {
    'cpp': [
        # 检测直接输出CRLF到HTTP响应
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @arg1
                        (_)? @arg2
                    )
                ) @call
                (#match? @func_name "^(printf|fprintf|cout|puts|fputs|write|send)$")
            ''',
            'message': '直接输出函数调用，可能包含CRLF'
        },
        # 检测设置HTTP头部的函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @header_name
                        (_) @header_value
                    )
                ) @call
                (#match? @func_name "^(addHeader|setHeader|appendHeader|header|setcookie)$")
            ''',
            'message': 'HTTP头部设置函数调用'
        },
        # 检测字符串拼接后设置HTTP头部
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @header_name
                        (binary_expression
                            left: (_) @left
                            operator: "+"
                            right: (_) @right
                        ) @concat_value
                    )
                ) @call
                (#match? @func_name "^(addHeader|setHeader|appendHeader|header)$")
            ''',
            'message': '字符串拼接后的HTTP头部设置'
        },
        # 检测sprintf/strcat等危险字符串操作后设置头部
        {
            'query': '''
                (call_expression
                    function: (identifier) @str_func
                    arguments: (argument_list (_)* @str_args)
                ) @str_call
                (#match? @str_func "^(sprintf|strcat|strcpy|wcscat|wcscpy|snprintf|strncat)$")
                .
                (call_expression
                    function: (identifier) @header_func
                    arguments: (argument_list 
                        (_) @header_name
                        (_) @header_value
                    )
                ) @header_call
                (#match? @header_func "^(addHeader|setHeader|appendHeader|header|setcookie)$")
            ''',
            'message': '危险字符串操作后设置HTTP头部'
        },
        # 检测直接输出用户输入到HTTP响应
        {
            'query': '''
                (call_expression
                    function: (identifier) @output_func
                    arguments: (argument_list 
                        (_) @output_arg
                    )
                ) @output_call
                (#match? @output_func "^(printf|fprintf|cout|puts|fputs|write|send)$")
            ''',
            'message': '直接输出用户输入到HTTP响应'
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
        },
        {
            'func_pattern': r'^(getParameter|getQueryString|getHeader|getCookie)$',
            'message': 'HTTP请求参数获取'
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
        r'^vswprintf$',
        r'^snprintf$',
        r'^strncat$'
    ]
}

# HTTP相关函数模式
HTTP_FUNCTIONS = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list (_)* @args)
        ) @call
    ''',
    'patterns': [
        r'^(printf|fprintf|cout|puts|fputs|write|send)$',
        r'^(addHeader|setHeader|appendHeader|header|setcookie)$',
        r'^(response\.write|response\.flush|response\.end)$',
        r'^(sendHeader|setStatus|setContentType)$'
    ]
}


def detect_cpp_http_response_splitting(code, language='cpp'):
    """
    检测C++代码中HTTP响应拆分漏洞

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
    http_calls = []  # 存储所有HTTP相关函数调用
    user_input_sources = []  # 存储用户输入源
    dangerous_string_ops = []  # 存储危险字符串操作

    # 第一步：收集所有HTTP相关函数调用
    for query_info in HTTP_RESPONSE_SPLITTING_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'str_func', 'header_func', 'output_func']:
                    name = node.text.decode('utf8')
                    current_capture['func'] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['arg1', 'arg2', 'header_name', 'header_value', 'output_arg', 'concat_value']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag in ['call', 'str_call', 'header_call', 'output_call'] and current_capture:
                    # 完成一个完整的捕获
                    if 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')

                        http_calls.append({
                            'type': 'http_call',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'query_type': query_info.get('message', '')
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

    # 第四步：分析HTTP响应拆分漏洞
    for call in http_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': 'HTTP响应拆分',
            'severity': '中危',
            'message': call['query_type']
        }

        # 检查是否包含CRLF字符
        if call['argument'] and contains_crlf(call['argument']):
            vulnerability_details['message'] = f"直接包含CRLF字符: {call['function']}"
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True

        # 检查参数是否来自用户输入
        elif call['arg_node'] and is_user_input_related(call['arg_node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入直接传递给HTTP函数: {call['function']}"
            is_vulnerable = True

        # 检查参数是否经过危险字符串操作
        elif call['arg_node'] and is_dangerous_string_operation(call['arg_node'], dangerous_string_ops, root):
            vulnerability_details['message'] = f"经过危险字符串操作后传递给HTTP函数: {call['function']}"
            is_vulnerable = True

        # 检查是否可能包含CRLF注入的字符
        elif call['argument'] and may_contain_crlf_injection(call['argument']):
            vulnerability_details['message'] = f"可能包含CRLF注入的字符: {call['function']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_crlf(text):
    """
    检查文本是否包含CRLF字符（\r\n）
    """
    crlf_patterns = [
        r'\\r\\n',
        r'\r\n',
        r'%0d%0a',
        r'%0D%0A',
        r'0x0d0x0a',
    ]

    for pattern in crlf_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def may_contain_crlf_injection(text):
    """
    检查文本是否可能包含CRLF注入的字符
    """
    injection_patterns = [
        r'\\n',
        r'\\r',
        r'%0a',
        r'%0d',
        r'0x0a',
        r'0x0d',
        r'\\x0a',
        r'\\x0d',
    ]

    for pattern in injection_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'buffer', 'param', 'query', 'data', 'user', 'request',
                       'argv', 'env', 'cmd', 'command', 'header', 'cookie']
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


def analyze_cpp_http_response_splitting(code_string):
    """
    分析C++代码字符串中的HTTP响应拆分漏洞
    """
    return detect_cpp_http_response_splitting(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdio>
#include <cstring>
#include <string>

using namespace std;

void vulnerable_http_response() {
    char user_input[100];
    char header_value[200];

    // 直接从用户输入获取数据
    cout << "Enter your name: ";
    cin.getline(user_input, 100);

    // 高危：直接输出包含CRLF的用户输入
    printf("Content-Type: text/html\\r\\n");
    printf("Set-Cookie: name=%s\\r\\n", user_input); // HTTP响应拆分漏洞

    // 高危：字符串拼接后设置头部
    string location = "Location: " + string(user_input);
    printf("%s\\r\\n", location.c_str()); // 可能包含CRLF

    // 高危：使用危险字符串函数
    sprintf(header_value, "X-User-Data: %s", user_input);
    printf("%s\\r\\n", header_value); // 可能包含CRLF

    // 中危：可能包含注入字符
    char* param = getenv("QUERY_STRING");
    if (param) {
        printf("X-Param: %s\\r\\n", param); // 用户输入直接输出
    }
}

void safe_http_response() {
    // 安全：硬编码的CRLF
    printf("Content-Type: text/html\\r\\n");
    printf("Set-Cookie: session=12345\\r\\n");

    // 安全：过滤后的用户输入
    char user_input[100];
    cin.getline(user_input, 100);

    // 移除CRLF字符
    for (int i = 0; user_input[i]; i++) {
        if (user_input[i] == '\\r' || user_input[i] == '\\n') {
            user_input[i] = '_';
        }
    }

    printf("X-User-Name: %s\\r\\n", user_input); // 安全的输出
}

void process_http_request(const char* query_string) {
    // 检测CRLF模式
    if (strstr(query_string, "%0d%0a") || strstr(query_string, "\\r\\n")) {
        printf("HTTP/1.1 400 Bad Request\\r\\n");
        return;
    }

    // 安全的处理
    printf("HTTP/1.1 200 OK\\r\\n");
    printf("Content-Type: text/html\\r\\n");
}

int main() {
    vulnerable_http_response();
    safe_http_response();
    return 0;
}
"""

    print("=" * 60)
    print("C++ HTTP响应拆分漏洞检测")
    print("=" * 60)

    results = analyze_cpp_http_response_splitting(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到HTTP响应拆分漏洞")