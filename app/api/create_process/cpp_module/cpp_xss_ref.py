import os
import re
from tree_sitter import Language, Parser

# 假设language_path已定义，与您的配置一致
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++ XSS反射型漏洞模式
XSS_REFLECTED_VULNERABILITIES = {
    'cpp': [
        # 检测HTTP响应输出函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf|cout|operator<<|write|send|WSASend)$',
            'message': '输出函数调用可能包含用户输入'
        },
        # 检测Web框架的输出函数
        {
            'query': '''
                (call_expression
                    function: (field_expression
                        object: (_) @obj
                        field: (_) @field
                    )
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'obj_pattern': r'^(response|res|out|cout|std::cout)$',
            'field_pattern': r'^(write|send|operator<<|print|println)$',
            'message': 'Web响应输出函数调用'
        },
        # 检测字符串构建后输出
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
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf|cout|operator<<|write|send)$',
            'message': '字符串拼接后的输出'
        },
        # 检测HTML标签构建
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string_literal) @html_string
                    )
                ) @call
                (#match? @html_string "<[a-zA-Z][^>]*>")
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf|cout|operator<<|write|send)$',
            'message': 'HTML标签直接输出'
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
            'func_pattern': r'^(getenv|_wgetenv)$',
            'message': '环境变量获取'
        },
        {
            'func_pattern': r'^(GetCommandLine|GetCommandLineW|argv)$',
            'message': '命令行参数获取'
        },
        {
            'func_pattern': r'^(getParameter|getQueryString|getHeader)$',
            'message': 'HTTP请求参数获取'
        },
        {
            'obj_pattern': r'^(std::cin|cin|request|req)$',
            'field_pattern': r'^(operator>>|get|getline|read|getParameter|getQueryString)$',
            'message': 'C++标准输入或HTTP请求'
        }
    ]
}

# 危险HTML/JS内容模式
DANGEROUS_CONTENT_PATTERNS = {
    'query': '''
        (string_literal) @string_lit
    ''',
    'patterns': [
        r'<script[^>]*>',
        r'javascript:',
        r'onload\s*=',
        r'onerror\s*=',
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'eval\s*\(',
        r'document\.cookie',
        r'alert\s*\(',
        r'innerHTML\s*=',
        r'outerHTML\s*=',
        r'document\.write',
        r'window\.location'
    ]
}

# 编码/净化函数模式
SANITIZATION_FUNCTIONS = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list (_)* @args)
        ) @call
    ''',
    'patterns': [
        r'^htmlspecialchars$',
        r'^htmlentities$',
        r'^escapeHtml$',
        r'^encodeURIComponent$',
        r'^encodeURI$',
        r'^URLEncode$',
        r'^replace$',
        r'^regex_replace$',
        r'^sanitize$',
        r'^filter_var$'
    ]
}


def detect_cpp_xss_reflected(code, language='cpp'):
    """
    检测C++代码中反射型XSS漏洞

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
    output_calls = []  # 存储所有输出函数调用
    user_input_sources = []  # 存储用户输入源
    dangerous_content = []  # 存储危险内容模式
    sanitization_calls = []  # 存储编码/净化函数调用

    # 第一步：收集所有输出函数调用
    for query_info in XSS_REFLECTED_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'field']:
                    name = node.text.decode('utf8')
                    func_pattern = query_info.get('func_pattern', '')
                    field_pattern = query_info.get('field_pattern', '')
                    obj_pattern = query_info.get('obj_pattern', '')

                    match = False
                    if func_pattern and re.match(func_pattern, name, re.IGNORECASE):
                        match = True
                    elif 'obj' in current_capture and field_pattern and obj_pattern:
                        if (re.match(obj_pattern, current_capture.get('obj', ''), re.IGNORECASE) and
                                re.match(field_pattern, name, re.IGNORECASE)):
                            match = True

                    if match:
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['obj']:
                    current_capture['obj'] = node.text.decode('utf8')

                elif tag in ['args', 'concat_arg', 'html_string']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag in ['call'] and current_capture:
                    if 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')
                        output_calls.append({
                            'type': 'output_call',
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

    # 第三步：收集危险内容模式
    try:
        query = LANGUAGES[language].query(DANGEROUS_CONTENT_PATTERNS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'string_lit':
                content = node.text.decode('utf8')
                for pattern in DANGEROUS_CONTENT_PATTERNS['patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        dangerous_content.append({
                            'line': node.start_point[0] + 1,
                            'content': content,
                            'pattern': pattern,
                            'code_snippet': node.text.decode('utf8'),
                            'node': node
                        })
                        break

    except Exception as e:
        print(f"危险内容模式查询错误: {e}")

    # 第四步：收集编码/净化函数调用
    try:
        query = LANGUAGES[language].query(SANITIZATION_FUNCTIONS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in SANITIZATION_FUNCTIONS['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        sanitization_calls.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break

    except Exception as e:
        print(f"净化函数查询错误: {e}")

    # 第五步：分析XSS漏洞
    for call in output_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '反射型XSS',
            'severity': '中危'
        }

        # 情况1: 检查参数是否来自用户输入
        if call['arg_node'] and is_user_input_related(call['arg_node'], user_input_sources, root):
            # 检查是否经过净化处理
            if not is_sanitized(call['arg_node'], sanitization_calls, root):
                vulnerability_details['message'] = f"未净化的用户输入直接输出: {call['function']}"
                vulnerability_details['severity'] = '高危'
                is_vulnerable = True

        # 情况2: 检查是否包含危险HTML/JS内容
        elif call['arg_node'] and contains_dangerous_content(call['arg_node'], dangerous_content, root):
            vulnerability_details['message'] = f"输出包含潜在危险内容: {call['function']}"
            is_vulnerable = True

        # 情况3: 检查是否直接输出HTML标签
        if call['arg_node'] and contains_html_tags(call['arg_node']):
            vulnerability_details['message'] = f"直接输出HTML标签: {call['function']}"
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'input', 'buffer', 'param', 'query', 'form', 'request', 'cookie']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_sanitized(arg_node, sanitization_calls, root_node):
    """
    检查参数是否经过净化处理
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查是否调用了净化函数
    for sanitize_call in sanitization_calls:
        # 简单的文本匹配（实际应用中需要更精确的数据流分析）
        if sanitize_call['function'] in arg_text:
            return True

    # 检查常见的编码模式
    sanitization_patterns = [
        r'htmlspecialchars\s*\(',
        r'escapeHtml\s*\(',
        r'encodeURIComponent\s*\(',
        r'replace\s*\([^)]*<[^>]*>[^)]*\)'
    ]

    for pattern in sanitization_patterns:
        if re.search(pattern, arg_text, re.IGNORECASE):
            return True

    return False


def contains_dangerous_content(arg_node, dangerous_content, root_node):
    """
    检查参数是否包含危险内容
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查是否包含已知的危险模式
    for content in dangerous_content:
        if content['pattern'] and re.search(content['pattern'], arg_text, re.IGNORECASE):
            return True

    return False


def contains_html_tags(arg_node):
    """
    检查参数是否包含HTML标签
    """
    arg_text = arg_node.text.decode('utf8')

    html_tag_patterns = [
        r'<script[^>]*>',
        r'<div[^>]*>',
        r'<span[^>]*>',
        r'<a[^>]*>',
        r'<img[^>]*>',
        r'<form[^>]*>',
        r'<input[^>]*>'
    ]

    for pattern in html_tag_patterns:
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


def analyze_cpp_code_xss(code_string):
    """
    分析C++代码字符串中的反射型XSS漏洞
    """
    return detect_cpp_xss_reflected(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdio>
#include <cstring>
#include <string>

using namespace std;

void vulnerable_xss_function(int argc, char* argv[]) {
    // 直接输出用户输入 - 高危XSS
    printf("Welcome %s", argv[1]); // 反射型XSS漏洞

    // 字符串拼接后输出 - 高危
    string html = "<div>User: " + string(argv[1]) + "</div>";
    cout << html; // XSS漏洞

    // 直接输出HTML标签 - 中危
    cout << "<script>console.log('test')</script>"; // 潜在XSS

    // 从标准输入读取并输出
    char input[100];
    cin.getline(input, 100);
    printf("Your input: %s", input); // XSS漏洞

    // 网络数据直接输出
    // char buffer[1024];
    // recv(socket, buffer, sizeof(buffer), 0);
    // cout << buffer; // XSS漏洞

    // 环境变量输出
    char* userAgent = getenv("HTTP_USER_AGENT");
    if (userAgent) {
        cout << "User Agent: " << userAgent; // 潜在XSS
    }
}

void safe_function() {
    // 安全输出 - 硬编码内容
    cout << "<h1>Welcome</h1>";

    // 安全输出 - 净化后的内容
    string userInput = "<script>alert('xss')</script>";
    // 假设有htmlspecialchars函数
    // string safeOutput = htmlspecialchars(userInput);
    // cout << safeOutput;

    // 安全输出 - 编码URL参数
    // string encoded = encodeURIComponent(userInput);
    // cout << "<a href='?param=" << encoded << "'>Link</a>";
}

void web_framework_example() {
    // 模拟Web框架响应输出
    // HttpResponse response;
    // response.write("Data: " + getQueryParameter("data")); // XSS漏洞

    // 安全方式
    // response.write(htmlspecialchars(getQueryParameter("data")));
}

int main(int argc, char* argv[]) {
    vulnerable_xss_function(argc, argv);
    safe_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++反射型XSS漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code_xss(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到反射型XSS漏洞")