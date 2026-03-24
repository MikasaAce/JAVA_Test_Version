import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 跨站脚本：反射型（XSS）漏洞模式
REFLECTED_XSS_VULNERABILITIES = {
    'c': [
        # 检测输出函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @output_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|sprintf|snprintf|fprintf|vprintf|vsprintf|vsnprintf|puts|fputs)$',
            'message': '输出函数调用'
        },
        # 检测网络输出函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @socket_arg
                        (_) @data_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(send|write|sendto|sendmsg)$',
            'message': '网络输出函数调用'
        },
        # 检测CGI输出函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @cgi_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(cgiOut|fcgiOut|cgiprintf)$',
            'message': 'CGI输出函数调用'
        }
    ]
}

# HTML输出上下文模式
HTML_OUTPUT_PATTERNS = {
    'c': [
        # 检测HTML标签字符串
        {
            'query': '''
                (string_literal) @html_string
            ''',
            'pattern': r'<[a-zA-Z][a-zA-Z0-9]*[^>]*>|</[a-zA-Z][a-zA-Z0-9]*>',
            'message': '字符串包含HTML标签'
        },
        # 检测HTTP响应头
        {
            'query': '''
                (string_literal) @http_header
            ''',
            'pattern': r'^Content-Type:.*text/html|^Location:|^Set-Cookie:',
            'message': '字符串包含HTTP响应头'
        },
        # 检测JavaScript上下文
        {
            'query': '''
                (string_literal) @js_context
            ''',
            'pattern': r'<script.*>.*</script>|onclick=|onload=|onerror=|javascript:',
            'message': '字符串包含JavaScript上下文'
        }
    ]
}

# Web上下文检测
WEB_CONTEXT = {
    'c': [
        # 检测Web相关头文件包含
        {
            'query': '''
                (preproc_include
                    path: (string_literal) @include_path
                ) @include
            ''',
            'pattern': r'.*(cgi|fcgi|http|www|html)\.h',
            'message': '包含Web相关头文件'
        },
        # 检测CGI相关函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(getenv|get_cgi_var|cgiGetVar|cgiFormString)$',
            'message': 'CGI参数获取函数'
        }
    ]
}

# 危险的输出模式
DANGEROUS_OUTPUT_PATTERNS = {
    'c': [
        # 检测未转义的用户输出
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string_literal) @format_str
                        (identifier) @user_var
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|sprintf|fprintf)$',
            'pattern': r'.*%s.*',
            'message': '未转义的用户输入直接输出'
        },
        # 检测字符串拼接输出
        {
            'query': '''
                (binary_expression
                    left: (string_literal) @html_part
                    operator: "+"
                    right: (identifier) @user_var
                ) @binary_expr
            ''',
            'message': 'HTML与用户输入拼接输出'
        }
    ]
}

# 用户输入源模式
C_USER_INPUT_SOURCES = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(scanf|fscanf|sscanf|gets|fgets|getchar|fgetc|getc|read|getline)$',
            'message': '标准输入函数'
        },
        {
            'func_pattern': r'^(recv|recvfrom|recvmsg|read)$',
            'message': '网络输入函数'
        },
        {
            'func_pattern': r'^(fread|fgetc|fgets)$',
            'message': '文件输入函数'
        },
        {
            'func_pattern': r'^(getenv)$',
            'message': '环境变量获取'
        },
        {
            'func_pattern': r'^(main)$',
            'arg_index': 1,
            'message': '命令行参数'
        }
    ]
}


def detect_c_xss_reflected(code, language='c'):
    """
    检测C代码中跨站脚本：反射型（XSS）漏洞

    Args:
        code: C源代码字符串
        language: 语言类型，默认为'c'

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
    output_function_calls = []  # 存储输出函数调用
    html_output_patterns = []  # 存储HTML输出模式
    web_context = []  # 存储Web上下文信息
    dangerous_output_patterns = []  # 存储危险的输出模式
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集输出函数调用
    for query_info in REFLECTED_XSS_VULNERABILITIES[language]:
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
                        current_capture['func_node'] = node

                elif tag in ['output_arg', 'data_arg', 'cgi_arg', 'socket_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag in ['call'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    output_function_calls.append({
                        'type': 'output_function',
                        'line': current_capture['line'],
                        'function': current_capture.get('func', ''),
                        'argument': current_capture.get('arg', ''),
                        'arg_node': current_capture.get('arg_node'),
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    })
                    current_capture = {}

        except Exception as e:
            print(f"输出函数查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第二步：收集HTML输出模式
    for query_info in HTML_OUTPUT_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['html_string', 'http_header', 'js_context']:
                    text = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')

                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        html_output_patterns.append({
                            'type': 'html_output',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'pattern_match': True,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"HTML输出模式查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第三步：收集Web上下文信息
    for query_info in WEB_CONTEXT[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                text = node.text.decode('utf8')

                if tag in ['include_path']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        web_context.append({
                            'type': 'web_include',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

                elif tag in ['func_name']:
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, text, re.IGNORECASE):
                        code_snippet = node.parent.text.decode('utf8')
                        web_context.append({
                            'type': 'web_function',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"Web上下文查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第四步：收集危险的输出模式
    for query_info in DANGEROUS_OUTPUT_PATTERNS[language]:
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

                elif tag in ['format_str']:
                    current_capture['format'] = node.text.decode('utf8')
                    current_capture['format_node'] = node
                    # 检查格式模式
                    format_pattern = query_info.get('pattern', '')
                    if format_pattern and re.search(format_pattern, current_capture['format'], re.IGNORECASE):
                        current_capture['format_match'] = True

                elif tag in ['user_var', 'html_part']:
                    current_capture['user_var'] = node.text.decode('utf8')
                    current_capture['user_node'] = node

                elif tag in ['call', 'binary_expr'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    dangerous_output_patterns.append({
                        'type': 'dangerous_output',
                        'line': current_capture['line'],
                        'function': current_capture.get('func', ''),
                        'format': current_capture.get('format', ''),
                        'user_variable': current_capture.get('user_var', ''),
                        'code_snippet': code_snippet,
                        'node': node,
                        'format_match': current_capture.get('format_match', False),
                        'message': query_info.get('message', '')
                    })
                    current_capture = {}

        except Exception as e:
            print(f"危险输出模式查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第五步：收集用户输入源
    try:
        query = LANGUAGES[language].query(C_USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                # 检查是否匹配任何用户输入模式
                for pattern_info in C_USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')

                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        code_snippet = node.parent.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'arg_index': pattern_info.get('arg_index', None)
                        })
                        break

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第六步：分析反射型XSS漏洞
    vulnerabilities.extend(analyze_reflected_xss_vulnerabilities(
        output_function_calls, html_output_patterns, web_context,
        dangerous_output_patterns, user_input_sources
    ))

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_reflected_xss_vulnerabilities(output_calls, html_patterns, web_context, dangerous_patterns,
                                          user_input_sources):
    """
    分析反射型XSS漏洞
    """
    vulnerabilities = []

    # 分析输出函数调用漏洞
    for call in output_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '跨站脚本：反射型(XSS)',
            'severity': '中危'
        }

        # 检查是否包含用户输入
        if call.get('arg_node') and is_user_input_related(call['arg_node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入直接传递给输出函数: {call['function']}"
            is_vulnerable = True

        # 检查在Web上下文中的潜在风险
        elif is_in_web_context(call['node'], web_context):
            vulnerability_details['message'] = f"Web上下文中的输出函数: {call['function']}"
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    # 分析HTML输出模式漏洞
    for pattern in html_patterns:
        is_vulnerable = False
        vulnerability_details = {
            'line': pattern['line'],
            'code_snippet': pattern['code_snippet'],
            'vulnerability_type': '跨站脚本：反射型(XSS)',
            'severity': '高危'
        }

        if pattern.get('pattern_match', False) and is_in_web_context(pattern['node'], web_context):
            vulnerability_details['message'] = f"Web上下文中的HTML输出: {pattern['message']}"
            is_vulnerable = True

        elif pattern.get('pattern_match', False) and has_user_input_nearby(pattern['node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入附近的HTML输出: {pattern['message']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    # 分析危险的输出模式
    for dangerous in dangerous_patterns:
        is_vulnerable = False
        vulnerability_details = {
            'line': dangerous['line'],
            'code_snippet': dangerous['code_snippet'],
            'vulnerability_type': '跨站脚本：反射型(XSS)',
            'severity': '高危'
        }

        if dangerous.get('format_match', False):
            vulnerability_details['message'] = f"未转义的用户输入直接输出: {dangerous['function']}"
            is_vulnerable = True

        elif dangerous.get('user_variable') and is_user_input_variable(dangerous['user_variable'], user_input_sources):
            vulnerability_details['message'] = f"用户输入与HTML拼接输出: {dangerous['message']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return vulnerabilities


def is_user_input_related(arg_node, user_input_sources):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'query', 'name', 'email']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_in_web_context(node, web_context):
    """
    检查节点是否在Web上下文中
    """
    node_line = node.start_point[0] + 1

    for context in web_context:
        context_line = context['line']
        # 如果Web上下文在调用之前或同一区域
        if context_line <= node_line and (node_line - context_line) < 50:
            return True

    return False


def has_user_input_nearby(node, user_input_sources):
    """
    检查节点附近是否有用户输入
    """
    node_line = node.start_point[0] + 1

    for source in user_input_sources:
        source_line = source['line']
        # 如果用户输入在节点附近
        if abs(source_line - node_line) < 10:
            return True

    return False


def is_user_input_variable(var_name, user_input_sources):
    """
    检查变量名是否与用户输入相关
    """
    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'query']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', var_name, re.IGNORECASE):
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


def analyze_reflected_xss(code_string):
    """
    分析C代码字符串中的跨站脚本：反射型(XSS)漏洞
    """
    return detect_c_xss_reflected(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - 反射型XSS场景
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cgic.h>

// 危险示例 - 反射型XSS漏洞
void vulnerable_xss_functions(int argc, char* argv[]) {
    // 漏洞1: 直接输出用户输入
    char* user_input = argv[1];
    printf("Search results for: %s", user_input);  // 反射型XSS漏洞

    // 漏洞2: 拼接HTML输出
    char html_output[500];
    sprintf(html_output, "<div>Welcome %s!</div>", argv[1]);  // XSS漏洞
    printf("%s", html_output);

    // 漏洞3: CGI环境输出
    char* query_string = getenv("QUERY_STRING");
    if (query_string != NULL) {
        printf("<p>Query: %s</p>", query_string);  // XSS漏洞
    }

    // 漏洞4: 直接输出到网络
    char response[1000];
    sprintf(response, "HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n\\r\\n<html><body>%s</body></html>", argv[2]);
    // send(socket_fd, response, strlen(response), 0);  // XSS漏洞

    // 漏洞5: JavaScript上下文中的用户输入
    char js_output[300];
    sprintf(js_output, "<script>var user = '%s';</script>", argv[1]);  // XSS漏洞
    printf("%s", js_output);

    // 漏洞6: HTML属性中的用户输入
    char attribute_output[200];
    sprintf(attribute_output, "<input value=\\"%s\\">", argv[3]);  // XSS漏洞
    printf("%s", attribute_output);

    // 漏洞7: URL重定向中的用户输入
    char redirect_output[300];
    sprintf(redirect_output, "<a href=\\"%s\\">Click here</a>", argv[4]);  // XSS漏洞
    printf("%s", redirect_output);
}

// CGI程序示例
int cgiMain() {
    // 漏洞8: CGI参数直接输出
    char name[100];
    cgiFormString("name", name, sizeof(name));
    printf("Content-type: text/html\\r\\n\\r\\n");
    printf("<html><body>");
    printf("<h1>Hello %s!</h1>", name);  // 反射型XSS漏洞
    printf("</body></html>");

    return 0;
}

// 相对安全的示例
void safe_output_functions() {
    // 安全1: 硬编码输出
    printf("Hello World");  // 安全

    // 安全2: 转义用户输入
    char safe_input[100];
    // HTML转义逻辑...
    // html_escape(user_input, safe_input);
    printf("<div>%s</div>", safe_input);  // 安全

    // 安全3: 数字输出
    int user_id = 123;
    printf("User ID: %d", user_id);  // 安全

    // 安全4: 过滤后的输出
    char filtered_input[100];
    // 输入过滤逻辑...
    // if (is_safe_input(user_input)) {
    //     strcpy(filtered_input, user_input);
    // }
    printf("%s", filtered_input);  // 相对安全
}

// Web服务器响应示例
void http_response_example(int argc, char* argv[]) {
    // 生成HTTP响应
    printf("HTTP/1.1 200 OK\\r\\n");
    printf("Content-Type: text/html\\r\\n");
    printf("\\r\\n");
    printf("<html>");
    printf("<head><title>Search Results</title></head>");
    printf("<body>");

    // 危险: 直接输出搜索词
    printf("<h1>Results for: %s</h1>", argv[1]);  // XSS漏洞

    // 相对安全: 转义输出
    // printf("<h1>Results for: %s</h1>", html_escape(argv[1]));

    printf("</body>");
    printf("</html>");
}

int main(int argc, char* argv[]) {
    vulnerable_xss_functions(argc, argv);
    safe_output_functions();
    http_response_example(argc, argv);
    return 0;
}
"""

    print("=" * 60)
    print("C语言跨站脚本：反射型(XSS)漏洞检测")
    print("=" * 60)

    results = analyze_reflected_xss(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在反射型XSS漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到反射型XSS漏洞")