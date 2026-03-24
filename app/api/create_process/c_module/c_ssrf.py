import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 服务端请求伪造（SSRF）漏洞模式
SSRF_VULNERABILITIES = {
    'c': [
        # 检测网络请求函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @url_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(curl_easy_perform|curl_easy_setopt|libcurl|wget|system|popen)$',
            'message': '网络请求函数调用'
        },
        # 检测socket网络连接
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @host_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(connect|sendto|recvfrom|gethostbyname|getaddrinfo)$',
            'message': '网络连接函数调用'
        },
        # 检测HTTP客户端函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @url_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(http_get|http_post|http_request|download_file|fetch_url)$',
            'message': 'HTTP客户端函数调用'
        },
        # 检测文件打开函数可能用于URL
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
            'func_pattern': r'^(fopen|open|fopen64|open64|freopen)$',
            'message': '文件打开函数可能用于URL访问'
        }
    ]
}

# URL处理相关模式
URL_HANDLING_PATTERNS = {
    'c': [
        # 检测URL格式的字符串
        {
            'query': '''
                (string_literal) @url_string
            ''',
            'pattern': r'^(http|https|ftp|file|gopher|dict|tftp)://',
            'message': '字符串包含URL协议'
        },
        # 检测URL拼接操作
        {
            'query': '''
                (binary_expression
                    left: (string_literal) @base_url
                    operator: "+"
                    right: (identifier) @user_input
                ) @binary_expr
            ''',
            'message': 'URL与用户输入拼接'
        },
        # 检测URL构建函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string_literal) @format_str
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(sprintf|snprintf|vsprintf|vsnprintf|strcat|strncat)$',
            'pattern': r'.*(http|https|ftp|file)://.*%s.*',
            'message': '格式化字符串构建URL'
        }
    ]
}

# 网络上下文检测
NETWORK_CONTEXT = {
    'c': [
        # 检测网络相关头文件包含
        {
            'query': '''
                (preproc_include
                    path: (string_literal) @include_path
                ) @include
            ''',
            'pattern': r'.*(curl|socket|netinet|arpa/inet|netdb|sys/socket)\.h',
            'message': '包含网络相关头文件'
        },
        # 检测网络相关类型
        {
            'query': '''
                (type_identifier) @type_name
            ''',
            'pattern': r'^(CURL|curl|sockaddr|sockaddr_in|sockaddr_in6|hostent|addrinfo)$',
            'message': '使用网络相关类型'
        },
        # 检测socket创建函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(socket|WSASocket|bind|listen|accept)$',
            'message': '网络socket函数'
        }
    ]
}

# 内部网络地址模式
INTERNAL_NETWORK_PATTERNS = {
    'c': [
        # 检测内部网络地址字符串
        {
            'query': '''
                (string_literal) @internal_addr
            ''',
            'pattern': r'(127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|::1|fc00::|fe80::)',
            'message': '字符串包含内部网络地址'
        },
        # 检测元网络地址
        {
            'query': '''
                (string_literal) @meta_addr
            ''',
            'pattern': r'(169\.254\.\d+\.\d+|224\.\d+\.\d+\.\d+|240\.\d+\.\d+\.\d+)',
            'message': '字符串包含特殊网络地址'
        }
    ]
}

# 用户输入源模式（复用之前的定义）
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


def detect_c_ssrf_vulnerabilities(code, language='c'):
    """
    检测C代码中服务端请求伪造（SSRF）漏洞

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
    network_function_calls = []  # 存储网络相关函数调用
    url_handling_patterns = []  # 存储URL处理模式
    network_context = []  # 存储网络上下文信息
    internal_network_patterns = []  # 存储内部网络地址模式
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集网络相关函数调用
    for query_info in SSRF_VULNERABILITIES[language]:
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

                elif tag in ['url_arg', 'host_arg', 'path_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node
                    # 检查参数模式
                    arg_pattern = query_info.get('pattern', '')
                    if arg_pattern and re.search(arg_pattern, current_capture['arg'], re.IGNORECASE):
                        current_capture['arg_match'] = True

                elif tag in ['call'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    network_function_calls.append({
                        'type': 'network_function',
                        'line': current_capture['line'],
                        'function': current_capture.get('func', ''),
                        'argument': current_capture.get('arg', ''),
                        'arg_node': current_capture.get('arg_node'),
                        'code_snippet': code_snippet,
                        'node': node,
                        'arg_match': current_capture.get('arg_match', False),
                        'message': query_info.get('message', '')
                    })
                    current_capture = {}

        except Exception as e:
            print(f"网络函数查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第二步：收集URL处理模式
    for query_info in URL_HANDLING_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['url_string', 'base_url', 'format_str']:
                    text = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')

                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        url_handling_patterns.append({
                            'type': 'url_pattern',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'pattern_match': True,
                            'message': query_info.get('message', '')
                        })

                elif tag in ['user_input', 'func_name']:
                    var_text = node.text.decode('utf8')
                    code_snippet = node.parent.text.decode('utf8')
                    url_handling_patterns.append({
                        'type': 'url_building',
                        'line': node.start_point[0] + 1,
                        'variable': var_text,
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    })

        except Exception as e:
            print(f"URL处理模式查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第三步：收集网络上下文信息
    for query_info in NETWORK_CONTEXT[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                text = node.text.decode('utf8')

                if tag in ['include_path']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        network_context.append({
                            'type': 'network_include',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

                elif tag in ['type_name']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        network_context.append({
                            'type': 'network_type',
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
                        network_context.append({
                            'type': 'network_function',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"网络上下文查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第四步：收集内部网络地址模式
    for query_info in INTERNAL_NETWORK_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['internal_addr', 'meta_addr']:
                    text = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')

                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        internal_network_patterns.append({
                            'type': 'internal_network',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"内部网络模式查询错误 {query_info.get('message', '未知')}: {e}")
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

    # 第六步：分析SSRF漏洞
    vulnerabilities.extend(analyze_ssrf_vulnerabilities(
        network_function_calls, url_handling_patterns, network_context,
        internal_network_patterns, user_input_sources
    ))

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_ssrf_vulnerabilities(network_calls, url_patterns, net_context, internal_networks, user_input_sources):
    """
    分析SSRF漏洞
    """
    vulnerabilities = []

    # 分析网络函数调用漏洞
    for call in network_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '服务端请求伪造(SSRF)',
            'severity': '高危'
        }

        # 检查是否包含用户输入
        if call.get('arg_node') and is_user_input_related(call['arg_node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入直接传递给网络函数: {call['function']}"
            is_vulnerable = True

        # 检查是否包含URL模式且可能动态构建
        elif call.get('arg_match', False):
            vulnerability_details['message'] = f"网络函数包含动态URL内容: {call['function']}"
            is_vulnerable = True

        # 检查文件操作函数在网络上下文中
        elif call['function'] in ['fopen', 'open'] and is_in_network_context(call['node'], net_context):
            vulnerability_details['message'] = f"网络上下文中的文件操作可能用于URL访问: {call['function']}"
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    # 分析URL处理模式漏洞
    for pattern in url_patterns:
        is_vulnerable = False
        vulnerability_details = {
            'line': pattern['line'],
            'code_snippet': pattern['code_snippet'],
            'vulnerability_type': '服务端请求伪造(SSRF)',
            'severity': '中危'
        }

        if pattern.get('pattern_match', False) and pattern.get('variable'):
            vulnerability_details['message'] = f"URL与用户输入拼接: {pattern['message']}"
            is_vulnerable = True

        elif pattern.get('variable') and is_user_input_variable(pattern.get('variable', ''), user_input_sources):
            vulnerability_details['message'] = f"用户输入变量用于URL构建: {pattern['message']}"
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True

        elif pattern.get('pattern_match', False) and is_in_network_context(pattern['node'], net_context):
            vulnerability_details['message'] = f"网络上下文中的URL处理: {pattern['message']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    # 分析内部网络访问模式
    for internal in internal_networks:
        is_vulnerable = False
        vulnerability_details = {
            'line': internal['line'],
            'code_snippet': internal['code_snippet'],
            'vulnerability_type': '服务端请求伪造(SSRF)',
            'severity': '中危'
        }

        if is_in_network_context(internal['node'], net_context):
            vulnerability_details['message'] = f"网络上下文中访问内部地址: {internal['message']}"
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
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'url', 'host', 'address']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_in_network_context(node, net_context):
    """
    检查节点是否在网络上下文中
    """
    node_line = node.start_point[0] + 1

    for context in net_context:
        context_line = context['line']
        # 如果网络上下文在调用之前或同一区域
        if context_line <= node_line and (node_line - context_line) < 50:
            return True

    return False


def is_user_input_variable(var_name, user_input_sources):
    """
    检查变量名是否与用户输入相关
    """
    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'url']
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


def analyze_ssrf(code_string):
    """
    分析C代码字符串中的服务端请求伪造(SSRF)漏洞
    """
    return detect_c_ssrf_vulnerabilities(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - SSRF场景
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// 危险示例 - SSRF漏洞
void vulnerable_ssrf_functions(int argc, char* argv[]) {
    CURL *curl;
    CURLcode res;

    // 漏洞1: 直接使用用户输入构建URL
    char* user_url = argv[1];
    char url1[200];
    sprintf(url1, "http://%s/api/data", user_url);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url1);  // SSRF漏洞
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    // 漏洞2: 直接使用用户输入的URL
    if (argc > 2) {
        curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_URL, argv[2]);  // 直接SSRF漏洞
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    // 漏洞3: 使用system执行curl命令
    char command[300];
    sprintf(command, "curl %s", argv[1]);
    system(command);  // 命令注入+SSRF

    // 漏洞4: socket直接连接用户输入的地址
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    char* user_host = argv[3];
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(80);
    inet_pton(AF_INET, user_host, &servaddr.sin_addr);  // SSRF漏洞

    connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    // 漏洞5: 文件协议SSRF
    char file_url[200];
    sprintf(file_url, "file://%s", argv[4]);
    // 可能用于读取本地文件

    // 漏洞6: 内部地址访问
    char internal_url[] = "http://127.0.0.1:8080/admin";
    curl_easy_setopt(curl, CURLOPT_URL, internal_url);  // 内部网络访问

    // 漏洞7: 使用wget下载
    char download_cmd[200];
    sprintf(download_cmd, "wget %s -O output.txt", argv[1]);
    system(download_cmd);  // SSRF漏洞
}

// 相对安全的示例
void safe_network_functions() {
    CURL *curl;

    // 安全1: 硬编码URL
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://api.example.com/public/data");
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    // 安全2: 经过验证的URL
    char validated_url[200];
    // URL验证逻辑...
    // if (is_valid_url(user_input)) {
    //     strcpy(validated_url, user_input);
    // }

    // 安全3: 限制访问范围
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://trusted-domain.com/api");
    // 设置允许的域名白名单
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}

// 其他网络函数示例
void socket_example(int argc, char* argv[]) {
    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // 危险: 使用用户输入的地址
    servaddr.sin_addr.s_addr = inet_addr(argv[1]);  // SSRF漏洞

    // 安全: 硬编码地址
    servaddr.sin_addr.s_addr = inet_addr("8.8.8.8");  // 安全
}

int main(int argc, char* argv[]) {
    vulnerable_ssrf_functions(argc, argv);
    safe_network_functions();
    socket_example(argc, argv);
    return 0;
}
"""

    print("=" * 60)
    print("C语言服务端请求伪造(SSRF)漏洞检测")
    print("=" * 60)

    results = analyze_ssrf(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在SSRF漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SSRF漏洞")