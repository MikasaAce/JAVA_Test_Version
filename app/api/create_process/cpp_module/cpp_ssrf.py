import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++ SSRF漏洞模式
SSRF_VULNERABILITIES = {
    'cpp': [
        # 检测网络请求函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(curl_easy_perform|curl_multi_perform|libcurl|send|recv|connect|WinHttpSendRequest|InternetReadFile|URLDownloadToFile|HttpSendRequest|WebClient|system|popen)$',
            'message': '网络请求函数调用'
        },
        # 检测URL处理函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(fopen|fopen_s|open|CreateFile|URLDownloadToFile|InternetOpenUrl|WinHttpOpenRequest)$',
            'message': 'URL或文件处理函数调用'
        },
        # 检测HTTP客户端库调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(HttpClient|WebRequest|WebClient|QNetworkAccessManager|QNetworkRequest|boost::asio|asio::ip::tcp)$',
            'message': 'HTTP客户端库调用'
        },
        # 检测字符串拼接构建URL
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
            'func_pattern': r'^(curl_easy_setopt|InternetOpenUrl|WinHttpOpenRequest|QNetworkRequest|HttpClient|WebClient)$',
            'message': '字符串拼接构建URL'
        },
        # 检测通过指针或引用传递的URL参数
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
            'func_pattern': r'^(curl_easy_setopt|InternetOpenUrl|WinHttpOpenRequest)$',
            'arg_index': 0,
            'opt_pattern': r'^(CURLOPT_URL|URL|szUrl|lpszUrlName)$',
            'message': 'URL参数传递'
        }
    ]
}

# C++用户输入源模式（与SSRF相关）
USER_INPUT_SOURCES_SSRF = {
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
            'func_pattern': r'^(GetDlgItemText|GetWindowText|GetMenuItemInfo)$',
            'message': 'UI输入获取'
        },
        {
            'func_pattern': r'^(RegQueryValue|GetPrivateProfileString|GetProfileString)$',
            'message': '配置/注册表读取'
        }
    ]
}

# URL相关的危险函数模式
URL_DANGEROUS_FUNCTIONS = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list (_)* @args)
        ) @call
    ''',
    'patterns': [
        r'^strcat$',
        r'^strcpy$',
        r'^sprintf$',
        r'^snprintf$',
        r'^vsprintf$',
        r'^wcscat$',
        r'^wcscpy$',
        r'^swprintf$'
    ]
}

# 内部网络地址模式
INTERNAL_NETWORK_PATTERNS = [
    r'^(10\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    r'^(172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})',
    r'^(192\.168\.\d{1,3}\.\d{1,3})',
    r'^(127\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    r'^(localhost|127\.0\.0\.1|::1)',
    r'^(169\.254\.\d{1,3}\.\d{1,3})',
    r'^(0\.0\.0\.0)',
    r'^(\[::\])',
    r'^(metadata\.google\.internal)',
    r'^(169\.254\.169\.254)',
    r'^(instance-data)'
]

# 危险URL协议模式
DANGEROUS_URL_PROTOCOLS = [
    r'^(file|ftp|gopher|jar|mailto|netdoc|nntp|telnet|ldap|dict)://',
    r'^\\\\.*',
    r'^//.*',
    r'^/.*',
    r'^[a-zA-Z]:\\\.*'
]


def detect_cpp_ssrf_vulnerabilities(code, language='cpp'):
    """
    检测C++代码中服务端请求伪造(SSRF)漏洞

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
    network_calls = []  # 存储所有网络相关函数调用
    user_input_sources = []  # 存储用户输入源
    dangerous_url_ops = []  # 存储危险URL操作

    # 第一步：收集所有网络相关函数调用
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

                elif tag in ['arg1', 'arg2', 'concat_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag == 'call' and current_capture:
                    # 完成一个完整的捕获
                    if 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')

                        network_calls.append({
                            'type': 'network_call',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'arg_index': query_info.get('arg_index', None),
                            'opt_pattern': query_info.get('opt_pattern', '')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有用户输入源
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES_SSRF['query'])
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
                for pattern_info in USER_INPUT_SOURCES_SSRF['patterns']:
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

    # 第三步：收集危险URL操作
    try:
        query = LANGUAGES[language].query(URL_DANGEROUS_FUNCTIONS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in URL_DANGEROUS_FUNCTIONS['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        dangerous_url_ops.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break

    except Exception as e:
        print(f"危险URL函数查询错误: {e}")

    # 第四步：分析SSRF漏洞
    for call in network_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '服务端请求伪造(SSRF)',
            'severity': '高危'
        }

        # 情况1: 检查URL参数是否包含内部网络地址
        if call['argument'] and contains_internal_network(call['argument']):
            vulnerability_details['message'] = f"网络请求包含内部网络地址: {call['function']}"
            is_vulnerable = True

        # 情况2: 检查URL参数是否使用危险协议
        elif call['argument'] and contains_dangerous_protocol(call['argument']):
            vulnerability_details['message'] = f"网络请求使用危险协议: {call['function']}"
            is_vulnerable = True

        # 情况3: 检查参数是否来自用户输入
        elif call['arg_node'] and is_user_input_related_ssrf(call['arg_node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入直接传递给网络请求函数: {call['function']}"
            is_vulnerable = True

        # 情况4: 检查参数是否经过危险字符串操作
        elif call['arg_node'] and is_dangerous_url_operation(call['arg_node'], dangerous_url_ops):
            vulnerability_details['message'] = f"经过危险字符串操作后传递给网络请求函数: {call['function']}"
            is_vulnerable = True

        # 情况5: 检查curl选项设置
        elif call['function'].startswith('curl_') and call['argument'] and is_curl_option_vulnerable(call):
            vulnerability_details['message'] = f"cURL选项设置可能导致SSRF: {call['function']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_internal_network(url):
    """
    检查URL是否包含内部网络地址
    """
    url_str = url.lower()

    # 检查常见的内部网络地址模式
    for pattern in INTERNAL_NETWORK_PATTERNS:
        if re.search(pattern, url_str, re.IGNORECASE):
            return True

    # 检查私有IP地址
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ip_matches = re.findall(ip_pattern, url_str)

    for ip in ip_matches:
        if is_private_ip(ip):
            return True

    return False


def is_private_ip(ip):
    """
    检查IP地址是否为私有地址
    """
    try:
        octets = list(map(int, ip.split('.')))
        # 10.0.0.0/8
        if octets[0] == 10:
            return True
        # 172.16.0.0/12
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        # 192.168.0.0/16
        if octets[0] == 192 and octets[1] == 168:
            return True
        # 127.0.0.0/8
        if octets[0] == 127:
            return True
        # 169.254.0.0/16
        if octets[0] == 169 and octets[1] == 254:
            return True
    except:
        pass

    return False


def contains_dangerous_protocol(url):
    """
    检查URL是否使用危险协议
    """
    url_str = url.strip().lower()

    for pattern in DANGEROUS_URL_PROTOCOLS:
        if re.match(pattern, url_str, re.IGNORECASE):
            return True

    return False


def is_user_input_related_ssrf(arg_node, user_input_sources):
    """
    检查参数节点是否与用户输入相关（SSRF专用）
    """
    arg_text = arg_node.text.decode('utf8').lower()

    # 检查常见的URL相关用户输入变量名
    url_input_vars = ['url', 'uri', 'endpoint', 'host', 'address', 'path',
                      'link', 'resource', 'api', 'service', 'proxy']

    for var in url_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node:
            return True

    return False


def is_dangerous_url_operation(arg_node, dangerous_url_ops):
    """
    检查参数是否经过危险URL操作
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查是否直接使用了危险字符串函数的缓冲区
    for op in dangerous_url_ops:
        if op['function'] in arg_text:
            return True

    return False


def is_curl_option_vulnerable(call):
    """
    检查cURL选项设置是否可能导致SSRF
    """
    if not call['argument']:
        return False

    arg_text = call['argument'].lower()

    # 检查危险的cURL选项
    dangerous_curl_options = [
        'curlopt_url',
        'curlopt_proxy',
        'curlopt_proxyport',
        'curlopt_proxyuserpwd',
        'curlopt_proxytype',
        'curlopt_redirect',
        'curlopt_followlocation',
        'curlopt_unrestricted_auth'
    ]

    for option in dangerous_curl_options:
        if option in arg_text:
            return True

    return False


def analyze_cpp_code_ssrf(code_string):
    """
    分析C++代码字符串中的SSRF漏洞
    """
    return detect_cpp_ssrf_vulnerabilities(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <curl/curl.h>
#include <windows.h>
#include <winhttp.h>

using namespace std;

void vulnerable_ssrf_function(int argc, char* argv[]) {
    // 直接访问内部网络 - 高危
    system("curl http://192.168.1.1/admin");

    // 用户输入直接构建URL - 高危
    if (argc > 1) {
        string url = "http://" + string(argv[1]) + "/api";
        system(("curl " + url).c_str());
    }

    // 使用危险协议 - 高危
    system("curl file:///etc/passwd");

    // cURL库直接使用用户输入 - 高危
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, argv[1]); // SSRF漏洞
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    // Windows HTTP API危险使用
    HINTERNET hSession = WinHttpOpen(L"UserAgent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, L"internal-server", INTERNET_DEFAULT_HTTP_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/admin", NULL, NULL, NULL, 0);
    WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);

    // 字符串拼接构建内部URL - 高危
    char internal_url[100];
    sprintf(internal_url, "http://10.0.0.1/%s", "secret.txt");
    system(("curl " + string(internal_url)).c_str());

    // 环境变量构建URL - 高危
    char* proxy = getenv("HTTP_PROXY");
    if (proxy) {
        string cmd = "curl --proxy " + string(proxy) + " http://example.com";
        system(cmd.c_str());
    }
}

void safe_network_function() {
    // 相对安全的做法 - 硬编码外部URL
    system("curl https://api.example.com/public/data");

    // 使用白名单验证
    const char* allowed_domains[] = {"api.example.com", "cdn.example.org", NULL};
    // 这里应该有域名验证逻辑

    // 使用参数化请求
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.example.com/data");
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L); // 禁用重定向
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

int main(int argc, char* argv[]) {
    vulnerable_ssrf_function(argc, argv);
    safe_network_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++服务端请求伪造(SSRF)漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code_ssrf(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在SSRF漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SSRF漏洞")