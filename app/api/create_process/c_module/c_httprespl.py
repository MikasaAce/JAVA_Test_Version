import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# HTTP响应拆分漏洞模式
HTTP_RESPONSE_SPLITTING_VULNERABILITIES = {
    'c': [
        # 检测HTTP头设置函数
        {
            'id': 'header_setting',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @header_name
                        . (string_literal) @header_value
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf|strcpy|strcat|memcpy|send|write)$',
            'header_pattern': r'^.*[Hh]eader.*$',
            'message': 'HTTP头设置函数调用'
        },
        # 检测CRLF字符在字符串字面量中
        {
            'id': 'crlf_in_string',
            'query': '''
                (string_literal) @crlf_string
            ''',
            'crlf_pattern': r'\\r\\n',
            'message': '字符串中包含CRLF字符'
        },
        # 检测换行符连接操作
        {
            'id': 'string_concatenation',
            'query': '''
                (call_expression
                    function: (identifier) @concat_func
                    arguments: (argument_list (_)* @concat_args)
                ) @concat_call
            ''',
            'func_pattern': r'^(strcat|strncat|sprintf|snprintf)$',
            'message': '字符串拼接函数可能用于构建HTTP响应'
        },
        # 检测用户输入直接用于HTTP头
        {
            'id': 'user_input_in_header',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @header_pattern
                        . (identifier) @user_input_var
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf)$',
            'header_pattern': r'^.*(%s|%d|%f).*$',
            'message': '用户输入直接用于HTTP头'
        },
        # 检测重定向操作
        {
            'id': 'redirect_operation',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @redirect_header
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf)$',
            'redirect_pattern': r'^.*[Ll]ocation.*$',
            'message': 'HTTP重定向头设置'
        },
        # 检测Cookie设置操作
        {
            'id': 'cookie_setting',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @cookie_header
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf)$',
            'cookie_pattern': r'^.*[Ss]et-[Cc]ookie.*$',
            'message': 'Cookie头设置'
        },
        # 检测变量赋值中的CRLF风险
        {
            'id': 'crlf_assignment',
            'query': '''
                (assignment_expression
                    left: (identifier) @var_name
                    right: (string_literal) @crlf_value
                ) @assignment
            ''',
            'message': '可能包含CRLF的字符串赋值'
        },
        # 检测HTTP响应状态码设置
        {
            'id': 'status_setting',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @status_header
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf)$',
            'status_pattern': r'^.*[Ss]tatus.*$',
            'message': 'HTTP状态头设置'
        }
    ]
}

# HTTP响应拆分检测配置
HTTP_RESPONSE_SPLITTING_CONFIG = {
    'crlf_patterns': [
        r'\\r\\n',  # CRLF
        r'%0d%0a',  # URL编码的CRLF
        r'%0a',  # URL编码的LF
        r'%0d',  # URL编码的CR
        r'\n',  # LF
        r'\r',  # CR
        r'0x0d0x0a',  # 十六进制CRLF
    ],
    'dangerous_headers': [
        'Location', 'Set-Cookie', 'Content-Type', 'Content-Length',
        'Status', 'Refresh', 'WWW-Authenticate'
    ],
    'vulnerable_functions': [
        'printf', 'fprintf', 'sprintf', 'snprintf', 'strcat', 'strncat',
        'strcpy', 'strncpy', 'memcpy', 'send', 'write'
    ],
    'safe_validation_functions': [
        'strstr', 'strchr', 'strcspn', 'strpbrk', 'validate', 'sanitize',
        'encode', 'escape', 'filter'
    ]
}

# CRLF注入关键词
CRLF_KEYWORDS = [
    'crlf', 'newline', 'linebreak', 'carriage', 'return',
    'header', 'response', 'http', 'redirect', 'cookie'
]


def get_node_id(node):
    """获取节点的唯一标识符"""
    return f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"


def detect_c_http_response_splitting(code, language='c'):
    """
    检测C代码中HTTP响应拆分漏洞

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
    http_operations = []  # 存储HTTP相关操作
    crlf_operations = []  # 存储CRLF相关操作
    user_input_sources = []  # 存储用户输入源
    processed_nodes = set()  # 记录已处理的节点ID

    # 第一步：收集用户输入源
    user_input_sources = collect_user_input_sources(root, code)

    # 第二步：收集所有HTTP响应相关操作
    for query_info in HTTP_RESPONSE_SPLITTING_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                node_id = get_node_id(node)
                if node_id in processed_nodes:
                    continue

                node_text = node.text.decode('utf8').strip('"\'')

                if tag in ['func_name']:
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, node_text, re.IGNORECASE):
                        current_capture['func'] = node_text
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['header_name', 'header_pattern', 'redirect_header',
                             'cookie_header', 'status_header']:
                    header_pattern = query_info.get('header_pattern', '')
                    if header_pattern and re.match(header_pattern, node_text, re.IGNORECASE):
                        current_capture['header'] = node_text
                        current_capture['header_node'] = node

                elif tag in ['header_value']:
                    if contains_crlf_patterns(node_text):
                        current_capture['crlf_value'] = node_text
                        current_capture['value_node'] = node

                elif tag in ['crlf_string']:
                    crlf_pattern = query_info.get('crlf_pattern', '')
                    if crlf_pattern and re.search(crlf_pattern, node_text, re.IGNORECASE):
                        current_capture['crlf_string'] = node_text
                        current_capture['crlf_node'] = node

                elif tag in ['concat_func']:
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, node_text, re.IGNORECASE):
                        current_capture['concat_func'] = node_text
                        current_capture['concat_node'] = node.parent

                elif tag in ['user_input_var']:
                    if is_user_input_variable(node_text, user_input_sources):
                        current_capture['user_input'] = node_text
                        current_capture['input_node'] = node

                elif tag in ['crlf_value']:
                    if contains_crlf_patterns(node_text):
                        current_capture['crlf_assignment'] = node_text
                        current_capture['assign_node'] = node

                elif tag in ['call', 'assignment', 'concat_call'] and current_capture:
                    # 完成捕获
                    node_id = get_node_id(node)
                    if node_id in processed_nodes:
                        current_capture = {}
                        continue

                    code_snippet = node.text.decode('utf8')
                    capture_data = {
                        'id': query_info['id'],
                        'type': query_info.get('message', 'unknown'),
                        'line': current_capture.get('line', node.start_point[0] + 1),
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    }

                    # 添加特定信息
                    for key in ['func', 'header', 'crlf_value', 'crlf_string',
                                'concat_func', 'user_input', 'crlf_assignment']:
                        if key in current_capture:
                            capture_data[key] = current_capture[key]

                    http_operations.append(capture_data)
                    processed_nodes.add(node_id)

                    # 如果是CRLF相关操作，单独记录
                    if any(key in current_capture for key in ['crlf_value', 'crlf_string', 'crlf_assignment']):
                        crlf_operations.append(capture_data)

                    current_capture = {}

        except Exception as e:
            print(f"HTTP响应拆分检测查询错误 {query_info.get('id', 'unknown')}: {e}")
            continue

    # 第三步：分析HTTP响应拆分漏洞 - 使用去重机制
    vulnerabilities = analyze_response_splitting(
        http_operations, crlf_operations, user_input_sources, code, root
    )

    return sorted(vulnerabilities, key=lambda x: x['line'])


def collect_user_input_sources(root, code):
    """
    收集用户输入源
    """
    user_input_sources = []

    # 定义用户输入函数模式
    input_functions = [
        'scanf', 'fscanf', 'sscanf', 'gets', 'fgets', 'getchar',
        'fgetc', 'getc', 'read', 'getline', 'recv', 'recvfrom',
        'recvmsg', 'getenv'
    ]

    query_pattern = '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    '''

    try:
        query = LANGUAGES['c'].query(query_pattern)
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                if func_name in input_functions:
                    user_input_sources.append({
                        'function': func_name,
                        'node': node.parent,
                        'line': node.start_point[0] + 1,
                        'code_snippet': node.parent.text.decode('utf8')
                    })
    except Exception as e:
        print(f"用户输入源收集错误: {e}")

    return user_input_sources


def analyze_response_splitting(http_operations, crlf_operations, user_input_sources, code, root):
    """
    分析HTTP响应拆分漏洞
    """
    vulnerabilities = []
    processed_locations = set()

    # 分析CRLF直接使用漏洞
    for operation in crlf_operations:
        location_key = f"{operation['line']}:{operation['id']}"
        if location_key in processed_locations:
            continue
        processed_locations.add(location_key)

        vuln = analyze_crlf_direct_usage(operation, code, root)
        if vuln:
            vulnerabilities.append(vuln)

    # 分析用户输入导致的CRLF注入
    for operation in http_operations:
        location_key = f"{operation['line']}:{operation['id']}"
        if location_key in processed_locations:
            continue

        if 'user_input' in operation and 'header' in operation:
            processed_locations.add(location_key)
            vuln = analyze_user_input_crlf(operation, user_input_sources, code, root)
            if vuln:
                vulnerabilities.append(vuln)

    # 分析字符串拼接导致的CRLF注入
    for operation in http_operations:
        location_key = f"{operation['line']}:{operation['id']}"
        if location_key in processed_locations:
            continue

        if 'concat_func' in operation:
            processed_locations.add(location_key)
            vuln = analyze_concat_crlf(operation, code, root)
            if vuln:
                vulnerabilities.append(vuln)

    # 分析重定向和Cookie头的CRLF风险
    redirect_cookie_vulns = analyze_redirect_cookie_vulnerabilities(http_operations, processed_locations, code, root)
    vulnerabilities.extend(redirect_cookie_vulns)

    return vulnerabilities


def analyze_crlf_direct_usage(operation, code, root):
    """
    分析直接使用CRLF字符的漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    # 检查是否在HTTP头上下文中使用CRLF
    if is_in_http_header_context(operation, code, root):
        crlf_pattern = extract_crlf_pattern(operation)

        return {
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'HTTP响应拆分',
            'severity': '高危',
            'message': f'HTTP头中直接使用CRLF字符: {crlf_pattern}',
            'rule_id': operation['id']
        }

    return None


def analyze_user_input_crlf(operation, user_input_sources, code, root):
    """
    分析用户输入导致的CRLF注入漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    if 'user_input' in operation and 'header' in operation:
        # 检查用户输入是否未经验证直接用于HTTP头
        if not has_input_validation(operation, user_input_sources, code, root):
            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': 'HTTP响应拆分',
                'severity': '严重',
                'message': '用户输入未经验证直接用于HTTP头，可能导致CRLF注入',
                'rule_id': operation['id']
            }

    return None


def analyze_concat_crlf(operation, code, root):
    """
    分析字符串拼接导致的CRLF注入漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    if 'concat_func' in operation:
        # 检查拼接操作是否用于构建HTTP头
        if is_http_header_construction(operation, code, root):
            # 检查是否有CRLF验证
            if not has_crlf_validation(operation, code, root):
                return {
                    'line': line,
                    'code_snippet': code_snippet,
                    'vulnerability_type': 'HTTP响应拆分',
                    'severity': '高危',
                    'message': '字符串拼接构建HTTP头，可能被CRLF注入',
                    'rule_id': operation['id']
                }

    return None


def analyze_redirect_cookie_vulnerabilities(http_operations, processed_locations, code, root):
    """
    分析重定向和Cookie头的特定漏洞
    """
    vulnerabilities = []

    for operation in http_operations:
        location_key = f"{operation['line']}:{operation['id']}"
        if location_key in processed_locations:
            continue

        if 'header' in operation:
            header_text = operation['header']

            # 检查重定向头
            if re.search(r'[Ll]ocation', header_text, re.IGNORECASE):
                processed_locations.add(location_key)
                vuln = analyze_redirect_vulnerability(operation, code, root)
                if vuln:
                    vulnerabilities.append(vuln)

            # 检查Cookie头
            elif re.search(r'[Ss]et-[Cc]ookie', header_text, re.IGNORECASE):
                processed_locations.add(location_key)
                vuln = analyze_cookie_vulnerability(operation, code, root)
                if vuln:
                    vulnerabilities.append(vuln)

    return vulnerabilities


def analyze_redirect_vulnerability(operation, code, root):
    """
    分析重定向头的CRLF注入漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    # 检查重定向值是否包含用户输入或未验证数据
    if is_redirect_value_vulnerable(operation, code, root):
        return {
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'HTTP响应拆分',
            'severity': '严重',
            'message': '重定向Location头可能被CRLF注入攻击',
            'rule_id': operation['id']
        }

    return None


def analyze_cookie_vulnerability(operation, code, root):
    """
    分析Cookie头的CRLF注入漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    if is_cookie_value_vulnerable(operation, code, root):
        return {
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'HTTP响应拆分',
            'severity': '高危',
            'message': 'Set-Cookie头可能被CRLF注入攻击',
            'rule_id': operation['id']
        }

    return None


def contains_crlf_patterns(text):
    """
    检查文本是否包含CRLF模式
    """
    for pattern in HTTP_RESPONSE_SPLITTING_CONFIG['crlf_patterns']:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def is_user_input_variable(var_name, user_input_sources):
    """
    检查变量名是否与用户输入相关
    """
    input_var_patterns = [
        r'.*input.*', r'.*user.*', r'.*param.*', r'.*arg.*',
        r'.*data.*', r'.*buffer.*', r'.*query.*', r'.*post.*',
        r'.*get.*', r'.*request.*'
    ]

    for pattern in input_var_patterns:
        if re.search(pattern, var_name, re.IGNORECASE):
            return True

    # 检查是否在用户输入源中
    for source in user_input_sources:
        if var_name in source['code_snippet']:
            return True

    return False


def is_in_http_header_context(operation, code, root):
    """
    检查操作是否在HTTP头上下文中
    """
    code_snippet = operation['code_snippet']

    # 检查是否包含HTTP头关键词
    header_indicators = [
        'Header', 'Location', 'Set-Cookie', 'Content-Type',
        'Status', 'HTTP/', 'HTTP_'
    ]

    for indicator in header_indicators:
        if indicator in code_snippet:
            return True

    # 检查父节点是否包含HTTP相关代码
    parent = operation['node'].parent
    while parent:
        parent_text = parent.text.decode('utf8')
        for indicator in header_indicators:
            if indicator in parent_text:
                return True
        parent = parent.parent

    return False


def extract_crlf_pattern(operation):
    """
    提取CRLF模式
    """
    text = ""
    for key in ['crlf_value', 'crlf_string', 'crlf_assignment']:
        if key in operation:
            text = operation[key]
            break

    for pattern in HTTP_RESPONSE_SPLITTING_CONFIG['crlf_patterns']:
        if re.search(pattern, text, re.IGNORECASE):
            return pattern

    return "unknown"


def has_input_validation(operation, user_input_sources, code, root):
    """
    检查用户输入是否有验证
    """
    line = operation['line']
    input_var = operation.get('user_input', '')

    # 查找输入验证函数调用
    validation_functions = HTTP_RESPONSE_SPLITTING_CONFIG['safe_validation_functions']

    # 检查操作之前的代码是否有验证
    node = operation['node']
    current = node.prev_sibling

    while current and current.start_point[0] >= max(0, line - 10):
        if current.type == 'call_expression':
            call_text = current.text.decode('utf8')
            for val_func in validation_functions:
                if val_func in call_text and input_var in call_text:
                    return True
        current = current.prev_sibling

    return False


def is_http_header_construction(operation, code, root):
    """
    检查字符串拼接是否用于构建HTTP头
    """
    code_snippet = operation['code_snippet']

    header_indicators = [
        'Header', 'Location', 'Set-Cookie', 'Content-Type',
        'Status', 'HTTP'
    ]

    for indicator in header_indicators:
        if indicator in code_snippet:
            return True

    return False


def has_crlf_validation(operation, code, root):
    """
    检查是否有CRLF验证
    """
    line = operation['line']

    # 查找CRLF检查函数
    crlf_check_functions = ['strstr', 'strchr', 'strcspn', 'strpbrk']
    node = operation['node']

    # 检查附近的函数调用
    current = node.prev_sibling
    while current and current.start_point[0] >= max(0, line - 5):
        if current.type == 'call_expression':
            call_text = current.text.decode('utf8')
            for check_func in crlf_check_functions:
                if check_func in call_text and ('\\r\\n' in call_text or '\\n' in call_text):
                    return True
        current = current.prev_sibling

    return False


def is_redirect_value_vulnerable(operation, code, root):
    """
    检查重定向值是否易受攻击
    """
    code_snippet = operation['code_snippet']

    # 检查是否包含用户输入模式
    user_input_indicators = ['%s', '%d', '%f', 'argv', 'input', 'user']

    for indicator in user_input_indicators:
        if indicator in code_snippet:
            return True

    return False


def is_cookie_value_vulnerable(operation, code, root):
    """
    检查Cookie值是否易受攻击
    """
    code_snippet = operation['code_snippet']

    # 检查是否包含动态内容
    dynamic_indicators = ['%s', 'argv', 'input', 'user', 'getenv']

    for indicator in dynamic_indicators:
        if indicator in code_snippet:
            return True

    return False


def analyze_c_code_for_response_splitting(code_string):
    """
    分析C代码字符串中的HTTP响应拆分漏洞
    """
    return detect_c_http_response_splitting(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - HTTP响应拆分示例
    test_c_code = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 存在HTTP响应拆分漏洞的示例
void vulnerable_http_response() {
    char* user_input = getenv("QUERY_STRING");

    // 漏洞1: 直接使用CRLF字符
    printf("Content-Type: text/html\\r\\n");  // 正常的CRLF使用
    printf("Location: /redirect\\r\\n\\r\\nInjected-Header: malicious\\r\\n");  // 可能被利用

    // 漏洞2: 用户输入直接用于重定向头
    if (user_input != NULL) {
        printf("Location: %s\\r\\n", user_input);  // CRLF注入风险
    }

    // 漏洞3: 字符串拼接构建HTTP头
    char redirect_header[256];
    char* redirect_url = user_input;
    sprintf(redirect_header, "Location: %s\\r\\n", redirect_url);  // 高风险

    // 漏洞4: 未验证的Cookie值
    char* cookie_value = user_input;
    printf("Set-Cookie: session=%s; Path=/\\r\\n", cookie_value);  // Cookie注入风险

    // 漏洞5: 多个头拼接
    char full_response[512];
    sprintf(full_response, "HTTP/1.1 302 Found\\r\\nLocation: %s\\r\\nContent-Type: text/html\\r\\n\\r\\n", user_input);
}

// 相对安全的HTTP响应处理示例
void secure_http_response() {
    char* user_input = getenv("QUERY_STRING");

    // 安全示例1: 验证和清理用户输入
    if (user_input != NULL) {
        // 移除CRLF字符
        char sanitized_input[256];
        sanitize_crlf(user_input, sanitized_input, sizeof(sanitized_input));

        printf("Location: %s\\r\\n", sanitized_input);  // 安全的重定向
    }

    // 安全示例2: 使用安全的头设置函数
    set_safe_header("Location", "/safe-redirect");
    set_safe_header("Set-Cookie", "session=secure; HttpOnly; Secure");

    // 安全示例3: 硬编码或验证过的值
    printf("Content-Type: text/html\\r\\n");
    printf("Content-Length: 100\\r\\n");
    printf("\\r\\n");
}

// CRLF清理函数
void sanitize_crlf(const char* input, char* output, size_t output_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] != '\\0' && j < output_size - 1; i++) {
        if (input[i] == '\\r' || input[i] == '\\n') {
            // 跳过CRLF字符
            continue;
        }
        output[j++] = input[i];
    }
    output[j] = '\\0';
}

// 安全的头设置函数
void set_safe_header(const char* header_name, const char* header_value) {
    // 验证头值是否安全
    if (strstr(header_value, "\\r\\n") == NULL && strchr(header_value, '\\n') == NULL) {
        printf("%s: %s\\r\\n", header_name, header_value);
    } else {
        // 记录安全事件或使用默认值
        printf("%s: invalid\\r\\n", header_name);
    }
}

// 存在风险的函数
void risky_redirect(char* url) {
    // 没有输入验证
    printf("Location: %s\\r\\n", url);  // 高风险
}

void process_user_request(char* username, char* action) {
    // 漏洞: 用户控制的数据直接用于HTTP头
    if (strcmp(action, "login") == 0) {
        printf("Set-Cookie: user=%s; Path=/\\r\\n", username);  // 需要验证
    } else if (strcmp(action, "redirect") == 0) {
        char redirect_url[100];
        sprintf(redirect_url, "/user/%s", username);
        printf("Location: %s\\r\\n", redirect_url);  // 需要验证
    }
}

int main() {
    vulnerable_http_response();
    secure_http_response();

    // 测试风险函数
    risky_redirect("http://example.com\\r\\nInjected-Header: value");

    process_user_request("admin", "login");
    process_user_request("user\\r\\nSet-Cookie: malicious=value", "redirect");

    return 0;
}
"""

    print("=" * 60)
    print("C语言HTTP响应拆分漏洞检测")
    print("=" * 60)

    results = analyze_c_code_for_response_splitting(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在HTTP响应拆分漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   规则ID: {vuln.get('rule_id', 'N/A')}")
    else:
        print("未检测到HTTP响应拆分漏洞")