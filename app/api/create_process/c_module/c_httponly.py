import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# Cookie安全：HTTPonly未设置漏洞模式
COOKIE_HTTPONLY_VULNERABILITIES = {
    'c': [
        # 检测Set-Cookie头设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @header_name
                        . (string_literal) @cookie_value
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf|strcpy|strcat|memcpy|send|write)$',
            'header_pattern': r'^.*[Ss]et-[Cc]ookie.*$',
            'message': 'Set-Cookie头设置函数调用'
        },
        # 检测HTTP头设置函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @header_arg
                        . (_) @value_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(add_header|set_header|http_header|respond|send_header)$',
            'message': 'HTTP头设置函数调用'
        },
        # 检测Cookie相关字符串操作
        {
            'query': '''
                (string_literal) @cookie_string
            ''',
            'cookie_pattern': r'[Ss]et-[Cc]ookie',
            'message': '包含Set-Cookie的字符串字面量'
        },
        # 检测Cookie属性设置
        {
            'query': '''
                (string_literal) @cookie_attr
            ''',
            'attr_pattern': r'^(HttpOnly|Secure|SameSite|Domain|Path|Expires|Max-Age)$',
            'message': 'Cookie属性字符串'
        },
        # 检测字符串拼接操作中的Cookie设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @concat_func
                    arguments: (argument_list (_)* @concat_args)
                ) @concat_call
            ''',
            'func_pattern': r'^(strcat|strncat|sprintf|snprintf)$',
            'message': '字符串拼接函数可能用于构建Cookie头'
        },
        # 检测变量赋值中的Cookie相关操作
        {
            'query': '''
                (assignment_expression
                    left: (identifier) @var_name
                    right: (string_literal) @cookie_value
                ) @assignment
            ''',
            'message': 'Cookie值赋值操作'
        },
        # 检测条件判断中的Cookie检查
        {
            'query': '''
                (if_statement
                    condition: (_) @condition
                    consequence: (_) @consequence
                ) @if_stmt
            ''',
            'message': '条件语句可能包含Cookie逻辑'
        },
        # 检测函数定义中的Cookie处理
        {
            'query': '''
                (function_definition
                    declarator: (function_declarator
                        declarator: (identifier) @func_name
                    )
                    body: (compound_statement) @func_body
                ) @func_def
            ''',
            'func_pattern': r'.*[Cc]ookie.*',
            'message': 'Cookie相关函数定义'
        }
    ]
}

# Cookie安全配置
COOKIE_SECURITY_CONFIG = {
    'required_attributes': ['HttpOnly', 'Secure'],
    'recommended_attributes': ['SameSite', 'Domain', 'Path'],
    'dangerous_patterns': [
        r'[Ss]et-[Cc]ookie:\s*[^;]*((?!(HttpOnly|Secure))[;]|$)',
        r'[Ss]et-[Cc]ookie:[^;]*;[^H]*(?!HttpOnly)',
        r'[Ss]et-[Cc]ookie:[^;]*;[^S]*(?!Secure)'
    ],
    'safe_patterns': [
        r'[Ss]et-[Cc]ookie:[^;]*;.*[Hh]ttp[Oo]nly',
        r'[Ss]et-[Cc]ookie:[^;]*;.*[Ss]ecure',
        r'[Ss]et-[Cc]ookie:[^;]*;.*[Hh]ttp[Oo]nly.*;.*[Ss]ecure'
    ]
}

# Cookie相关关键词
COOKIE_KEYWORDS = [
    'cookie', 'set-cookie', 'httponly', 'secure', 'samesite',
    'domain', 'path', 'expires', 'max-age', 'session'
]


def detect_c_cookie_httponly_vulnerability(code, language='c'):
    """
    检测C代码中Cookie安全：HTTPonly未设置漏洞

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
    cookie_operations = []  # 存储Cookie相关操作
    set_cookie_calls = []  # 存储Set-Cookie调用

    # 第一步：收集所有Cookie相关操作
    for query_info in COOKIE_HTTPONLY_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                node_text = node.text.decode('utf8').strip('"\'')

                if tag in ['func_name']:
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, node_text, re.IGNORECASE):
                        current_capture['func'] = node_text
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['header_name', 'header_arg']:
                    header_pattern = query_info.get('header_pattern', '')
                    if header_pattern and re.match(header_pattern, node_text, re.IGNORECASE):
                        current_capture['header'] = node_text
                        current_capture['header_node'] = node

                elif tag in ['cookie_value', 'value_arg']:
                    if is_cookie_related(node_text):
                        current_capture['cookie_value'] = node_text
                        current_capture['value_node'] = node

                elif tag in ['cookie_string']:
                    cookie_pattern = query_info.get('cookie_pattern', '')
                    if cookie_pattern and re.search(cookie_pattern, node_text, re.IGNORECASE):
                        current_capture['cookie_string'] = node_text
                        current_capture['string_node'] = node

                elif tag in ['cookie_attr']:
                    attr_pattern = query_info.get('attr_pattern', '')
                    if attr_pattern and re.match(attr_pattern, node_text, re.IGNORECASE):
                        current_capture['cookie_attr'] = node_text
                        current_capture['attr_node'] = node

                elif tag in ['concat_func']:
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, node_text, re.IGNORECASE):
                        current_capture['concat_func'] = node_text
                        current_capture['concat_node'] = node.parent

                elif tag in ['var_name']:
                    if is_cookie_related_variable(node_text):
                        current_capture['var_name'] = node_text
                        current_capture['var_node'] = node

                elif tag in ['func_name']:  # 函数定义中的函数名
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, node_text, re.IGNORECASE):
                        current_capture['def_func'] = node_text
                        current_capture['def_node'] = node.parent

                elif tag in ['call', 'assignment', 'concat_call', 'if_stmt', 'func_def'] and current_capture:
                    # 完成捕获
                    code_snippet = node.text.decode('utf8')
                    capture_data = {
                        'type': query_info.get('message', 'unknown'),
                        'line': current_capture.get('line', node.start_point[0] + 1),
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    }

                    # 添加特定信息
                    for key in ['func', 'header', 'cookie_value', 'cookie_string',
                                'cookie_attr', 'concat_func', 'var_name', 'def_func']:
                        if key in current_capture:
                            capture_data[key] = current_capture[key]

                    cookie_operations.append(capture_data)

                    # 如果是Set-Cookie相关操作，单独记录
                    if 'header' in current_capture and 'Set-Cookie' in current_capture['header']:
                        set_cookie_calls.append(capture_data)

                    current_capture = {}

        except Exception as e:
            print(f"Cookie安全检测查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：分析Cookie安全漏洞
    vulnerabilities = analyze_cookie_security(cookie_operations, set_cookie_calls, code, root)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_cookie_security(cookie_operations, set_cookie_calls, code, root):
    """
    分析Cookie安全漏洞
    """
    vulnerabilities = []
    processed_locations = set()

    # 分析Set-Cookie调用
    for operation in set_cookie_calls:
        location_key = f"{operation['line']}:{operation['type']}"
        if location_key in processed_locations:
            continue
        processed_locations.add(location_key)

        vuln = analyze_set_cookie_operation(operation, code, root)
        if vuln:
            vulnerabilities.append(vuln)

    # 分析其他Cookie相关操作
    for operation in cookie_operations:
        location_key = f"{operation['line']}:{operation['type']}"
        if location_key in processed_locations:
            continue
        processed_locations.add(location_key)

        vuln = analyze_general_cookie_operation(operation, code, root)
        if vuln:
            vulnerabilities.append(vuln)

    # 检测缺失的HttpOnly属性
    missing_httponly = detect_missing_httponly(set_cookie_calls, cookie_operations, code, root)
    vulnerabilities.extend(missing_httponly)

    return vulnerabilities


def analyze_set_cookie_operation(operation, code, root):
    """
    分析Set-Cookie操作的安全性
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    # 检查是否包含HttpOnly属性
    if not contains_httponly_attribute(operation, code_snippet):
        return {
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Cookie安全：HTTPonly未设置',
            'severity': '中危',
            'message': 'Set-Cookie头未设置HttpOnly属性'
        }

    # 检查是否包含Secure属性
    if not contains_secure_attribute(operation, code_snippet):
        return {
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Cookie安全',
            'severity': '中危',
            'message': 'Set-Cookie头未设置Secure属性'
        }

    return None


def analyze_general_cookie_operation(operation, code, root):
    """
    分析一般Cookie操作的安全性
    """
    line = operation['line']
    code_snippet = operation['code_snippet']
    op_type = operation['type']

    if op_type == '字符串拼接函数可能用于构建Cookie头':
        if is_dangerous_cookie_concatenation(operation, code_snippet):
            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': 'Cookie安全',
                'severity': '中危',
                'message': '字符串拼接可能用于构建不安全的Cookie头'
            }

    elif op_type == 'Cookie值赋值操作':
        if is_unsafe_cookie_assignment(operation, code_snippet):
            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': 'Cookie安全',
                'severity': '低危',
                'message': 'Cookie值赋值操作可能存在问题'
            }

    return None


def contains_httponly_attribute(operation, code_snippet):
    """
    检查是否包含HttpOnly属性
    """
    # 直接检查代码片段
    if re.search(r'[Hh]ttp[Oo]nly', code_snippet, re.IGNORECASE):
        return True

    # 检查操作中的属性
    if 'cookie_attr' in operation and 'HttpOnly' in operation['cookie_attr']:
        return True

    # 检查相关的字符串拼接
    if 'concat_func' in operation:
        # 查找相关的字符串操作
        concat_context = get_concat_context(operation['node'], code_snippet)
        if concat_context and re.search(r'[Hh]ttp[Oo]nly', concat_context, re.IGNORECASE):
            return True

    return False


def contains_secure_attribute(operation, code_snippet):
    """
    检查是否包含Secure属性
    """
    if re.search(r'[Ss]ecure', code_snippet, re.IGNORECASE):
        return True

    if 'cookie_attr' in operation and 'Secure' in operation['cookie_attr']:
        return True

    if 'concat_func' in operation:
        concat_context = get_concat_context(operation['node'], code_snippet)
        if concat_context and re.search(r'[Ss]ecure', concat_context, re.IGNORECASE):
            return True

    return False


def is_dangerous_cookie_concatenation(operation, code_snippet):
    """
    检查是否危险的Cookie字符串拼接
    """
    # 检查是否包含Set-Cookie但不包含安全属性
    if re.search(r'[Ss]et-[Cc]ookie', code_snippet, re.IGNORECASE):
        if not re.search(r'[Hh]ttp[Oo]nly', code_snippet, re.IGNORECASE):
            return True
        if not re.search(r'[Ss]ecure', code_snippet, re.IGNORECASE):
            return True

    return False


def is_unsafe_cookie_assignment(operation, code_snippet):
    """
    检查是否不安全的Cookie赋值
    """
    var_name = operation.get('var_name', '')
    if is_cookie_related_variable(var_name):
        # 检查赋值值是否包含敏感信息但不包含安全属性
        value = operation.get('cookie_value', '')
        if value and is_sensitive_cookie_value(value):
            if not re.search(r'[Hh]ttp[Oo]nly', code_snippet, re.IGNORECASE):
                return True

    return False


def detect_missing_httponly(set_cookie_calls, cookie_operations, code, root):
    """
    检测缺失HttpOnly属性的情况
    """
    vulnerabilities = []

    for operation in set_cookie_calls:
        if not contains_httponly_attribute(operation, operation['code_snippet']):
            # 检查是否有相关的属性设置但在不同的地方
            if not has_httponly_nearby(operation, cookie_operations, root):
                vulnerabilities.append({
                    'line': operation['line'],
                    'code_snippet': operation['code_snippet'],
                    'vulnerability_type': 'Cookie安全：HTTPonly未设置',
                    'severity': '中危',
                    'message': 'Set-Cookie头缺少HttpOnly属性，可能被XSS攻击利用'
                })

    return vulnerabilities


def has_httponly_nearby(operation, cookie_operations, root):
    """
    检查附近是否有HttpOnly属性设置
    """
    operation_line = operation['line']

    for op in cookie_operations:
        if op['line'] == operation_line or abs(op['line'] - operation_line) <= 5:
            if 'cookie_attr' in op and 'HttpOnly' in op['cookie_attr']:
                return True
            if 'cookie_string' in op and 'HttpOnly' in op['cookie_string']:
                return True

    return False


def is_cookie_related(text):
    """
    检查文本是否与Cookie相关
    """
    if not text:
        return False

    text_lower = text.lower()
    for keyword in COOKIE_KEYWORDS:
        if keyword in text_lower:
            return True

    return False


def is_cookie_related_variable(var_name):
    """
    检查变量名是否与Cookie相关
    """
    cookie_var_patterns = [
        r'.*cookie.*', r'.*session.*', r'.*auth.*', r'.*token.*',
        r'.*setcookie.*', r'.*header.*', r'.*http.*'
    ]

    for pattern in cookie_var_patterns:
        if re.search(pattern, var_name, re.IGNORECASE):
            return True

    return False


def is_sensitive_cookie_value(value):
    """
    检查Cookie值是否敏感
    """
    sensitive_patterns = [
        r'.*session.*', r'.*token.*', r'.*auth.*', r'.*login.*',
        r'.*user.*', r'.*admin.*', r'.*password.*'
    ]

    for pattern in sensitive_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return True

    return False


def get_concat_context(node, full_code):
    """
    获取字符串拼接操作的上下文
    """
    # 简单的实现：获取节点周围的代码
    start_byte = node.start_byte
    end_byte = node.end_byte

    # 扩展范围以获取更多上下文
    context_start = max(0, start_byte - 200)
    context_end = min(len(full_code), end_byte + 200)

    return full_code[context_start:context_end]


def analyze_c_code_for_cookie_security(code_string):
    """
    分析C代码字符串中的Cookie安全漏洞
    """
    return detect_c_cookie_httponly_vulnerability(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - Cookie安全示例
    test_c_code = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 存在Cookie安全漏洞的示例
void insecure_cookie_handling() {
    // 漏洞1: 未设置HttpOnly的Set-Cookie
    printf("Set-Cookie: sessionid=abc123; Path=/\\n");  // 缺少HttpOnly和Secure

    // 漏洞2: 字符串拼接构建不安全的Cookie头
    char cookie_header[256];
    char* session_id = "xyz789";
    sprintf(cookie_header, "Set-Cookie: session=%s; Path=/", session_id);  // 缺少安全属性

    // 漏洞3: 分开设置Cookie属性但遗漏HttpOnly
    printf("Set-Cookie: auth_token=def456; ");
    printf("Path=/; ");
    printf("Secure; ");  // 有Secure但没有HttpOnly
    printf("SameSite=Strict\\n");

    // 漏洞4: 动态构建Cookie头但忘记安全属性
    char* user_role = "admin";
    char dynamic_cookie[300];
    snprintf(dynamic_cookie, sizeof(dynamic_cookie), 
             "Set-Cookie: role=%s; Domain=.example.com; Path=/", user_role);
}

// 相对安全的Cookie处理示例
void secure_cookie_handling() {
    // 安全示例1: 包含HttpOnly和Secure
    printf("Set-Cookie: sessionid=abc123; Path=/; HttpOnly; Secure\\n");

    // 安全示例2: 完整的安全属性设置
    printf("Set-Cookie: auth_token=xyz789; Path=/; HttpOnly; Secure; SameSite=Strict\\n");

    // 安全示例3: 字符串拼接包含所有安全属性
    char secure_cookie[256];
    char* token = "securetoken";
    sprintf(secure_cookie, "Set-Cookie: token=%s; Path=/; HttpOnly; Secure; SameSite=Lax", token);

    // 安全示例4: 分开设置但包含所有必要属性
    printf("Set-Cookie: user_prefs=settings; ");
    printf("HttpOnly; ");  // 首先设置HttpOnly
    printf("Secure; ");
    printf("Path=/; ");
    printf("Max-Age=3600\\n");
}

// Cookie相关函数
void set_user_cookie(char* user_id, int is_secure) {
    char cookie[200];
    if (is_secure) {
        snprintf(cookie, sizeof(cookie), 
                 "Set-Cookie: user=%s; Path=/; HttpOnly; Secure", user_id);
    } else {
        snprintf(cookie, sizeof(cookie), 
                 "Set-Cookie: user=%s; Path=/", user_id);  // 不安全版本
    }
    printf("%s\\n", cookie);
}

void process_authentication(char* username, char* password) {
    // 认证逻辑...
    char session_id[50];
    generate_session_id(session_id);

    // 设置会话Cookie - 应该包含HttpOnly
    printf("Set-Cookie: SESSIONID=%s; Path=/\\n", session_id);  // 缺少HttpOnly

    // 更好的做法
    printf("Set-Cookie: SESSIONID=%s; Path=/; HttpOnly; Secure; SameSite=Strict\\n", session_id);
}

void generate_session_id(char* buffer) {
    // 生成会话ID的逻辑
    strcpy(buffer, "generated_session_id_12345");
}

int main() {
    insecure_cookie_handling();
    secure_cookie_handling();

    set_user_cookie("john_doe", 0);  // 不安全调用
    set_user_cookie("jane_smith", 1);  // 安全调用

    process_authentication("user", "pass");

    return 0;
}
"""

    print("=" * 60)
    print("C语言Cookie安全：HTTPonly未设置漏洞检测")
    print("=" * 60)

    results = analyze_c_code_for_cookie_security(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在Cookie安全漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Cookie安全漏洞")