import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 日志伪造漏洞模式
LOG_FORGERY_VULNERABILITIES = {
    'c': [
        # 检测日志输出函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @log_args)
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf|syslog|vsprintf|vsnprintf|vprintf|vfprintf)$',
            'message': '日志输出函数调用'
        },
        # 检测文件写入操作（可能用于日志）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @write_args)
                ) @call
            ''',
            'func_pattern': r'^(fwrite|fputs|puts|write|fprintf)$',
            'message': '文件写入函数可能用于日志记录'
        },
        # 检测用户输入直接插入日志
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @log_template
                        . (identifier) @user_input
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|fprintf|sprintf|snprintf)$',
            'template_pattern': r'^.*".*%s.*".*$',
            'message': '用户输入直接插入日志模板'
        },
        # 检测日志格式字符串
        {
            'query': '''
                (string_literal) @log_format
            ''',
            'format_pattern': r'^.*(error|warning|info|debug|log|audit|security|failed|success).*$',
            'message': '日志格式字符串'
        },
        # 检测日志级别设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (identifier) @log_level
                        . (string_literal) @log_message
                    )
                ) @call
            ''',
            'func_pattern': r'^(syslog|log_message|log_event)$',
            'message': '日志级别设置函数'
        },
        # 检测字符串拼接构建日志
        {
            'query': '''
                (call_expression
                    function: (identifier) @concat_func
                    arguments: (argument_list (_)* @concat_args)
                ) @concat_call
            ''',
            'func_pattern': r'^(strcat|strncat|sprintf|snprintf)$',
            'message': '字符串拼接可能用于构建日志消息'
        },
        # 检测日志文件操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @log_file
                    )
                ) @call
            ''',
            'func_pattern': r'^(fopen|freopen|open|creat)$',
            'file_pattern': r'.*(\.log|\.txt|log/|var/log).*',
            'message': '日志文件操作'
        },
        # 检测时间戳记录操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @time_func
                    arguments: (argument_list (_)* @time_args)
                ) @call
            ''',
            'func_pattern': r'^(time|ctime|localtime|strftime|gettimeofday)$',
            'message': '时间戳函数可能用于日志'
        }
    ]
}

# 日志伪造检测配置
LOG_FORGERY_CONFIG = {
    'log_keywords': [
        'log', 'error', 'warning', 'info', 'debug', 'audit', 'security',
        'failed', 'success', 'access', 'event', 'record', 'trace'
    ],
    'sensitive_operations': [
        'login', 'logout', 'password', 'auth', 'authenticate', 'authorize',
        'transaction', 'payment', 'transfer', 'admin', 'root', 'privilege'
    ],
    'injection_patterns': [
        r'.*%s.*\\n.*',  # 用户输入可能注入换行
        r'.*%s.*//.*',  # 用户输入可能注入注释
        r'.*%s.*#.*',  # 用户输入可能注入注释
        r'.*%s.*;.*',  # 用户输入可能注入命令分隔符
        r'.*%s.*\\.\\..*',  # 用户输入可能包含路径遍历
    ],
    'log_validation_functions': [
        'sanitize_log', 'escape_string', 'validate_input', 'filter_log',
        'encode_html', 'strip_tags', 'htmlspecialchars'
    ],
    'dangerous_log_contexts': [
        'authentication', 'authorization', 'financial', 'medical',
        'personal', 'sensitive', 'confidential'
    ]
}


def detect_c_log_forgery(code, language='c'):
    """
    检测C代码中日志伪造漏洞

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
    log_operations = []  # 存储日志相关操作
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集用户输入源
    user_input_sources = collect_user_input_sources(root, code)

    # 第二步：收集所有日志相关操作
    for query_info in LOG_FORGERY_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                node_text = node.text.decode('utf8').strip('"\'')

                if tag in ['func_name', 'concat_func', 'time_func']:
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, node_text, re.IGNORECASE):
                        current_capture['func'] = node_text
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['log_template']:
                    template_pattern = query_info.get('template_pattern', '')
                    if template_pattern and re.match(template_pattern, node_text, re.IGNORECASE):
                        current_capture['log_template'] = node_text
                        current_capture['template_node'] = node

                elif tag in ['user_input']:
                    if is_user_input_variable(node_text, user_input_sources):
                        current_capture['user_input'] = node_text
                        current_capture['input_node'] = node

                elif tag in ['log_format']:
                    format_pattern = query_info.get('format_pattern', '')
                    if format_pattern and re.search(format_pattern, node_text, re.IGNORECASE):
                        current_capture['log_format'] = node_text
                        current_capture['format_node'] = node

                elif tag in ['log_level']:
                    if is_log_level_variable(node_text):
                        current_capture['log_level'] = node_text
                        current_capture['level_node'] = node

                elif tag in ['log_message']:
                    if is_log_message(node_text):
                        current_capture['log_message'] = node_text
                        current_capture['message_node'] = node

                elif tag in ['log_file']:
                    file_pattern = query_info.get('file_pattern', '')
                    if file_pattern and re.search(file_pattern, node_text, re.IGNORECASE):
                        current_capture['log_file'] = node_text
                        current_capture['file_node'] = node

                elif tag in ['call', 'concat_call'] and current_capture:
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
                    for key in ['func', 'log_template', 'user_input', 'log_format',
                                'log_level', 'log_message', 'log_file']:
                        if key in current_capture:
                            capture_data[key] = current_capture[key]

                    log_operations.append(capture_data)
                    current_capture = {}

        except Exception as e:
            print(f"日志伪造检测查询错误 {query_info.get('message')}: {e}")
            continue

    # 第三步：分析日志伪造漏洞
    vulnerabilities = analyze_log_forgery(
        log_operations, user_input_sources, code, root
    )

    return sorted(vulnerabilities, key=lambda x: x['line'])


def collect_user_input_sources(root, code):
    """
    收集用户输入源
    """
    user_input_sources = []

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


def analyze_log_forgery(log_operations, user_input_sources, code, root):
    """
    分析日志伪造漏洞
    """
    vulnerabilities = []
    processed_locations = set()

    # 分析直接用户输入插入日志
    for operation in log_operations:
        location_key = f"{operation['line']}:direct_insertion"
        if location_key in processed_locations:
            continue
        processed_locations.add(location_key)

        vuln = analyze_direct_log_insertion(operation, user_input_sources, code, root)
        if vuln:
            vulnerabilities.append(vuln)

    # 分析字符串拼接构建日志
    for operation in log_operations:
        if 'func' in operation and operation['func'] in ['strcat', 'strncat', 'sprintf']:
            location_key = f"{operation['line']}:concat_build"
            if location_key in processed_locations:
                continue
            processed_locations.add(location_key)

            vuln = analyze_concat_log_build(operation, user_input_sources, code, root)
            if vuln:
                vulnerabilities.append(vuln)

    # 分析敏感操作日志记录
    for operation in log_operations:
        location_key = f"{operation['line']}:sensitive_operation"
        if location_key in processed_locations:
            continue
        processed_locations.add(location_key)

        vuln = analyze_sensitive_operation_log(operation, code, root)
        if vuln:
            vulnerabilities.append(vuln)

    # 分析日志注入特定模式
    injection_vulns = analyze_log_injection_patterns(log_operations, code, root)
    vulnerabilities.extend(injection_vulns)

    return vulnerabilities


def analyze_direct_log_insertion(operation, user_input_sources, code, root):
    """
    分析直接用户输入插入日志的漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    if 'user_input' in operation and 'log_template' in operation:
        template = operation['log_template']

        # 检查是否缺少输入验证
        if not has_log_input_validation(operation, user_input_sources, code, root):
            severity = '高危' if is_sensitive_log_context(operation, code, root) else '中危'

            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': '日志伪造',
                'severity': severity,
                'message': '用户输入未经验证直接插入日志模板'
            }

    return None


def analyze_concat_log_build(operation, user_input_sources, code, root):
    """
    分析字符串拼接构建日志的漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    # 检查是否用于构建日志
    if is_log_construction(operation, code, root):
        # 检查是否包含用户输入且缺少验证
        if contains_user_input(operation, user_input_sources) and not has_log_validation(operation, code, root):
            severity = '高危' if is_sensitive_log_context(operation, code, root) else '中危'

            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': '日志伪造',
                'severity': severity,
                'message': '字符串拼接构建日志，用户输入缺少验证'
            }

    return None


def analyze_sensitive_operation_log(operation, code, root):
    """
    分析敏感操作日志记录漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    if is_sensitive_operation(operation, code, root):
        # 检查敏感操作日志是否包含未验证的用户输入
        if contains_unvalidated_sensitive_input(operation, code, root):
            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': '日志伪造',
                'severity': '严重',
                'message': '敏感操作日志记录包含未验证的用户输入'
            }

    return None


def analyze_log_injection_patterns(log_operations, code, root):
    """
    分析日志注入特定模式
    """
    vulnerabilities = []

    for operation in log_operations:
        if 'log_template' in operation:
            template = operation['log_template']

            # 检查是否存在注入风险模式
            for pattern in LOG_FORGERY_CONFIG['injection_patterns']:
                if re.match(pattern, template):
                    vuln = analyze_specific_injection_pattern(operation, pattern, code, root)
                    if vuln:
                        vulnerabilities.append(vuln)
                    break

    return vulnerabilities


def analyze_specific_injection_pattern(operation, pattern, code, root):
    """
    分析特定注入模式
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    injection_type = get_injection_type(pattern)

    return {
        'line': line,
        'code_snippet': code_snippet,
        'vulnerability_type': '日志伪造',
        'severity': '高危',
        'message': f'日志模板存在{injection_type}注入风险'
    }


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


def is_log_level_variable(var_name):
    """
    检查变量名是否与日志级别相关
    """
    log_levels = [
        'LOG_EMERG', 'LOG_ALERT', 'LOG_CRIT', 'LOG_ERR',
        'LOG_WARNING', 'LOG_NOTICE', 'LOG_INFO', 'LOG_DEBUG',
        'ERROR', 'WARN', 'INFO', 'DEBUG'
    ]

    return var_name.upper() in [level.upper() for level in log_levels]


def is_log_message(text):
    """
    检查文本是否类似日志消息
    """
    if not text:
        return False

    log_indicators = LOG_FORGERY_CONFIG['log_keywords']

    for indicator in log_indicators:
        if indicator.lower() in text.lower():
            return True

    return False


def has_log_input_validation(operation, user_input_sources, code, root):
    """
    检查日志输入是否有验证
    """
    line = operation['line']
    input_var = operation.get('user_input', '')

    # 查找日志验证函数
    validation_functions = LOG_FORGERY_CONFIG['log_validation_functions']

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


def is_log_construction(operation, code, root):
    """
    检查操作是否用于日志构建
    """
    code_snippet = operation['code_snippet']

    # 检查是否包含日志关键词
    log_indicators = LOG_FORGERY_CONFIG['log_keywords']

    for indicator in log_indicators:
        if indicator.lower() in code_snippet.lower():
            return True

    # 检查函数名是否日志相关
    if 'func' in operation:
        func_name = operation['func'].lower()
        if any(keyword in func_name for keyword in ['log', 'print', 'write']):
            return True

    return False


def contains_user_input(operation, user_input_sources):
    """
    检查操作是否包含用户输入
    """
    code_snippet = operation['code_snippet']

    # 检查用户输入变量名模式
    input_patterns = [
        r'argv', r'argc', r'input', r'user', r'param', r'data',
        r'buffer', r'query', r'post', r'get'
    ]

    for pattern in input_patterns:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True

    # 检查用户输入函数
    input_functions = ['scanf', 'fgets', 'getenv', 'recv']
    for func in input_functions:
        if func in code_snippet:
            return True

    return False


def has_log_validation(operation, code, root):
    """
    检查是否有日志验证
    """
    line = operation['line']

    # 查找日志验证函数
    validation_functions = LOG_FORGERY_CONFIG['log_validation_functions']
    node = operation['node']

    # 检查附近的函数调用
    current = node.prev_sibling
    while current and current.start_point[0] >= max(0, line - 5):
        if current.type == 'call_expression':
            call_text = current.text.decode('utf8')
            for val_func in validation_functions:
                if val_func in call_text:
                    return True
        current = current.prev_sibling

    return False


def is_sensitive_log_context(operation, code, root):
    """
    检查是否在敏感日志上下文中
    """
    code_snippet = operation['code_snippet']

    sensitive_contexts = LOG_FORGERY_CONFIG['dangerous_log_contexts']

    for context in sensitive_contexts:
        if context.lower() in code_snippet.lower():
            return True

    # 检查父节点是否包含敏感上下文
    parent = operation['node'].parent
    while parent:
        parent_text = parent.text.decode('utf8')
        for context in sensitive_contexts:
            if context.lower() in parent_text.lower():
                return True
        parent = parent.parent

    return False


def is_sensitive_operation(operation, code, root):
    """
    检查是否敏感操作
    """
    code_snippet = operation['code_snippet']

    sensitive_ops = LOG_FORGERY_CONFIG['sensitive_operations']

    for op in sensitive_ops:
        if op.lower() in code_snippet.lower():
            return True

    return False


def contains_unvalidated_sensitive_input(operation, code, root):
    """
    检查敏感操作是否包含未验证的输入
    """
    # 简化实现：检查是否包含用户输入模式且没有验证
    code_snippet = operation['code_snippet']

    input_indicators = ['%s', 'argv', 'input', 'user', 'getenv']
    has_input = any(indicator in code_snippet for indicator in input_indicators)

    if has_input:
        return not has_log_validation(operation, code, root)

    return False


def get_injection_type(pattern):
    """
    获取注入类型描述
    """
    injection_types = {
        r'.*%s.*\\n.*': '换行符',
        r'.*%s.*//.*': '单行注释',
        r'.*%s.*#.*': '注释符',
        r'.*%s.*;.*': '命令分隔符',
        r'.*%s.*\\.\\..*': '路径遍历'
    }

    return injection_types.get(pattern, '未知类型')


def analyze_c_code_for_log_forgery(code_string):
    """
    分析C代码字符串中的日志伪造漏洞
    """
    return detect_c_log_forgery(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - 日志伪造示例
    test_c_code = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

// 存在日志伪造漏洞的示例
void vulnerable_logging() {
    char* user_input = getenv("USER_INPUT");
    char* username = getenv("USERNAME");

    // 漏洞1: 直接拼接用户输入到日志
    printf("User action: %s\\n", user_input);  // 高风险

    // 漏洞2: 敏感操作日志缺少验证
    sprintf(log_buffer, "User %s performed admin action: %s", username, user_input);  // 严重风险

    // 漏洞3: 字符串拼接构建日志
    char log_message[512];
    strcpy(log_message, "Event: ");
    strcat(log_message, user_input);  // 注入风险
    strcat(log_message, " at ");
    strcat(log_message, get_current_time());

    // 漏洞4: 系统日志直接使用用户输入
    syslog(LOG_INFO, "User activity: %s", user_input);  // 高风险

    // 漏洞5: 文件日志操作
    FILE* log_file = fopen("/var/log/app.log", "a");
    if (log_file) {
        fprintf(log_file, "Error: %s\\n", user_input);  // 文件日志注入
        fclose(log_file);
    }
}

// 相对安全的日志处理示例
void secure_logging() {
    char* user_input = getenv("USER_INPUT");
    char* username = getenv("USERNAME");

    // 安全示例1: 输入验证和转义
    if (user_input != NULL) {
        char sanitized_input[256];
        sanitize_log_input(user_input, sanitized_input, sizeof(sanitized_input));

        printf("User action: %s\\n", sanitized_input);
    }

    // 安全示例2: 使用固定的日志格式
    if (username != NULL) {
        printf("User %s performed action\\n", sanitize_string(username));
    }

    // 安全示例3: 使用日志库函数
    log_security_event("user_login", username, "success");

    // 安全示例4: 参数化日志
    log_message(LOG_INFO, "User performed action", "action_type", "normal");
}

// 日志输入清理函数
void sanitize_log_input(const char* input, char* output, size_t output_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] != '\\0' && j < output_size - 1; i++) {
        // 移除或转义危险字符
        switch (input[i]) {
            case '\\n':
            case '\\r':
            case ';':
            case '|':
            case '&':
            case '`':
            case '$':
            case '(':
            case ')':
            case '{':
            case '}':
            case '[':
            case ']':
                // 跳过或替换危险字符
                output[j++] = '_';
                break;
            default:
                output[j++] = input[i];
                break;
        }
    }
    output[j] = '\\0';
}

// 字符串清理函数
char* sanitize_string(const char* input) {
    static char buffer[256];
    size_t j = 0;
    for (size_t i = 0; input[i] != '\\0' && j < sizeof(buffer) - 1; i++) {
        if (isalnum(input[i]) || input[i] == ' ' || input[i] == '-' || input[i] == '_') {
            buffer[j++] = input[i];
        }
    }
    buffer[j] = '\\0';
    return buffer;
}

// 安全日志函数
void log_security_event(const char* event_type, const char* username, const char* status) {
    char sanitized_user[256];
    if (username != NULL) {
        strncpy(sanitized_user, sanitize_string(username), sizeof(sanitized_user));
    } else {
        strcpy(sanitized_user, "unknown");
    }

    syslog(LOG_INFO, "Security event: type=%s, user=%s, status=%s", 
           event_type, sanitized_user, status);
}

void log_message(int level, const char* message, ...) {
    // 安全的日志记录实现
    char formatted_message[512];
    va_list args;
    va_start(args, message);
    vsnprintf(formatted_message, sizeof(formatted_message), message, args);
    va_end(args);

    // 记录到文件或系统日志
    printf("LOG[%d]: %s\\n", level, formatted_message);
}

// 存在风险的认证日志函数
void log_authentication_attempt(char* username, char* ip_address, int success) {
    // 漏洞: 用户输入直接用于日志
    if (success) {
        syslog(LOG_INFO, "Successful login: user=%s from IP=%s", username, ip_address);
    } else {
        syslog(LOG_WARNING, "Failed login attempt: user=%s from IP=%s", username, ip_address);
    }
}

// 财务操作日志（高风险）
void log_financial_transaction(char* from_user, char* to_user, double amount) {
    char log_entry[512];
    // 漏洞: 金额和用户输入未经验证
    sprintf(log_entry, "Transaction: %s -> %s: $%.2f", from_user, to_user, amount);
    write_to_audit_log(log_entry);
}

void write_to_audit_log(const char* message) {
    FILE* audit_log = fopen("/var/log/audit.log", "a");
    if (audit_log) {
        fprintf(audit_log, "%s\\n", message);
        fclose(audit_log);
    }
}

char* get_current_time() {
    static char time_buffer[64];
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return time_buffer;
}

int main() {
    vulnerable_logging();
    secure_logging();

    // 测试风险函数
    char* malicious_input = "normal input\\n[ERROR] System compromised!\\n";
    log_authentication_attempt("admin", "192.168.1.100", 1);
    log_financial_transaction("user1", "user2", 1000.0);

    return 0;
}
"""

    print("=" * 60)
    print("C语言日志伪造漏洞检测")
    print("=" * 60)

    results = analyze_c_code_for_log_forgery(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在日志伪造漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到日志伪造漏洞")