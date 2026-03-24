import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# JSON注入漏洞模式
JSON_INJECTION_VULNERABILITIES = {
    'c': [
        # 检测JSON字符串构建操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @json_args)
                ) @call
            ''',
            'func_pattern': r'^(sprintf|snprintf|strcat|strncat|strcpy|strncpy)$',
            'message': '字符串函数可能用于构建JSON'
        },
        # 检测JSON相关字符串字面量
        {
            'query': '''
                (string_literal) @json_string
            ''',
            'json_pattern': r'^.*[{}\[\]]|"json"|"JSON"|"key"|"value"|"array"|"object".*$',
            'message': 'JSON相关字符串字面量'
        },
        # 检测用户输入直接插入JSON
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @json_template
                        . (identifier) @user_input
                    )
                ) @call
            ''',
            'func_pattern': r'^(sprintf|snprintf|printf|fprintf)$',
            'template_pattern': r'^.*".*%s.*".*$',
            'message': '用户输入直接插入JSON模板'
        },
        # 检测JSON键值对构建
        {
            'query': '''
                (assignment_expression
                    left: (identifier) @json_var
                    right: (string_literal) @json_value
                ) @assignment
            ''',
            'message': 'JSON值赋值操作'
        },
        # 检测JSON数组构建
        {
            'query': '''
                (initializer_list
                    (_)* @array_elements
                ) @array_init
            ''',
            'message': '数组初始化可能用于JSON数组'
        },
        # 检测JSON对象构建函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @json_func
                    arguments: (argument_list (_)* @obj_args)
                ) @call
            ''',
            'func_pattern': r'^(json_object|json_array|json_string|json_number|json_boolean)$',
            'message': 'JSON对象构建函数'
        },
        # 检测JSON序列化函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @serialize_func
                    arguments: (argument_list (_)* @serialize_args)
                ) @call
            ''',
            'func_pattern': r'^(json_serialize|json_stringify|json_encode|json_dump)$',
            'message': 'JSON序列化函数'
        },
        # 检测JSON解析函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @parse_func
                    arguments: (argument_list (_)* @parse_args)
                ) @call
            ''',
            'func_pattern': r'^(json_parse|json_decode|json_load)$',
            'message': 'JSON解析函数'
        },
        # 检测字符串替换操作中的JSON风险
        {
            'query': '''
                (call_expression
                    function: (identifier) @replace_func
                    arguments: (argument_list (_)* @replace_args)
                ) @call
            ''',
            'func_pattern': r'^(strstr|strchr|strreplace|strtok)$',
            'message': '字符串替换操作可能影响JSON结构'
        }
    ]
}

# JSON注入检测配置
JSON_INJECTION_CONFIG = {
    'json_keywords': [
        'json', 'object', 'array', 'key', 'value', 'string', 'number',
        'boolean', 'null', 'true', 'false', 'encode', 'decode', 'parse',
        'serialize', 'stringify'
    ],
    'dangerous_characters': [
        '"', '{', '}', '[', ']', '\\', '/', ':', ','
    ],
    'injection_patterns': [
        r'^.*%s.*".*:.*".*$',  # 用户输入在键或值中
        r'^.*".*:.*%s.*$',  # 用户输入在值中
        r'^.*%s.*[{\[].*$',  # 用户输入可能注入新对象
        r'^.*".*%s.*".*$'  # 用户输入在引号内
    ],
    'safe_encoding_functions': [
        'json_escape', 'json_encode', 'escape_json', 'sanitize_json',
        'str_replace', 'htmlspecialchars', 'addslashes'
    ],
    'vulnerable_contexts': [
        'api_response', 'web_service', 'ajax_call', 'rest_api',
        'data_export', 'config_output', 'log_output'
    ]
}


def detect_c_json_injection(code, language='c'):
    """
    检测C代码中JSON注入漏洞

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
    json_operations = []  # 存储JSON相关操作
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集用户输入源
    user_input_sources = collect_user_input_sources(root, code)

    # 第二步：收集所有JSON相关操作
    for query_info in JSON_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                node_text = node.text.decode('utf8').strip('"\'')

                if tag in ['func_name', 'json_func', 'serialize_func', 'parse_func', 'replace_func']:
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, node_text, re.IGNORECASE):
                        current_capture['func'] = node_text
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['json_string']:
                    json_pattern = query_info.get('json_pattern', '')
                    if json_pattern and re.search(json_pattern, node_text, re.IGNORECASE):
                        current_capture['json_string'] = node_text
                        current_capture['string_node'] = node

                elif tag in ['json_template']:
                    template_pattern = query_info.get('template_pattern', '')
                    if template_pattern and re.match(template_pattern, node_text, re.IGNORECASE):
                        current_capture['json_template'] = node_text
                        current_capture['template_node'] = node

                elif tag in ['user_input']:
                    if is_user_input_variable(node_text, user_input_sources):
                        current_capture['user_input'] = node_text
                        current_capture['input_node'] = node

                elif tag in ['json_var']:
                    if is_json_related_variable(node_text):
                        current_capture['json_var'] = node_text
                        current_capture['var_node'] = node

                elif tag in ['json_value']:
                    if is_json_like_value(node_text):
                        current_capture['json_value'] = node_text
                        current_capture['value_node'] = node

                elif tag in ['array_elements']:
                    if contains_json_like_data(node_text):
                        current_capture['array_element'] = node_text
                        current_capture['array_node'] = node

                elif tag in ['call', 'assignment', 'array_init'] and current_capture:
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
                    for key in ['func', 'json_string', 'json_template', 'user_input',
                                'json_var', 'json_value', 'array_element']:
                        if key in current_capture:
                            capture_data[key] = current_capture[key]

                    json_operations.append(capture_data)
                    current_capture = {}

        except Exception as e:
            print(f"JSON注入检测查询错误 {query_info.get('message')}: {e}")
            continue

    # 第三步：分析JSON注入漏洞
    vulnerabilities = analyze_json_injection(
        json_operations, user_input_sources, code, root
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


def analyze_json_injection(json_operations, user_input_sources, code, root):
    """
    分析JSON注入漏洞
    """
    vulnerabilities = []
    processed_locations = set()

    # 分析直接用户输入插入JSON
    for operation in json_operations:
        location_key = f"{operation['line']}:direct_insertion"
        if location_key in processed_locations:
            continue
        processed_locations.add(location_key)

        vuln = analyze_direct_json_insertion(operation, user_input_sources, code, root)
        if vuln:
            vulnerabilities.append(vuln)

    # 分析字符串拼接构建JSON
    for operation in json_operations:
        if 'func' in operation and operation['func'] in ['sprintf', 'snprintf', 'strcat']:
            location_key = f"{operation['line']}:concat_build"
            if location_key in processed_locations:
                continue
            processed_locations.add(location_key)

            vuln = analyze_concat_json_build(operation, user_input_sources, code, root)
            if vuln:
                vulnerabilities.append(vuln)

    # 分析JSON序列化中的注入风险
    for operation in json_operations:
        if 'func' in operation and 'json' in operation['func'].lower():
            location_key = f"{operation['line']}:serialization_risk"
            if location_key in processed_locations:
                continue
            processed_locations.add(location_key)

            vuln = analyze_json_serialization_risk(operation, user_input_sources, code, root)
            if vuln:
                vulnerabilities.append(vuln)

    # 分析JSON解析中的注入风险
    parse_vulns = analyze_json_parsing_risks(json_operations, code, root)
    vulnerabilities.extend(parse_vulns)

    return vulnerabilities


def analyze_direct_json_insertion(operation, user_input_sources, code, root):
    """
    分析直接用户输入插入JSON的漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    if 'user_input' in operation and 'json_template' in operation:
        template = operation['json_template']

        # 检查是否缺少输入验证
        if not has_json_input_validation(operation, user_input_sources, code, root):
            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': 'JSON注入',
                'severity': '高危',
                'message': '用户输入未经验证直接插入JSON模板'
            }

    return None


def analyze_concat_json_build(operation, user_input_sources, code, root):
    """
    分析字符串拼接构建JSON的漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    # 检查是否用于构建JSON
    if is_json_construction(operation, code, root):
        # 检查是否包含用户输入且缺少验证
        if contains_user_input(operation, user_input_sources) and not has_json_validation(operation, code, root):
            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': 'JSON注入',
                'severity': '高危',
                'message': '字符串拼接构建JSON，用户输入缺少验证'
            }

    return None


def analyze_json_serialization_risk(operation, user_input_sources, code, root):
    """
    分析JSON序列化中的注入风险
    """
    line = operation['line']
    code_snippet = operation['code_snippet']
    func_name = operation.get('func', '')

    if 'serialize' in func_name.lower() or 'stringify' in func_name.lower():
        # 检查序列化的数据是否包含未验证的用户输入
        if contains_unvalidated_input(operation, user_input_sources, code, root):
            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': 'JSON注入',
                'severity': '中危',
                'message': f'JSON序列化函数 {func_name} 可能处理未验证的用户输入'
            }

    return None


def analyze_json_parsing_risks(json_operations, code, root):
    """
    分析JSON解析中的注入风险
    """
    vulnerabilities = []

    for operation in json_operations:
        if 'func' in operation and 'parse' in operation['func'].lower():
            # 检查解析后的JSON是否被不安全地使用
            vuln = analyze_json_parsing_usage(operation, code, root)
            if vuln:
                vulnerabilities.append(vuln)

    return vulnerabilities


def analyze_json_parsing_usage(operation, code, root):
    """
    分析解析后JSON的使用风险
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    # 检查解析的JSON是否来自不可信源
    if is_json_from_untrusted_source(operation, code, root):
        # 检查是否缺少验证
        if not has_parsed_json_validation(operation, code, root):
            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': 'JSON注入',
                'severity': '中危',
                'message': '解析不可信JSON数据缺少验证'
            }

    return None


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


def is_json_related_variable(var_name):
    """
    检查变量名是否与JSON相关
    """
    json_var_patterns = [
        r'.*json.*', r'.*obj.*', r'.*array.*', r'.*config.*',
        r'.*data.*', r'.*response.*', r'.*request.*', r'.*api.*'
    ]

    for pattern in json_var_patterns:
        if re.search(pattern, var_name, re.IGNORECASE):
            return True

    return False


def is_json_like_value(text):
    """
    检查文本是否类似JSON值
    """
    if not text:
        return False

    # 检查JSON特征
    json_indicators = [
        r'^{.*}$',  # 对象
        r'^\[.*\]$',  # 数组
        r'^".*"$',  # 字符串
        r'^[0-9]+$',  # 数字
        r'^true|false$',  # 布尔值
        r'^null$'  # null
    ]

    for pattern in json_indicators:
        if re.match(pattern, text):
            return True

    # 检查是否包含JSON结构字符
    if any(char in text for char in ['{', '}', '[', ']', ':', ',']):
        return True

    return False


def contains_json_like_data(text):
    """
    检查文本是否包含JSON类数据
    """
    json_patterns = [
        r'".*":.*',  # 键值对
        r'\[.*\]',  # 数组
        r'\{.*\}',  # 对象
    ]

    for pattern in json_patterns:
        if re.search(pattern, text):
            return True

    return False


def has_json_input_validation(operation, user_input_sources, code, root):
    """
    检查JSON输入是否有验证
    """
    line = operation['line']
    input_var = operation.get('user_input', '')

    # 查找JSON转义或验证函数
    validation_functions = JSON_INJECTION_CONFIG['safe_encoding_functions']

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


def is_json_construction(operation, code, root):
    """
    检查操作是否用于JSON构建
    """
    code_snippet = operation['code_snippet']

    # 检查是否包含JSON特征
    json_indicators = [
        '{', '}', '[', ']', '"key"', '"value"', '"json"'
    ]

    for indicator in json_indicators:
        if indicator in code_snippet:
            return True

    # 检查变量名是否JSON相关
    if 'json_var' in operation:
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


def has_json_validation(operation, code, root):
    """
    检查是否有JSON验证
    """
    line = operation['line']

    # 查找JSON验证函数
    validation_functions = JSON_INJECTION_CONFIG['safe_encoding_functions']
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


def contains_unvalidated_input(operation, user_input_sources, code, root):
    """
    检查是否包含未验证的输入
    """
    code_snippet = operation['code_snippet']

    # 检查是否包含用户输入且没有验证函数
    if contains_user_input(operation, user_input_sources):
        return not has_json_validation(operation, code, root)

    return False


def is_json_from_untrusted_source(operation, code, root):
    """
    检查JSON是否来自不可信源
    """
    code_snippet = operation['code_snippet']

    # 检查是否来自网络、文件或用户输入
    untrusted_sources = [
        'recv', 'read', 'fread', 'fgets', 'getenv', 'argv'
    ]

    for source in untrusted_sources:
        if source in code_snippet:
            return True

    return False


def has_parsed_json_validation(operation, code, root):
    """
    检查解析的JSON是否有验证
    """
    line = operation['line']

    # 检查后续代码是否有验证逻辑
    node = operation['node']
    current = node.next_sibling

    validation_indicators = [
        'if', 'switch', 'validate', 'check', 'verify', 'assert'
    ]

    while current and current.start_point[0] <= line + 10:
        current_text = current.text.decode('utf8')
        for indicator in validation_indicators:
            if indicator in current_text:
                return True
        current = current.next_sibling

    return False


def analyze_c_code_for_json_injection(code_string):
    """
    分析C代码字符串中的JSON注入漏洞
    """
    return detect_c_json_injection(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - JSON注入示例
    test_c_code = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 存在JSON注入漏洞的示例
void vulnerable_json_handling() {
    char* user_input = getenv("USER_DATA");

    // 漏洞1: 直接拼接用户输入到JSON
    char json_buffer[512];
    sprintf(json_buffer, "{\\"user\\": \\"%s\\", \\"role\\": \\"guest\\"}", user_input);  // 高风险

    // 漏洞2: 构建JSON数组缺少验证
    char* items[] = {user_input, "item2", "item3"};
    char array_json[256];
    sprintf(array_json, "[\\"%s\\", \\"item2\\", \\"item3\\"]", user_input);  // 数组注入风险

    // 漏洞3: 动态构建JSON键
    char* dynamic_key = user_input;
    sprintf(json_buffer, "{\\"%s\\": \\"value\\"}", dynamic_key);  // 键注入风险

    // 漏洞4: 多层JSON构建
    char inner_json[200];
    sprintf(inner_json, "{\\"data\\": \\"%s\\"}", user_input);
    sprintf(json_buffer, "{\\"response\\": %s}", inner_json);  // 嵌套注入风险
}

// 相对安全的JSON处理示例
void secure_json_handling() {
    char* user_input = getenv("USER_DATA");

    // 安全示例1: 输入验证和转义
    if (user_input != NULL) {
        char sanitized_input[256];
        sanitize_json_input(user_input, sanitized_input, sizeof(sanitized_input));

        char json_buffer[512];
        sprintf(json_buffer, "{\\"user\\": \\"%s\\", \\"role\\": \\"guest\\"}", sanitized_input);
    }

    // 安全示例2: 使用JSON库函数
    json_object* jobj = json_object_new_object();
    json_object_object_add(jobj, "user", json_object_new_string(user_input));
    json_object_object_add(jobj, "role", json_object_new_string("guest"));

    const char* safe_json = json_object_to_json_string(jobj);

    // 安全示例3: 硬编码或验证过的值
    printf("{\\"status\\": \\"ok\\", \\"version\\": \\"1.0\\"}");
}

// JSON输入清理函数
void sanitize_json_input(const char* input, char* output, size_t output_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] != '\\0' && j < output_size - 1; i++) {
        // 转义JSON特殊字符
        switch (input[i]) {
            case '"': 
                if (j + 1 < output_size - 1) {
                    output[j++] = '\\\\';
                    output[j++] = '"';
                }
                break;
            case '\\\\':
                if (j + 1 < output_size - 1) {
                    output[j++] = '\\\\';
                    output[j++] = '\\\\';
                }
                break;
            case '/':
                if (j + 1 < output_size - 1) {
                    output[j++] = '\\\\';
                    output[j++] = '/';
                }
                break;
            case '\\b':
                if (j + 1 < output_size - 1) {
                    output[j++] = '\\\\';
                    output[j++] = 'b';
                }
                break;
            case '\\f':
                if (j + 1 < output_size - 1) {
                    output[j++] = '\\\\';
                    output[j++] = 'f';
                }
                break;
            case '\\n':
                if (j + 1 < output_size - 1) {
                    output[j++] = '\\\\';
                    output[j++] = 'n';
                }
                break;
            case '\\r':
                if (j + 1 < output_size - 1) {
                    output[j++] = '\\\\';
                    output[j++] = 'r';
                }
                break;
            case '\\t':
                if (j + 1 < output_size - 1) {
                    output[j++] = '\\\\';
                    output[j++] = 't';
                }
                break;
            default:
                output[j++] = input[i];
                break;
        }
    }
    output[j] = '\\0';
}

// 存在风险的API响应函数
void send_api_response(char* user_data, int is_authenticated) {
    char response[1024];

    if (is_authenticated) {
        // 漏洞: 用户数据直接用于JSON
        sprintf(response, "{\\"status\\": \\"success\\", \\"user\\": \\"%s\\"}", user_data);
    } else {
        sprintf(response, "{\\"status\\": \\"error\\", \\"message\\": \\"Unauthorized\\"}");
    }

    printf("Content-Type: application/json\\r\\n");
    printf("Content-Length: %d\\r\\n", (int)strlen(response));
    printf("\\r\\n");
    printf("%s", response);
}

// 配置输出函数（可能存在JSON注入）
void output_config(char* config_name, char* config_value) {
    char config_json[512];
    // 漏洞: 配置值可能包含恶意JSON
    sprintf(config_json, "{\\"%s\\": \\"%s\\"}", config_name, config_value);
    save_to_file("config.json", config_json);
}

void save_to_file(const char* filename, const char* content) {
    // 保存到文件的实现
    FILE* fp = fopen(filename, "w");
    if (fp) {
        fputs(content, fp);
        fclose(fp);
    }
}

int main() {
    vulnerable_json_handling();
    secure_json_handling();

    // 测试风险函数
    char* test_input = "malicious\\", \\"injected\\": \\"value";
    send_api_response(test_input, 1);

    output_config("setting", "normal_value");
    output_config("malicious", "value\\", \\"hacked\\": true}");

    return 0;
}
"""

    print("=" * 60)
    print("C语言JSON注入漏洞检测")
    print("=" * 60)

    results = analyze_c_code_for_json_injection(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在JSON注入漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到JSON注入漏洞")