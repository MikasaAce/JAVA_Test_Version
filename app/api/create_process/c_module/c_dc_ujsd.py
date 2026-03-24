import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 修复后的C语言不安全JSON反序列化漏洞模式
UNSAFE_JSON_DESERIALIZATION_VULNERABILITIES = {
    'c': [
        # 检测JSON解析库的危险函数使用
        {
            'id': 'json_parse_unsafe_input',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(json_tokener_parse|json_object_from_file|json_object_from_fd|json_tokener_parse_verbose)$',
            'message': 'JSON解析函数可能接受不可信输入'
        },
        # 检测JSON对象到C结构体的自动转换
        {
            'id': 'json_to_struct_unsafe',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (identifier) @json_obj (identifier) @struct_ptr)
                ) @call
            ''',
            'func_pattern': r'^(json_object_object_get_ex|json_object_get_boolean|json_object_get_int|json_object_get_double|json_object_get_string)$',
            'message': 'JSON对象到C结构体的转换可能存在类型安全问题'
        },
        # 检测JSON数组的危险操作
        {
            'id': 'json_array_unsafe',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (identifier) @json_array (identifier) @index)
                ) @call
            ''',
            'func_pattern': r'^(json_object_array_get_idx|json_object_array_put_idx)$',
            'message': 'JSON数组索引操作可能越界'
        },
        # 检测JSON字符串提取和直接使用
        {
            'id': 'json_string_unsafe',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (identifier) @json_string)
                ) @call
            ''',
            'func_pattern': r'^(json_object_get_string|json_object_to_json_string)$',
            'message': 'JSON字符串提取后直接使用可能存在风险'
        },
        # 检测内存分配与JSON解析的组合（修复查询语法）
        {
            'id': 'json_malloc_combination',
            'query': '''
                (call_expression
                    function: (identifier) @alloc_func
                    arguments: (argument_list) @alloc_args
                ) @alloc_call
                (call_expression
                    function: (identifier) @json_func
                    arguments: (argument_list) @json_args
                ) @json_call
            ''',
            'alloc_pattern': r'^(malloc|calloc|realloc|strdup)$',
            'json_pattern': r'^(json_|cJSON_)',
            'message': '内存分配与JSON解析组合使用可能被利用'
        },
        # 检测JSON解析后的指针解引用
        {
            'id': 'json_pointer_deref',
            'query': '''
                (assignment_expression
                    left: (pointer_expression) @ptr_left
                    right: (call_expression
                        function: (identifier) @json_func
                        arguments: (argument_list) @json_args
                    ) @json_call
                ) @assignment
            ''',
            'json_pattern': r'^(json_|cJSON_)',
            'message': 'JSON解析结果直接赋值给指针可能被利用'
        },
        # 检测联合体(union)定义
        {
            'id': 'union_type_confusion',
            'query': '''
                (union_specifier) @union_def
            ''',
            'message': '联合体使用可能导致类型混淆'
        },
        # 检测不安全的类型转换与JSON
        {
            'id': 'json_unsafe_cast',
            'query': '''
                (cast_expression
                    type: (type_descriptor) @target_type
                    value: (call_expression
                        function: (identifier) @json_func
                        arguments: (argument_list) @json_args
                    ) @json_call
                ) @cast
            ''',
            'json_pattern': r'^(json_|cJSON_)',
            'message': 'JSON解析结果的不安全类型转换'
        },
        # 检测JSON解析错误处理缺失
        {
            'id': 'json_error_handling_missing',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(json_tokener_parse|json_object_from_file|cJSON_Parse)$',
            'message': 'JSON解析函数调用可能缺少错误检查'
        }
    ]
}

# JSON相关的用户输入源
JSON_USER_INPUT_SOURCES = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(recv|recvfrom|recvmsg|read)$',
            'message': '网络输入可能包含JSON数据'
        },
        {
            'func_pattern': r'^(fread|fgets|fscanf)$',
            'message': '文件输入可能包含JSON数据'
        },
        {
            'func_pattern': r'^(scanf|gets)$',
            'message': '标准输入可能包含JSON数据'
        },
        {
            'func_pattern': r'^(main)$',
            'arg_index': 1,
            'message': '命令行参数可能包含JSON'
        }
    ]
}


def get_node_id(node):
    """获取节点的唯一标识符"""
    return f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"


def detect_c_json_deserialization_vulnerabilities(code, language='c'):
    """
    检测C代码中不安全的JSON反序列化漏洞

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
    processed_node_ids = set()  # 记录已处理的节点ID，避免重复

    # 第一步：收集JSON相关操作
    for query_info in UNSAFE_JSON_DESERIALIZATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                # 跳过已处理的节点
                node_id = get_node_id(node)
                if node_id in processed_node_ids:
                    continue

                if tag in ['func_name', 'json_func', 'alloc_func']:
                    name = node.text.decode('utf8')

                    # 检查JSON函数模式
                    json_pattern = query_info.get('json_pattern', '')
                    if json_pattern and re.match(json_pattern, name, re.IGNORECASE):
                        current_capture['json_func'] = name
                        current_capture['json_node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                    # 检查特定函数模式
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                    # 检查分配函数模式
                    alloc_pattern = query_info.get('alloc_pattern', '')
                    if alloc_pattern and re.match(alloc_pattern, name, re.IGNORECASE):
                        current_capture['alloc_func'] = name
                        current_capture['alloc_node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['call', 'json_call', 'alloc_call', 'assignment', 'cast', 'union_def']:
                    # 完成一个完整的捕获
                    node_id = get_node_id(node)
                    if node_id in processed_node_ids:
                        current_capture = {}
                        continue

                    code_snippet = node.text.decode('utf8')

                    json_operation = {
                        'id': query_info['id'],
                        'type': tag,
                        'line': node.start_point[0] + 1,
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    }

                    # 添加特定信息
                    if 'json_func' in current_capture:
                        json_operation['json_function'] = current_capture['json_func']
                    if 'func' in current_capture:
                        json_operation['function'] = current_capture['func']
                    if 'alloc_func' in current_capture:
                        json_operation['alloc_function'] = current_capture['alloc_func']

                    json_operations.append(json_operation)
                    processed_node_ids.add(node_id)  # 标记节点已处理
                    current_capture = {}

        except Exception as e:
            print(f"JSON反序列化查询错误 '{query_info.get('id', 'unknown')}': {str(e)}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(JSON_USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                # 跳过已处理的节点
                parent_node = node.parent
                parent_id = get_node_id(parent_node)
                if parent_id in processed_node_ids:
                    continue

                func_name = node.text.decode('utf8')
                # 检查是否匹配任何用户输入模式
                for pattern_info in JSON_USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')

                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        code_snippet = parent_node.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': code_snippet,
                            'node': parent_node,
                            'arg_index': pattern_info.get('arg_index', None)
                        })
                        processed_node_ids.add(parent_id)  # 标记节点已处理
                        break

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：分析JSON反序列化漏洞 - 使用更精确的判断逻辑
    processed_lines = set()  # 记录已处理的行号，避免重复报告

    for operation in json_operations:
        # 检查是否已处理过该行
        line_key = f"{operation['line']}:{operation['id']}"
        if line_key in processed_lines:
            continue

        is_vulnerable = False
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': '不安全JSON反序列化',
            'severity': '高危',
            'rule_id': operation['id']
        }

        # 根据规则ID进行特定的漏洞判断
        rule_id = operation['id']

        if rule_id in ['json_parse_unsafe_input', 'json_error_handling_missing']:
            # JSON解析函数安全检查
            if is_json_function_unsafe(operation['node'], user_input_sources):
                vulnerability_details['message'] = operation['message']
                is_vulnerable = True

        elif rule_id == 'json_to_struct_unsafe':
            # JSON到结构体转换安全检查
            if is_dangerous_json_usage(operation):
                vulnerability_details['message'] = operation['message']
                is_vulnerable = True

        elif rule_id == 'json_array_unsafe':
            # JSON数组操作安全检查
            vulnerability_details['message'] = operation['message']
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        elif rule_id == 'json_string_unsafe':
            # JSON字符串使用安全检查
            if is_dangerous_json_usage(operation):
                vulnerability_details['message'] = operation['message']
                is_vulnerable = True

        elif rule_id == 'json_malloc_combination':
            # 内存分配与JSON组合检查
            if operation.get('alloc_function') and operation.get('json_function'):
                vulnerability_details['message'] = operation['message']
                is_vulnerable = True

        elif rule_id == 'json_pointer_deref':
            # JSON指针解引用检查
            vulnerability_details['message'] = operation['message']
            is_vulnerable = True

        elif rule_id == 'union_type_confusion':
            # 联合体使用检查
            vulnerability_details['message'] = operation['message']
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        elif rule_id == 'json_unsafe_cast':
            # 不安全类型转换检查
            vulnerability_details['message'] = operation['message']
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)
            processed_lines.add(line_key)  # 标记该行已处理

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_json_function_unsafe(json_node, user_input_sources):
    """
    检查JSON函数调用是否不安全（处理用户输入）
    """
    # 检查参数是否来自用户输入
    json_text = json_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    unsafe_indicators = ['argv', 'buffer', 'input', 'data', 'user', 'network', 'packet', 'fgets', 'scanf', 'recv']

    for indicator in unsafe_indicators:
        if re.search(rf'\b{indicator}\b', json_text, re.IGNORECASE):
            return True

    # 检查用户输入源
    for source in user_input_sources:
        source_text = source['node'].text.decode('utf8')
        # 简单的文本关联检查
        if has_variable_flow(source_text, json_text):
            return True

    return False


def is_dangerous_json_usage(operation):
    """
    检查JSON使用是否危险
    """
    code_snippet = operation['code_snippet']

    # 检查是否缺少错误处理
    if 'json_tokener_parse' in code_snippet or 'json_object_from_file' in code_snippet:
        if 'if' not in code_snippet and 'NULL' not in code_snippet:
            return True

    # 检查是否用于危险操作
    dangerous_patterns = [
        r'system\s*\(\s*json_object_get_string',
        r'malloc\s*\(\s*json_object_get_int',
        r'exec\w*\s*\(\s*json_object_get_string'
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True

    return False


def has_variable_flow(source_text, target_text):
    """
    简化版变量流分析
    """
    # 提取源文本中的变量名
    source_vars = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{2,})\b', source_text)

    for var in source_vars:
        # 避免常见的关键词误报
        if var.lower() in ['int', 'char', 'void', 'return', 'if', 'else', 'for', 'while']:
            continue

        if re.search(rf'\b{var}\b', target_text):
            return True

    return False


def analyze_c_json_vulnerabilities(code_string):
    """
    分析C代码字符串中的不安全JSON反序列化漏洞
    """
    return detect_c_json_deserialization_vulnerabilities(code_string, 'c')


# 测试函数
def test_json_vulnerability_detection():
    """
    测试JSON反序列化漏洞检测
    """
    # 测试C代码 - 包含JSON反序列化漏洞的示例
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

// 危险示例：不安全的JSON反序列化
void vulnerable_json_deserialization(int argc, char* argv[]) {
    // 直接解析命令行参数中的JSON
    struct json_object* json = json_tokener_parse(argv[1]);  // 高危：直接解析用户输入

    // 没有错误检查的JSON解析
    struct json_object* unsafe_json = json_object_from_file("untrusted.json");  // 缺少错误检查

    // JSON解析结果直接用于系统命令
    struct json_object* cmd_json = json_tokener_parse(argv[2]);
    const char* command = json_object_get_string(cmd_json);
    system(command);  // 极度危险：JSON数据直接执行命令

    // JSON数据用于内存分配
    struct json_object* size_json = json_tokener_parse(argv[3]);
    int size = json_object_get_int(size_json);
    char* buffer = malloc(size);  // 危险：JSON控制内存分配大小

    // 不安全的类型转换
    struct json_object* ptr_json = json_tokener_parse(argv[4]);
    void* pointer = (void*)json_object_get_int64(ptr_json);  // 危险的指针转换

    // 联合体类型混淆
    union dangerous_union {
        int number;
        char* string;
        void* pointer;
    } data;

    struct json_object* union_json = json_tokener_parse(argv[5]);
    data.number = json_object_get_int(union_json);  // 可能被利用进行类型混淆
}

// 相对安全的JSON处理示例
void safe_json_handling() {
    // 安全的JSON解析：硬编码数据
    struct json_object* json = json_tokener_parse("{\\"key\\": \\"value\\"}");

    // 带错误检查的JSON解析
    struct json_object* safe_json = json_object_from_file("trusted_config.json");
    if (safe_json == NULL) {
        fprintf(stderr, "Failed to parse JSON file\\n");
        return;
    }

    // 安全的JSON字段访问
    struct json_object* value;
    if (json_object_object_get_ex(safe_json, "safe_key", &value)) {
        const char* str = json_object_get_string(value);
        if (str != NULL) {
            printf("Value: %s\\n", str);
        }
    }

    // 安全的数值范围检查
    int size = json_object_get_int(value);
    if (size > 0 && size < 1024) {
        char* buffer = malloc(size);
        // 使用buffer...
        free(buffer);
    }
}

int main(int argc, char* argv[]) {
    vulnerable_json_deserialization(argc, argv);
    safe_json_handling();
    return 0;
}
"""

    print("=" * 60)
    print("C语言不安全JSON反序列化漏洞检测")
    print("=" * 60)

    results = analyze_c_json_vulnerabilities(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   规则ID: {vuln.get('rule_id', 'N/A')}")
    else:
        print("未检测到不安全的JSON反序列化漏洞")


if __name__ == "__main__":
    test_json_vulnerability_detection()