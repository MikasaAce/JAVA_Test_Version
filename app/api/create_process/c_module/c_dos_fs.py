import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 格式字符串漏洞检测模式
FORMAT_STRING_VULNERABILITIES = {
    'c': [
        # 检测不安全的printf系列函数调用
        {
            'id': 'printf_family',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @format_arg
                        (_)* @other_args
                    )
                ) @call
            ''',
            'func_pattern': r'^(printf|sprintf|fprintf|snprintf|vsprintf|vsnprintf|vprintf|vfprintf)$',
            'message': '格式字符串函数调用'
        },
        # 检测scanf系列函数调用
        {
            'id': 'scanf_family',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @format_arg
                        (_)* @other_args
                    )
                ) @call
            ''',
            'func_pattern': r'^(scanf|fscanf|sscanf|vscanf|vfscanf|vsscanf)$',
            'message': '格式输入函数调用'
        },
        # 检测syslog函数调用
        {
            'id': 'syslog_call',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @priority_arg
                        (_) @format_arg
                        (_)* @other_args
                    )
                ) @call
            ''',
            'func_pattern': r'^syslog$',
            'message': 'syslog函数调用'
        },
        # 检测自定义格式字符串函数
        {
            'id': 'custom_printf',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @format_arg
                        (_)* @other_args
                    )
                ) @call
            ''',
            'func_pattern': r'.*printf.*',  # 匹配任何包含printf的函数名
            'message': '自定义格式字符串函数调用'
        },
        # 检测可变参数函数调用（可能包含格式字符串）
        {
            'id': 'variadic_functions',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (_) @first_arg
                        (_)* @var_args
                    )
                ) @call
            ''',
            'func_pattern': r'^(execle|execlp|execl|execvp|execv|execvpe)$',
            'message': '可变参数函数调用'
        }
    ]
}

# 用户可控的格式字符串源
USER_CONTROLLED_FORMAT_SOURCES = {
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
            'func_pattern': r'^(strcpy|strncpy|memcpy|memmove|strcat|strncat)$',
            'message': '字符串复制函数'
        }
    ]
}

# 安全的格式字符串常量模式
SAFE_FORMAT_STRING_PATTERNS = [
    r'^"[^%]*"$',  # 不包含%的字符串字面量
    r'^"[^%]*%[dfscxpu]"$',  # 简单的格式说明符
    r'^"[^%]*%[0-9]*[dfscxpu]"$',  # 带宽度的简单格式说明符
    r'^"[^%]*%\.[0-9]*[f]"$',  # 带精度的浮点数格式
]


def get_node_id(node):
    """获取节点的唯一标识符"""
    return f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"


def detect_c_format_string_vulnerabilities(code, language='c'):
    """
    检测C代码中格式字符串漏洞

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
    format_function_calls = []  # 存储格式字符串函数调用
    user_controlled_sources = []  # 存储用户可控的数据源
    processed_nodes = set()  # 记录已处理的节点ID

    # 第一步：收集格式字符串函数调用
    for query_info in FORMAT_STRING_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                node_id = get_node_id(node)
                if node_id in processed_nodes:
                    continue

                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, func_name, re.IGNORECASE):
                        current_capture['func_name'] = func_name
                        current_capture['func_node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'format_arg':
                    current_capture['format_arg'] = node
                    current_capture['format_text'] = node.text.decode('utf8')

                elif tag == 'first_arg' and 'func_name' in current_capture:
                    # 对于可变参数函数，第一个参数可能是格式字符串
                    if current_capture['func_name'] in ['execle', 'execlp', 'execl']:
                        current_capture['format_arg'] = node
                        current_capture['format_text'] = node.text.decode('utf8')

                elif tag == 'call' and current_capture:
                    # 完成一个完整的捕获
                    node_id = get_node_id(node)
                    if node_id in processed_nodes:
                        current_capture = {}
                        continue

                    if 'format_arg' in current_capture:
                        code_snippet = node.text.decode('utf8')

                        format_function_calls.append({
                            'id': query_info['id'],
                            'type': 'format_function',
                            'line': current_capture['line'],
                            'function': current_capture['func_name'],
                            'format_arg': current_capture['format_arg'],
                            'format_text': current_capture['format_text'],
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })
                        processed_nodes.add(node_id)

                    current_capture = {}

        except Exception as e:
            print(f"格式字符串查询错误 {query_info.get('id', 'unknown')}: {e}")
            continue

    # 第二步：收集用户可控的数据源
    try:
        query = LANGUAGES[language].query(USER_CONTROLLED_FORMAT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                node_id = get_node_id(node.parent)
                if node_id in processed_nodes:
                    continue

                func_name = node.text.decode('utf8')
                # 检查是否匹配任何用户输入模式
                for pattern_info in USER_CONTROLLED_FORMAT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')

                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        code_snippet = node.parent.text.decode('utf8')
                        user_controlled_sources.append({
                            'type': 'user_controlled',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'message': pattern_info.get('message', '')
                        })
                        processed_nodes.add(node_id)
                        break

    except Exception as e:
        print(f"用户可控源查询错误: {e}")

    # 第三步：分析格式字符串漏洞 - 使用去重机制
    processed_vulnerabilities = set()

    for call in format_function_calls:
        # 使用行号+规则ID作为唯一标识
        vulnerability_key = f"{call['line']}:{call['id']}"
        if vulnerability_key in processed_vulnerabilities:
            continue

        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '拒绝服务：格式字符串',
            'severity': '高危',
            'function': call['function'],
            'rule_id': call['id']
        }

        format_text = call['format_text'].strip()

        # 检查格式字符串是否来自用户可控源
        if is_user_controlled_format(call['format_arg'], user_controlled_sources, root):
            vulnerability_details['message'] = f"用户控制的格式字符串: {call['function']} 使用外部输入的格式字符串"
            vulnerability_details['risk'] = '确认漏洞 - 格式字符串完全可控'
            is_vulnerable = True

        # 检查格式字符串是否包含危险模式
        elif not is_safe_format_string(format_text):
            vulnerability_details['message'] = f"潜在不安全的格式字符串: {call['function']} 使用复杂或危险的格式说明符"
            vulnerability_details['risk'] = '潜在漏洞 - 需要进一步分析'
            is_vulnerable = True

        # 检查是否缺少格式字符串参数
        elif has_missing_format_args(call):
            vulnerability_details['message'] = f"格式字符串参数不匹配: {call['function']} 可能缺少对应的参数"
            vulnerability_details['risk'] = '潜在漏洞 - 参数数量不匹配'
            is_vulnerable = True

        # 检查syslog的特殊情况
        elif call['function'] == 'syslog' and not is_safe_syslog_format(format_text):
            vulnerability_details['message'] = f"不安全的syslog调用: 格式字符串可能包含用户输入"
            vulnerability_details['risk'] = '潜在漏洞 - syslog格式字符串问题'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)
            processed_vulnerabilities.add(vulnerability_key)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_user_controlled_format(format_arg_node, user_controlled_sources, root_node):
    """
    检查格式字符串参数是否来自用户可控源
    """
    # 检查是否是变量（非字符串字面量）
    format_text = format_arg_node.text.decode('utf8')

    # 如果是字符串字面量，直接检查内容
    if format_text.startswith('"') and format_text.endswith('"'):
        return False  # 字符串字面量通常不是用户可控的

    # 检查是否是变量，且该变量来自用户可控源
    if is_variable_from_user_source(format_arg_node, user_controlled_sources, root_node):
        return True

    # 检查是否是复杂的表达式（可能包含用户输入）
    if is_complex_expression(format_arg_node):
        return True

    return False


def is_variable_from_user_source(node, user_controlled_sources, root_node):
    """
    检查变量是否来自用户可控源
    """
    node_text = node.text.decode('utf8')

    # 简单的变量名检查
    user_input_vars = [
        'argv', 'argc', 'input', 'buffer', 'data', 'param', 'user',
        'cmd', 'format', 'fmt', 'str', 'string', 'buf'
    ]

    for var in user_input_vars:
        if re.search(rf'\b{var}\b', node_text, re.IGNORECASE):
            return True

    # 检查数据流是否来自用户可控函数
    for source in user_controlled_sources:
        if is_data_flow_from_source(node, source, root_node):
            return True

    return False


def is_data_flow_from_source(target_node, source_node, root_node):
    """
    简单检查数据流关系（基于变量名和位置）
    """
    target_text = target_node.text.decode('utf8')
    source_text = source_node['node'].text.decode('utf8')

    # 提取变量名
    target_vars = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', target_text)
    source_vars = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', source_text)

    # 检查是否有共同的变量
    common_vars = set(target_vars) & set(source_vars)
    if common_vars:
        return True

    # 检查位置关系（简单的控制流分析）
    target_line = target_node.start_point[0]
    source_line = source_node['node'].start_point[0]

    # 如果源在目标之前，可能存在数据流
    if source_line < target_line:
        return True

    return False


def is_safe_format_string(format_text):
    """
    检查格式字符串是否安全
    """
    # 移除字符串引号
    if format_text.startswith('"') and format_text.endswith('"'):
        format_text = format_text[1:-1]

    # 空字符串或没有格式说明符的字符串是安全的
    if not format_text or '%' not in format_text:
        return True

    # 检查是否匹配安全模式
    for pattern in SAFE_FORMAT_STRING_PATTERNS:
        quoted_pattern = f'"{pattern[1:-1]}"'  # 添加引号进行匹配
        if re.match(quoted_pattern, f'"{format_text}"'):
            return True

    # 检查是否包含危险的格式说明符
    dangerous_specifiers = [
        r'%n',  # 写入字符数
        r'%s',  # 字符串（可能造成读取越界）
        r'%\d*\*',  # 可变宽度/精度
        r'%hhn',  # 单字节写入
        r'%ln',  # 长整型写入
    ]

    for specifier in dangerous_specifiers:
        if re.search(specifier, format_text):
            return False

    # 检查格式字符串的复杂性
    percent_count = format_text.count('%')
    if percent_count > 5:  # 过多的格式说明符可能表示复杂格式
        return False

    return True


def is_safe_syslog_format(format_text):
    """
    检查syslog调用的格式字符串是否安全
    """
    # syslog的格式字符串应该相对简单
    if format_text.startswith('"') and format_text.endswith('"'):
        format_text = format_text[1:-1]

    # 检查是否包含明显的用户数据占位符
    user_data_indicators = ['%s', '%[', '%c', 'username', 'user', 'input']
    for indicator in user_data_indicators:
        if indicator in format_text:
            return False

    return True


def has_missing_format_args(call_info):
    """
    检查格式字符串调用是否可能缺少参数
    """
    format_text = call_info['format_text']
    function_name = call_info['function']

    if format_text.startswith('"') and format_text.endswith('"'):
        format_text = format_text[1:-1]

    # 计算格式说明符的数量
    format_specifiers = re.findall(r'%[^%a-zA-Z]*[a-zA-Z]', format_text)
    specifier_count = len(format_specifiers)

    # 根据函数类型确定需要的参数数量
    if function_name in ['printf', 'vprintf']:
        # printf需要与格式说明符数量匹配的参数
        expected_args = specifier_count
    elif function_name in ['fprintf', 'sprintf', 'snprintf', 'vfprintf', 'vsprintf', 'vsnprintf']:
        # 这些函数需要额外的文件/缓冲区参数
        expected_args = specifier_count + 1
    elif function_name == 'syslog':
        # syslog需要优先级参数 + 格式说明符数量的参数
        expected_args = specifier_count + 1
    else:
        return False  # 无法确定

    # 简单的启发式检查：如果格式说明符很多但代码片段看起来参数很少
    code_snippet = call_info['code_snippet']
    comma_count = code_snippet.count(',')

    # 粗略估计参数数量（逗号数量 + 1）
    apparent_args = comma_count + 1

    if specifier_count > 0 and apparent_args < expected_args:
        return True

    return False


def is_complex_expression(node):
    """
    检查节点是否是复杂表达式（可能包含用户输入）
    """
    node_type = node.type
    complex_types = [
        'binary_expression',  # 二元运算
        'call_expression',  # 函数调用
        'subscript_expression',  # 数组下标
        'pointer_expression',  # 指针解引用
    ]

    if node_type in complex_types:
        return True

    # 检查子节点是否复杂
    for child in node.children:
        if is_complex_expression(child):
            return True

    return False


def analyze_c_code_for_format_strings(code_string):
    """
    分析C代码字符串中的格式字符串漏洞
    """
    return detect_c_format_string_vulnerabilities(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

// 漏洞示例
void vulnerable_functions(int argc, char* argv[]) {
    char user_input[100];
    char format_string[100];

    // 案例1: 直接使用用户输入作为格式字符串
    printf(argv[1]);  // 高危漏洞！

    // 案例2: 用户控制的部分格式字符串
    sprintf(format_string, "Result: %s", argv[1]);
    printf(format_string);  // 潜在漏洞

    // 案例3: 危险的格式说明符
    printf("Count: %n", &argc);  # %n写入操作

    // 案例4: syslog漏洞
    syslog(LOG_INFO, argv[1]);  // 用户控制的syslog格式

    // 案例5: 复杂的用户构造格式字符串
    char buffer[100];
    strcpy(buffer, "Error: ");
    strcat(buffer, argv[1]);
    printf(buffer);  // 间接的用户控制

    // 案例6: 缺少参数的格式字符串
    printf("Values: %d %d %d", 1, 2);  // 参数不匹配
}

// 相对安全的示例
void safe_functions() {
    // 安全的硬编码格式字符串
    printf("Hello World\\n");
    printf("Value: %d\\n", 42);
    printf("Name: %s, Age: %d\\n", "Alice", 30);

    // 安全的syslog使用
    syslog(LOG_INFO, "System started successfully");

    // 安全的sprintf使用
    char buffer[100];
    sprintf(buffer, "Result: %d", 100);
}

// 边界案例
void edge_cases() {
    char* static_string = "Static format: %d";
    printf(static_string, 10);  // 可能安全，但需要检查来源

    // 多重格式字符串
    printf("%s %d", "test", 123);  // 安全

    // 带有宽度和精度的格式
    printf("Float: %.2f", 3.14159);  // 安全
}

int main(int argc, char* argv[]) {
    vulnerable_functions(argc, argv);
    safe_functions();
    edge_cases();
    return 0;
}
"""

    print("=" * 60)
    print("C语言格式字符串漏洞检测")
    print("=" * 60)

    results = analyze_c_code_for_format_strings(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在格式字符串漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   函数: {vuln['function']}")
            print(f"   风险等级: {vuln['risk']}")
            print(f"   代码片段: {vuln['code_snippet'][:80]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   规则ID: {vuln.get('rule_id', 'N/A')}")
    else:
        print("未检测到格式字符串漏洞")