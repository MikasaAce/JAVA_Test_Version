import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# XStream反序列化漏洞模式
XSTREAM_DESERIALIZATION_VULNERABILITIES = {
    'c': [
        # 检测XML反序列化函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @xml_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(xml_deserialize|xstream_from_xml|xml_to_object|unmarshal_xml|deserialize_xml)$',
            'message': 'XML反序列化函数调用'
        },
        # 检测对象创建相关的XML处理
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @class_arg
                        (_) @xml_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(create_object_from_xml|xml_instantiate|new_from_xml)$',
            'message': 'XML到对象创建函数调用'
        },
        # 检测类型转换相关的XML处理
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @type_arg
                        (_) @xml_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(cast_xml_to_type|xml_to_struct|parse_xml_to_object)$',
            'message': 'XML到类型转换函数调用'
        },
        # 检测动态类加载相关的XML处理
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @class_name_arg
                        (_) @xml_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(load_class_from_xml|xml_to_dynamic_class|instantiate_class_xml)$',
            'message': 'XML动态类加载函数调用'
        }
    ]
}

# XStream特定模式
XSTREAM_SPECIFIC_PATTERNS = {
    'c': [
        # 检测XStream相关字符串
        {
            'query': '''
                (string_literal) @xstream_string
            ''',
            'pattern': r'xstream|XStream|com\.thoughtworks\.xstream',
            'message': '字符串包含XStream相关关键词'
        },
        # 检测动态类型相关字符串
        {
            'query': '''
                (string_literal) @dynamic_type_string
            ''',
            'pattern': r'dynamic-type|dynamicClass|instantiate|newInstance',
            'message': '字符串包含动态类型相关关键词'
        },
        # 检测Java类名模式
        {
            'query': '''
                (string_literal) @java_class_string
            ''',
            'pattern': r'java\.|javax\.|com\.|org\.|net\.',
            'message': '字符串包含Java类名模式'
        }
    ]
}

# 反序列化上下文检测
DESERIALIZATION_CONTEXT = {
    'c': [
        # 检测反序列化相关头文件包含
        {
            'query': '''
                (preproc_include
                    path: (string_literal) @include_path
                ) @include
            ''',
            'pattern': r'.*(xstream|serialize|deserialize|marshal|unmarshal)\.h',
            'message': '包含反序列化相关头文件'
        },
        # 检测反序列化相关类型
        {
            'query': '''
                (type_identifier) @type_name
            ''',
            'pattern': r'^(XStream|Serializer|Deserializer|Marshaller|Unmarshaller)$',
            'message': '使用反序列化相关类型'
        },
        # 检测反序列化初始化函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(xstream_init|xstream_new|create_xstream|init_deserializer)$',
            'message': '反序列化器初始化函数'
        }
    ]
}

# 危险的XML反序列化模式
DANGEROUS_DESERIALIZATION_PATTERNS = {
    'c': [
        # 检测未受限制的类加载
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string_literal) @class_name
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(load_class|find_class|get_class|instantiate_class)$',
            'pattern': r'.*(Runtime|ProcessBuilder|FileOutputStream|URLClassLoader).*',
            'message': '可能加载危险类'
        },
        # 检测类型转换安全检查缺失
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @xml_input
                        (_)*
                    )
                ) @call
                (#not-match? @func_name "validate|check|safe")
            ''',
            'func_pattern': r'^(deserialize|unmarshal|from_xml|parse_xml)$',
            'message': '反序列化函数缺少安全检查'
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


def detect_c_xstream_deserialization(code, language='c'):
    """
    检测C代码中XStream反序列化漏洞

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
    deserialization_calls = []  # 存储反序列化函数调用
    xstream_patterns = []  # 存储XStream特定模式
    deserialization_context = []  # 存储反序列化上下文信息
    dangerous_patterns = []  # 存储危险的反序列化模式
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集反序列化函数调用（使用节点ID去重）
    processed_function_nodes = set()

    for query_info in XSTREAM_DESERIALIZATION_VULNERABILITIES[language]:
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

                elif tag in ['xml_arg', 'class_arg', 'type_arg', 'class_name_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag in ['call'] and current_capture:
                    # 使用节点位置作为唯一标识
                    node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"

                    if node_id not in processed_function_nodes:
                        # 完成一个完整的捕获
                        code_snippet = node.text.decode('utf8')

                        deserialization_calls.append({
                            'type': 'deserialization_function',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'node_id': node_id,
                            'message': query_info.get('message', '')
                        })
                        processed_function_nodes.add(node_id)

                    current_capture = {}

        except Exception as e:
            print(f"反序列化函数查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第二步：收集XStream特定模式（使用节点ID去重）
    processed_string_nodes = set()

    for query_info in XSTREAM_SPECIFIC_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['xstream_string', 'dynamic_type_string', 'java_class_string']:
                    # 使用节点位置作为唯一标识
                    node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"

                    if node_id not in processed_string_nodes:
                        text = node.text.decode('utf8')
                        pattern = query_info.get('pattern', '')

                        if pattern and re.search(pattern, text, re.IGNORECASE):
                            code_snippet = node.text.decode('utf8')
                            xstream_patterns.append({
                                'type': 'xstream_pattern',
                                'line': node.start_point[0] + 1,
                                'text': text,
                                'code_snippet': code_snippet,
                                'node': node,
                                'node_id': node_id,
                                'pattern_match': True,
                                'message': query_info.get('message', '')
                            })
                            processed_string_nodes.add(node_id)

        except Exception as e:
            print(f"XStream模式查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第三步：收集反序列化上下文信息
    for query_info in DESERIALIZATION_CONTEXT[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                text = node.text.decode('utf8')

                if tag in ['include_path']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        deserialization_context.append({
                            'type': 'deserialization_include',
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
                        deserialization_context.append({
                            'type': 'deserialization_type',
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
                        deserialization_context.append({
                            'type': 'deserialization_function',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"反序列化上下文查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第四步：收集危险的反序列化模式（使用节点ID去重）
    processed_dangerous_nodes = set()

    for query_info in DANGEROUS_DESERIALIZATION_PATTERNS[language]:
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

                elif tag in ['class_name', 'xml_input']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node
                    # 检查参数模式
                    arg_pattern = query_info.get('pattern', '')
                    if arg_pattern and re.search(arg_pattern, current_capture['arg'], re.IGNORECASE):
                        current_capture['arg_match'] = True

                elif tag in ['call'] and current_capture:
                    # 使用节点位置作为唯一标识
                    node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"

                    if node_id not in processed_dangerous_nodes:
                        # 完成一个完整的捕获
                        code_snippet = node.text.decode('utf8')

                        dangerous_patterns.append({
                            'type': 'dangerous_deserialization',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'node_id': node_id,
                            'arg_match': current_capture.get('arg_match', False),
                            'message': query_info.get('message', '')
                        })
                        processed_dangerous_nodes.add(node_id)

                    current_capture = {}

        except Exception as e:
            print(f"危险反序列化模式查询错误 {query_info.get('message', '未知')}: {e}")
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

    # 第六步：分析XStream反序列化漏洞（使用智能去重）
    vulnerabilities = analyze_xstream_deserialization_vulnerabilities_with_deduplication(
        deserialization_calls, xstream_patterns, deserialization_context,
        dangerous_patterns, user_input_sources
    )

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_xstream_deserialization_vulnerabilities_with_deduplication(deserialization_calls, xstream_patterns,
                                                                       deserialization_context,
                                                                       dangerous_patterns, user_input_sources):
    """
    分析XStream反序列化漏洞并进行智能去重
    """
    all_vulnerabilities = []

    # 分析反序列化函数调用漏洞
    for call in deserialization_calls:
        vulnerability_details = analyze_deserialization_function_vulnerability(call, user_input_sources,
                                                                               deserialization_context)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 分析XStream特定模式漏洞
    for pattern in xstream_patterns:
        vulnerability_details = analyze_xstream_pattern_vulnerability(pattern, user_input_sources,
                                                                      deserialization_context)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 分析危险的反序列化模式
    for dangerous in dangerous_patterns:
        vulnerability_details = analyze_dangerous_deserialization_vulnerability(dangerous, user_input_sources)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 智能去重
    return intelligent_xstream_deduplication(all_vulnerabilities)


def intelligent_xstream_deduplication(vulnerabilities):
    """
    智能去重：基于代码上下文和语义合并相似漏洞
    """
    if not vulnerabilities:
        return []

    # 按行号分组
    line_groups = {}
    for vuln in vulnerabilities:
        line = vuln['line']
        if line not in line_groups:
            line_groups[line] = []
        line_groups[line].append(vuln)

    # 对每行的漏洞进行智能合并
    deduplicated = []
    for line, vulns in line_groups.items():
        if len(vulns) == 1:
            deduplicated.append(vulns[0])
        else:
            # 多个漏洞，选择最准确的一个
            best_vuln = select_best_xstream_vulnerability(vulns)
            deduplicated.append(best_vuln)

    return deduplicated


def select_best_xstream_vulnerability(vulns):
    """
    从同一行的多个漏洞中选择最准确的一个
    """
    if len(vulns) == 1:
        return vulns[0]

    # 优先级：用户输入直接传递 > 危险模式 > XStream模式 > 上下文风险
    priority_order = {
        'user_input_direct': 1,
        'dangerous_deserialization': 2,
        'xstream_pattern': 3,
        'deserialization_context': 4
    }

    # 按优先级排序
    sorted_vulns = sorted(vulns, key=lambda x: priority_order.get(
        x.get('detection_type', 'deserialization_context'), 5
    ))

    # 选择优先级最高的漏洞
    best_vuln = sorted_vulns[0]

    # 如果同一行有多个XStream模式，合并描述
    xstream_patterns = [v for v in vulns if v.get('detection_type') == 'xstream_pattern']
    if len(xstream_patterns) > 1:
        pattern_count = len(xstream_patterns)
        best_vuln['message'] = f"发现 {pattern_count} 个XStream相关模式"

    return best_vuln


def analyze_deserialization_function_vulnerability(call, user_input_sources, deserialization_context):
    """
    分析反序列化函数调用漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': call['line'],
        'code_snippet': call['code_snippet'],
        'vulnerability_type': 'XStream反序列化',
        'severity': '高危',
        'detection_type': 'deserialization_context'
    }

    # 检查是否包含用户输入
    if call.get('arg_node') and is_user_input_related(call['arg_node'], user_input_sources):
        vulnerability_details['message'] = f"用户输入直接传递给反序列化函数: {call['function']}"
        vulnerability_details['detection_type'] = 'user_input_direct'
        is_vulnerable = True

    # 检查在反序列化上下文中的潜在风险
    elif is_in_deserialization_context(call['node'], deserialization_context):
        vulnerability_details['message'] = f"反序列化上下文中的函数调用: {call['function']}"
        vulnerability_details['severity'] = '中危'
        vulnerability_details['detection_type'] = 'deserialization_context'
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def analyze_xstream_pattern_vulnerability(pattern, user_input_sources, deserialization_context):
    """
    分析XStream特定模式漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': pattern['line'],
        'code_snippet': pattern['code_snippet'],
        'vulnerability_type': 'XStream反序列化',
        'severity': '高危',
        'detection_type': 'xstream_pattern'
    }

    if pattern.get('pattern_match', False) and is_in_deserialization_context(pattern['node'], deserialization_context):
        vulnerability_details['message'] = f"反序列化上下文中的XStream模式: {pattern['message']}"
        is_vulnerable = True

    elif pattern.get('pattern_match', False) and has_user_input_nearby(pattern['node'], user_input_sources):
        vulnerability_details['message'] = f"用户输入附近的XStream模式: {pattern['message']}"
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def analyze_dangerous_deserialization_vulnerability(dangerous, user_input_sources):
    """
    分析危险的反序列化模式漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': dangerous['line'],
        'code_snippet': dangerous['code_snippet'],
        'vulnerability_type': 'XStream反序列化',
        'severity': '高危',
        'detection_type': 'dangerous_deserialization'
    }

    if dangerous.get('arg_match', False):
        vulnerability_details['message'] = f"可能加载危险类: {dangerous['function']} - {dangerous['argument']}"
        is_vulnerable = True

    elif dangerous.get('arg_node') and is_user_input_related(dangerous['arg_node'], user_input_sources):
        vulnerability_details['message'] = f"用户输入控制反序列化参数: {dangerous['function']}"
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def is_user_input_related(arg_node, user_input_sources):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'xml', 'class', 'type']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_in_deserialization_context(node, deserialization_context):
    """
    检查节点是否在反序列化上下文中
    """
    node_line = node.start_point[0] + 1

    for context in deserialization_context:
        context_line = context['line']
        # 如果反序列化上下文在调用之前或同一区域
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


def analyze_xstream_deserialization(code_string):
    """
    分析C代码字符串中的XStream反序列化漏洞
    """
    return detect_c_xstream_deserialization(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - XStream反序列化场景
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xstream.h>

// 危险示例 - XStream反序列化漏洞
void vulnerable_xstream_functions(int argc, char* argv[]) {
    XStream* xstream;
    void* object;

    // 初始化XStream
    xstream = xstream_init();

    // 漏洞1: 直接反序列化用户输入的XML
    char* user_xml = argv[1];
    object = xstream_from_xml(xstream, user_xml);  // XStream反序列化漏洞

    // 漏洞2: 从文件读取XML并反序列化
    FILE* fp = fopen("data.xml", "r");
    if (fp) {
        char xml_content[4096];
        fread(xml_content, 1, sizeof(xml_content), fp);
        fclose(fp);
        object = xstream_from_xml(xstream, xml_content);  // 潜在漏洞
    }

    // 漏洞3: 动态类加载反序列化
    char* dynamic_class = "com.example.EvilClass";
    object = load_class_from_xml(xstream, dynamic_class, argv[2]);  // 危险

    // 漏洞4: 未受限制的类型转换
    char* xml_data = getenv("XML_DATA");
    if (xml_data) {
        object = xml_to_object(xstream, xml_data);  // 反序列化漏洞
    }

    // 漏洞5: 使用危险的类名
    char malicious_xml[] = "<?xml version=\\"1.0\\"?>\\n"
                          "<dynamic-type>\\n"
                          "<class>java.lang.Runtime</class>\\n"
                          "<method>exec</method>\\n"
                          "<args>calc.exe</args>\\n"
                          "</dynamic-type>";
    object = deserialize_xml(xstream, malicious_xml);  // XStream漏洞

    // 漏洞6: 网络数据反序列化
    char network_xml[2048];
    // recv(socket_fd, network_xml, sizeof(network_xml), 0);
    object = unmarshal_xml(xstream, network_xml);  // 反序列化漏洞

    xstream_cleanup(xstream);
}

// 相对安全的示例
void safe_deserialization_functions() {
    XStream* safe_xstream = xstream_init();

    // 安全1: 启用类型安全检查
    xstream_set_mode(safe_xstream, XSTREAM_SAFE_MODE);

    // 安全2: 使用白名单
    char* allowed_classes[] = {"com.example.SafeClass", "com.example.DataClass", NULL};
    xstream_set_allowed_classes(safe_xstream, allowed_classes);

    // 安全3: 硬编码XML数据
    char safe_xml[] = "<?xml version=\\"1.0\\"?><data>safe content</data>";
    void* safe_object = xstream_from_xml(safe_xstream, safe_xml);  // 相对安全

    // 安全4: 验证输入数据
    char* user_xml = get_user_input();
    if (validate_xml_schema(user_xml)) {
        void* validated_object = xstream_from_xml(safe_xstream, user_xml);  // 经过验证
    }

    xstream_cleanup(safe_xstream);
}

// 其他反序列化示例
void custom_deserializer_example(int argc, char* argv[]) {
    // 自定义反序列化器
    Deserializer* deserializer = create_deserializer();

    // 危险: 未限制类加载
    void* obj = deserialize_from_xml(deserializer, argv[1]);  // 反序列化漏洞

    // 相对安全: 使用安全配置
    deserializer_set_security_policy(deserializer, STRICT_POLICY);
    void* safe_obj = deserialize_from_xml(deserializer, argv[1]);  // 相对安全

    destroy_deserializer(deserializer);
}

int main(int argc, char* argv[]) {
    vulnerable_xstream_functions(argc, argv);
    safe_deserialization_functions();
    custom_deserializer_example(argc, argv);
    return 0;
}
"""

    print("=" * 60)
    print("C语言XStream反序列化漏洞检测（智能去重版）")
    print("=" * 60)

    results = analyze_xstream_deserialization(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在XStream反序列化漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到XStream反序列化漏洞")