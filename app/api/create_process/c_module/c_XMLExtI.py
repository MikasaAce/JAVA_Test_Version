import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# XML外部实体注入（XXE）漏洞模式
XXE_VULNERABILITIES = {
    'c': [
        # 检测XML解析函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @xml_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(xmlParseFile|xmlReadFile|xmlCtxtReadFile|xmlParseMemory|xmlReadMemory|xmlCtxtReadMemory)$',
            'message': 'XML解析函数调用'
        },
        # 检测XML文档创建函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @doc_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(xmlNewDoc|xmlParseDoc|xmlReadDoc|xmlCtxtReadDoc)$',
            'message': 'XML文档创建函数调用'
        },
        # 检测XML解析器创建函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @parser_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(xmlNewParserCtxt|xmlCreateParserCtxt|xmlSAXParseFile|xmlSAXParseMemory)$',
            'message': 'XML解析器创建函数调用'
        },
        # 检测XML实体相关函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @entity_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(xmlAddDocEntity|xmlAddDtdEntity|xmlGetPredefinedEntity|xmlEncodeEntities)$',
            'message': 'XML实体相关函数调用'
        }
    ]
}

# XML外部实体模式
XML_EXTERNAL_ENTITY_PATTERNS = {
    'c': [
        # 检测DOCTYPE和ENTITY声明
        {
            'query': '''
                (string_literal) @xml_string
            ''',
            'pattern': r'<!DOCTYPE.*SYSTEM.*>|<!ENTITY.*SYSTEM.*>|<!ENTITY.*PUBLIC.*>',
            'message': '字符串包含DOCTYPE或ENTITY声明'
        },
        # 检测外部实体引用
        {
            'query': '''
                (string_literal) @entity_ref
            ''',
            'pattern': r'&[a-zA-Z_][a-zA-Z0-9_]*;|%[a-zA-Z_][a-zA-Z0-9_]*;',
            'message': '字符串包含实体引用'
        },
        # 检测XML文件包含
        {
            'query': '''
                (string_literal) @xml_include
            ''',
            'pattern': r'<!\[CDATA\[.*\]\]>|<!ENTITY.*%.*>',
            'message': '字符串包含XML包含语法'
        }
    ]
}

# XML解析器上下文检测
XML_PARSER_CONTEXT = {
    'c': [
        # 检测XML相关头文件包含
        {
            'query': '''
                (preproc_include
                    path: (string_literal) @include_path
                ) @include
            ''',
            'pattern': r'.*(libxml|xml|expat|libexpat|xmlparser)\.h',
            'message': '包含XML解析相关头文件'
        },
        # 检测XML相关类型
        {
            'query': '''
                (type_identifier) @type_name
            ''',
            'pattern': r'^(xmlDoc|xmlNode|xmlParserCtxt|xmlSAXHandler|xmlTextReader|XML_Parser)$',
            'message': '使用XML解析相关类型'
        },
        # 检测XML解析器初始化函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(xmlInitParser|XML_ParserCreate|XML_ParserCreateNS)$',
            'message': 'XML解析器初始化函数'
        }
    ]
}

# 危险的XML解析选项模式
DANGEROUS_XML_OPTIONS = {
    'c': [
        # 检测外部实体启用选项
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @parser_arg
                        (string_literal) @option_name
                        (_) @option_value
                    )
                ) @call
            ''',
            'func_pattern': r'^(xmlSetFeature|xmlCtxtUseOptions|XML_SetParamEntityParsing)$',
            'pattern': r'.*(external.*entity|load.*external.*dtd|resolve.*externals).*',
            'message': '启用外部实体解析选项'
        },
        # 检测XML解析选项常量
        {
            'query': '''
                (identifier) @option_constant
            ''',
            'pattern': r'^(XML_PARSE_NOENT|XML_PARSE_DTDLOAD|XML_PARSE_DTDATTR|XML_PARSE_DTDVALID)$',
            'message': '使用危险的XML解析选项'
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


def detect_c_xxe_vulnerabilities(code, language='c'):
    """
    检测C代码中XML外部实体注入（XXE）漏洞

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
    xml_function_calls = []  # 存储XML相关函数调用
    xml_entity_patterns = []  # 存储XML实体模式
    xml_parser_context = []  # 存储XML解析器上下文信息
    dangerous_xml_options = []  # 存储危险的XML选项
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集XML相关函数调用（使用节点ID去重）
    processed_function_nodes = set()

    for query_info in XXE_VULNERABILITIES[language]:
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

                elif tag in ['xml_arg', 'doc_arg', 'parser_arg', 'entity_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag in ['call'] and current_capture:
                    # 使用节点位置作为唯一标识
                    node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"

                    if node_id not in processed_function_nodes:
                        # 完成一个完整的捕获
                        code_snippet = node.text.decode('utf8')

                        xml_function_calls.append({
                            'type': 'xml_function',
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
            print(f"XML函数查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第二步：收集XML实体模式（使用节点ID去重）
    processed_string_nodes = set()

    for query_info in XML_EXTERNAL_ENTITY_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['xml_string', 'entity_ref', 'xml_include']:
                    # 使用节点位置作为唯一标识
                    node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"

                    if node_id not in processed_string_nodes:
                        text = node.text.decode('utf8')
                        pattern = query_info.get('pattern', '')

                        if pattern and re.search(pattern, text, re.IGNORECASE):
                            code_snippet = node.text.decode('utf8')
                            xml_entity_patterns.append({
                                'type': 'xml_entity',
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
            print(f"XML实体模式查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第三步：收集XML解析器上下文信息
    for query_info in XML_PARSER_CONTEXT[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                text = node.text.decode('utf8')

                if tag in ['include_path']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        xml_parser_context.append({
                            'type': 'xml_include',
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
                        xml_parser_context.append({
                            'type': 'xml_type',
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
                        xml_parser_context.append({
                            'type': 'xml_function',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"XML解析器上下文查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第四步：收集危险的XML选项（使用节点ID去重）
    processed_option_nodes = set()

    for query_info in DANGEROUS_XML_OPTIONS[language]:
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

                elif tag in ['option_name', 'option_constant']:
                    current_capture['option'] = node.text.decode('utf8')
                    current_capture['option_node'] = node
                    # 检查选项模式
                    option_pattern = query_info.get('pattern', '')
                    if option_pattern and re.search(option_pattern, current_capture['option'], re.IGNORECASE):
                        current_capture['option_match'] = True

                elif tag in ['call'] and current_capture:
                    # 使用节点位置作为唯一标识
                    node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"

                    if node_id not in processed_option_nodes:
                        # 完成一个完整的捕获
                        code_snippet = node.text.decode('utf8')

                        dangerous_xml_options.append({
                            'type': 'dangerous_option',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'option': current_capture.get('option', ''),
                            'option_node': current_capture.get('option_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'node_id': node_id,
                            'option_match': current_capture.get('option_match', False),
                            'message': query_info.get('message', '')
                        })
                        processed_option_nodes.add(node_id)

                    current_capture = {}

        except Exception as e:
            print(f"危险XML选项查询错误 {query_info.get('message', '未知')}: {e}")
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

    # 第六步：分析XXE漏洞（使用智能去重）
    vulnerabilities = analyze_xxe_vulnerabilities_with_deduplication(
        xml_function_calls, xml_entity_patterns, xml_parser_context,
        dangerous_xml_options, user_input_sources
    )

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_xxe_vulnerabilities_with_deduplication(xml_calls, entity_patterns, xml_context, dangerous_options,
                                                   user_input_sources):
    """
    分析XXE漏洞并进行智能去重
    """
    all_vulnerabilities = []

    # 分析XML函数调用漏洞
    for call in xml_calls:
        vulnerability_details = analyze_xml_function_vulnerability(call, user_input_sources, xml_context)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 分析XML实体模式漏洞
    for pattern in entity_patterns:
        vulnerability_details = analyze_xml_entity_vulnerability(pattern, user_input_sources, xml_context)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 分析危险的XML选项
    for option in dangerous_options:
        vulnerability_details = analyze_dangerous_option_vulnerability(option, user_input_sources)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 智能去重
    return intelligent_xxe_deduplication(all_vulnerabilities)


def intelligent_xxe_deduplication(vulnerabilities):
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
            best_vuln = select_best_xxe_vulnerability(vulns)
            deduplicated.append(best_vuln)

    return deduplicated


def select_best_xxe_vulnerability(vulns):
    """
    从同一行的多个漏洞中选择最准确的一个
    """
    if len(vulns) == 1:
        return vulns[0]

    # 优先级：用户输入直接传递 > 危险选项 > 实体模式 > XML上下文风险
    priority_order = {
        'user_input_direct': 1,
        'dangerous_option': 2,
        'xml_entity': 3,
        'xml_context': 4
    }

    # 按优先级排序
    sorted_vulns = sorted(vulns, key=lambda x: priority_order.get(
        x.get('detection_type', 'xml_context'), 5
    ))

    # 选择优先级最高的漏洞
    best_vuln = sorted_vulns[0]

    # 如果存在更具体的证据，更新消息
    for vuln in sorted_vulns[1:]:
        if '用户输入' in vuln['message'] and '用户输入' not in best_vuln['message']:
            best_vuln['message'] += f" | 检测到用户输入"
            best_vuln['severity'] = max_severity(best_vuln['severity'], vuln['severity'])

    return best_vuln


def max_severity(sev1, sev2):
    """
    返回两个严重程度中较高的一个
    """
    severity_order = {'低危': 1, '中危': 2, '高危': 3}
    return sev1 if severity_order.get(sev1, 0) >= severity_order.get(sev2, 0) else sev2


def analyze_xml_function_vulnerability(call, user_input_sources, xml_context):
    """
    分析XML函数调用漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': call['line'],
        'code_snippet': call['code_snippet'],
        'vulnerability_type': 'XML外部实体注入(XXE)',
        'severity': '高危',
        'detection_type': 'xml_context'
    }

    # 检查是否包含用户输入
    if call.get('arg_node') and is_user_input_related(call['arg_node'], user_input_sources):
        vulnerability_details['message'] = f"用户输入直接传递给XML解析函数: {call['function']}"
        vulnerability_details['detection_type'] = 'user_input_direct'
        is_vulnerable = True

    # 检查在XML上下文中的潜在风险
    elif is_in_xml_context(call['node'], xml_context):
        vulnerability_details['message'] = f"XML上下文中的潜在XXE风险: {call['function']}"
        vulnerability_details['severity'] = '中危'
        vulnerability_details['detection_type'] = 'xml_context'
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def analyze_xml_entity_vulnerability(pattern, user_input_sources, xml_context):
    """
    分析XML实体模式漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': pattern['line'],
        'code_snippet': pattern['code_snippet'],
        'vulnerability_type': 'XML外部实体注入(XXE)',
        'severity': '高危',
        'detection_type': 'xml_entity'
    }

    if pattern.get('pattern_match', False) and is_in_xml_context(pattern['node'], xml_context):
        vulnerability_details['message'] = f"XML上下文中的外部实体语法: {pattern['message']}"
        is_vulnerable = True

    elif pattern.get('pattern_match', False) and has_user_input_nearby(pattern['node'], user_input_sources):
        vulnerability_details['message'] = f"用户输入附近的外部实体语法: {pattern['message']}"
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def analyze_dangerous_option_vulnerability(option, user_input_sources):
    """
    分析危险的XML选项漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': option['line'],
        'code_snippet': option['code_snippet'],
        'vulnerability_type': 'XML外部实体注入(XXE)',
        'severity': '高危',
        'detection_type': 'dangerous_option'
    }

    if option.get('option_match', False):
        vulnerability_details['message'] = f"启用危险XML解析选项: {option['function']} - {option['option']}"
        is_vulnerable = True

    elif option.get('option_node') and is_user_input_related(option['option_node'], user_input_sources):
        vulnerability_details['message'] = f"用户输入控制XML解析选项: {option['function']}"
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def is_user_input_related(arg_node, user_input_sources):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'xml', 'file', 'url']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_in_xml_context(node, xml_context):
    """
    检查节点是否在XML上下文中
    """
    node_line = node.start_point[0] + 1

    for context in xml_context:
        context_line = context['line']
        # 如果XML上下文在调用之前或同一区域
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


def analyze_xxe(code_string):
    """
    分析C代码字符串中的XML外部实体注入(XXE)漏洞
    """
    return detect_c_xxe_vulnerabilities(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - XXE场景
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

// 危险示例 - XXE漏洞
void vulnerable_xxe_functions(int argc, char* argv[]) {
    xmlDoc* doc;

    // 漏洞1: 直接使用用户输入解析XML文件
    char* user_file = argv[1];
    doc = xmlReadFile(user_file, NULL, 0);  // XXE漏洞

    // 漏洞2: 使用用户输入的XML内容
    if (argc > 2) {
        doc = xmlReadMemory(argv[2], strlen(argv[2]), "noname.xml", NULL, 0);  // XXE漏洞
    }

    // 漏洞3: 启用外部实体解析
    xmlParserCtxt* ctxt = xmlNewParserCtxt();
    xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_DTDLOAD);  // 危险选项
    doc = xmlCtxtReadFile(ctxt, "input.xml", NULL, 0);  // XXE漏洞

    // 漏洞4: 直接解析包含外部实体的XML
    char malicious_xml[] = "<?xml version=\\"1.0\\"?>\\n"
                          "<!DOCTYPE root [\\n"
                          "<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">\\n"
                          "]>\\n"
                          "<root>&xxe;</root>";
    doc = xmlParseDoc((xmlChar*)malicious_xml);  // XXE漏洞

    // 漏洞5: 使用SAX解析器
    xmlSAXHandler* sax = malloc(sizeof(xmlSAXHandler));
    memset(sax, 0, sizeof(xmlSAXHandler));
    doc = xmlSAXParseFile(sax, argv[1], 0);  // XXE漏洞

    if (doc != NULL) {
        xmlFreeDoc(doc);
    }
}

// 相对安全的示例
void safe_xml_functions() {
    xmlDoc* doc;

    // 安全1: 禁用外部实体解析
    xmlParserCtxt* safe_ctxt = xmlNewParserCtxt();
    xmlCtxtUseOptions(safe_ctxt, XML_PARSE_NOENT | XML_PARSE_NODTD);  // 禁用DTD

    // 安全2: 使用安全的解析选项
    int options = XML_PARSE_NONET;  // 禁止网络访问
    options |= XML_PARSE_NODTD;     // 禁用DTD

    doc = xmlReadFile("local_file.xml", NULL, options);  // 相对安全

    // 安全3: 硬编码XML内容
    char safe_xml[] = "<?xml version=\\"1.0\\"?><root>Hello</root>";
    doc = xmlParseDoc((xmlChar*)safe_xml);  // 安全

    if (safe_ctxt != NULL) {
        xmlFreeParserCtxt(safe_ctxt);
    }
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }
}

int main(int argc, char* argv[]) {
    vulnerable_xxe_functions(argc, argv);
    safe_xml_functions();
    return 0;
}
"""

    print("=" * 60)
    print("C语言XML外部实体注入(XXE)漏洞检测（智能去重版）")
    print("=" * 60)

    results = analyze_xxe(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在XXE漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到XXE漏洞")