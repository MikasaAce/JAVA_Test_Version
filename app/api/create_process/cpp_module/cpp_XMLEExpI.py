import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在config_path中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义XML实体扩展注入漏洞模式
XML_ENTITY_EXPANSION_VULNERABILITIES = {
    'cpp': [
        # 检测XML解析器初始化时禁用实体扩展的情况
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_)* @args
                    )
                ) @call
                (#match? @func_name "^(xmlTextReader|xmlCtxt|xmlParser|XML_Parser).*")
            ''',
            'message': 'XML解析器函数调用'
        },
        # 检测XML解析选项设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @arg1
                        (_) @arg2
                    )
                ) @call
                (#match? @func_name "^(xmlTextReaderSetParserProp|xmlSetFeature|XML_SetFeature)$")
            ''',
            'message': 'XML解析器属性设置'
        },
        # 检测libxml2相关函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_)* @args
                    )
                ) @call
                (#match? @func_name "^(xmlParse|xmlRead|xmlCtxtRead|xmlDocGetRootElement)$")
            ''',
            'message': 'libxml2 XML解析函数'
        },
        # 检测expat相关函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_)* @args
                    )
                ) @call
                (#match? @func_name "^(XML_Parse|XML_SetExternalEntityRefHandler)$")
            ''',
            'message': 'expat XML解析函数'
        },
        # 检测Qt XML相关函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_)* @args
                    )
                ) @call
                (#match? @func_name "^(QDomDocument::setContent|QXmlStreamReader::addData)$")
            ''',
            'message': 'Qt XML解析函数'
        },
        # 检测pugixml相关函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_)* @args
                    )
                ) @call
                (#match? @func_name "^(pugi::xml_document::load|pugi::xml_document::load_buffer)$")
            ''',
            'message': 'pugixml解析函数'
        }
    ]
}

# XML解析器安全配置检查模式
XML_SECURITY_CONFIGURATIONS = {
    'query': '''
        [
            (assignment_expression
                left: (_) @var_name
                right: (_) @value
            )
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list 
                    (_) @arg1
                    (_) @arg2
                )
            ) @call
        ]
    ''',
    'patterns': [
        {
            'var_pattern': r'.*(feature|option|property).*',
            'value_pattern': r'.*(XML_PARSE_NOENT|XML_PARSE_DTDLOAD|XML_PARSE_DTDATTR|XML_PARSE_DTDVALID).*',
            'message': '可能启用外部实体扩展的配置'
        },
        {
            'func_pattern': r'^(xmlTextReaderSetParserProp|xmlSetFeature|XML_SetFeature)$',
            'arg_pattern': r'.*(XML_PARSE_NOENT|XML_PARSE_DTDLOAD|XML_PARSE_DTDATTR|XML_PARSE_DTDVALID).*',
            'message': '可能启用外部实体扩展的函数调用'
        }
    ]
}

# 用户输入源模式（与XML处理相关）
XML_USER_INPUT_SOURCES = {
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
            'func_pattern': r'^(fread|read|recv|recvfrom)$',
            'message': '文件或网络输入函数'
        },
        {
            'func_pattern': r'^(QIODevice::read|QTcpSocket::read)$',
            'message': 'Qt输入函数'
        },
        {
            'func_pattern': r'^(std::getline|std::cin|ifstream::read)$',
            'message': 'C++标准输入函数'
        }
    ]
}

# 危险XML内容处理模式
DANGEROUS_XML_HANDLING = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list 
                (_) @xml_content
            )
        ) @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(xmlParseMemory|xmlReadMemory|XML_Parse)$',
            'message': '直接解析内存中的XML内容'
        },
        {
            'func_pattern': r'^(QDomDocument::setContent|QXmlStreamReader::addData)$',
            'message': 'Qt直接解析XML内容'
        }
    ]
}


def detect_cpp_xml_entity_expansion(code, language='cpp'):
    """
    检测C++代码中XML实体扩展注入漏洞

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
    xml_parsing_calls = []  # 存储XML解析相关调用
    security_configs = []  # 存储安全配置信息
    user_input_sources = []  # 存储用户输入源
    dangerous_xml_handling = []  # 存储危险的XML处理方式

    # 第一步：收集所有XML解析相关调用
    for query_info in XML_ENTITY_EXPANSION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    xml_parsing_calls.append({
                        'type': 'xml_parsing',
                        'line': node.start_point[0] + 1,
                        'function': func_name,
                        'code_snippet': node.parent.text.decode('utf8'),
                        'node': node.parent,
                        'message': query_info.get('message', 'XML解析调用')
                    })

        except Exception as e:
            print(f"XML解析查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集安全配置信息
    try:
        query = LANGUAGES[language].query(XML_SECURITY_CONFIGURATIONS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['var_name', 'func_name']:
                current_capture['name'] = node.text.decode('utf8')
                current_capture['node'] = node
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['value', 'arg2']:
                current_capture['value'] = node.text.decode('utf8')

            elif tag in ['call', 'assignment'] and current_capture:
                # 检查是否匹配任何安全配置模式
                for pattern_info in XML_SECURITY_CONFIGURATIONS['patterns']:
                    var_pattern = pattern_info.get('var_pattern', '')
                    value_pattern = pattern_info.get('value_pattern', '')
                    func_pattern = pattern_info.get('func_pattern', '')
                    arg_pattern = pattern_info.get('arg_pattern', '')

                    match = False
                    if var_pattern and value_pattern and 'name' in current_capture and 'value' in current_capture:
                        if (re.search(var_pattern, current_capture['name'], re.IGNORECASE) and
                                re.search(value_pattern, current_capture['value'], re.IGNORECASE)):
                            match = True
                    elif func_pattern and arg_pattern and 'name' in current_capture and 'value' in current_capture:
                        if (re.search(func_pattern, current_capture['name'], re.IGNORECASE) and
                                re.search(arg_pattern, current_capture['value'], re.IGNORECASE)):
                            match = True

                    if match:
                        code_snippet = node.text.decode('utf8')
                        security_configs.append({
                            'type': 'security_config',
                            'line': current_capture['line'],
                            'name': current_capture.get('name', ''),
                            'value': current_capture.get('value', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': pattern_info.get('message', '')
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"安全配置查询错误: {e}")

    # 第三步：收集用户输入源
    try:
        query = LANGUAGES[language].query(XML_USER_INPUT_SOURCES['query'])
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
                for pattern_info in XML_USER_INPUT_SOURCES['patterns']:
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
                            'node': node,
                            'message': pattern_info.get('message', '')
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第四步：收集危险的XML处理方式
    try:
        query = LANGUAGES[language].query(DANGEROUS_XML_HANDLING['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern_info in DANGEROUS_XML_HANDLING['patterns']:
                    if re.match(pattern_info['func_pattern'], func_name, re.IGNORECASE):
                        dangerous_xml_handling.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent,
                            'message': pattern_info.get('message', '')
                        })
                        break

    except Exception as e:
        print(f"危险XML处理查询错误: {e}")

    # 第五步：分析漏洞
    for xml_call in xml_parsing_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': xml_call['line'],
            'code_snippet': xml_call['code_snippet'],
            'vulnerability_type': 'XML实体扩展注入',
            'severity': '高危',
            'function': xml_call['function']
        }

        # 情况1: 检查是否启用了危险的外部实体功能
        if has_dangerous_configuration(xml_call['node'], security_configs, root):
            vulnerability_details['message'] = f"XML解析器配置可能启用了外部实体扩展: {xml_call['function']}"
            is_vulnerable = True

        # 情况2: 检查XML内容是否来自用户输入
        elif is_xml_from_user_input(xml_call['node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户提供的XML数据被直接解析: {xml_call['function']}"
            is_vulnerable = True

        # 情况3: 检查是否使用危险的内存解析方式
        elif is_dangerous_xml_handling(xml_call, dangerous_xml_handling):
            vulnerability_details['message'] = f"使用可能不安全的XML解析方式: {xml_call['function']}"
            is_vulnerable = True

        # 情况4: 检查是否缺少明确的安全配置
        elif lacks_explicit_security_config(xml_call['node'], security_configs, root):
            vulnerability_details['message'] = f"XML解析调用缺少明确的安全配置: {xml_call['function']}"
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def has_dangerous_configuration(xml_call_node, security_configs, root_node):
    """
    检查XML解析调用是否关联了危险的安全配置
    """
    call_line = xml_call_node.start_point[0] + 1

    # 查找在调用附近的安全配置
    for config in security_configs:
        config_line = config['line']
        # 检查配置是否在调用之前或附近（+/- 20行）
        if abs(config_line - call_line) <= 20:
            dangerous_patterns = [
                r'XML_PARSE_NOENT',
                r'XML_PARSE_DTDLOAD',
                r'XML_PARSE_DTDATTR',
                r'XML_PARSE_DTDVALID',
                r'XML_FEATURE_NOENT',
                r'XML_FEATURE_DTDLOAD'
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, config['value'], re.IGNORECASE):
                    return True

    return False


def is_xml_from_user_input(xml_call_node, user_input_sources, root_node):
    """
    检查XML解析调用的参数是否来自用户输入
    """
    # 获取调用的参数
    if xml_call_node.type == 'call_expression':
        # 查找参数节点
        for child in xml_call_node.children:
            if child.type == 'argument_list':
                for arg in child.children:
                    if arg.type != '(' and arg.type != ')':
                        arg_text = arg.text.decode('utf8')

                        # 检查常见的用户输入指示符
                        user_input_indicators = [
                            r'\bargv\b',
                            r'\bstdin\b',
                            r'\bfile\b',
                            r'\bbuffer\b',
                            r'\bdata\b',
                            r'\binput\b',
                            r'\buser\b',
                            r'\bnetwork\b',
                            r'\bsocket\b',
                            r'\brecv\b'
                        ]

                        for pattern in user_input_indicators:
                            if re.search(pattern, arg_text, re.IGNORECASE):
                                return True

                        # 检查是否匹配已知的用户输入源
                        for source in user_input_sources:
                            if is_child_node(arg, source['node']) or is_data_flow_related(arg, source['node'],
                                                                                          root_node):
                                return True

    return False


def is_dangerous_xml_handling(xml_call, dangerous_xml_handling):
    """
    检查是否使用危险的XML处理方式
    """
    func_name = xml_call['function']

    # 检查是否是已知的危险函数
    dangerous_functions = [
        'xmlParseMemory',
        'xmlReadMemory',
        'XML_Parse',
        'setContent',
        'addData'
    ]

    for dangerous_func in dangerous_functions:
        if dangerous_func in func_name:
            return True

    return False


def lacks_explicit_security_config(xml_call_node, security_configs, root_node):
    """
    检查XML解析调用是否缺少明确的安全配置
    """
    call_line = xml_call_node.start_point[0] + 1

    # 查找调用附近的安全配置
    has_security_config = False
    for config in security_configs:
        config_line = config['line']
        if abs(config_line - call_line) <= 10:
            safe_patterns = [
                r'XML_PARSE_NONET',
                r'XML_PARSE_NOENT.*0',
                r'XML_FEATURE_NOENT.*0',
                r'XML_SetFeature.*0'
            ]

            for pattern in safe_patterns:
                if re.search(pattern, config['value'], re.IGNORECASE):
                    has_security_config = True
                    break

    # 如果没有找到明确的安全配置，则认为可能存在问题
    return not has_security_config


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


def is_data_flow_related(node1, node2, root_node):
    """
    简单检查两个节点是否可能在数据流上相关
    """
    # 这里实现简单的文本相关性检查
    # 实际应用中应该使用更复杂的数据流分析

    text1 = node1.text.decode('utf8')
    text2 = node2.text.decode('utf8')

    # 检查是否有共同的变量名
    variables1 = re.findall(r'\b[a-zA-Z_]\w*\b', text1)
    variables2 = re.findall(r'\b[a-zA-Z_]\w*\b', text2)

    common_vars = set(variables1) & set(variables2)
    return len(common_vars) > 0


def analyze_cpp_xml_code(code_string):
    """
    分析C++代码字符串中的XML实体扩展注入漏洞
    """
    return detect_cpp_xml_entity_expansion(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <expat.h>
#include <string>

void vulnerable_xml_parsing() {
    // 危险：启用外部实体扩展
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    xmlTextReaderSetParserProp(ctxt, XML_PARSE_NOENT, 1); // 启用外部实体

    // 从用户输入读取XML
    std::string user_xml;
    std::cin >> user_xml;
    xmlDocPtr doc = xmlParseMemory(user_xml.c_str(), user_xml.length()); // 危险

    // 使用expat解析器，未禁用外部实体
    XML_Parser parser = XML_ParserCreate(NULL);
    XML_Parse(parser, user_xml.c_str(), user_xml.length(), 1); // 危险

    // Qt XML解析，未配置安全选项
    QDomDocument dom_doc;
    dom_doc.setContent(user_xml.c_str()); // 可能危险
}

void safe_xml_parsing() {
    // 安全：明确禁用外部实体
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    xmlTextReaderSetParserProp(ctxt, XML_PARSE_NOENT, 0); // 禁用外部实体
    xmlTextReaderSetParserProp(ctxt, XML_PARSE_NONET, 1); // 禁用网络访问

    // 安全：使用受信任的XML内容
    const char* safe_xml = "<root>safe content</root>";
    xmlDocPtr doc = xmlParseMemory(safe_xml, strlen(safe_xml));

    // 安全：expat配置
    XML_Parser parser = XML_ParserCreate(NULL);
    XML_SetFeature(parser, XML_FEATURE_NOENT, 0); // 禁用外部实体
}

void mixed_xml_parsing() {
    // 混合情况：部分安全配置
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    // 缺少明确的安全配置 - 可能有问题

    std::string config_xml = getConfigFromFile("config.xml");
    xmlDocPtr doc = xmlReadMemory(config_xml.c_str(), config_xml.length(), 
                                NULL, NULL, XML_PARSE_DTDLOAD); // 危险：启用DTD加载
}

int main() {
    vulnerable_xml_parsing();
    safe_xml_parsing();
    mixed_xml_parsing();
    return 0;
}
"""

    print("=" * 60)
    print("C++ XML实体扩展注入漏洞检测")
    print("=" * 60)

    results = analyze_cpp_xml_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   函数: {vuln['function']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到XML实体扩展注入漏洞")