import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在配置中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++ XML外部实体注入漏洞模式
XXE_VULNERABILITIES = {
    'cpp': [
        # 检测libxml2库的xmlParseMemory/xmlParseFile等函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(xmlParseMemory|xmlParseFile|xmlReadMemory|xmlReadFile|xmlCtxtReadMemory|xmlCtxtReadFile)$',
            'message': 'libxml2 XML解析函数调用'
        },
        # 检测TinyXML2库的解析函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(Parse|LoadFile)$',
            'class_pattern': r'^(tinyxml2::XMLDocument|XMLDocument)$',
            'message': 'TinyXML2 XML解析函数调用'
        },
        # 检测Poco XML解析器
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(parse|load)$',
            'class_pattern': r'^(Poco::XML::DOMParser|DOMParser)$',
            'message': 'Poco XML解析函数调用'
        },
        # 检测Qt XML解析器
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(setContent|read)$',
            'class_pattern': r'^(QDomDocument|QXmlStreamReader)$',
            'message': 'Qt XML解析函数调用'
        },
        # 检测Xerces-C++解析器
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(parse|parseFirst)$',
            'class_pattern': r'^(xercesc::SAXParser|DOMParser)$',
            'message': 'Xerces-C++ XML解析函数调用'
        },
        # 检测XML解析器配置相关函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(xmlCtxtUseOptions|xmlSetFeature|setFeature)$',
            'message': 'XML解析器配置函数调用'
        }
    ]
}

# XML解析器配置模式（检测是否禁用外部实体）
XML_PARSER_CONFIGURATIONS = {
    'query': '''
        [
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list 
                    (_) @arg1
                    (_) @arg2
                )
            ) @call
            (assignment_expression
                left: (_) @left
                right: (_) @right
            ) @assign
        ]
    ''',
    'patterns': [
        {
            'func_pattern': r'^(xmlSetFeature|setFeature)$',
            'arg1_pattern': r'^(XML_PARSE_NOENT|XML_PARSE_DTDLOAD|XML_PARSE_DTDATTR|XML_PARSE_DTDVALID)$',
            'arg2_pattern': r'^(1|true|TRUE)$',
            'message': '启用了危险的外部实体解析选项'
        },
        {
            'func_pattern': r'^(xmlCtxtUseOptions)$',
            'arg1_pattern': r'.*',
            'arg2_pattern': r'.*(XML_PARSE_NOENT|XML_PARSE_DTDLOAD|XML_PARSE_DTDATTR|XML_PARSE_DTDVALID).*',
            'message': '启用了危险的外部实体解析选项'
        },
        {
            'left_pattern': r'.*(feature|option).*',
            'right_pattern': r'^(1|true|TRUE|XML_PARSE_NOENT|XML_PARSE_DTDLOAD|XML_PARSE_DTDATTR|XML_PARSE_DTDVALID)$',
            'message': '启用了危险的外部实体解析选项'
        }
    ]
}

# 安全配置模式（检测是否禁用外部实体）
SECURE_CONFIGURATIONS = {
    'query': '''
        [
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list 
                    (_) @arg1
                    (_) @arg2
                )
            ) @call
            (assignment_expression
                left: (_) @left
                right: (_) @right
            ) @assign
        ]
    ''',
    'patterns': [
        {
            'func_pattern': r'^(xmlSetFeature|setFeature)$',
            'arg1_pattern': r'^(XML_PARSE_NOENT|XML_PARSE_DTDLOAD|XML_PARSE_DTDATTR|XML_PARSE_DTDVALID)$',
            'arg2_pattern': r'^(0|false|FALSE)$',
            'message': '安全配置：禁用了外部实体解析'
        },
        {
            'func_pattern': r'^(xmlCtxtUseOptions)$',
            'arg1_pattern': r'.*',
            'arg2_pattern': r'.*(XML_PARSE_NONET).*',
            'message': '安全配置：禁用了网络访问'
        }
    ]
}

# C++用户输入源模式（与命令注入相同）
USER_INPUT_SOURCES = {
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
            'func_pattern': r'^(fread|fgetc|fgets|getline)$',
            'message': '文件输入函数'
        },
        {
            'obj_pattern': r'^(std::cin|cin)$',
            'field_pattern': r'^(operator>>|get|getline|read)$',
            'message': 'C++标准输入'
        },
        {
            'func_pattern': r'^(getenv|_wgetenv)$',
            'message': '环境变量获取'
        },
        {
            'func_pattern': r'^(GetCommandLine|GetCommandLineW)$',
            'message': '命令行参数获取'
        }
    ]
}


def detect_cpp_xxe_vulnerabilities(code, language='cpp'):
    """
    检测C++代码中XML外部实体注入漏洞

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
    xml_parsing_calls = []  # 存储XML解析函数调用
    user_input_sources = []  # 存储用户输入源
    dangerous_configs = []  # 存储危险配置
    secure_configs = []  # 存储安全配置

    # 第一步：收集所有XML解析函数调用
    for query_info in XXE_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')

                    # 检查函数名是否匹配模式
                    if pattern and re.match(pattern, func_name, re.IGNORECASE):
                        current_capture['func'] = func_name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['code_snippet'] = node.parent.text.decode('utf8')

                elif tag == 'call' and current_capture:
                    # 检查类名模式（如果存在）
                    class_pattern = query_info.get('class_pattern', '')
                    if class_pattern:
                        # 查找类名上下文（需要更复杂的AST分析）
                        class_context = find_class_context(node)
                        if class_context and re.match(class_pattern, class_context, re.IGNORECASE):
                            xml_parsing_calls.append(current_capture.copy())
                    else:
                        xml_parsing_calls.append(current_capture.copy())

                    current_capture = {}

        except Exception as e:
            print(f"XML解析函数查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有用户输入源
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
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
                for pattern_info in USER_INPUT_SOURCES['patterns']:
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

    # 第三步：收集XML解析器配置
    try:
        # 收集危险配置
        query = LANGUAGES[language].query(XML_PARSER_CONFIGURATIONS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'arg1', 'arg2', 'left', 'right']:
                text = node.text.decode('utf8')
                current_capture[tag] = text
                current_capture[f'{tag}_node'] = node

            elif tag in ['call', 'assign'] and current_capture:
                # 检查是否匹配任何配置模式
                for pattern_info in XML_PARSER_CONFIGURATIONS['patterns']:
                    match = True

                    if 'func_name' in current_capture:
                        func_pattern = pattern_info.get('func_pattern', '')
                        if func_pattern and not re.match(func_pattern, current_capture['func_name'], re.IGNORECASE):
                            match = False

                    if 'arg1' in current_capture:
                        arg1_pattern = pattern_info.get('arg1_pattern', '')
                        if arg1_pattern and not re.match(arg1_pattern, current_capture['arg1'], re.IGNORECASE):
                            match = False

                    if 'arg2' in current_capture:
                        arg2_pattern = pattern_info.get('arg2_pattern', '')
                        if arg2_pattern and not re.match(arg2_pattern, current_capture['arg2'], re.IGNORECASE):
                            match = False

                    if 'left' in current_capture:
                        left_pattern = pattern_info.get('left_pattern', '')
                        if left_pattern and not re.match(left_pattern, current_capture['left'], re.IGNORECASE):
                            match = False

                    if 'right' in current_capture:
                        right_pattern = pattern_info.get('right_pattern', '')
                        if right_pattern and not re.match(right_pattern, current_capture['right'], re.IGNORECASE):
                            match = False

                    if match:
                        dangerous_configs.append({
                            'line': node.start_point[0] + 1,
                            'code_snippet': node.text.decode('utf8'),
                            'message': pattern_info['message'],
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"XML配置查询错误: {e}")

    # 第四步：收集安全配置
    try:
        query = LANGUAGES[language].query(SECURE_CONFIGURATIONS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'arg1', 'arg2', 'left', 'right']:
                text = node.text.decode('utf8')
                current_capture[tag] = text
                current_capture[f'{tag}_node'] = node

            elif tag in ['call', 'assign'] and current_capture:
                # 检查是否匹配任何安全配置模式
                for pattern_info in SECURE_CONFIGURATIONS['patterns']:
                    match = True

                    if 'func_name' in current_capture:
                        func_pattern = pattern_info.get('func_pattern', '')
                        if func_pattern and not re.match(func_pattern, current_capture['func_name'], re.IGNORECASE):
                            match = False

                    if 'arg1' in current_capture:
                        arg1_pattern = pattern_info.get('arg1_pattern', '')
                        if arg1_pattern and not re.match(arg1_pattern, current_capture['arg1'], re.IGNORECASE):
                            match = False

                    if 'arg2' in current_capture:
                        arg2_pattern = pattern_info.get('arg2_pattern', '')
                        if arg2_pattern and not re.match(arg2_pattern, current_capture['arg2'], re.IGNORECASE):
                            match = False

                    if match:
                        secure_configs.append({
                            'line': node.start_point[0] + 1,
                            'code_snippet': node.text.decode('utf8'),
                            'message': pattern_info['message'],
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"安全配置查询错误: {e}")

    # 第五步：分析漏洞
    for call in xml_parsing_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': 'XML外部实体注入',
            'severity': '高危'
        }

        # 情况1: 检查是否存在危险配置
        has_dangerous_config = any(
            is_nearby_config(call['node'], config['node'], root)
            for config in dangerous_configs
        )

        # 情况2: 检查是否缺少安全配置
        has_secure_config = any(
            is_nearby_config(call['node'], config['node'], root)
            for config in secure_configs
        )

        # 情况3: 检查是否使用用户输入作为XML源
        uses_user_input = is_user_input_related(call['node'], user_input_sources, root)

        if has_dangerous_config:
            vulnerability_details['message'] = f"XML解析函数 {call['func']} 使用了危险的外部实体配置"
            is_vulnerable = True
        elif not has_secure_config and uses_user_input:
            vulnerability_details['message'] = f"XML解析函数 {call['func']} 使用了用户输入但未禁用外部实体"
            is_vulnerable = True
        elif uses_user_input:
            vulnerability_details['message'] = f"XML解析函数 {call['func']} 使用了用户输入，需要进一步验证安全配置"
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def find_class_context(node):
    """
    查找函数调用的类上下文
    """
    # 简单的实现：查找成员函数调用
    parent = node.parent
    while parent:
        if parent.type == 'field_expression':
            # 找到 object.field 形式的调用
            object_node = parent.child_by_field_name('object')
            if object_node:
                return object_node.text.decode('utf8')
        parent = parent.parent
    return None


def is_nearby_config(call_node, config_node, root_node):
    """
    检查配置节点是否在调用节点附近（同一函数或相近位置）
    """
    # 简单的实现：检查行号是否接近
    call_line = call_node.start_point[0]
    config_line = config_node.start_point[0]

    # 如果配置在调用之前50行内，认为相关
    return 0 <= (call_line - config_line) <= 50


def is_user_input_related(node, user_input_sources, root_node):
    """
    检查节点是否与用户输入相关
    """
    node_text = node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'data', 'xml', 'buffer', 'content', 'file', 'stream']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', node_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if is_child_node(source['node'], node) or is_sibling_node(source['node'], node, root_node):
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


def is_sibling_node(node1, node2, root_node):
    """
    检查两个节点是否是兄弟节点（有共同的父节点）
    """
    return node1.parent == node2.parent


def analyze_cpp_xxe_code(code_string):
    """
    分析C++代码字符串中的XXE漏洞
    """
    return detect_cpp_xxe_vulnerabilities(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <tinyxml2.h>
#include <Poco/DOM/DOMParser.h>
#include <QDomDocument>

using namespace std;
using namespace tinyxml2;
using namespace Poco::XML;

void vulnerable_xxe_function(int argc, char* argv[]) {
    // 危险：直接解析用户输入的XML
    if (argc > 1) {
        xmlDocPtr doc = xmlParseFile(argv[1]); // XXE漏洞
        xmlFreeDoc(doc);
    }

    // 危险：启用外部实体解析
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_DTDLOAD); // 危险配置
    xmlDocPtr doc2 = xmlCtxtReadFile(ctxt, "input.xml", NULL, 0);
    xmlFreeDoc(doc2);
    xmlFreeParserCtxt(ctxt);

    // 危险：TinyXML2解析用户输入
    XMLDocument tinyDoc;
    string userInput;
    cin >> userInput;
    tinyDoc.Parse(userInput.c_str()); // 潜在XXE

    // 危险：Poco解析器
    DOMParser parser;
    parser.setFeature(XMLReader::FEATURE_EXTERNAL_GENERAL_ENTITIES, true); // 启用外部实体
    AutoPtr<Document> pocoDoc = parser.parseString("<root></root>");

    // 相对安全的做法：禁用外部实体
    xmlParserCtxtPtr safeCtxt = xmlNewParserCtxt();
    xmlCtxtUseOptions(safeCtxt, XML_PARSE_NONET); // 安全配置：禁用网络
    xmlDocPtr safeDoc = xmlCtxtReadFile(safeCtxt, "safe.xml", NULL, 0);
    xmlFreeDoc(safeDoc);
    xmlFreeParserCtxt(safeCtxt);

    // 安全：TinyXML2禁用外部实体（默认安全）
    XMLDocument safeTinyDoc;
    safeTinyDoc.Parse("<root>safe</root>"); // 安全

    // 安全：Poco解析器禁用外部实体
    DOMParser safeParser;
    safeParser.setFeature(XMLReader::FEATURE_EXTERNAL_GENERAL_ENTITIES, false); // 禁用外部实体
    AutoPtr<Document> safePocoDoc = safeParser.parseString("<root></root>");
}

void safe_xml_function() {
    // 安全：硬编码XML解析
    xmlDocPtr doc = xmlParseFile("static.xml"); // 相对安全
    xmlFreeDoc(doc);

    // 安全：明确禁用危险选项
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    xmlCtxtUseOptions(ctxt, XML_PARSE_NONET); // 安全配置
    xmlDocPtr doc2 = xmlCtxtReadFile(ctxt, "input.xml", NULL, 0);
    xmlFreeDoc(doc2);
    xmlFreeParserCtxt(ctxt);
}

int main(int argc, char* argv[]) {
    vulnerable_xxe_function(argc, argv);
    safe_xml_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++ XML外部实体注入漏洞检测")
    print("=" * 60)

    results = analyze_cpp_xxe_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到XML外部实体注入漏洞")