import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义XML实体扩展注入漏洞模式
XXE_VULNERABILITIES = {
    'javascript': [
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
            'pattern': r'^(DOMParser|XMLSerializer)$',
            'property_pattern': r'^(parseFromString)$',
            'message': 'DOMParser.parseFromString调用发现'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(parseXML|parseXml|loadXML|loadXml|parseFromString|parseFromXml)$',
            'message': 'XML解析函数调用'
        },
        {
            'query': '''
                (new_expression
                    constructor: (identifier) @constructor
                    arguments: (arguments) @args
                ) @new
            ''',
            'pattern': r'^(DOMParser|XMLParser|XMLReader|XMLSerializer)$',
            'message': 'XML解析器实例化'
        },
        {
            'query': '''
                (assignment_expression
                    left: (member_expression
                        object: (_) @object
                        property: (property_identifier) @property
                    )
                    right: (_) @value
                ) @assignment
            ''',
            'pattern': r'.*',
            'property_pattern': r'^(resolveExternalEntities|resolveExternals|externalEntities|loadExternalEntities)$',
            'message': 'XML解析器配置属性设置'
        },
        {
            'query': '''
                (pair
                    key: (property_identifier) @key
                    value: (_) @value
                ) @pair
            ''',
            'pattern': r'^(resolveExternalEntities|resolveExternals|externalEntities|loadExternalEntities)$',
            'message': 'XML解析器配置对象属性设置'
        }
    ]
}


def detect_js_xxe_exp_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中XML实体扩展注入漏洞

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
    xml_parsing_operations = []  # 存储所有XML解析操作
    parser_configurations = []  # 存储解析器配置

    # 第一步：收集所有XML解析操作
    for query_info in XXE_VULNERABILITIES[language][:3]:
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

                elif tag in ['call', 'new', 'args'] and current_capture:
                    if 'object' in current_capture:
                        # 获取完整的代码片段
                        code_snippet = current_capture['node'].text.decode('utf8')

                        xml_parsing_operations.append({
                            'type': 'xml_parse',
                            'line': current_capture['line'],
                            'object': current_capture.get('object', ''),
                            'property': current_capture.get('property', ''),
                            'code_snippet': code_snippet,
                            'node': current_capture['node']
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有解析器配置
    for query_info in XXE_VULNERABILITIES[language][3:]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag == 'key' or tag == 'property':
                    key_name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    prop_pattern = query_info.get('property_pattern', '')

                    if ((pattern and re.match(pattern, key_name, re.IGNORECASE)) or
                            (prop_pattern and re.match(prop_pattern, key_name, re.IGNORECASE))):
                        current_capture['key'] = key_name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['value', 'assignment'] and current_capture:
                    if 'key' in current_capture:
                        value_text = node.text.decode('utf8')

                        parser_configurations.append({
                            'line': current_capture['line'],
                            'key': current_capture['key'],
                            'value': value_text,
                            'code_snippet': current_capture['node'].text.decode('utf8'),
                            'type': 'config'
                        })
                    current_capture = {}

        except Exception as e:
            print(f"配置查询错误 {query_info.get('message')}: {e}")
            continue

    # 第三步：分析漏洞
    for xml_op in xml_parsing_operations:
        xml_line = xml_op['line']
        is_vulnerable = True
        safe_config_found = False

        # 检查是否有安全配置
        for config in parser_configurations:
            config_line = config['line']

            # 检查配置是否在合理范围内（同一函数或相近行数）
            line_diff = abs(config_line - xml_line)

            if line_diff < 50:  # 放宽范围以捕获相关配置
                if config['key'].lower() in ['resolveexternalentities', 'resolveexternals',
                                             'externalentities', 'loadexternalentities']:
                    # 检查配置值是否为假值（安全）
                    if not is_truthy_js_value(config['value']):
                        safe_config_found = True
                        break

        # 额外检查：直接检查代码片段中是否有安全配置
        code_snippet = xml_op['code_snippet'].lower()

        # 检查是否明确设置了安全配置
        if re.search(r'resolveexternalentities\s*[:=]\s*false', code_snippet, re.IGNORECASE):
            safe_config_found = True
        elif re.search(r'resolveexternals\s*[:=]\s*false', code_snippet, re.IGNORECASE):
            safe_config_found = True
        elif re.search(r'externalentities\s*[:=]\s*false', code_snippet, re.IGNORECASE):
            safe_config_found = True
        elif re.search(r'loadexternalentities\s*[:=]\s*false', code_snippet, re.IGNORECASE):
            safe_config_found = True

        # 检查是否使用了DOMParser但没有配置选项（默认不安全）
        if 'domparser' in code_snippet.lower() and 'new' in code_snippet.lower():
            # 查找是否有配置对象
            if not re.search(r'new\s+DOMParser\s*\([^)]*\)', code_snippet):
                # 没有配置参数，使用默认配置（不安全）
                safe_config_found = False
            else:
                # 有配置参数，但需要进一步分析配置内容
                config_match = re.search(r'new\s+DOMParser\s*\(\s*({[^}]*})\s*\)', code_snippet)
                if config_match:
                    config_str = config_match.group(1)
                    if ('resolveexternalentities:false' in config_str or
                            'resolveexternals:false' in config_str):
                        safe_config_found = True

        # 如果没有找到安全配置，报告漏洞
        if not safe_config_found:
            vulnerabilities.append({
                'line': xml_line,
                'message': 'XXE Vulnerability: XML parsing with external entity resolution enabled',
                'code_snippet': xml_op['code_snippet'],
                'vulnerability_type': 'XML实体扩展注入',
                'severity': '高危',
                'recommendation': '禁用外部实体解析: resolveExternalEntities: false 或使用安全的XML解析器'
            })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_truthy_js_value(value):
    """
    检查JavaScript中的真值

    Args:
        value: 参数值字符串

    Returns:
        bool: 是否为真值
    """
    if not value:
        return False

    # 清理值
    cleaned_value = re.sub(r'[\s\'"]', '', value.lower())

    truthy_values = ['true', '1', 'yes', 'on']
    falsy_values = ['false', '0', 'no', 'off', 'null', 'undefined', 'nan']

    if cleaned_value in truthy_values:
        return True
    elif cleaned_value in falsy_values:
        return False

    # 检查数字值
    try:
        num_value = float(cleaned_value)
        return bool(num_value)
    except ValueError:
        pass

    # 默认情况下，如果有值但不是明确假值，认为是真值
    return len(cleaned_value) > 0


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
const xmlString = '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>';
const xmlDoc = parser.parseFromString(xmlString, 'text/xml');

// 不安全的XML解析函数
function parseUserXML(xmlData) {
    return parser.parseFromString(xmlData, 'text/xml');
}

// 使用第三方XML解析库（假设默认不安全）
const xml2js = require('xml2js');
const parser2 = new xml2js.Parser();
parser2.parseString(xmlString, (err, result) => {
    console.log(result);
});

// 配置了但设置为true（不安全）
const unsafeParser = new DOMParser({
    resolveExternalEntities: true,
    // 其他配置...
});

// 安全配置的示例
const safeParser = new DOMParser({
    resolveExternalEntities: false,
    externalEntities: false
});

// 安全的使用方式
const safeXmlDoc = safeParser.parseFromString(xmlString, 'text/xml');

// 使用XMLSerializer（通常不需要担心XXE，但包含在检测中）
const serializer = new XMLSerializer();
const xmlOutput = serializer.serializeToString(xmlDoc);

// 其他XML相关操作
const reader = new XMLReader();
reader.read(xmlString);

// 赋值方式配置解析器
const config = {};
config.resolveExternalEntities = true; // 不安全

// 对象字面量中的配置
const options = {
    resolveExternals: true, // 不安全
    loadExternalEntities: 1 // 不安全
};
"""

    print("=" * 60)
    print("JavaScript XXE漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在XXE漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   修复建议: {vuln['recommendation']}")
    else:
        print("未检测到XXE漏洞")