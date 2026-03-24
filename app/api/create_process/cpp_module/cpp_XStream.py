import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在config_path中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义XStream反序列化漏洞模式
XSTREAM_DESERIALIZATION_VULNERABILITIES = {
    'cpp': [
        # 检测XStream对象创建和fromXML调用
        {
            'query': '''
                (call_expression
                    function: (field_expression
                        object: (_) @xstream_obj
                        field: (_) @method_name
                    )
                    arguments: (argument_list (_) @xml_arg)
                ) @xstream_call
                (#match? @method_name "^(fromXML|unmarshal)$")
            ''',
            'message': 'XStream反序列化方法调用'
        },
        # 检测XStream构造函数调用
        {
            'query': '''
                (declaration
                    declarator: (init_declarator
                        declarator: (identifier) @var_name
                        value: (call_expression
                            function: (identifier) @ctor_name
                            arguments: (argument_list)? @ctor_args
                        ) @ctor_call
                    )
                ) @decl
                (#match? @ctor_name "^XStream$")
            ''',
            'message': 'XStream对象创建'
        },
        # 检测XStream对象作为参数传递
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list
                        (identifier) @xstream_arg
                    ) @func_call
                ) @call
                (#match? @xstream_arg ".*[xX][sS]tream.*")
            ''',
            'message': 'XStream对象作为参数传递'
        },
        # 检测XML数据来自不可信源
        {
            'query': '''
                (call_expression
                    function: (field_expression
                        object: (_) @xstream_obj
                        field: (_) @method_name
                    )
                    arguments: (argument_list
                        (identifier) @xml_var
                    ) @xstream_call
                ) @call
                (#match? @method_name "^(fromXML|unmarshal)$")
            ''',
            'message': 'XStream反序列化变量参数'
        },
        # 检测网络数据直接反序列化
        {
            'query': '''
                (call_expression
                    function: (field_expression
                        object: (_) @xstream_obj
                        field: (_) @method_name
                    )
                    arguments: (argument_list
                        (call_expression
                            function: (identifier) @net_func
                            arguments: (argument_list) @net_args
                        ) @net_call
                    ) @xstream_call
                ) @call
                (#match? @method_name "^(fromXML|unmarshal)$")
                (#match? @net_func "^(recv|read|fread|fgets|getline)$")
            ''',
            'message': '网络数据直接反序列化'
        }
    ]
}

# XStream相关类和方法模式
XSTREAM_RELATED_PATTERNS = {
    'query': '''
        [
            (call_expression
                function: (field_expression
                    object: (_) @obj
                    field: (identifier) @method
                )
                arguments: (argument_list) @args
            )
            (call_expression
                function: (identifier) @func
                arguments: (argument_list) @args
            )
        ] @call
    ''',
    'patterns': [
        {
            'obj_pattern': r'.*[xX][sS]tream.*',
            'method_pattern': r'^(fromXML|unmarshal|toXML|marshal|alias|omitField|allowTypes|denyTypes)$',
            'message': 'XStream核心方法调用'
        },
        {
            'func_pattern': r'^XStream$',
            'message': 'XStream构造函数调用'
        }
    ]
}

# 不可信数据源模式
UNTRUSTED_DATA_SOURCES = {
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
            'func_pattern': r'^(recv|recvfrom|recvmsg|read|fread|fgets|getline|gets|scanf|sscanf|fscanf)$',
            'message': '网络或文件输入'
        },
        {
            'func_pattern': r'^(getenv|_wgetenv)$',
            'message': '环境变量'
        },
        {
            'func_pattern': r'^(GetCommandLine|GetCommandLineW)$',
            'message': '命令行参数'
        },
        {
            'obj_pattern': r'^(std::cin|cin)$',
            'field_pattern': r'^(operator>>|get|getline|read)$',
            'message': '标准输入'
        },
        {
            'func_pattern': r'^(HTTP|Socket|CURL).*',
            'message': 'HTTP或网络库调用'
        }
    ]
}

# 安全配置模式（缓解措施）
SECURITY_CONFIGURATIONS = {
    'query': '''
        (call_expression
            function: (field_expression
                object: (_) @xstream_obj
                field: (identifier) @config_method
            )
            arguments: (argument_list) @config_args
        ) @config_call
    ''',
    'patterns': [
        {
            'config_method': r'^(setMode|addPermission|denyTypes|allowTypes|requirePermission)$',
            'message': 'XStream安全配置'
        }
    ]
}


def detect_cpp_xstream_deserialization(code, language='cpp'):
    """
    检测C++代码中XStream反序列化漏洞

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
    xstream_calls = []  # 存储XStream相关调用
    untrusted_sources = []  # 存储不可信数据源
    security_configs = []  # 存储安全配置

    # 第一步：收集所有XStream相关调用
    for query_info in XSTREAM_DESERIALIZATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['xstream_obj', 'ctor_name', 'func_name', 'method_name', 'xstream_arg', 'xml_var',
                           'net_func']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture[f'{tag}_node'] = node
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['xstream_call', 'ctor_call', 'func_call', 'net_call', 'call'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    xstream_info = {
                        'type': 'xstream_call',
                        'line': current_capture.get('line', node.start_point[0] + 1),
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info['message']
                    }

                    # 添加特定信息
                    if 'method_name' in current_capture:
                        xstream_info['method'] = current_capture['method_name']
                    if 'xstream_obj' in current_capture:
                        xstream_info['object'] = current_capture['xstream_obj']
                    if 'xml_var' in current_capture:
                        xstream_info['xml_variable'] = current_capture['xml_var']
                    if 'net_func' in current_capture:
                        xstream_info['network_function'] = current_capture['net_func']

                    xstream_calls.append(xstream_info)
                    current_capture = {}

        except Exception as e:
            print(f"XStream查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有不可信数据源
    try:
        query = LANGUAGES[language].query(UNTRUSTED_DATA_SOURCES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag == 'func_name':
                current_capture['func'] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['obj', 'field']:
                current_capture[tag] = node.text.decode('utf8')

            elif tag == 'call' and current_capture:
                # 检查是否匹配任何不可信数据源模式
                for pattern_info in UNTRUSTED_DATA_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    obj_pattern = pattern_info.get('obj_pattern', '')
                    field_pattern = pattern_info.get('field_pattern', '')

                    match = False
                    if func_pattern and 'func' in current_capture:
                        if re.match(func_pattern, current_capture['func'], re.IGNORECASE):
                            match = True
                    elif obj_pattern and field_pattern and 'obj' in current_capture and 'field' in current_capture:
                        if (re.match(obj_pattern, current_capture['obj'], re.IGNORECASE) and
                                re.match(field_pattern, current_capture['field'], re.IGNORECASE)):
                            match = True

                    if match:
                        untrusted_sources.append({
                            'type': 'untrusted_source',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'object': current_capture.get('obj', ''),
                            'field': current_capture.get('field', ''),
                            'code_snippet': node.text.decode('utf8'),
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"不可信数据源查询错误: {e}")

    # 第三步：收集安全配置
    try:
        query = LANGUAGES[language].query(SECURITY_CONFIGURATIONS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag == 'config_method':
                method_name = node.text.decode('utf8')
                for pattern_info in SECURITY_CONFIGURATIONS['patterns']:
                    if re.match(pattern_info['config_method'], method_name, re.IGNORECASE):
                        security_configs.append({
                            'line': node.start_point[0] + 1,
                            'method': method_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break

    except Exception as e:
        print(f"安全配置查询错误: {e}")

    # 第四步：分析漏洞
    for xstream_call in xstream_calls:
        is_vulnerable = True
        vulnerability_details = {
            'line': xstream_call['line'],
            'code_snippet': xstream_call['code_snippet'],
            'vulnerability_type': 'XStream反序列化漏洞',
            'severity': '高危',
            'message': xstream_call.get('message', 'XStream反序列化操作')
        }

        # 检查是否有安全配置缓解
        if has_security_configuration(xstream_call, security_configs):
            vulnerability_details['severity'] = '中危'
            vulnerability_details['message'] += ' (有安全配置但仍需验证)'

        # 检查是否使用不可信数据
        if uses_untrusted_data(xstream_call, untrusted_sources):
            vulnerability_details['message'] += ' - 使用不可信数据源'

        vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def has_security_configuration(xstream_call, security_configs):
    """
    检查XStream调用是否有安全配置
    """
    # 简单的实现：检查同一作用域内是否有安全配置
    call_line = xstream_call['line']

    for config in security_configs:
        # 如果安全配置在XStream调用之前
        if config['line'] < call_line:
            return True

    return False


def uses_untrusted_data(xstream_call, untrusted_sources):
    """
    检查XStream调用是否使用不可信数据
    """
    call_snippet = xstream_call['code_snippet'].lower()

    # 检查代码片段中是否包含常见的不可信数据模式
    untrusted_patterns = [
        r'argv\[',
        r'getenv\(',
        r'cin\s*>>',
        r'std::cin',
        r'recv\(',
        r'read\(',
        r'fread\(',
        r'fgets\(',
        r'scanf\('
    ]

    for pattern in untrusted_patterns:
        if re.search(pattern, call_snippet):
            return True

    # 检查是否直接使用不可信数据源
    for source in untrusted_sources:
        if source['node'] and is_child_node(source['node'], xstream_call['node']):
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


def analyze_cpp_code(code_string):
    """
    分析C++代码字符串中的XStream反序列化漏洞
    """
    return detect_cpp_xstream_deserialization(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>

// 假设的XStream类（实际中可能是第三方库）
class XStream {
public:
    XStream();
    template<typename T> T fromXML(const std::string& xml);
    template<typename T> void toXML(const T& obj, std::string& xml);
    void alias(const std::string& name, const std::type_info& type);
    void setMode(int mode);
    void denyTypes(const std::vector<std::string>& types);
};

void vulnerable_function(int argc, char* argv[]) {
    XStream xstream;

    // 高危：直接反序列化命令行参数
    if (argc > 1) {
        std::string xmlData = argv[1];
        auto obj = xstream.fromXML<MyObject>(xmlData); // 漏洞点
    }

    // 高危：从网络读取数据并反序列化
    std::string networkData = readFromSocket();
    auto obj2 = xstream.fromXML<MyObject>(networkData); // 漏洞点

    // 高危：从标准输入读取
    std::string userInput;
    std::cin >> userInput;
    auto obj3 = xstream.fromXML<MyObject>(userInput); // 漏洞点
}

void partially_secure_function() {
    XStream xstream;

    // 配置了一些安全措施，但仍需谨慎
    xstream.setMode(XStream::SECURE_MODE);
    xstream.denyTypes({"java.lang.Runtime", "ProcessBuilder"});

    std::string externalData = getExternalData();
    auto obj = xstream.fromXML<MyObject>(externalData); // 中危
}

void secure_function() {
    XStream xstream;

    // 完整的安全配置
    xstream.setMode(XStream::STRICT_MODE);
    xstream.denyTypes(getBlacklistedTypes());
    xstream.allowTypes(getWhitelistedTypes());

    // 只反序列化可信数据
    std::string trustedData = getTrustedInternalData();
    auto obj = xstream.fromXML<MyObject>(trustedData); // 相对安全
}

void another_vulnerable_pattern() {
    // 另一种漏洞模式：XML数据拼接
    XStream xstream;
    std::string baseXml = "<object><field>";
    std::string userValue;
    std::cin >> userValue;
    std::string fullXml = baseXml + userValue + "</field></object>";

    auto obj = xstream.fromXML<MyObject>(fullXml); // 漏洞点
}

int main(int argc, char* argv[]) {
    vulnerable_function(argc, argv);
    partially_secure_function();
    secure_function();
    another_vulnerable_pattern();
    return 0;
}
"""

    print("=" * 60)
    print("C++ XStream反序列化漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到XStream反序列化漏洞")