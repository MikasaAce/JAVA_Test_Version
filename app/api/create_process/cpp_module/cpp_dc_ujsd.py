import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义不安全的JSON反序列化漏洞模式
UNSAFE_JSON_DESERIALIZATION_VULNERABILITIES = {
    'cpp': [
        # 检测直接使用std::istringstream或类似流进行解析
        {
            'query': '''
                (call_expression
                    function: (qualified_identifier
                        scope: (namespace_identifier) @scope
                        name: (identifier) @func_name
                    )
                    arguments: (argument_list (_) @arg)
                ) @call
                (#match? @scope "^(std|json)$")
            ''',
            'func_pattern': r'^(parse|operator>>|from_json|load)$',
            'message': '直接JSON解析函数调用'
        },
        # 检测常见的JSON库危险函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(json::parse|Json::Reader::parse|Json::Value::operator=|\
                            rapidjson::Document::Parse|nlohmann::json::parse)$',
            'message': 'JSON库解析函数调用'
        },
        # 检测Boost JSON解析
        {
            'query': '''
                (call_expression
                    function: (qualified_identifier
                        scope: (namespace_identifier) @scope
                        name: (identifier) @func_name
                    )
                    arguments: (argument_list (_)* @args)
                ) @call
                (#match? @scope "^boost$")
            ''',
            'func_pattern': r'^(json::parse|property_tree::json_parser::read_json)$',
            'message': 'Boost JSON解析函数'
        },
        # 检测Qt JSON解析
        {
            'query': '''
                (call_expression
                    function: (qualified_identifier
                        scope: (namespace_identifier) @scope
                        name: (identifier) @func_name
                    )
                    arguments: (argument_list (_)* @args)
                ) @call
                (#match? @scope "^QJson$")
            ''',
            'func_pattern': r'^(QJsonDocument::fromJson|QJsonDocument::fromRawData|\
                            QJsonValue::fromVariant)$',
            'message': 'Qt JSON解析函数'
        },
        # 检测自定义反序列化函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(deserialize|fromString|fromJsonString|loadFromJson|\
                            parseJson|unmarshal|decode)$',
            'message': '自定义反序列化函数'
        },
        # 检测动态类型转换或any类型的危险使用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(any_cast|dynamic_cast|static_cast|reinterpret_cast|\
                            boost::any_cast)$',
            'message': '动态类型转换函数'
        }
    ]
}

# JSON数据源模式（可能包含用户输入）
JSON_DATA_SOURCES = {
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
            (assignment_expression
                left: (_) @left
                right: (call_expression) @right_call
            )
        ] @source
    ''',
    'patterns': [
        {
            'func_pattern': r'^(recv|recvfrom|read|fread|fgets|getline)$',
            'message': '网络或文件输入'
        },
        {
            'func_pattern': r'^(std::getline|std::cin\.get|std::cin\.read)$',
            'message': '标准输入'
        },
        {
            'func_pattern': r'^(QNetworkReply::readAll|QIODevice::readAll|\
                            QTcpSocket::readAll)$',
            'message': 'Qt网络输入'
        },
        {
            'func_pattern': r'^(curl_easy_perform|libcurl|HttpRequest|download)$',
            'message': 'HTTP客户端输入'
        },
        {
            'func_pattern': r'^(getenv|_wgetenv|GetEnvironmentVariable)$',
            'message': '环境变量输入'
        },
        {
            'func_pattern': r'^(argv|main\.args|CommandLineToArgvW)$',
            'message': '命令行参数输入'
        }
    ]
}

# 危险的对象构造模式
DANGEROUS_OBJECT_CONSTRUCTIONS = {
    'query': '''
        [
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list (_)* @args)
            )
            (constructor_declaration
                parameters: (parameter_list (_)* @params)
            )
        ] @construction
    ''',
    'patterns': [
        r'^std::function$',
        r'^boost::function$',
        r'^std::any$',
        r'^boost::any$',
        r'^std::variant$',
        r'^std::shared_ptr$',
        r'^std::unique_ptr$',
        r'^new$',
        r'^malloc$',
        r'^calloc$'
    ]
}


def detect_cpp_json_deserialization_vulnerabilities(code, language='cpp'):
    """
    检测C++代码中不安全的JSON反序列化漏洞

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
    json_parsing_calls = []  # 存储JSON解析函数调用
    json_data_sources = []  # 存储JSON数据源
    dangerous_constructions = []  # 存储危险的对象构造

    # 第一步：收集所有JSON解析函数调用
    for query_info in UNSAFE_JSON_DESERIALIZATION_VULNERABILITIES[language]:
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

                elif tag in ['arg', 'args']:
                    if 'args' not in current_capture:
                        current_capture['args'] = []
                    current_capture['args'].append({
                        'text': node.text.decode('utf8'),
                        'node': node
                    })

                elif tag in ['call'] and current_capture:
                    if 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')

                        json_parsing_calls.append({
                            'type': 'json_parse',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'arguments': current_capture.get('args', []),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"JSON解析查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有JSON数据源
    try:
        query = LANGUAGES[language].query(JSON_DATA_SOURCES['query'])
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

            elif tag == 'source' and current_capture:
                # 检查是否匹配任何数据源模式
                for pattern_info in JSON_DATA_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')

                    match = False
                    if func_pattern and 'func' in current_capture:
                        if re.match(func_pattern, current_capture['func'], re.IGNORECASE):
                            match = True

                    if match:
                        code_snippet = node.text.decode('utf8')
                        json_data_sources.append({
                            'type': 'data_source',
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
        print(f"数据源查询错误: {e}")

    # 第三步：收集危险的对象构造
    try:
        query = LANGUAGES[language].query(DANGEROUS_OBJECT_CONSTRUCTIONS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in DANGEROUS_OBJECT_CONSTRUCTIONS['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        dangerous_constructions.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break

    except Exception as e:
        print(f"危险构造查询错误: {e}")

    # 第四步：分析漏洞
    for call in json_parsing_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '不安全的JSON反序列化',
            'severity': '高危'
        }

        # 检查参数是否来自不可信源
        for arg in call.get('arguments', []):
            if is_untrusted_source(arg['node'], json_data_sources, root):
                vulnerability_details['message'] = \
                    f"不可信数据直接传递给JSON解析函数: {call['function']}"
                is_vulnerable = True
                break

        # 检查是否涉及危险的对象构造
        if not is_vulnerable and is_dangerous_construction_related(call['node'],
                                                                   dangerous_constructions, root):
            vulnerability_details['message'] = \
                f"JSON解析结果用于危险的对象构造: {call['function']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_untrusted_source(arg_node, json_data_sources, root_node):
    """
    检查参数节点是否来自不可信源
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的不可信变量名
    untrusted_vars = ['input', 'data', 'jsonstr', 'buffer', 'content',
                      'response', 'request', 'payload']
    for var in untrusted_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的数据源
    for source in json_data_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    # 检查是否包含明显的网络或文件操作
    network_patterns = [
        r'recv\(', r'recvfrom\(', r'read\(', r'fread\(', r'fgets\(',
        r'QNetwork', r'QTcp', r'curl_', r'Http', r'download'
    ]
    for pattern in network_patterns:
        if re.search(pattern, arg_text, re.IGNORECASE):
            return True

    return False


def is_dangerous_construction_related(call_node, dangerous_constructions, root_node):
    """
    检查JSON解析调用是否与危险的对象构造相关
    """
    call_text = call_node.text.decode('utf8')

    # 检查是否直接用于危险构造
    for construction in dangerous_constructions:
        construction_text = construction['code_snippet']
        if construction['function'] in call_text:
            return True

    # 检查是否在赋值给动态类型变量
    dynamic_type_patterns = [
        r'std::any\s*[a-zA-Z_]\w*\s*=',
        r'boost::any\s*[a-zA-Z_]\w*\s*=',
        r'std::variant\s*[a-zA-Z_]\w*\s*=',
        r'std::function\s*[a-zA-Z_]\w*\s*=',
        r'auto\s*[a-zA-Z_]\w*\s*='
    ]
    for pattern in dynamic_type_patterns:
        if re.search(pattern, call_text, re.IGNORECASE):
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


def analyze_cpp_json_vulnerabilities(code_string):
    """
    分析C++代码字符串中的不安全JSON反序列化漏洞
    """
    return detect_cpp_json_deserialization_vulnerabilities(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <QJsonDocument>
#include <any>

using json = nlohmann::json;
using namespace std;

void vulnerable_function(const string& input) {
    // 直接解析不可信输入 - 高危
    json data = json::parse(input); // 漏洞: 直接解析用户输入

    // Boost属性树解析
    boost::property_tree::ptree pt;
    std::istringstream iss(input);
    boost::property_tree::json_parser::read_json(iss, pt); // 漏洞

    // Qt JSON解析
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(input)); // 漏洞

    // 动态类型转换危险使用
    auto value = std::any_cast<json>(data); // 可能危险
}

void safe_function() {
    // 相对安全的做法 - 验证和过滤输入
    string trusted_input = "{\\"safe\\": \\"data\\"}";
    json data = json::parse(trusted_input); // 安全: 使用可信数据

    // 使用schema验证
    // (需要额外的验证逻辑)
}

void network_vulnerability() {
    // 从网络接收数据并直接解析 - 高危
    char buffer[1024];
    recv(socket, buffer, sizeof(buffer), 0);
    json data = json::parse(buffer); // 严重漏洞

    // 文件输入直接解析
    ifstream file("data.json");
    string content((istreambuf_iterator<char>(file)), 
                  istreambuf_iterator<char>());
    json file_data = json::parse(content); // 可能危险，如果文件不可信
}

int main() {
    string user_input;
    cout << "Enter JSON: ";
    getline(cin, user_input);

    vulnerable_function(user_input); // 传递用户输入到危险函数
    safe_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++不安全JSON反序列化漏洞检测")
    print("=" * 60)

    results = analyze_cpp_json_vulnerabilities(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到不安全的JSON反序列化漏洞")