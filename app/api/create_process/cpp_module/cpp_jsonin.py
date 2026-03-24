import os
import re
import json
from tree_sitter import Language, Parser
from collections import defaultdict

# 假设language_path已经在配置中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++ JSON注入漏洞模式（优化查询，避免重叠）
JSON_INJECTION_VULNERABILITIES = {
    'cpp': [
        # 检测JSON字符串拼接操作
        {
            'query': '''
                (binary_expression
                    left: (string_literal) @left
                    operator: "+"
                    right: (_) @right
                ) @binary_expr
                (#match? @left ".*json.*|.*JSON.*|.*\\\"[^\\\"]*:[^\\\"]*\\\".*")
            ''',
            'message': 'JSON字符串字面量拼接操作'
        },
        # 检测变量拼接JSON
        {
            'query': '''
                (binary_expression
                    left: (_) @left
                    operator: "+"
                    right: (string_literal) @right
                ) @binary_expr
                (#match? @right ".*json.*|.*JSON.*|.*\\\"[^\\\"]*:[^\\\"]*\\\".*")
            ''',
            'message': '变量与JSON字符串拼接操作'
        },
        # 检测sprintf等格式化函数构建JSON
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @format_arg
                        (_)* @other_args
                    )
                ) @call
                (#match? @func_name "^(sprintf|snprintf|swprintf|vsprintf|vsnprintf)$")
                (#match? @format_arg ".*json.*|.*JSON.*|.*\\\"[^\\\"]*:[^\\\"]*%s.*")
            ''',
            'message': '使用格式化函数构建JSON字符串'
        },
        # 检测JSON库的危险使用模式
        {
            'query': '''
                (call_expression
                    function: (field_expression
                        object: (_) @obj
                        field: (identifier) @field
                    )
                    arguments: (argument_list 
                        (string_literal) @key
                        (_) @value
                    )
                ) @call
                (#match? @obj ".*(json|JSON|Json|rapidjson|RapidJSON).*")
                (#match? @field "^(AddMember|PushBack|SetString|operator\\[\\])$")
            ''',
            'message': 'JSON库成员添加操作'
        },
        # 检测字符串替换函数构建JSON
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
                (#match? @func_name "^(replace|insert|append|strcat|wcscat)$")
                (#match? @call ".*json.*|.*JSON.*")
            ''',
            'message': '使用字符串操作函数构建JSON'
        }
    ]
}

# C++用户输入源模式
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

# JSON相关函数模式
JSON_FUNCTIONS = {
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
            'func_pattern': r'^(json::parse|Json::parse|rapidjson::Document::Parse|parseJson)$',
            'message': 'JSON解析函数'
        },
        {
            'func_pattern': r'^(json::dump|Json::dump|rapidjson::Writer|stringify|to_string)$',
            'message': 'JSON序列化函数'
        },
        {
            'obj_pattern': r'^(json|Json|rapidjson)$',
            'field_pattern': r'^(parse|dump|stringify|to_string)$',
            'message': 'JSON库方法'
        }
    ]
}


def detect_cpp_json_injection(code, language='cpp'):
    """
    检测C++代码中JSON注入漏洞

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
    json_operations = []  # 存储所有JSON相关操作
    user_input_sources = []  # 存储用户输入源
    json_functions = []  # 存储JSON函数调用

    # 使用集合来跟踪已经处理过的节点，避免重复
    processed_nodes = set()

    # 第一步：收集所有JSON相关操作（避免重复）
    for query_info in JSON_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['binary_expr', 'call'] and id(node) not in processed_nodes:
                    processed_nodes.add(id(node))
                    code_snippet = node.text.decode('utf8')
                    line = node.start_point[0] + 1

                    json_operations.append({
                        'type': 'json_operation',
                        'line': line,
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info['message'],
                        'node_id': id(node)  # 用于去重
                    })

        except Exception as e:
            print(f"JSON操作查询错误 {query_info.get('message')}: {e}")
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

    # 第三步：收集JSON相关函数调用
    try:
        query = LANGUAGES[language].query(JSON_FUNCTIONS['query'])
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
                # 检查是否匹配任何JSON函数模式
                for pattern_info in JSON_FUNCTIONS['patterns']:
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
                        json_functions.append({
                            'type': 'json_function',
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
        print(f"JSON函数查询错误: {e}")

    # 第四步：分析JSON注入漏洞（使用去重机制）
    seen_vulnerabilities = set()

    for operation in json_operations:
        is_vulnerable = False
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': 'JSON注入',
            'severity': '中危',
            'message': operation['message']
        }

        # 检查操作是否涉及用户输入
        user_input_related = is_user_input_related_json(operation['node'], user_input_sources, json_functions, root)

        # 检查是否包含明显的注入模式
        injection_patterns = contains_json_injection_patterns(operation['code_snippet'])

        # 创建唯一标识符用于去重
        vuln_key = f"{operation['line']}:{operation['code_snippet'][:50]}"

        if user_input_related:
            vulnerability_details['severity'] = '高危'
            vulnerability_details['message'] += ' - 涉及用户输入'
            is_vulnerable = True
            vuln_key += ":user_input"

        elif injection_patterns:
            vulnerability_details['message'] += ' - 包含可疑模式'
            is_vulnerable = True
            vuln_key += ":injection_pattern"

        if is_vulnerable and vuln_key not in seen_vulnerabilities:
            seen_vulnerabilities.add(vuln_key)
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_user_input_related_json(operation_node, user_input_sources, json_functions, root_node):
    """
    检查JSON操作节点是否与用户输入相关
    """
    operation_text = operation_node.text.decode('utf8')

    # 检查是否包含常见的用户输入变量名
    user_input_vars = ['argv', 'input', 'data', 'param', 'user', 'request', 'query', 'cin', 'getline']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', operation_text, re.IGNORECASE):
            return True

    # 检查是否在数据流上与用户输入源相关
    for source in user_input_sources:
        if is_data_flow_related(operation_node, source['node'], root_node):
            return True

    return False


def is_data_flow_related(node1, node2, root_node, max_depth=10):
    """
    简化的数据流关系检查
    """
    # 这里实现一个简化的版本，检查两个节点是否在相同的变量使用上下文中
    node1_text = node1.text.decode('utf8')
    node2_text = node2.text.decode('utf8')

    # 提取可能的变量名
    node1_vars = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', node1_text)
    node2_vars = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', node2_text)

    # 检查是否有共同的变量
    common_vars = set(node1_vars) & set(node2_vars)
    if common_vars:
        return True

    return False


def contains_json_injection_patterns(code_snippet):
    """
    检查代码片段是否包含JSON注入的典型模式
    """
    injection_patterns = [
        # 字符串拼接模式
        r'\"\s*\+\s*[^"]+\s*\+\s*\"',
        r'\"\s*\+\s*[^"]+',
        r'[^"]+\s*\+\s*\"',

        # 格式化字符串中的变量
        r'sprintf\([^)]*%[^)]*[a-zA-Z_][a-zA-Z0-9_]*[^)]*\)',

        # JSON键值对中的变量
        r'\"[^\"]*\"\s*:\s*[a-zA-Z_][a-zA-Z0-9_]*',

        # 明显的注入特征
        r'escape|encode|sanitize',

        # 特殊字符检查
        r'[{}[\]"]',  # JSON特殊字符
    ]

    for pattern in injection_patterns:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True

    return False


def analyze_cpp_code_json_injection(code_string):
    """
    分析C++代码字符串中的JSON注入漏洞
    """
    return detect_cpp_json_injection(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <string>
#include <cstdio>
#include "json.hpp"

using json = nlohmann::json;
using namespace std;

void vulnerable_json_function(int argc, char* argv[]) {
    // 直接JSON字符串拼接 - 高危
    string userInput;
    cin >> userInput;
    string jsonStr = "{\"name\": \"" + userInput + "\", \"age\": 30}"; // JSON注入漏洞

    // sprintf构建JSON - 高危
    char buffer[100];
    sprintf(buffer, "{\"data\": \"%s\"}", argv[1]); // JSON注入漏洞

    // rapidjson危险使用
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Value nameValue;
    string userName = getenv("USER_NAME");
    nameValue.SetString(userName.c_str(), doc.GetAllocator()); // 可能危险
    doc.AddMember("name", nameValue, doc.GetAllocator());

    // 字符串替换操作
    string templateJson = "{\"user\": \"##USER##\"}";
    size_t pos = templateJson.find("##USER##");
    if (pos != string::npos) {
        templateJson.replace(pos, 8, userInput); // JSON注入漏洞
    }

    // 相对安全的做法
    json safeJson;
    safeJson["name"] = "fixed value"; // 安全
    safeJson["age"] = 30;

    // 用户输入经过转义
    string safeInput = escape_json(userInput); // 假设有转义函数
    safeJson["input"] = safeInput; // 相对安全
}

void safe_json_function() {
    // 安全的硬编码JSON
    json safeData = {
        {"name", "John"},
        {"age", 30},
        {"city", "New York"}
    };

    // 使用库函数安全构建
    string jsonStr = safeData.dump(); // 安全
}

string escape_json(const string &input) {
    // 简单的JSON转义函数
    string output;
    for (char c : input) {
        switch (c) {
            case '"': output += "\\\\\""; break;
            case '\\\\': output += "\\\\\\\\"; break;
            case '\\b': output += "\\\\b"; break;
            case '\\f': output += "\\\\f"; break;
            case '\\n': output += "\\\\n"; break;
            case '\\r': output += "\\\\r"; break;
            case '\\t': output += "\\\\t"; break;
            default: output += c; break;
        }
    }
    return output;
}

int main(int argc, char* argv[]) {
    vulnerable_json_function(argc, argv);
    safe_json_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++ JSON注入漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code_json_injection(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到JSON注入漏洞")