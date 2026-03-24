import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++不安全的反序列化漏洞模式
UNSAFE_DESERIALIZATION_VULNERABILITIES = {
    'cpp': [
        # 检测原生C++反序列化模式
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(fread|read|recv|memcpy|memmove|bcopy|reinterpret_cast|static_cast)$',
            'message': '原始内存操作函数，可能用于不安全反序列化'
        },
        # 检测C++流操作符反序列化
        {
            'query': '''
                (binary_expression
                    left: (_) @left
                    operator: ">>"
                    right: (identifier) @var_name
                ) @bin_expr
            ''',
            'message': 'C++流提取操作符，可能用于反序列化'
        },
        # 检测对象类型转换
        {
            'query': '''
                (cast_expression
                    type: (_) @cast_type
                    value: (_) @cast_value
                ) @cast
            ''',
            'type_pattern': r'^(.*\*|void\*|char\*|unsigned char\*|byte\*)$',
            'message': '指针类型转换，可能用于不安全反序列化'
        },
        # 检测union类型的使用
        {
            'query': '''
                (union_specifier
                    name: (type_identifier)? @union_name
                ) @union
            ''',
            'message': 'union类型定义，可能用于类型双关和反序列化'
        },
        # 检测序列化库的危险函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(boost::archive|boost::serialization|cereal|protobuf|avro|thrift|msgpack|yaml|json)',
            'message': '序列化库函数调用'
        },
        # 检测指针算术运算
        {
            'query': '''
                (binary_expression
                    left: (identifier) @ptr_var
                    operator: "+" @op
                    right: (_) @offset
                ) @ptr_arithmetic
            ''',
            'message': '指针算术运算，可能用于反序列化操作'
        },
        # 检测内存分配和对象构造
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(malloc|calloc|realloc|new|operator new|placement new)$',
            'message': '内存分配函数，可能用于反序列化缓冲区'
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
            'func_pattern': r'^(recv|recvfrom|recvmsg|read|fread|ReadFile)$',
            'message': '网络/文件输入函数'
        },
        {
            'func_pattern': r'^(fgets|getline|gets|scanf|sscanf|fscanf)$',
            'message': '标准输入函数'
        },
        {
            'obj_pattern': r'^(std::cin|cin)$',
            'field_pattern': r'^(operator>>|get|getline|read)$',
            'message': 'C++标准输入'
        }
    ]
}

# 危险的内存和类型操作模式
DANGEROUS_MEMORY_OPERATIONS = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list (_)* @args)
        ) @call
    ''',
    'patterns': [
        r'^memcpy$',
        r'^memmove$',
        r'^memset$',
        r'^bcopy$',
        r'^reinterpret_cast$',
        r'^static_cast$',
        r'^const_cast$',
        r'^dynamic_cast$'
    ]
}

# 虚函数表相关模式（RTTI和虚函数调用）
VIRTUAL_FUNCTION_PATTERNS = {
    'query': '''
        [
            (call_expression
                function: (field_expression
                    object: (_) @obj
                    field: (_) @field
                )
                arguments: (argument_list) @args
            )
            (function_declarator
                declarator: (pointer_declarator) @ptr
            )
        ] @virtual_call
    ''',
    'patterns': [
        {
            'message': '虚函数调用，可能被反序列化攻击利用'
        }
    ]
}


def detect_cpp_deserialization_vulnerabilities(code, language='cpp'):
    """
    检测C++代码中不安全的反序列化漏洞

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
    deserialization_operations = []  # 存储反序列化相关操作
    user_input_sources = []  # 存储用户输入源
    dangerous_memory_ops = []  # 存储危险内存操作
    virtual_function_calls = []  # 存储虚函数调用

    # 第一步：收集所有反序列化相关操作
    for query_info in UNSAFE_DESERIALIZATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'union_name']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', query_info.get('type_pattern', ''))
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['name'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['type'] = 'function_call' if tag == 'func_name' else 'union_definition'

                elif tag in ['cast_type']:
                    type_name = node.text.decode('utf8')
                    pattern = query_info.get('type_pattern', '')
                    if pattern and re.match(pattern, type_name, re.IGNORECASE):
                        current_capture['cast_type'] = type_name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['type'] = 'cast_operation'

                elif tag in ['call', 'bin_expr', 'cast', 'union', 'ptr_arithmetic'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    operation_info = {
                        'type': current_capture.get('type', 'unknown'),
                        'line': current_capture['line'],
                        'name': current_capture.get('name', ''),
                        'cast_type': current_capture.get('cast_type', ''),
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    }

                    deserialization_operations.append(operation_info)
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
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

    # 第三步：收集危险内存操作
    try:
        query = LANGUAGES[language].query(DANGEROUS_MEMORY_OPERATIONS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in DANGEROUS_MEMORY_OPERATIONS['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        dangerous_memory_ops.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break

    except Exception as e:
        print(f"危险内存操作查询错误: {e}")

    # 第四步：收集虚函数调用
    try:
        query = LANGUAGES[language].query(VIRTUAL_FUNCTION_PATTERNS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'virtual_call':
                code_snippet = node.text.decode('utf8')
                virtual_function_calls.append({
                    'line': node.start_point[0] + 1,
                    'code_snippet': code_snippet,
                    'node': node
                })

    except Exception as e:
        print(f"虚函数调用查询错误: {e}")

    # 第五步：分析漏洞
    for operation in deserialization_operations:
        is_vulnerable = False
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': '不安全的反序列化',
            'severity': '高危'
        }

        # 情况1: 直接操作来自用户输入的数据
        if is_user_input_related(operation['node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入数据直接用于 {operation['name']} 操作"
            is_vulnerable = True

        # 情况2: 结合危险内存操作
        elif is_dangerous_memory_operation(operation['node'], dangerous_memory_ops, root):
            vulnerability_details['message'] = f"危险内存操作与 {operation['name']} 结合使用"
            is_vulnerable = True

        # 情况3: 涉及虚函数调用（可能用于vtable劫持）
        elif involves_virtual_functions(operation['node'], virtual_function_calls, root):
            vulnerability_details['message'] = f"反序列化操作涉及虚函数调用"
            is_vulnerable = True

        # 情况4: 原始类型转换和内存操作
        elif operation['type'] in ['cast_operation', 'function_call'] and is_raw_memory_operation(operation):
            vulnerability_details['message'] = f"原始内存操作: {operation['name']} {operation.get('cast_type', '')}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_user_input_related(node, user_input_sources, root_node):
    """
    检查节点是否与用户输入相关
    """
    node_text = node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['buffer', 'data', 'input', 'recv', 'read', 'network', 'socket']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', node_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == node or is_child_node(node, source['node']):
            return True

    return False


def is_dangerous_memory_operation(node, dangerous_memory_ops, root_node):
    """
    检查节点是否涉及危险内存操作
    """
    node_text = node.text.decode('utf8')

    # 检查是否直接使用了危险内存函数
    for op in dangerous_memory_ops:
        if op['function'] in node_text:
            return True

    return False


def involves_virtual_functions(node, virtual_function_calls, root_node):
    """
    检查节点是否涉及虚函数调用
    """
    node_text = node.text.decode('utf8')

    # 简单的关键字检查（实际需要更复杂的分析）
    virtual_keywords = ['virtual', 'override', 'vtable', 'vptr']
    for keyword in virtual_keywords:
        if re.search(rf'\b{keyword}\b', node_text, re.IGNORECASE):
            return True

    return False


def is_raw_memory_operation(operation):
    """
    检查是否是原始内存操作
    """
    raw_patterns = [
        r'reinterpret_cast',
        r'static_cast<.*\*>',
        r'memcpy',
        r'memmove',
        r'fread',
        r'read',
        r'recv'
    ]

    code = operation['code_snippet']
    for pattern in raw_patterns:
        if re.search(pattern, code, re.IGNORECASE):
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


def analyze_cpp_deserialization(code_string):
    """
    分析C++代码字符串中的不安全反序列化漏洞
    """
    return detect_cpp_deserialization_vulnerabilities(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <vector>

using namespace std;

class Base {
public:
    virtual void execute() {
        cout << "Base execute" << endl;
    }
    virtual ~Base() {}
};

class Derived : public Base {
public:
    void execute() override {
        cout << "Derived execute" << endl;
    }
};

void vulnerable_deserialization() {
    // 从网络接收数据并直接转换为对象 - 高危
    char network_buffer[1024];
    recv(socket_fd, network_buffer, sizeof(network_buffer), 0);

    // 危险的反序列化：直接将网络数据转换为对象指针
    Base* obj = reinterpret_cast<Base*>(network_buffer);
    obj->execute(); // 可能执行恶意代码

    // 文件读取并直接转换 - 高危
    ifstream file("data.bin", ios::binary);
    char file_buffer[1024];
    file.read(file_buffer, sizeof(file_buffer));

    Derived* derived_obj = reinterpret_cast<Derived*>(file_buffer);
    derived_obj->execute();

    // 内存拷贝到对象 - 高危
    char external_data[256];
    // 假设external_data来自不可信源
    Base another_obj;
    memcpy(&another_obj, external_data, sizeof(Base));

    // 联合体类型双关 - 可能危险
    union DataUnion {
        int integer;
        float floating;
        char bytes[4];
    } data;

    memcpy(data.bytes, network_buffer, 4);
    cout << "Integer: " << data.integer << endl;
}

void safe_deserialization() {
    // 相对安全的反序列化：验证和清洗数据
    char buffer[1024];
    recv(socket_fd, buffer, sizeof(buffer), 0);

    // 验证数据格式和内容
    if (is_valid_data(buffer, sizeof(buffer))) {
        // 使用安全的反序列化方法
        SafeData data = parse_safe_data(buffer);
        process_data(data);
    }
}

bool is_valid_data(const char* data, size_t size) {
    // 实现数据验证逻辑
    return true;
}

SafeData parse_safe_data(const char* buffer) {
    SafeData data;
    // 安全的解析逻辑
    return data;
}

int main() {
    vulnerable_deserialization();
    safe_deserialization();
    return 0;
}
"""

    print("=" * 60)
    print("C++不安全反序列化漏洞检测")
    print("=" * 60)

    results = analyze_cpp_deserialization(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到不安全反序列化漏洞")