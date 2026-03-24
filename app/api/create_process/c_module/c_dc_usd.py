import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 定义C语言动态解析代码漏洞模式
DYNAMIC_CODE_VULNERABILITIES = {
    'c': [
        # 检测system函数调用
        {
            'id': 'system_call',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(system|popen|execl|execlp|execle|execv|execvp|execvpe)$',
            'message': '系统命令执行函数调用'
        },
        # 检测eval类函数（如PHP的eval，C中可能通过动态库实现）
        {
            'id': 'eval_call',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(eval|exec|dlopen|dlsym)$',
            'message': '动态代码执行函数'
        },
        # 检测脚本解释器调用
        {
            'id': 'interpreter_call',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @first_arg)
                ) @call
            ''',
            'func_pattern': r'^(popen|fopen|fexecve|system)$',
            'message': '脚本解释器调用'
        },
        # 检测动态库加载
        {
            'id': 'dll_load',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @lib_arg)
                ) @call
            ''',
            'func_pattern': r'^(dlopen|LoadLibrary|LoadLibraryEx)$',
            'message': '动态库加载函数'
        },
        # 检测函数指针动态调用
        {
            'id': 'func_pointer_call',
            'query': '''
                (call_expression
                    function: (pointer_expression) @func_ptr
                    arguments: (argument_list) @args
                ) @call
            ''',
            'message': '函数指针动态调用'
        }
    ]
}

# 不安全反序列化漏洞模式
UNSAFE_DESERIALIZATION_VULNERABILITIES = {
    'c': [
        # 检测内存直接操作函数
        {
            'id': 'memory_operation',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(memcpy|memmove|memset|bcopy|memccpy)$',
            'message': '内存操作函数可能被用于不安全反序列化'
        },
        # 检测指针类型转换
        {
            'id': 'pointer_cast',
            'query': '''
                (cast_expression
                    type: (type_descriptor) @type_desc
                    value: (_) @value
                ) @cast
            ''',
            'message': '指针类型转换可能用于类型混淆'
        },
        # 检测联合体(union)使用
        {
            'id': 'union_usage',
            'query': '''
                (union_specifier) @union_def
            ''',
            'message': '联合体使用可能导致类型混淆'
        },
        # 检测反序列化相关的文件操作
        {
            'id': 'file_operation',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(fread|read|recv|recvfrom|recvmsg)$',
            'message': '数据读取函数可能用于反序列化'
        },
        # 检测不安全的类型转换
        {
            'id': 'unsafe_cast',
            'query': '''
                (cast_expression
                    type: (type_descriptor) @type
                    value: (identifier) @value
                ) @cast
            ''',
            'message': '不安全的类型转换'
        },
        # 检测可变参数函数
        {
            'id': 'variadic_function',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) (_)* @var_args)
                ) @call
            ''',
            'func_pattern': r'^(printf|scanf|sscanf|fscanf|vprintf|vsprintf)$',
            'message': '可变参数函数可能被利用'
        }
    ]
}

# 用户输入源模式（C语言特定）
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


def get_node_id(node):
    """获取节点的唯一标识符"""
    return f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"


def detect_c_deserialization_vulnerabilities(code, language='c'):
    """
    检测C代码中动态解析代码和不安全反序列化漏洞

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
    dynamic_code_calls = []  # 存储动态代码相关调用
    deserialization_issues = []  # 存储反序列化问题
    user_input_sources = []  # 存储用户输入源
    processed_nodes = set()  # 记录已处理的节点ID

    # 第一步：收集动态代码相关调用
    for query_info in DYNAMIC_CODE_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                node_id = get_node_id(node)
                if node_id in processed_nodes:
                    continue

                if tag in ['func_name']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['func_node'] = node

                elif tag in ['arg', 'lib_arg', 'first_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node
                    # 检查参数模式
                    arg_pattern = query_info.get('arg_pattern', '')
                    if arg_pattern and re.search(arg_pattern, current_capture['arg'], re.IGNORECASE):
                        current_capture['arg_match'] = True

                elif tag in ['func_ptr']:
                    current_capture['func_ptr'] = True
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['call', 'cast', 'union_def'] and current_capture:
                    # 完成一个完整的捕获
                    node_id = get_node_id(node)
                    if node_id in processed_nodes:
                        current_capture = {}
                        continue

                    code_snippet = node.text.decode('utf8')

                    if 'func_ptr' in current_capture:
                        dynamic_code_calls.append({
                            'id': query_info['id'],
                            'type': 'function_pointer',
                            'line': current_capture['line'],
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })
                    elif 'func' in current_capture:
                        dynamic_code_calls.append({
                            'id': query_info['id'],
                            'type': 'dynamic_code',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'arg_match': current_capture.get('arg_match', False),
                            'message': query_info.get('message', '')
                        })
                    elif tag == 'union_def':
                        dynamic_code_calls.append({
                            'id': query_info['id'],
                            'type': 'union_usage',
                            'line': node.start_point[0] + 1,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

                    processed_nodes.add(node_id)
                    current_capture = {}

        except Exception as e:
            print(f"动态代码查询错误 {query_info.get('id', 'unknown')}: {e}")
            continue

    # 第二步：收集反序列化相关问题
    for query_info in UNSAFE_DESERIALIZATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                node_id = get_node_id(node)
                if node_id in processed_nodes:
                    continue

                if tag in ['func_name']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        code_snippet = node.parent.text.decode('utf8')
                        deserialization_issues.append({
                            'id': query_info['id'],
                            'type': 'deserialization_func',
                            'line': node.start_point[0] + 1,
                            'function': name,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'message': query_info.get('message', '')
                        })
                        processed_nodes.add(get_node_id(node.parent))

                elif tag in ['cast', 'union_def']:
                    code_snippet = node.text.decode('utf8')
                    deserialization_issues.append({
                        'id': query_info['id'],
                        'type': 'deserialization_cast',
                        'line': node.start_point[0] + 1,
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    })
                    processed_nodes.add(node_id)

        except Exception as e:
            print(f"反序列化查询错误 {query_info.get('id', 'unknown')}: {e}")
            continue

    # 第三步：收集用户输入源
    try:
        query = LANGUAGES[language].query(C_USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                node_id = get_node_id(node.parent)
                if node_id in processed_nodes:
                    continue

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
                        processed_nodes.add(node_id)
                        break

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第四步：分析漏洞 - 使用去重机制
    processed_vulnerabilities = set()

    # 分析动态代码漏洞
    for call in dynamic_code_calls:
        vulnerability_key = f"{call['line']}:{call['id']}"
        if vulnerability_key in processed_vulnerabilities:
            continue

        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '动态代码执行',
            'severity': '高危',
            'rule_id': call['id']
        }

        if call['type'] == 'function_pointer':
            vulnerability_details['message'] = f"函数指针动态调用: {call['message']}"
            is_vulnerable = True
        elif call.get('arg_match', False):
            vulnerability_details['message'] = f"动态代码执行: {call['function']} 调用包含脚本解释器"
            is_vulnerable = True
        elif call.get('argument') and is_dynamic_code_indicator(call['argument']):
            vulnerability_details['message'] = f"动态代码执行: {call['function']} 调用包含动态内容"
            is_vulnerable = True
        elif call.get('arg_node') and is_user_input_related(call['arg_node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入传递给动态代码函数: {call['function']}"
            is_vulnerable = True
        elif call['type'] == 'union_usage':
            vulnerability_details['message'] = f"联合体使用可能导致类型混淆: {call['message']}"
            vulnerability_details['vulnerability_type'] = '不安全反序列化'
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)
            processed_vulnerabilities.add(vulnerability_key)

    # 分析反序列化漏洞
    for issue in deserialization_issues:
        vulnerability_key = f"{issue['line']}:{issue['id']}"
        if vulnerability_key in processed_vulnerabilities:
            continue

        is_vulnerable = False
        vulnerability_details = {
            'line': issue['line'],
            'code_snippet': issue['code_snippet'],
            'vulnerability_type': '不安全反序列化',
            'severity': '中危',
            'rule_id': issue['id']
        }

        if issue['type'] == 'deserialization_func':
            # 检查函数参数是否来自用户输入
            if has_user_input_argument(issue['node'], user_input_sources):
                vulnerability_details['message'] = f"用户输入用于不安全操作: {issue.get('function', '未知函数')}"
                is_vulnerable = True
            else:
                vulnerability_details['message'] = f"潜在的不安全操作: {issue.get('function', '未知函数')}"
                is_vulnerable = True
        elif issue['type'] == 'deserialization_cast':
            # 对于类型转换，只报告真正危险的转换
            if is_dangerous_cast(issue['code_snippet']):
                vulnerability_details['message'] = f"不安全的类型转换: {issue['message']}"
                is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)
            processed_vulnerabilities.add(vulnerability_key)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_dynamic_code_indicator(argument):
    """
    检查参数是否包含动态代码指示器
    """
    indicators = [
        r'.*\.(so|dll|dylib).*',  # 动态库文件
        r'.*(python|perl|php|ruby|bash|sh).*',  # 脚本解释器
        r'.*(eval|exec|compile).*',  # 动态执行关键词
        r'.*(\$\(|`).*',  # 命令替换
    ]

    for pattern in indicators:
        if re.search(pattern, argument, re.IGNORECASE):
            return True

    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def has_user_input_argument(func_node, user_input_sources):
    """
    检查函数调用是否包含用户输入参数
    """
    func_text = func_node.text.decode('utf8')

    # 简单的文本匹配检查
    user_input_indicators = ['argv', 'argc', 'stdin', 'getchar', 'scanf', 'fgets']
    for indicator in user_input_indicators:
        if indicator in func_text:
            return True

    return False


def is_dangerous_cast(code_snippet):
    """
    检查类型转换是否真正危险
    """
    # 安全的类型转换模式（基本类型之间的转换）
    safe_patterns = [
        r'\(int\)\s*\w+',
        r'\(float\)\s*\w+',
        r'\(double\)\s*\w+',
        r'\(char\)\s*\w+',
        r'\(long\)\s*\w+',
    ]

    # 危险的类型转换模式（涉及指针的转换）
    dangerous_patterns = [
        r'\(\w+\s*\*\)',  # 指针类型转换
        r'\(void\s*\*\)',  # void指针转换
        r'\(struct\s+\w+\s*\*\)',  # 结构体指针转换
    ]

    # 如果是安全的转换，返回False
    for pattern in safe_patterns:
        if re.search(pattern, code_snippet):
            return False

    # 如果是危险的转换，返回True
    for pattern in dangerous_patterns:
        if re.search(pattern, code_snippet):
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


def analyze_c_code(code_string):
    """
    分析C代码字符串中的动态代码和不安全反序列化漏洞
    """
    return detect_c_deserialization_vulnerabilities(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

// 危险示例
void vulnerable_functions(int argc, char* argv[]) {
    // 动态代码执行漏洞
    system("ls -la");  // 直接命令执行

    char command[100];
    sprintf(command, "echo %s", argv[1]);
    system(command);  // 命令注入

    // 动态库加载
    void* handle = dlopen("malicious.so", RTLD_LAZY);  // 动态库加载

    // 函数指针动态调用
    void (*func_ptr)() = NULL;
    func_ptr();  // 危险的函数指针调用

    // 不安全反序列化漏洞
    struct data {
        int type;
        char buffer[100];
    };

    union dangerous_union {
        int integer;
        char* pointer;
        float floating;
    };

    // 内存操作可能被利用
    char buffer[100];
    memcpy(buffer, argv[1], strlen(argv[1]));  // 可能的内存破坏

    // 类型混淆
    int* int_ptr = (int*)argv[1];  // 危险的类型转换
    printf("Value: %d\\n", *int_ptr);

    // 从网络读取数据并直接使用
    char network_data[1024];
    read(0, network_data, sizeof(network_data));  // 可能包含恶意数据
    memcpy(buffer, network_data, 100);  // 不安全的数据处理

    // 用户输入直接使用
    char user_input[100];
    scanf("%s", user_input);  // 直接用户输入
    system(user_input);  // 危险！
}

// 相对安全的示例
void safe_functions() {
    // 安全的硬编码命令
    system("echo 'Hello World'");

    // 安全的动态库加载（硬编码路径）
    void* handle = dlopen("/usr/lib/libc.so.6", RTLD_LAZY);

    // 安全的类型转换
    int x = 10;
    float y = (float)x;  // 基本类型转换是安全的

    // 安全的字符串操作
    char safe_buffer[100];
    strncpy(safe_buffer, "constant string", sizeof(safe_buffer));
}

int main(int argc, char* argv[]) {
    vulnerable_functions(argc, argv);
    safe_functions();
    return 0;
}
"""

    print("=" * 60)
    print("C语言动态代码和不安全反序列化漏洞检测")
    print("=" * 60)

    results = analyze_c_code(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   规则ID: {vuln.get('rule_id', 'N/A')}")
    else:
        print("未检测到动态代码或不安全反序列化漏洞")