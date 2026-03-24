import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在配置中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++拒绝服务漏洞模式（修复后的查询语法）
DOS_VULNERABILITIES = {
    'cpp': [
        # 检测无限循环
        {
            'query': '''
                (while_statement
                    condition: (_) @condition
                ) @while_loop
            ''',
            'condition_pattern': r'^\s*(true|1)\s*$',
            'message': '无限循环可能导致拒绝服务'
        },
        {
            'query': '''
                (for_statement
                    condition: (_) @condition
                ) @for_loop
            ''',
            'condition_pattern': r'^\s*(true|1)\s*$',
            'message': '无限循环可能导致拒绝服务'
        },
        # 检测资源耗尽模式
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(malloc|calloc|new|fopen|open|CreateFile|socket|accept)$',
            'message': '资源分配函数未检查返回值或限制'
        },
        # 检测大内存分配
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(malloc|calloc|new|realloc)$',
            'message': '大内存分配可能导致资源耗尽'
        },
        # 检测大文件操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(fopen|open|CreateFile|freopen)$',
            'message': '文件操作未设置适当限制'
        },
        # 检测未限制的容器操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(push_back|insert|push|resize|reserve|append)$',
            'message': '容器操作未设置适当限制'
        },
        # 检测未处理的异常
        {
            'query': '''
                (throw_statement) @throw
            ''',
            'message': '未处理的异常可能导致程序崩溃'
        },
        # 检测空指针解引用
        {
            'query': '''
                (unary_expression
                    operator: "*"
                    argument: (identifier) @pointer
                ) @deref
            ''',
            'message': '可能的空指针解引用'
        }
    ]
}

# 用户输入源模式（简化版）
USER_INPUT_SOURCES = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
        ) @call
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
            'func_pattern': r'^(getenv|_wgetenv)$',
            'message': '环境变量获取'
        },
        {
            'func_pattern': r'^(GetCommandLine|GetCommandLineW)$',
            'message': '命令行参数获取'
        }
    ]
}

# 资源限制检查模式（简化版）
RESOURCE_LIMIT_CHECKS = {
    'query': '''
        (if_statement
            condition: (_) @condition
        ) @if
    ''',
    'patterns': [
        r'NULL|nullptr',
        r'==\s*0',
        r'!=\s*0',
        r'<\s*0',
        r'>\s*0'
    ]
}

# 递归调用检测模式
RECURSIVE_CALL_PATTERN = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
        ) @call
    '''
}


def detect_cpp_dos_vulnerabilities(code, language='cpp'):
    """
    检测C++代码中拒绝服务漏洞

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
    potential_dos_patterns = []  # 存储潜在DoS模式
    user_input_sources = []  # 存储用户输入源
    resource_checks = []  # 存储资源检查
    function_definitions = []  # 存储函数定义

    # 第一步：收集所有函数定义
    try:
        function_query = LANGUAGES[language].query('''
            (function_definition
                declarator: (function_declarator
                    declarator: (_) @func_name
                )
                body: (compound_statement) @body
            ) @function
        ''')

        captures = function_query.captures(root)
        current_func = {}
        for node, tag in captures:
            if tag == 'func_name':
                current_func['name'] = node.text.decode('utf8')
                current_func['name_node'] = node
                current_func['line'] = node.start_point[0] + 1
            elif tag == 'function':
                current_func['node'] = node
                current_func['code_snippet'] = node.text.decode('utf8')[:100] + '...'
                function_definitions.append(current_func.copy())
                current_func = {}
    except Exception as e:
        print(f"函数定义查询错误: {e}")

    # 第二步：收集所有潜在的DoS模式
    for query_info in DOS_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['func_name', 'condition', 'pointer']:
                    name = node.text.decode('utf8')

                    # 检查模式匹配
                    is_match = False
                    if 'condition_pattern' in query_info and tag == 'condition':
                        if re.match(query_info['condition_pattern'], name, re.IGNORECASE):
                            is_match = True

                    if 'func_pattern' in query_info and tag == 'func_name':
                        if re.match(query_info['func_pattern'], name, re.IGNORECASE):
                            is_match = True

                    # 如果没有特定模式要求，也认为是匹配
                    if not any(key in query_info for key in ['condition_pattern', 'func_pattern']):
                        is_match = True

                    if is_match:
                        potential_dos_patterns.append({
                            'type': 'dos_pattern',
                            'line': node.start_point[0] + 1,
                            'pattern_type': tag,
                            'name': name,
                            'node': node,
                            'code_snippet': node.parent.text.decode('utf8')[:100] + '...',
                            'message': query_info['message']
                        })

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第三步：收集所有用户输入源
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                # 检查是否匹配任何用户输入模式
                for pattern_info in USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'node': node.parent,
                            'code_snippet': node.parent.text.decode('utf8')[:100] + '...'
                        })
                        break

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第四步：收集资源检查
    try:
        query = LANGUAGES[language].query(RESOURCE_LIMIT_CHECKS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'condition':
                condition_text = node.text.decode('utf8')
                for pattern in RESOURCE_LIMIT_CHECKS['patterns']:
                    if re.search(pattern, condition_text, re.IGNORECASE):
                        resource_checks.append({
                            'line': node.start_point[0] + 1,
                            'condition': condition_text,
                            'node': node.parent,
                            'code_snippet': node.parent.text.decode('utf8')[:100] + '...'
                        })
                        break

    except Exception as e:
        print(f"资源检查查询错误: {e}")

    # 第五步：检测递归函数
    for func in function_definitions:
        try:
            query = LANGUAGES[language].query(RECURSIVE_CALL_PATTERN['query'])
            captures = query.captures(func['node'])

            for node, tag in captures:
                if tag == 'func_name' and node.text.decode('utf8') == func['name']:
                    potential_dos_patterns.append({
                        'type': 'recursive_call',
                        'line': func['line'],
                        'pattern_type': 'recursive',
                        'name': func['name'],
                        'node': func['node'],
                        'code_snippet': func['code_snippet'],
                        'message': '递归函数可能缺少适当的退出条件'
                    })
                    break
        except Exception as e:
            print(f"递归检测错误: {e}")

    # 第六步：分析漏洞
    for pattern in potential_dos_patterns:
        is_vulnerable = False
        vulnerability_details = {
            'line': pattern['line'],
            'code_snippet': pattern['code_snippet'],
            'vulnerability_type': '拒绝服务',
            'severity': '中危',
            'message': pattern['message']
        }

        # 情况1: 无限循环
        if pattern['pattern_type'] in ['condition'] and pattern['name'].strip() in ['true', '1']:
            vulnerability_details['severity'] = '高危'
            vulnerability_details['message'] = '无限循环可能导致CPU资源耗尽'
            is_vulnerable = True

        # 情况2: 资源分配未检查
        elif pattern['pattern_type'] == 'func_name' and re.match(
                r'^(malloc|calloc|new|fopen|open|CreateFile|socket|accept)$', pattern['name'], re.IGNORECASE):
            # 检查是否有相应的资源检查
            has_check = False
            for check in resource_checks:
                if is_nearby(pattern['node'], check['node'], max_distance=5):
                    has_check = True
                    break

            if not has_check:
                vulnerability_details['message'] = f'资源分配函数 {pattern["name"]} 未进行适当的错误检查'
                vulnerability_details['severity'] = '中危'
                is_vulnerable = True

        # 情况3: 基于用户输入的循环或资源分配
        elif is_user_input_related(pattern['node'], user_input_sources):
            vulnerability_details['message'] = f'基于用户输入的操作未设置适当限制: {pattern["message"]}'
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True

        # 情况4: 递归函数
        elif pattern['pattern_type'] == 'recursive':
            vulnerability_details['message'] = f'递归函数 {pattern["name"]} 可能缺少适当的退出条件'
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        # 情况5: 异常和空指针
        elif pattern['pattern_type'] in ['throw', 'pointer']:
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_user_input_related(node, user_input_sources):
    """
    检查节点是否与用户输入相关（简化版）
    """
    node_text = node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', node_text, re.IGNORECASE):
            return True

    # 检查是否在用户输入源附近
    for source in user_input_sources:
        if is_nearby(node, source['node']):
            return True

    return False


def is_nearby(node1, node2, max_distance=10):
    """
    检查两个节点是否在代码中相邻
    """
    line1 = node1.start_point[0]
    line2 = node2.start_point[0]

    return abs(line1 - line2) <= max_distance


def analyze_cpp_code(code_string):
    """
    分析C++代码字符串中的拒绝服务漏洞
    """
    return detect_cpp_dos_vulnerabilities(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdlib>
#include <vector>
#include <string>

using namespace std;

void vulnerable_dos_function(int argc, char* argv[]) {
    // 无限循环 - 高危
    while (true) {
        // 做一些工作
    }

    // 另一个无限循环
    while (1) {
        // 做一些工作
    }

    // 基于用户输入的循环 - 高危
    int n;
    cin >> n;
    for (int i = 0; i < n; i++) {
        // 处理用户输入
    }

    // 资源分配未检查 - 中危
    char* buffer = (char*)malloc(1024 * 1024 * 100); // 分配100MB
    // 没有检查malloc是否成功

    FILE* file = fopen("large_file.txt", "r");
    // 没有检查fopen是否成功

    // 递归函数可能栈溢出 - 中危
    void recursive_function(int depth) {
        if (depth > 0) {
            recursive_function(depth - 1);
        }
    }

    // 基于用户输入的递归 - 高危
    void user_input_recursion(int user_input) {
        if (user_input > 0) {
            user_input_recursion(user_input - 1);
        }
    }

    // 未处理的异常 - 中危
    throw runtime_error("Something went wrong");

    // 可能的空指针解引用 - 中危
    char* ptr = nullptr;
    if (argc > 10) {
        ptr = argv[1];
    }
    cout << *ptr; // 可能的空指针解引用
}

void safe_function() {
    // 有限循环 - 安全
    for (int i = 0; i < 10; i++) {
        // 有限的工作
    }

    // 资源分配有检查 - 安全
    char* buffer = (char*)malloc(1024);
    if (buffer == nullptr) {
        // 处理分配失败
        return;
    }

    // 文件操作有检查 - 安全
    FILE* file = fopen("file.txt", "r");
    if (file == NULL) {
        // 处理打开失败
        return;
    }
    fclose(file);
}

int main(int argc, char* argv[]) {
    vulnerable_dos_function(argc, argv);
    safe_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++拒绝服务漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到拒绝服务漏洞")