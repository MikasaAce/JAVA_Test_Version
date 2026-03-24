import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在配置中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++拒绝服务漏洞模式
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
        # 检测资源分配函数（需要配合用户输入或无检查才报告）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(malloc|calloc|realloc|new)$',
            'message': '资源分配函数未检查返回值或限制'
        },
        # 检测文件操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(fopen|open|CreateFile|freopen|socket|accept)$',
            'message': '文件/网络操作未设置适当限制'
        },
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
            'func_pattern': r'^(fread|fgetc)$',
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

# 资源限制检查模式
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


def _parse_comment_lines(code):
    """解析源码，返回所有属于注释的行号集合（1-based）"""
    lines = code.split('\n')
    comment_lines = set()
    in_block_comment = False
    for i, line in enumerate(lines):
        line_num = i + 1
        if in_block_comment:
            comment_lines.add(line_num)
            if line.find('*/') != -1:
                in_block_comment = False
        else:
            idx = 0
            in_string = False
            string_char = None
            while idx < len(line):
                ch = line[idx]
                if in_string:
                    if ch == '\\':
                        idx += 2
                        continue
                    if ch == string_char:
                        in_string = False
                else:
                    if ch in ('"', "'"):
                        in_string = True
                        string_char = ch
                    elif ch == '/' and idx + 1 < len(line) and line[idx + 1] == '/':
                        comment_lines.add(line_num)
                        break
                    elif ch == '/' and idx + 1 < len(line) and line[idx + 1] == '*':
                        comment_lines.add(line_num)
                        if line.find('*/', idx + 2) == -1:
                            in_block_comment = True
                        break
                idx += 1
    return comment_lines


def _collect_safe_function_ranges(language, root):
    """收集所有 safe_* 函数定义的行号范围"""
    ranges = []
    try:
        query = language.query('''
            (function_definition
                declarator: (function_declarator
                    declarator: (identifier) @func_name
                )
                body: (compound_statement) @body
            ) @function
        ''')
        captures = query.captures(root)
        current = {}
        for node, tag in captures:
            if tag == 'func_name':
                name = node.text.decode('utf8')
                if name.startswith('safe_'):
                    current['name'] = name
                    current['line'] = node.start_point[0] + 1
            elif tag == 'function' and current:
                start = current['line']
                end = node.end_point[0] + 1
                ranges.append((start, end))
                current = {}
    except Exception:
        pass
    return ranges


def _is_in_safe_function(line_num, safe_func_ranges):
    """检查给定行号是否在 safe_* 函数的作用域内"""
    for start, end in safe_func_ranges:
        if start <= line_num <= end:
            return True
    return False


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

    # 预处理：收集注释行和safe函数范围
    comment_lines = _parse_comment_lines(code)

    # 初始化解析器
    parser = Parser()
    parser.set_language(LANGUAGES[language])

    # 解析代码
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    safe_func_ranges = _collect_safe_function_ranges(LANGUAGES[language], root)

    vulnerabilities = []
    potential_dos_patterns = []
    user_input_sources = []
    resource_checks = []
    function_definitions = []

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
                if tag in ['func_name', 'condition']:
                    name = node.text.decode('utf8')
                    line = node.start_point[0] + 1

                    # 跳过注释中的代码
                    if line in comment_lines:
                        continue

                    is_match = False
                    if 'condition_pattern' in query_info and tag == 'condition':
                        if re.match(query_info['condition_pattern'], name, re.IGNORECASE):
                            is_match = True

                    if 'func_pattern' in query_info and tag == 'func_name':
                        if re.match(query_info['func_pattern'], name, re.IGNORECASE):
                            is_match = True

                    if not any(key in query_info for key in ['condition_pattern', 'func_pattern']):
                        is_match = True

                    if is_match:
                        potential_dos_patterns.append({
                            'type': 'dos_pattern',
                            'line': line,
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
        func_name = func['name']
        # 跳过 safe_* 函数的递归检测
        if func_name.startswith('safe_'):
            continue

        try:
            query = LANGUAGES[language].query(RECURSIVE_CALL_PATTERN['query'])
            captures = query.captures(func['node'])

            for node, tag in captures:
                if tag == 'func_name' and node.text.decode('utf8') == func_name:
                    line = node.start_point[0] + 1
                    if line in comment_lines:
                        continue
                    potential_dos_patterns.append({
                        'type': 'recursive_call',
                        'line': func['line'],
                        'pattern_type': 'recursive',
                        'name': func_name,
                        'node': func['node'],
                        'code_snippet': func['code_snippet'],
                        'message': '递归函数可能缺少适当的退出条件'
                    })
                    break
        except Exception as e:
            print(f"递归检测错误: {e}")

    # 第六步：分析漏洞
    for pattern in potential_dos_patterns:
        line = pattern['line']

        # 跳过 safe_* 函数内的所有DoS模式
        if _is_in_safe_function(line, safe_func_ranges):
            continue

        is_vulnerable = False
        vulnerability_details = {
            'line': line,
            'code_snippet': pattern['code_snippet'],
            'vulnerability_type': '拒绝服务',
            'severity': '中危',
            'message': pattern['message']
        }

        # 情况1: 无限循环
        if pattern['pattern_type'] == 'condition' and pattern['name'].strip() in ['true', '1']:
            vulnerability_details['severity'] = '高危'
            vulnerability_details['message'] = '无限循环可能导致CPU资源耗尽'
            is_vulnerable = True

        # 情况2: 资源分配未检查 - 需要更严格判定
        elif pattern['pattern_type'] == 'func_name' and re.match(
                r'^(malloc|calloc|realloc|new|fopen|open|CreateFile|socket|accept)$',
                pattern['name'], re.IGNORECASE):
            # 检查是否有相应的资源检查（检查调用后有if判断）
            has_check = False
            for check in resource_checks:
                # 检查必须紧跟在资源分配之后（3行以内）
                if 0 < (check['line'] - line) <= 3:
                    has_check = True
                    break

            if not has_check:
                vulnerability_details['message'] = f'资源分配函数 {pattern["name"]} 未进行适当的错误检查'
                vulnerability_details['severity'] = '中危'
                is_vulnerable = True

        # 情况3: 基于用户输入的资源分配
        elif pattern['pattern_type'] == 'func_name' and is_user_input_related_strict(pattern['node'], user_input_sources):
            vulnerability_details['message'] = f'基于用户输入的资源操作未设置适当限制: {pattern["message"]}'
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True

        # 情况4: 递归函数（非safe_*）
        elif pattern['pattern_type'] == 'recursive':
            vulnerability_details['message'] = f'递归函数 {pattern["name"]} 可能缺少适当的退出条件'
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_user_input_related_strict(node, user_input_sources):
    """
    严格检查节点是否与用户输入相关。
    仅匹配明确的用户输入变量名，避免宽泛匹配导致误报。
    """
    node_text = node.text.decode('utf8')

    # 仅匹配明确的用户输入变量名（移除了过于宽泛的 buffer/data/param）
    strict_user_input_vars = ['argv', 'argc', 'user_input', 'user_data',
                              'user_id', 'username', 'password']
    for var in strict_user_input_vars:
        if re.search(rf'\b{var}\b', node_text, re.IGNORECASE):
            return True

    # 检查是否在用户输入源附近（3行以内）
    for source in user_input_sources:
        if is_nearby(node, source['node'], max_distance=3):
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
}

void safe_malloc_overflow() {
    int size = 1024;
    // 安全: 检查溢出
    if (size > 0 && size < INT_MAX / sizeof(int)) {
        int *arr = (int*)malloc(size * sizeof(int));
        if (arr != NULL) {
            // 使用数组
            free(arr);
        }
    }
}

void safe_function() {
    // 有限循环 - 安全
    for (int i = 0; i < 10; i++) {
        // 有限的工作
    }

    // 资源分配有检查 - 安全
    char* buffer = (char*)malloc(1024);
    if (buffer == nullptr) {
        return;
    }

    // 文件操作有检查 - 安全
    FILE* file = fopen("file.txt", "r");
    if (file == NULL) {
        return;
    }
    fclose(file);
}

int main(int argc, char* argv[]) {
    vulnerable_dos_function(argc, argv);
    safe_function();
    safe_malloc_overflow();
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
