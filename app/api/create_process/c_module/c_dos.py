import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 拒绝服务漏洞模式
DENIAL_OF_SERVICE_VULNERABILITIES = {
    'c': [
        # 检测无限循环
        {
            'id': 'infinite_while_loop',
            'query': '''
                (while_statement
                    condition: (_) @condition
                ) @while_loop
            ''',
            'message': 'while循环可能造成无限循环'
        },
        {
            'id': 'infinite_for_loop',
            'query': '''
                (for_statement
                    condition: (_) @condition
                ) @for_loop
            ''',
            'message': 'for循环可能造成无限循环'
        },
        {
            'id': 'infinite_do_loop',
            'query': '''
                (do_statement
                    condition: (_) @condition
                ) @do_loop
            ''',
            'message': 'do-while循环可能造成无限循环'
        },
        # 检测递归函数无退出条件
        {
            'id': 'recursive_function',
            'query': '''
                (function_definition
                    declarator: (function_declarator
                        declarator: (_) @func_name
                    )
                    body: (compound_statement) @body
                ) @function
            ''',
            'message': '函数定义，检查递归调用'
        },
        # 检测资源耗尽操作
        {
            'id': 'resource_exhaustion',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(malloc|calloc|realloc|mmap|fopen|open|create)$',
            'message': '动态内存分配或文件创建函数'
        },
        {
            'id': 'unsafe_string_ops',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(strcpy|strcat|sprintf|vsprintf|gets)$',
            'message': '不安全的字符串操作函数'
        },
        # 检测大内存分配
        {
            'id': 'large_memory_allocation',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @size_arg)
                ) @call
            ''',
            'func_pattern': r'^(malloc|calloc|realloc)$',
            'message': '内存分配函数，检查分配大小'
        },
        # 检测文件操作无大小限制
        {
            'id': 'unbounded_file_ops',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(fread|read|recv|recvfrom)$',
            'message': '数据读取函数，检查缓冲区大小'
        },
        # 检测算术运算可能溢出
        {
            'id': 'arithmetic_overflow',
            'query': '''
                (binary_expression
                    left: (_) @left
                    operator: ["+" | "-" | "*" | "/" | "%"] @operator
                    right: (_) @right
                ) @arithmetic
            ''',
            'message': '算术运算可能发生溢出'
        },
        # 检测整数溢出
        {
            'id': 'integer_overflow',
            'query': '''
                (cast_expression
                    type: (type_descriptor) @type
                    value: (_) @value
                ) @cast
            ''',
            'message': '类型转换可能导致整数溢出'
        },
        # 检测死锁条件
        {
            'id': 'deadlock_risk',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(pthread_mutex_lock|pthread_mutex_trylock|sem_wait)$',
            'message': '锁操作函数，可能造成死锁'
        },
        # 检测数组越界访问
        {
            'id': 'array_out_of_bounds',
            'query': '''
                (subscript_expression
                    array: (_) @array
                    index: (_) @index
                ) @subscript
            ''',
            'message': '数组访问可能越界'
        },
        # 检测除零操作
        {
            'id': 'division_by_zero',
            'query': '''
                (binary_expression
                    operator: "/" @operator
                    right: (_) @divisor
                ) @division
            ''',
            'message': '除法运算，检查除数是否可能为零'
        },
        # 检测无超时的阻塞操作
        {
            'id': 'blocking_without_timeout',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(recv|recvfrom|accept|read|select|poll)$',
            'message': '阻塞操作函数，检查是否有超时设置'
        }
    ]
}

# 资源限制检查模式
RESOURCE_LIMIT_CHECKS = {
    'c': [
        # 检查内存分配大小验证
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @size_arg)
                ) @malloc_call
                (#match? @func_name "^(malloc|calloc|realloc)$")
                .
                (if_statement
                    condition: (binary_expression
                        left: (identifier) @var
                        operator: "=="
                        right: (null) @null
                    ) @condition
                ) @null_check
            ''',
            'message': '内存分配后检查NULL指针'
        },
        # 检查循环退出条件
        {
            'query': '''
                (while_statement
                    condition: (binary_expression
                        left: (_) @left
                        operator: ["<" | "<=" | ">" | ">=" | "!="] @op
                        right: (_) @right
                    ) @condition
                ) @while_with_condition
            ''',
            'message': '循环有明确的退出条件'
        }
    ]
}


def get_node_id(node):
    """获取节点的唯一标识符"""
    return f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"


def detect_c_dos_vulnerabilities(code, language='c'):
    """
    检测C代码中拒绝服务漏洞

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
    dos_issues = []  # 存储DoS相关问题
    safe_patterns = []  # 存储安全模式
    processed_nodes = set()  # 记录已处理的节点ID

    # 第一步：收集潜在的DoS问题
    for query_info in DENIAL_OF_SERVICE_VULNERABILITIES[language]:
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

                elif tag in ['size_arg', 'divisor', 'index', 'condition']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['while_loop', 'for_loop', 'do_loop', 'call',
                             'arithmetic', 'cast', 'subscript', 'division', 'function']:
                    # 完成一个完整的捕获
                    node_id = get_node_id(node)
                    if node_id in processed_nodes:
                        current_capture = {}
                        continue

                    code_snippet = node.text.decode('utf8')

                    issue_info = {
                        'id': query_info['id'],
                        'type': tag,
                        'line': node.start_point[0] + 1,
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    }

                    # 添加特定信息
                    if 'func' in current_capture:
                        issue_info['function'] = current_capture['func']
                    if 'size_arg' in current_capture:
                        issue_info['size_argument'] = current_capture['size_arg']
                    if 'divisor' in current_capture:
                        issue_info['divisor'] = current_capture['divisor']
                    if 'index' in current_capture:
                        issue_info['index'] = current_capture['index']
                    if 'condition' in current_capture:
                        issue_info['condition'] = current_capture['condition']

                    dos_issues.append(issue_info)
                    processed_nodes.add(node_id)
                    current_capture = {}

        except Exception as e:
            print(f"DoS查询错误 {query_info.get('id', 'unknown')}: {e}")
            continue

    # 第二步：收集安全模式（用于减少误报）
    for query_info in RESOURCE_LIMIT_CHECKS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['null_check', 'while_with_condition']:
                    safe_patterns.append({
                        'type': 'safe_pattern',
                        'line': node.start_point[0] + 1,
                        'node': node,
                        'message': query_info.get('message', '')
                    })
        except Exception as e:
            print(f"安全模式查询错误: {e}")
            continue

    # 第三步：分析漏洞 - 使用去重机制
    processed_vulnerabilities = set()

    for issue in dos_issues:
        # 使用行号+规则ID作为唯一标识
        vulnerability_key = f"{issue['line']}:{issue['id']}"
        if vulnerability_key in processed_vulnerabilities:
            continue

        is_vulnerable = False
        vulnerability_details = {
            'line': issue['line'],
            'code_snippet': issue['code_snippet'],
            'vulnerability_type': '拒绝服务',
            'severity': '中危',  # 默认严重程度
            'rule_id': issue['id']
        }

        # 根据问题类型进行具体分析
        if issue['type'] in ['while_loop', 'for_loop', 'do_loop']:
            if is_potential_infinite_loop(issue, root):
                vulnerability_details['message'] = f"潜在无限循环: {issue['message']}"
                vulnerability_details['severity'] = '高危'
                is_vulnerable = True

        elif issue['type'] == 'function':
            if is_recursive_without_exit(issue, root):
                vulnerability_details['message'] = f"递归函数可能无退出条件: {issue['message']}"
                vulnerability_details['severity'] = '高危'
                is_vulnerable = True

        elif issue['type'] == 'call' and 'function' in issue:
            func_name = issue['function']

            # 内存分配函数检查
            if func_name in ['malloc', 'calloc', 'realloc']:
                if is_large_memory_allocation(issue):
                    vulnerability_details['message'] = f"大内存分配可能导致资源耗尽: {func_name}"
                    vulnerability_details['severity'] = '高危'
                    is_vulnerable = True
                elif not has_null_check_after_malloc(issue, safe_patterns):
                    vulnerability_details['message'] = f"内存分配后未检查NULL: {func_name}"
                    is_vulnerable = True

            # 不安全字符串函数
            elif func_name in ['strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets']:
                vulnerability_details['message'] = f"不安全的字符串操作可能导致缓冲区溢出: {func_name}"
                vulnerability_details['severity'] = '高危'
                is_vulnerable = True

            # 阻塞操作检查
            elif func_name in ['recv', 'recvfrom', 'accept', 'read']:
                if not has_timeout_mechanism(issue, root):
                    vulnerability_details['message'] = f"阻塞操作无超时机制: {func_name}"
                    is_vulnerable = True

        elif issue['type'] == 'arithmetic':
            if is_potential_arithmetic_overflow(issue):
                vulnerability_details['message'] = f"算术运算可能溢出: {issue['message']}"
                is_vulnerable = True

        elif issue['type'] == 'division':
            if is_potential_division_by_zero(issue, root):
                vulnerability_details['message'] = f"除法运算可能除零: {issue['message']}"
                vulnerability_details['severity'] = '高危'
                is_vulnerable = True

        elif issue['type'] == 'subscript':
            if is_potential_array_out_of_bounds(issue, root):
                vulnerability_details['message'] = f"数组访问可能越界: {issue['message']}"
                vulnerability_details['severity'] = '高危'
                is_vulnerable = True

        if is_vulnerable and not is_false_positive(issue, safe_patterns):
            vulnerabilities.append(vulnerability_details)
            processed_vulnerabilities.add(vulnerability_key)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_potential_infinite_loop(loop_issue, root):
    """
    检查循环是否可能是无限循环
    """
    condition = loop_issue.get('condition', '')

    # 检查明显的无限循环条件
    infinite_indicators = [
        r'^\s*1\s*$',  # while(1)
        r'^\s*true\s*$',  # while(true)
        r'^\s*[1-9]\d*\s*$',  # while(非零常量)
    ]

    for pattern in infinite_indicators:
        if re.match(pattern, condition, re.IGNORECASE):
            return True

    # 检查循环条件是否包含可能不变的变量
    if re.search(r'^\s*[a-zA-Z_]\w*\s*$', condition):
        # 简单变量条件，需要进一步分析变量是否可能改变
        return True

    return False


def is_recursive_without_exit(func_issue, root):
    """
    检查递归函数是否缺乏明确的退出条件
    """
    # 简化检查：如果函数体内有递归调用但没有明显的退出条件检查
    func_body = func_issue['code_snippet']

    # 检查是否有递归调用自身
    func_name_match = re.search(r'(\w+)\s*\([^)]*\)\s*{', func_issue['code_snippet'])
    if func_name_match:
        func_name = func_name_match.group(1)
        if re.search(rf'\b{func_name}\s*\(', func_body):
            # 有递归调用，检查是否有退出条件
            exit_indicators = [
                r'if\s*\([^)]*(return|break)',
                r'return\s+[^;]*;',
                r'while\s*\([^)]*\)\s*{.*break',
            ]

            has_exit_condition = any(re.search(pattern, func_body) for pattern in exit_indicators)
            return not has_exit_condition

    return False


def is_large_memory_allocation(malloc_issue):
    """
    检查内存分配是否可能过大
    """
    size_arg = malloc_issue.get('size_argument', '')

    # 检查大常量分配
    large_constants = re.findall(r'\b(\d{7,})\b', size_arg)  # 百万级别以上的常量
    if large_constants:
        return True

    # 检查变量分配（保守判断）
    if re.search(r'[a-zA-Z_]\w*', size_arg) and not re.search(r'sizeof', size_arg):
        return True

    return False


def has_null_check_after_malloc(malloc_issue, safe_patterns):
    """
    检查内存分配后是否有NULL指针检查
    """
    line_num = malloc_issue['line']

    # 检查附近是否有安全模式
    for pattern in safe_patterns:
        if pattern['type'] == 'safe_pattern' and abs(pattern['line'] - line_num) <= 5:
            return True

    return False


def has_timeout_mechanism(blocking_issue, root):
    """
    检查阻塞操作是否有超时机制
    """
    # 简化检查：查找附近的超时相关代码
    func_body = get_function_body(blocking_issue['node'])

    timeout_indicators = [
        r'timeout',
        r'select\s*\([^)]*timeval',
        r'setsockopt.*SO_RCVTIMEO',
        r'SO_SNDTIMEO',
        r'poll\s*\([^)]*timeout',
    ]

    return any(re.search(pattern, func_body, re.IGNORECASE) for pattern in timeout_indicators)


def is_potential_arithmetic_overflow(arithmetic_issue):
    """
    检查算术运算是否可能溢出
    """
    # 简化检查：查找整数类型的大数值运算
    code = arithmetic_issue['code_snippet']

    overflow_indicators = [
        r'INT_MAX\s*[+\-*/]',
        r'UINT_MAX\s*[+\-*/]',
        r'\d{8,}\s*[*/]\s*\d+',  # 大数运算
        r'[a-zA-Z_]\w*\s*\*\s*[a-zA-Z_]\w*',  # 变量相乘
    ]

    return any(re.search(pattern, code) for pattern in overflow_indicators)


def is_potential_division_by_zero(division_issue, root):
    """
    检查除法运算是否可能除零
    """
    divisor = division_issue.get('divisor', '')

    # 检查明显的零除
    if re.match(r'^\s*0\s*$', divisor) or re.match(r'^\s*0\.0', divisor):
        return True

    # 检查变量除（保守判断）
    if re.search(r'[a-zA-Z_]\w*', divisor) and not re.search(r'[1-9]', divisor):
        return True

    return False


def is_potential_array_out_of_bounds(subscript_issue, root):
    """
    检查数组访问是否可能越界
    """
    index = subscript_issue.get('index', '')

    # 检查大索引或负索引
    if re.search(r'-?\d{5,}', index):  # 大数值索引
        return True

    # 检查变量索引（保守判断）
    if re.search(r'[a-zA-Z_]\w*', index):
        return True

    return False


def is_false_positive(issue, safe_patterns):
    """
    检查是否为误报
    """
    line_num = issue['line']

    # 检查附近是否有安全模式可以解释当前问题
    for pattern in safe_patterns:
        if abs(pattern['line'] - line_num) <= 3:
            return True

    return False


def get_function_body(node):
    """
    获取函数体内容
    """
    # 向上查找函数定义
    current = node
    while current and current.type != 'function_definition':
        current = current.parent

    if current and current.type == 'function_definition':
        # 查找函数体
        for child in current.children:
            if child.type == 'compound_statement':
                return child.text.decode('utf8')

    return ""


def analyze_c_dos_vulnerabilities(code_string):
    """
    分析C代码字符串中的拒绝服务漏洞
    """
    return detect_c_dos_vulnerabilities(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// 危险示例 - 可能导致DoS的代码
void vulnerable_dos_functions(int argc, char* argv[]) {
    // 无限循环
    while(1) {  // 明显的无限循环
        printf("Running...\\n");
    }

    // 潜在无限循环
    int flag = 1;
    while(flag) {  // 变量控制，可能无限循环
        // 缺少flag修改
    }

    // 大内存分配
    char* huge_buffer = malloc(1000000000);  // 1GB分配
    if (huge_buffer == NULL) {
        // 虽然有检查，但分配过大
        printf("Allocation failed\\n");
    }

    // 不安全的字符串操作
    char buffer[100];
    strcpy(buffer, argv[1]);  // 可能缓冲区溢出

    // 除零风险
    int divisor = atoi(argv[2]);
    int result = 100 / divisor;  // 可能除零

    // 数组越界
    int array[10];
    for(int i = 0; i <= 10; i++) {  // 越界访问
        array[i] = i;
    }

    // 算术溢出
    int large_num = 2000000000;
    int sum = large_num + large_num;  // 整数溢出

    // 无超时的阻塞操作
    char data[1024];
    recv(0, data, sizeof(data), 0);  // 无超时设置

    // 死锁风险
    pthread_mutex_t mutex;
    pthread_mutex_lock(&mutex);
    pthread_mutex_lock(&mutex);  // 重复加锁
}

// 递归函数无退出条件
void recursive_function(int n) {
    printf("n = %d\\n", n);
    recursive_function(n + 1);  // 无限递归
}

// 相对安全的示例
void safe_functions() {
    // 有限循环
    for(int i = 0; i < 100; i++) {
        printf("Safe loop\\n");
    }

    // 合理的内存分配
    char* buffer = malloc(1024);
    if (buffer == NULL) {
        return;  // 正确检查NULL
    }
    free(buffer);

    // 安全的字符串操作
    char safe_buffer[100];
    strncpy(safe_buffer, "constant", sizeof(safe_buffer));

    // 除法安全检查
    int divisor = 5;
    if (divisor != 0) {
        int result = 100 / divisor;
    }

    // 数组边界检查
    int array[10];
    for(int i = 0; i < 10; i++) {
        array[i] = i;
    }
}

int main(int argc, char* argv[]) {
    vulnerable_dos_functions(argc, argv);
    safe_functions();
    return 0;
}
"""

    print("=" * 60)
    print("C语言拒绝服务漏洞检测")
    print("=" * 60)

    results = analyze_c_dos_vulnerabilities(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在拒绝服务漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   规则ID: {vuln.get('rule_id', 'N/A')}")
    else:
        print("未检测到拒绝服务漏洞")