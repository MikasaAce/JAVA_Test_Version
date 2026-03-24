import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# HTTP参数污染漏洞模式（优化版）
HTTP_PARAMETER_POLLUTION_VULNERABILITIES = {
    'c': [
        # 检测HTTP参数获取函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(getenv|get_query_param|get_parameter|get_post_param|get_request_param|get_cgi_param)$',
            'message': 'HTTP参数获取函数调用',
            'category': 'parameter_acquisition'
        },
        # 检测CGI环境变量访问
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (string_literal) @env_var)
                ) @call
            ''',
            'func_pattern': r'^(getenv)$',
            'env_pattern': r'^(QUERY_STRING|REQUEST_METHOD|CONTENT_LENGTH|CONTENT_TYPE|HTTP_.*)$',
            'message': 'CGI环境变量访问',
            'category': 'parameter_acquisition'
        },
        # 检测参数解析逻辑中的多次赋值
        {
            'query': '''
                (assignment_expression
                    left: (identifier) @param_var
                    right: (_) @param_value
                ) @assignment
            ''',
            'message': '参数变量赋值操作',
            'category': 'parameter_assignment'
        },
        # 检测参数验证函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @param_arg)
                ) @call
            ''',
            'func_pattern': r'^(validate_param|check_parameter|sanitize_input|filter_param)$',
            'message': '参数验证函数调用',
            'category': 'parameter_validation'
        },
        # 检测危险操作中的参数使用（合并检测）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @danger_args)
                ) @danger_call
            ''',
            'func_pattern': r'^(system|popen|exec|mysql_query|sqlite3_exec|fopen|open|printf|sprintf)$',
            'message': '危险操作中的参数使用',
            'category': 'dangerous_usage'
        },
        # 检测数组或列表形式的参数处理
        {
            'query': '''
                (subscript_expression
                    array: (identifier) @array_var
                    index: (_) @index
                ) @subscript
            ''',
            'message': '数组下标访问可能涉及参数数组',
            'category': 'parameter_processing'
        },
        # 检测循环中的参数处理
        {
            'query': '''
                (for_statement
                    init: (_) @init
                    condition: (_) @condition
                    update: (_) @update
                    body: (_) @body
                ) @for_loop
            ''',
            'message': '循环语句可能用于处理多个参数',
            'category': 'parameter_processing'
        }
    ]
}

# 参数污染特定模式
PARAM_POLLUTION_PATTERNS = {
    'parameter_variables': [
        r'.*param.*', r'.*query.*', r'.*get.*', r'.*post.*', r'.*request.*',
        r'.*input.*', r'.*arg.*', r'.*var.*', r'.*val.*', r'.*data.*'
    ],
    'multiple_assignment_indicators': [
        'for', 'while', 'loop', 'iterate', 'each', 'every'
    ]
}

# HTTP参数污染检测配置
HPP_DETECTION_CONFIG = {
    'max_parameter_assignments': 3,
    'min_parameter_length': 2,
    'dangerous_categories': {
        'sql_injection': ['mysql_query', 'sqlite3_exec', 'PQexec'],
        'command_injection': ['system', 'popen', 'exec', 'execl', 'execv'],
        'path_traversal': ['fopen', 'open', 'creat', 'mkdir'],
        'xss': ['printf', 'fprintf', 'sprintf', 'snprintf']
    }
}


class VulnerabilityTracker:
    """漏洞跟踪器，用于避免重复报告"""

    def __init__(self):
        self.reported_locations = set()
        self.reported_patterns = set()

    def is_already_reported(self, line, pattern_key):
        """检查是否已经报告过相同位置的相同模式"""
        location_key = f"{line}:{pattern_key}"
        if location_key in self.reported_locations:
            return True
        self.reported_locations.add(location_key)
        return False

    def is_pattern_reported(self, pattern_key):
        """检查是否已经报告过相同模式"""
        if pattern_key in self.reported_patterns:
            return True
        self.reported_patterns.add(pattern_key)
        return False


def detect_c_hpp_vulnerabilities(code, language='c'):
    """
    检测C代码中HTTP参数污染漏洞（优化版，避免重复）
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
    parameter_operations = []
    assignment_tracker = {}
    vulnerability_tracker = VulnerabilityTracker()

    # 第一步：收集所有参数相关操作
    for query_info in HTTP_PARAMETER_POLLUTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name']:
                    func_name = node.text.decode('utf8')
                    func_pattern = query_info.get('func_pattern', '')

                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        current_capture['func'] = func_name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['category'] = query_info.get('category', 'general')

                elif tag in ['env_var']:
                    env_var = node.text.decode('utf8').strip('"\'')
                    env_pattern = query_info.get('env_pattern', '')

                    if env_pattern and re.match(env_pattern, env_var, re.IGNORECASE):
                        current_capture['env_var'] = env_var

                elif tag in ['param_var']:
                    var_name = node.text.decode('utf8')
                    if is_parameter_variable(var_name):
                        current_capture['param_var'] = var_name

                elif tag in ['danger_args']:
                    arg_text = node.text.decode('utf8')
                    if contains_parameter_reference(arg_text):
                        current_capture['arg'] = arg_text

                elif tag in ['array_var']:
                    array_name = node.text.decode('utf8')
                    if is_parameter_variable(array_name):
                        current_capture['array_var'] = array_name

                elif tag in ['call', 'assignment', 'subscript', 'for_loop', 'danger_call'] and current_capture:
                    # 完成捕获
                    code_snippet = node.text.decode('utf8')
                    capture_data = {
                        'type': query_info.get('message', 'unknown'),
                        'category': current_capture.get('category', 'general'),
                        'line': current_capture.get('line', node.start_point[0] + 1),
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    }

                    # 添加特定信息
                    for key in ['func', 'env_var', 'param_var', 'arg', 'array_var']:
                        if key in current_capture:
                            capture_data[key] = current_capture[key]

                    if 'param_var' in current_capture:
                        track_assignment(current_capture['param_var'], assignment_tracker, node)

                    parameter_operations.append(capture_data)
                    current_capture = {}

        except Exception as e:
            print(f"参数污染检测查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：分析参数污染漏洞（优化逻辑，避免重复）
    vulnerabilities = analyze_parameter_operations(
        parameter_operations,
        assignment_tracker,
        vulnerability_tracker,
        code,
        root
    )

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_parameter_operations(operations, assignment_tracker, tracker, code, root):
    """分析参数操作，避免重复报告"""
    vulnerabilities = []
    processed_nodes = set()

    for operation in operations:
        node_id = id(operation['node'])
        if node_id in processed_nodes:
            continue
        processed_nodes.add(node_id)

        vuln = analyze_single_operation(operation, assignment_tracker, tracker, code, root)
        if vuln:
            vulnerabilities.append(vuln)

    # 添加特定模式检测
    hpp_patterns = detect_hpp_specific_patterns(code, root, assignment_tracker, tracker)
    vulnerabilities.extend(hpp_patterns)

    return vulnerabilities


def analyze_single_operation(operation, assignment_tracker, tracker, code, root):
    """分析单个操作，返回漏洞信息或None"""
    line = operation['line']
    category = operation.get('category', 'general')

    # 检查危险操作中的参数使用（合并检测）
    if category == 'dangerous_usage':
        return analyze_dangerous_usage(operation, tracker, code)

    # 检查参数获取
    elif category == 'parameter_acquisition':
        return analyze_parameter_acquisition(operation, tracker)

    # 检查参数赋值
    elif category == 'parameter_assignment':
        return analyze_parameter_assignment(operation, assignment_tracker, tracker)

    # 检查参数处理
    elif category == 'parameter_processing':
        return analyze_parameter_processing(operation, tracker, root)

    return None


def analyze_dangerous_usage(operation, tracker, code):
    """分析危险操作中的参数使用（合并检测）"""
    line = operation['line']
    func_name = operation.get('func', '')
    arg_text = operation.get('arg', '')

    # 生成唯一的模式键
    pattern_key = f"dangerous_usage_{line}_{func_name}"
    if tracker.is_already_reported(line, pattern_key):
        return None

    # 分类危险操作
    danger_type = classify_dangerous_operation(func_name, arg_text)
    if not danger_type:
        return None

    severity = get_severity_by_danger_type(danger_type)
    message = get_message_by_danger_type(danger_type, func_name)

    return {
        'line': line,
        'code_snippet': operation['code_snippet'],
        'vulnerability_type': 'HTTP参数污染',
        'severity': severity,
        'message': message,
        'danger_type': danger_type
    }


def classify_dangerous_operation(func_name, arg_text):
    """分类危险操作类型"""
    func_name_lower = func_name.lower()

    if any(sql_func in func_name_lower for sql_func in HPP_DETECTION_CONFIG['dangerous_categories']['sql_injection']):
        return 'sql_injection'
    elif any(cmd_func in func_name_lower for cmd_func in
             HPP_DETECTION_CONFIG['dangerous_categories']['command_injection']):
        return 'command_injection'
    elif any(path_func in func_name_lower for path_func in
             HPP_DETECTION_CONFIG['dangerous_categories']['path_traversal']):
        return 'path_traversal'
    elif any(xss_func in func_name_lower for xss_func in HPP_DETECTION_CONFIG['dangerous_categories']['xss']):
        return 'xss'

    return None


def get_severity_by_danger_type(danger_type):
    """根据危险类型获取严重程度"""
    severity_map = {
        'sql_injection': '严重',
        'command_injection': '严重',
        'path_traversal': '高危',
        'xss': '中危'
    }
    return severity_map.get(danger_type, '中危')


def get_message_by_danger_type(danger_type, func_name):
    """根据危险类型生成消息"""
    message_map = {
        'sql_injection': f'参数直接用于SQL查询: {func_name}',
        'command_injection': f'参数直接用于系统命令: {func_name}',
        'path_traversal': f'参数直接用于文件路径: {func_name}',
        'xss': f'参数直接用于输出: {func_name}'
    }
    return message_map.get(danger_type, f'参数用于危险操作: {func_name}')


def analyze_parameter_acquisition(operation, tracker):
    """分析参数获取操作"""
    line = operation['line']
    func_name = operation.get('func', '')
    env_var = operation.get('env_var', '')

    pattern_key = f"param_acquisition_{line}_{func_name}"
    if tracker.is_already_reported(line, pattern_key):
        return None

    if env_var == 'QUERY_STRING':
        return {
            'line': line,
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': 'HTTP参数污染',
            'severity': '高危',
            'message': f'直接访问QUERY_STRING环境变量'
        }
    elif func_name:
        return {
            'line': line,
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': 'HTTP参数污染',
            'severity': '中危',
            'message': f'HTTP参数获取: {func_name}'
        }

    return None


def analyze_parameter_assignment(operation, assignment_tracker, tracker):
    """分析参数赋值操作"""
    line = operation['line']
    param_var = operation.get('param_var', '')

    if not param_var:
        return None

    pattern_key = f"param_assignment_{line}_{param_var}"
    if tracker.is_already_reported(line, pattern_key):
        return None

    if has_multiple_assignments(param_var, assignment_tracker):
        return {
            'line': line,
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': 'HTTP参数污染',
            'severity': '高危',
            'message': f"参数变量'{param_var}'被多次赋值"
        }

    return None


def analyze_parameter_processing(operation, tracker, root):
    """分析参数处理操作"""
    line = operation['line']
    operation_type = operation['type']

    pattern_key = f"param_processing_{line}_{operation_type}"
    if tracker.is_already_reported(line, pattern_key):
        return None

    if operation_type == '循环语句可能用于处理多个参数':
        if contains_parameter_processing(operation['node'], root):
            return {
                'line': line,
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'HTTP参数污染',
                'severity': '中危',
                'message': '循环中处理多个参数'
            }

    return None


# 原有的辅助函数保持不变（稍作优化）
def is_parameter_variable(var_name):
    """检查变量名是否与参数相关"""
    patterns = PARAM_POLLUTION_PATTERNS['parameter_variables']
    for pattern in patterns:
        if re.search(pattern, var_name, re.IGNORECASE):
            return True
    return False


def track_assignment(param_var, assignment_tracker, node):
    """跟踪参数变量的赋值次数"""
    if param_var not in assignment_tracker:
        assignment_tracker[param_var] = {
            'count': 0,
            'lines': [],
            'nodes': []
        }

    assignment_tracker[param_var]['count'] += 1
    assignment_tracker[param_var]['lines'].append(node.start_point[0] + 1)
    assignment_tracker[param_var]['nodes'].append(node)


def has_multiple_assignments(param_var, assignment_tracker):
    """检查参数变量是否被多次赋值"""
    if param_var in assignment_tracker:
        return assignment_tracker[param_var]['count'] > HPP_DETECTION_CONFIG['max_parameter_assignments']
    return False


def contains_parameter_reference(text):
    """检查文本是否包含参数引用"""
    if not text:
        return False
    return is_parameter_variable(text)


def contains_parameter_processing(loop_node, root_node):
    """检查循环中是否包含参数处理逻辑"""
    loop_text = loop_node.text.decode('utf8').lower()
    param_indicators = PARAM_POLLUTION_PATTERNS['parameter_variables']

    for indicator in param_indicators:
        if re.search(indicator, loop_text):
            return True
    return False


def detect_hpp_specific_patterns(code, root_node, assignment_tracker, tracker):
    """检测HTTP参数污染特定模式（避免重复）"""
    vulnerabilities = []
    processed_params = set()

    # 检测多次赋值模式
    for param_var, tracker_info in assignment_tracker.items():
        if param_var in processed_params:
            continue
        processed_params.add(param_var)

        if tracker_info['count'] > 1 and has_conditional_assignments(tracker_info['nodes']):
            pattern_key = f"multiple_assignments_{param_var}"
            if not tracker.is_pattern_reported(pattern_key):
                vulnerabilities.append({
                    'line': tracker_info['lines'][0],
                    'code_snippet': f"参数 '{param_var}' 被多次赋值",
                    'vulnerability_type': 'HTTP参数污染',
                    'severity': '高危',
                    'message': f"参数'{param_var}'在多个位置被赋值，可能被污染"
                })

    # 检测直接使用模式（避免重复）
    direct_usage = detect_direct_parameter_usage(root_node, code, tracker)
    vulnerabilities.extend(direct_usage)

    return vulnerabilities


def has_conditional_assignments(nodes):
    """检查赋值是否发生在不同的条件分支中"""
    parent_types = set()
    for node in nodes:
        parent = node.parent
        while parent:
            if parent.type in ['if_statement', 'switch_statement', 'conditional_expression']:
                parent_types.add(parent.type)
                break
            parent = parent.parent
    return len(parent_types) > 1


def detect_direct_parameter_usage(root_node, code, tracker):
    """检测参数未经验证直接使用的情况（避免重复）"""
    vulnerabilities = []

    query_pattern = '''
        (compound_statement
            (expression_statement
                (call_expression
                    function: (identifier) @get_func
                    arguments: (argument_list (_) @get_arg)
                )
            )
            (expression_statement
                (call_expression
                    function: (identifier) @use_func
                    arguments: (argument_list (_) @use_arg)
                )
            )
        ) @block
    '''

    try:
        query = LANGUAGES['c'].query(query_pattern)
        captures = query.captures(root_node)

        get_functions = ['getenv', 'get_query_param', 'get_parameter']
        dangerous_functions = ['system', 'popen', 'mysql_query', 'fopen', 'printf']

        current_block = {}
        for node, tag in captures:
            if tag == 'get_func':
                func_name = node.text.decode('utf8')
                if func_name in get_functions:
                    current_block['get_func'] = func_name
                    current_block['get_node'] = node.parent

            elif tag == 'use_func':
                func_name = node.text.decode('utf8')
                if func_name in dangerous_functions:
                    current_block['use_func'] = func_name
                    current_block['use_node'] = node.parent

            elif tag == 'block' and current_block.get('get_func') and current_block.get('use_func'):
                line = current_block['get_node'].start_point[0] + 1
                pattern_key = f"direct_usage_{line}_{current_block['get_func']}_{current_block['use_func']}"

                if not tracker.is_already_reported(line, pattern_key) and is_direct_usage(current_block['get_node'],
                                                                                          current_block['use_node'],
                                                                                          root_node):
                    vulnerabilities.append({
                        'line': line,
                        'code_snippet': get_code_snippet(code, current_block['get_node']),
                        'vulnerability_type': 'HTTP参数污染',
                        'severity': '高危',
                        'message': f"参数获取后直接用于危险操作: {current_block['get_func']} -> {current_block['use_func']}"
                    })
                current_block = {}

    except Exception as e:
        print(f"直接参数使用检测错误: {e}")

    return vulnerabilities


def is_direct_usage(get_node, use_node, root_node):
    """检查参数获取后是否直接使用（没有验证）"""
    get_line = get_node.start_point[0]
    use_line = use_node.start_point[0]

    if use_line <= get_line:
        return False

    validation_functions = ['validate', 'check', 'sanitize', 'filter', 'verify']
    current = get_node.next_sibling

    while current and current.start_point[0] < use_line:
        if current.type == 'call_expression':
            func_text = current.text.decode('utf8').lower()
            for val_func in validation_functions:
                if val_func in func_text:
                    return False
        current = current.next_sibling

    return True


def get_code_snippet(full_code, node):
    """从完整代码中提取节点对应的代码片段"""
    start_byte = node.start_byte
    end_byte = node.end_byte
    return full_code[start_byte:end_byte]


def analyze_c_code_for_hpp(code_string):
    """分析C代码字符串中的HTTP参数污染漏洞"""
    return detect_c_hpp_vulnerabilities(code_string, 'c')


# 示例使用（保持不变）
if __name__ == "__main__":
    # 测试代码保持不变...
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>

// 存在HTTP参数污染漏洞的示例
void vulnerable_web_app(int argc, char* argv[]) {
    char* query_string = getenv("QUERY_STRING");

    char* action = NULL;
    char* id = NULL;

    if (query_string != NULL) {
        char* token = strtok(query_string, "&");
        while (token != NULL) {
            if (strncmp(token, "action=", 7) == 0) {
                action = token + 7;
            }
            token = strtok(NULL, "&");
        }

        token = strtok(query_string, "&");
        while (token != NULL) {
            if (strncmp(token, "action=", 7) == 0) {
                action = token + 7;
            }
            if (strncmp(token, "id=", 3) == 0) {
                id = token + 3;
            }
            token = strtok(NULL, "&");
        }
    }

    if (action != NULL && id != NULL) {
        char sql_query[256];
        sprintf(sql_query, "SELECT * FROM users WHERE action='%s' AND id=%s", action, id);
        mysql_query(connection, sql_query);
    }

    char* filename = getenv("FILE_NAME");
    if (filename != NULL) {
        char command[100];
        sprintf(command, "cat %s", filename);
        system(command);
    }
}

void secure_web_app() {
    // 安全代码...
}

int main(int argc, char* argv[]) {
    vulnerable_web_app(argc, argv);
    secure_web_app();
    return 0;
}
"""

    print("=" * 60)
    print("C语言HTTP参数污染漏洞检测（优化版）")
    print("=" * 60)

    results = analyze_c_code_for_hpp(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在HTTP参数污染漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到HTTP参数污染漏洞")