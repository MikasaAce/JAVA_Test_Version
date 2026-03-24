import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 设置操纵漏洞模式
SETTINGS_MANIPULATION_VULNERABILITIES = {
    'c': [
        # 检测环境变量操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(putenv|setenv|unsetenv|clearenv)$',
            'message': '环境变量设置函数',
            'priority': 1
        },
        # 检测文件权限设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(chmod|fchmod|chown|fchown|lchown|fchmodat)$',
            'message': '文件权限设置函数',
            'priority': 1
        },
        # 检测进程权限设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(setuid|seteuid|setgid|setegid|setreuid|setregid|setresuid|setresgid)$',
            'message': '进程权限设置函数',
            'priority': 1
        },
        # 检测系统配置操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(sysctl|system|ulimit)$',
            'message': '系统配置操作函数',
            'priority': 1
        },
        # 检测信号处理设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(signal|sigaction|sigprocmask|pthread_sigmask)$',
            'message': '信号处理设置函数',
            'priority': 2
        },
        # 检测资源限制设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(setrlimit|getrlimit|prlimit)$',
            'message': '资源限制设置函数',
            'priority': 2
        },
        # 检测路径操作相关函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(chdir|fchdir|mkdir|rmdir|rename|remove|unlink)$',
            'message': '路径和目录操作函数',
            'priority': 2
        },
        # 检测时间设置函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(settimeofday|adjtimex|clock_settime|stime)$',
            'message': '系统时间设置函数',
            'priority': 2
        },
        # 检测网络配置操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(ioctl|setsockopt|bind|listen)$',
            'message': '网络配置操作函数',
            'priority': 2
        }
    ]
}

# 危险配置模式
DANGEROUS_CONFIG_PATTERNS = {
    'c': [
        # 检测硬编码的敏感路径
        {
            'query': '''
                (string_literal) @string_lit
            ''',
            'pattern': r'"(/etc/passwd|/etc/shadow|/proc/|/sys/|/dev/|\.\./|~/|/root/)"',
            'message': '硬编码敏感路径'
        },
        # 检测宽权限设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) 
                        (number_literal) @mode_value
                    )
                ) @call
            ''',
            'func_pattern': r'^(chmod|fchmod)$',
            'mode_pattern': r'^(0?777|0?666|0?7777|0?6666)$',
            'message': '过度宽松的文件权限设置'
        },
        # 检测危险的UID/GID设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (number_literal) @uid_value
                    )
                ) @call
            ''',
            'func_pattern': r'^(setuid|seteuid|setgid|setegid)$',
            'uid_pattern': r'^0$',
            'message': '设置为root权限'
        },
        # 检测环境变量中的关键变量操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string_literal) @env_var
                    )
                ) @call
            ''',
            'func_pattern': r'^(putenv|setenv)$',
            'env_pattern': r'"(PATH|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB)"',
            'message': '关键环境变量设置'
        }
    ]
}

# 用户输入源模式
SETTING_USER_INPUT_SOURCES = {
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
            'func_pattern': r'^(main)$',
            'arg_index': 1,
            'message': '命令行参数'
        }
    ]
}


def get_node_id(node):
    """
    获取节点的唯一标识符（行号+起始位置）
    """
    return f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"


def detect_c_setting_manipulation(code, language='c'):
    """
    检测C代码中的设置操纵漏洞

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
    setting_operations = []  # 存储设置操作相关调用
    dangerous_configs = []  # 存储危险配置
    user_input_sources = []  # 存储用户输入源
    processed_node_ids = set()  # 记录已处理的节点ID，避免重复

    # 第一步：收集设置操作相关调用
    for query_info in SETTINGS_MANIPULATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')

                    if pattern and re.match(pattern, func_name, re.IGNORECASE):
                        # 检查是否已经处理过这个节点
                        node_id = get_node_id(node.parent)
                        if node_id in processed_node_ids:
                            continue

                        code_snippet = node.parent.text.decode('utf8')
                        setting_operations.append({
                            'type': 'setting_operation',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'node_id': node_id,
                            'message': query_info.get('message', ''),
                            'priority': query_info.get('priority', 1)
                        })
                        processed_node_ids.add(node_id)

        except Exception as e:
            print(f"设置操作查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集危险配置模式
    for query_info in DANGEROUS_CONFIG_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        # 检查是否已经处理过这个节点
                        node_id = get_node_id(node.parent)
                        if node_id in processed_node_ids:
                            continue

                        current_capture['func'] = func_name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['node_id'] = node_id

                elif tag == 'mode_value' and 'func' in current_capture:
                    mode_value = node.text.decode('utf8')
                    mode_pattern = query_info.get('mode_pattern', '')
                    if mode_pattern and re.match(mode_pattern, mode_value):
                        current_capture['mode'] = mode_value
                        current_capture['mode_node'] = node

                elif tag == 'uid_value' and 'func' in current_capture:
                    uid_value = node.text.decode('utf8')
                    uid_pattern = query_info.get('uid_pattern', '')
                    if uid_pattern and re.match(uid_pattern, uid_value):
                        current_capture['uid'] = uid_value
                        current_capture['uid_node'] = node

                elif tag == 'env_var' and 'func' in current_capture:
                    env_var = node.text.decode('utf8')
                    env_pattern = query_info.get('env_pattern', '')
                    if env_pattern and re.search(env_pattern, env_var, re.IGNORECASE):
                        current_capture['env'] = env_var
                        current_capture['env_node'] = node

                elif tag == 'string_lit':
                    string_content = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, string_content, re.IGNORECASE):
                        # 检查是否在排除的函数调用中
                        parent_call = find_parent_call_expression(node)
                        if parent_call:
                            parent_id = get_node_id(parent_call)
                            if parent_id in processed_node_ids:
                                continue

                        node_id = get_node_id(node)
                        if node_id in processed_node_ids:
                            continue

                        dangerous_configs.append({
                            'type': 'dangerous_string',
                            'line': node.start_point[0] + 1,
                            'content': string_content,
                            'node': node,
                            'node_id': node_id,
                            'message': query_info.get('message', ''),
                            'code_snippet': string_content
                        })
                        processed_node_ids.add(node_id)

                elif tag == 'call' and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = current_capture['node'].text.decode('utf8')

                    config_info = {
                        'type': 'dangerous_config',
                        'line': current_capture['node'].start_point[0] + 1,
                        'function': current_capture['func'],
                        'code_snippet': code_snippet,
                        'node': current_capture['node'],
                        'node_id': current_capture['node_id'],
                        'message': query_info.get('message', '')
                    }

                    if 'mode' in current_capture:
                        config_info['mode'] = current_capture['mode']
                    if 'uid' in current_capture:
                        config_info['uid'] = current_capture['uid']
                    if 'env' in current_capture:
                        config_info['env'] = current_capture['env']

                    dangerous_configs.append(config_info)
                    processed_node_ids.add(current_capture['node_id'])
                    current_capture = {}

        except Exception as e:
            print(f"危险配置查询错误 {query_info.get('message')}: {e}")
            continue

    # 第三步：收集用户输入源
    try:
        query = LANGUAGES[language].query(SETTING_USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                # 检查是否匹配任何用户输入模式
                for pattern_info in SETTING_USER_INPUT_SOURCES['patterns']:
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
                        break

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第四步：分析设置操纵漏洞 - 避免重复报告
    processed_lines = set()  # 记录已处理的行号

    # 优先分析危险配置（更具体的检测）
    for config in dangerous_configs:
        line_key = f"{config['line']}_{config.get('function', '')}"
        if line_key in processed_lines:
            continue

        vulnerability_details = {
            'line': config['line'],
            'code_snippet': config.get('code_snippet', config.get('content', 'N/A')),
            'vulnerability_type': '危险配置',
            'severity': '中危'
        }

        if config['type'] == 'dangerous_string':
            vulnerability_details['message'] = f"硬编码敏感路径: {config['content']}"
        elif config['type'] == 'dangerous_config':
            if 'mode' in config:
                vulnerability_details['message'] = f"过度宽松的文件权限设置: {config['function']} {config['mode']}"
            elif 'uid' in config:
                vulnerability_details['message'] = f"设置为root权限: {config['function']} {config['uid']}"
            elif 'env' in config:
                vulnerability_details['message'] = f"关键环境变量设置: {config['function']} {config['env']}"
            else:
                vulnerability_details['message'] = config.get('message', '危险配置')

        vulnerabilities.append(vulnerability_details)
        processed_lines.add(line_key)

    # 然后分析设置操作（更通用的检测）
    for operation in setting_operations:
        line_key = f"{operation['line']}_{operation['function']}"
        if line_key in processed_lines:
            continue

        is_vulnerable = False
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': '设置操纵',
            'severity': '中危'
        }

        # 检查是否涉及用户输入
        if has_user_input_argument(operation['node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入影响系统设置: {operation['function']} 调用"
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True
        # 检查是否涉及敏感操作
        elif is_sensitive_setting_operation(operation['function'], operation['code_snippet']):
            vulnerability_details['message'] = f"敏感系统设置操作: {operation['function']} 调用"
            is_vulnerable = True
        # 检查是否缺少权限验证
        elif lacks_privilege_check(operation['node'], root):
            vulnerability_details['message'] = f"可能缺少权限验证的设置操作: {operation['function']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)
            processed_lines.add(line_key)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def find_parent_call_expression(node):
    """
    查找父级的call_expression节点
    """
    current = node
    while current:
        if current.type == 'call_expression':
            return current
        current = current.parent
    return None


def is_sensitive_setting_operation(func_name, code_snippet):
    """
    检查是否为敏感的系统设置操作
    """
    sensitive_operations = {
        'setuid', 'seteuid', 'setgid', 'setegid', 'setreuid', 'setregid',
        'setresuid', 'setresgid', 'chmod', 'chown', 'putenv', 'setenv',
        'sysctl', 'system'
    }

    return func_name in sensitive_operations


def lacks_privilege_check(node, root):
    """
    检查设置操作前是否缺少适当的权限验证
    """
    current_line = node.start_point[0] + 1
    code_before = get_code_before_line(root, current_line, 10)

    privilege_indicators = [
        r'getuid\s*\(\s*\)\s*!=\s*0',
        r'geteuid\s*\(\s*\)\s*!=\s*0',
        r'if\s*\(\s*.*[uU]id.*\)',
        r'privilege|permission|root|admin',
        r'access\s*\(|faccessat\s*\('
    ]

    for pattern in privilege_indicators:
        if re.search(pattern, code_before, re.IGNORECASE):
            return False

    return True


def get_code_before_line(root, line_number, lines_before=5):
    """
    获取指定行号之前的代码
    """
    code_lines = root.text.decode('utf8').split('\n')
    start_line = max(0, line_number - lines_before - 1)
    end_line = line_number - 1

    return '\n'.join(code_lines[start_line:end_line])


def has_user_input_argument(func_node, user_input_sources):
    """
    检查函数调用是否包含用户输入参数
    """
    func_text = func_node.text.decode('utf8')

    for source in user_input_sources:
        if is_child_node(source['node'], func_node) or nodes_related(source['node'], func_node):
            return True

    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'env']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', func_text, re.IGNORECASE):
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


def nodes_related(node1, node2):
    """
    检查两个节点是否相关
    """
    text1 = node1.text.decode('utf8')
    text2 = node2.text.decode('utf8')

    identifiers1 = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', text1)
    identifiers2 = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', text2)

    common_identifiers = set(identifiers1) & set(identifiers2)
    return len(common_identifiers) > 0


def analyze_c_code_for_settings_manipulation(code_string):
    """
    分析C代码字符串中的设置操纵漏洞
    """
    return detect_c_setting_manipulation(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - 设置操纵漏洞示例
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

// 危险示例 - 设置操纵漏洞
void vulnerable_settings_operations(int argc, char* argv[]) {
    // 环境变量操纵漏洞
    putenv("PATH=/tmp:/bin:/usr/bin");
    setenv("LD_PRELOAD", "/tmp/malicious.so", 1);

    // 文件权限设置漏洞
    chmod("/tmp/sensitive_file", 0777);
    chown("/etc/passwd", 0, 0);

    // 进程权限设置漏洞
    setuid(0);
    seteuid(atoi(argv[1]));

    // 系统配置操作
    system("sysctl kernel.randomize_va_space=0");

    // 资源限制设置
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_CORE, &rl);

    // 信号处理设置
    signal(SIGSEGV, SIG_IGN);

    // 路径操作漏洞
    chdir("/tmp");
    char user_input[100];
    scanf("%s", user_input);
    chdir(user_input);

    // 网络配置漏洞
    int sock = socket(AF_INFT, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

// 相对安全的示例
void safe_settings_operations() {
    // 安全的权限检查
    if (getuid() != 0) {
        fprintf(stderr, "需要root权限\\n");
        return;
    }

    // 安全的文件权限设置
    chmod("/var/log/app.log", 0644);

    // 安全的UID设置（在验证后）
    if (geteuid() == 0) {
        setuid(1000);
    }

    // 安全的环境变量操作
    char* path = getenv("PATH");
    if (path) {
        setenv("BACKUP_PATH", path, 1);
    }

    // 安全的信号处理
    signal(SIGINT, SIG_DFL);
}

int main(int argc, char* argv[]) {
    vulnerable_settings_operations(argc, argv);
    safe_settings_operations();
    return 0;
}
"""

    print("=" * 60)
    print("C语言设置操纵漏洞检测")
    print("=" * 60)

    results = analyze_c_code_for_settings_manipulation(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到设置操纵漏洞")