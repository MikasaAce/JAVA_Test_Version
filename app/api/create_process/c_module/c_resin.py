import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 资源注入漏洞模式
RESOURCE_INJECTION_VULNERABILITIES = {
    'c': [
        # 检测文件操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @first_arg)
                ) @call
            ''',
            'func_pattern': r'^(fopen|open|creat|freopen|tmpfile|fclose)$',
            'message': '文件操作函数'
        },
        # 检测目录操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @first_arg)
                ) @call
            ''',
            'func_pattern': r'^(opendir|chdir|mkdir|rmdir|rename|remove|unlink)$',
            'message': '目录操作函数'
        },
        # 检测进程操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @first_arg)
                ) @call
            ''',
            'func_pattern': r'^(system|popen|exec[lv]?p?e?|spawn[lv]?p?e?|fork|wait)$',
            'message': '进程操作函数'
        },
        # 检测网络操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @first_arg)
                ) @call
            ''',
            'func_pattern': r'^(socket|connect|bind|listen|accept|send|recv)$',
            'message': '网络操作函数'
        },
        # 检测动态库加载函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @first_arg)
                ) @call
            ''',
            'func_pattern': r'^(dlopen|LoadLibrary|LoadLibraryEx|dlsym|GetProcAddress)$',
            'message': '动态库加载函数'
        },
        # 检测系统调用函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @first_arg)
                ) @call
            ''',
            'func_pattern': r'^(syscall|ioctl|fcntl)$',
            'message': '系统调用函数'
        }
    ]
}

# 资源路径相关模式
RESOURCE_PATTERNS = {
    'sensitive_paths': [
        r'/etc/passwd', r'/etc/shadow', r'/etc/hosts', r'/etc/hostname',
        r'/proc/', r'/sys/', r'/dev/', r'/boot/', r'/root/',
        r'\.\./', r'~/', r'//', r'\\\\'
    ],
    'sensitive_files': [
        r'passwd', r'shadow', r'hosts', r'bash_history', r'ssh/',
        r'config', r'\.env', r'\.key', r'\.pem', r'\.crt'
    ],
    'network_patterns': [
        r'://', r'localhost', r'127\.', r'0\.0\.0\.0', r'::1',
        r'\.sock$', r'\.socket$'
    ],
    'dangerous_commands': [
        r'rm\s+-', r'mkdir', r'rmdir', r'touch', r'cat\s+/',
        r'chmod', r'chown', r'dd\s+if=', r'nc\s+-l', r'bash\s+-i'
    ],
    'safe_path_indicators': [
        r'^/[a-zA-Z0-9_/-]+$',  # 绝对路径但无特殊字符
        r'^[a-zA-Z0-9_/-]+$',  # 相对路径但无特殊字符
        r'\.txt$', r'\.log$', r'\.dat$'  # 常见安全文件扩展名
    ]
}


def detect_c_resource_injection(code, language='c'):
    """
    检测C代码中的资源注入漏洞
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
    resource_operations = []  # 存储资源相关操作
    user_input_sources = []  # 存储用户输入源
    string_operations = []  # 存储字符串操作

    # 第一步：收集资源操作函数调用
    for query_info in RESOURCE_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag == 'func_name':
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture = {
                            'func': name,
                            'node': node.parent,
                            'line': node.start_point[0] + 1,
                            'func_node': node
                        }

                elif tag == 'first_arg' and current_capture:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag == 'call' and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    # 确保arg_node存在
                    if 'arg_node' in current_capture and current_capture['arg_node']:
                        resource_operations.append({
                            'type': 'resource_operation',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"资源注入查询错误 {query_info.get('message')}: {str(e)[:100]}")

    # 第二步：收集用户输入源
    try:
        user_input_sources = find_user_input_sources(root)
    except Exception as e:
        print(f"收集用户输入源错误: {e}")

    # 第三步：收集字符串操作
    try:
        string_operations = find_string_operations(root)
    except Exception as e:
        print(f"收集字符串操作错误: {e}")

    # 第四步：分析漏洞（添加安全检查）
    try:
        vulnerabilities.extend(analyze_direct_resource_injection(resource_operations, user_input_sources))
    except Exception as e:
        print(f"分析直接资源注入错误: {e}")

    try:
        vulnerabilities.extend(
            analyze_indirect_resource_injection(resource_operations, string_operations, user_input_sources))
    except Exception as e:
        print(f"分析间接资源注入错误: {e}")

    try:
        vulnerabilities.extend(analyze_path_traversal(resource_operations, user_input_sources))
    except Exception as e:
        print(f"分析路径遍历错误: {e}")

    try:
        vulnerabilities.extend(analyze_command_injection(resource_operations, user_input_sources))
    except Exception as e:
        print(f"分析命令注入错误: {e}")

    # 去重处理
    return remove_duplicate_vulnerabilities(vulnerabilities)


def find_user_input_sources(root):
    """查找用户输入源"""
    user_inputs = []

    # 用户输入函数模式
    input_patterns = [
        r'^scanf$', r'^fscanf$', r'^sscanf$', r'^gets$', r'^fgets$',
        r'^getchar$', r'^fgetc$', r'^getc$', r'^read$', r'^getline$',
        r'^recv$', r'^recvfrom$', r'^recvmsg$', r'^fread$',
        r'^getenv$'
    ]

    try:
        query = LANGUAGES['c'].query('''
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list) @args
            ) @call
        ''')
        captures = query.captures(root)

        current_call = {}
        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in input_patterns:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        current_call = {
                            'func_name': func_name,
                            'func_node': node
                        }
                        break

            elif tag == 'call' and current_call:
                args = get_function_arguments(node)
                user_inputs.append({
                    'node': node,
                    'func_name': current_call['func_name'],
                    'line': node.start_point[0] + 1,
                    'arguments': args,
                    'code_snippet': node.text.decode('utf8'),
                    'type': 'user_input_function'
                })
                current_call = {}

    except Exception as e:
        print(f"查找用户输入源错误: {e}")

    # 添加main函数的argv参数
    try:
        query = LANGUAGES['c'].query('''
            (function_definition
                declarator: (function_declarator
                    declarator: (identifier) @func_name
                )
            ) @func_def
        ''')
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name' and node.text.decode('utf8') == 'main':
                user_inputs.append({
                    'node': node.parent,
                    'func_name': 'main',
                    'line': node.start_point[0] + 1,
                    'arguments': ['argv'],
                    'code_snippet': node.parent.text.decode('utf8')[:100],
                    'type': 'main_argv'
                })
                break

    except Exception as e:
        print(f"查找main函数错误: {e}")

    return user_inputs


def find_string_operations(root):
    """查找字符串操作"""
    string_ops = []

    try:
        # 查找字符串格式化函数
        query = LANGUAGES['c'].query('''
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list) @args
            ) @call
        ''')
        captures = query.captures(root)

        current_call = {}
        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                if re.match(r'^(sprintf|snprintf|strcpy|strncpy|strcat|strncat)$', func_name, re.IGNORECASE):
                    current_call = {
                        'func_name': func_name,
                        'func_node': node
                    }

            elif tag == 'call' and current_call:
                args = get_function_arguments(node)
                string_ops.append({
                    'node': node,
                    'func_name': current_call['func_name'],
                    'line': node.start_point[0] + 1,
                    'arguments': args,
                    'code_snippet': node.text.decode('utf8'),
                    'type': 'string_operation'
                })
                current_call = {}

    except Exception as e:
        print(f"查找字符串操作错误: {e}")

    return string_ops


def analyze_direct_resource_injection(resource_ops, user_inputs):
    """分析直接资源注入"""
    vulnerabilities = []

    for op in resource_ops:
        # 添加安全检查
        if 'arg_node' not in op or op['arg_node'] is None:
            continue

        # 检查资源操作参数是否直接来自用户输入
        if is_direct_user_input(op['arg_node'], user_inputs):
            vulnerabilities.append({
                'line': op['line'],
                'code_snippet': op['code_snippet'],
                'vulnerability_type': '资源注入',
                'severity': '高危',
                'message': f"用户输入直接用于资源操作: {op['function']}",
                'function': op['function'],
                'argument': op.get('argument', '')
            })

    return vulnerabilities


def analyze_indirect_resource_injection(resource_ops, string_ops, user_inputs):
    """分析间接资源注入（通过字符串操作）"""
    vulnerabilities = []

    for resource_op in resource_ops:
        # 添加安全检查
        if 'arg_node' not in resource_op or resource_op['arg_node'] is None:
            continue

        # 检查资源操作参数是否通过字符串操作间接来自用户输入
        for string_op in string_ops:
            if is_indirect_user_input(resource_op, string_op, user_inputs):
                vulnerabilities.append({
                    'line': resource_op['line'],
                    'code_snippet': resource_op['code_snippet'],
                    'vulnerability_type': '资源注入',
                    'severity': '中危',
                    'message': f"用户输入通过字符串操作间接用于资源操作: {resource_op['function']}",
                    'function': resource_op['function'],
                    'related_string_op': string_op['func_name']
                })
                break

    return vulnerabilities


def analyze_path_traversal(resource_ops, user_inputs):
    """分析路径遍历漏洞"""
    vulnerabilities = []

    for op in resource_ops:
        # 添加安全检查
        if 'arg_node' not in op or op['arg_node'] is None:
            continue

        arg_text = op.get('argument', '')

        # 检查是否包含路径遍历模式
        if contains_path_traversal(arg_text):
            # 检查是否涉及用户输入
            if is_user_input_related(op['arg_node'], user_inputs):
                vulnerabilities.append({
                    'line': op['line'],
                    'code_snippet': op['code_snippet'],
                    'vulnerability_type': '路径遍历',
                    'severity': '高危',
                    'message': f"路径遍历漏洞: {op['function']} 参数包含路径遍历模式",
                    'function': op['function'],
                    'malicious_pattern': extract_malicious_pattern(arg_text)
                })

    return vulnerabilities


def analyze_command_injection(resource_ops, user_inputs):
    """分析命令注入漏洞"""
    vulnerabilities = []

    for op in resource_ops:
        # 添加安全检查
        if 'arg_node' not in op or op['arg_node'] is None:
            continue

        # 特别检查进程操作函数
        if re.match(r'^(system|popen|exec)', op.get('function', ''), re.IGNORECASE):
            arg_text = op.get('argument', '')

            # 检查是否包含危险命令模式
            if contains_dangerous_command(arg_text):
                # 检查是否涉及用户输入
                if is_user_input_related(op['arg_node'], user_inputs):
                    vulnerabilities.append({
                        'line': op['line'],
                        'code_snippet': op['code_snippet'],
                        'vulnerability_type': '命令注入',
                        'severity': '高危',
                        'message': f"命令注入漏洞: {op['function']} 参数包含危险命令",
                        'function': op['function'],
                        'dangerous_command': extract_dangerous_command(arg_text)
                    })

    return vulnerabilities


def is_direct_user_input(arg_node, user_inputs):
    """检查参数节点是否直接来自用户输入"""
    if arg_node is None:
        return False

    try:
        arg_text = arg_node.text.decode('utf8')
    except:
        return False

    # 检查是否直接使用用户输入变量
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_inputs:
        if is_same_node(arg_node, source['node']):
            return True

    return False


def is_indirect_user_input(resource_op, string_op, user_inputs):
    """检查是否通过字符串操作间接使用用户输入"""
    # 检查字符串操作是否在资源操作附近（5行范围内）
    if abs(resource_op['line'] - string_op['line']) > 5:
        return False

    # 检查字符串操作是否使用用户输入
    for arg in string_op.get('arguments', []):
        for user_input in user_inputs:
            if user_input['func_name'] in arg:
                return True

    # 检查字符串操作的结果是否用于资源操作
    resource_args = ' '.join(get_function_arguments(resource_op['node']))
    string_op_code = string_op.get('code_snippet', '')

    # 简单的文本关联检查
    if any(arg in resource_args for arg in string_op.get('arguments', []) if len(arg) > 3):
        return True

    return False


def is_user_input_related(node, user_inputs):
    """检查节点是否与用户输入相关"""
    if node is None:
        return False

    try:
        node_text = node.text.decode('utf8')
    except:
        return False

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', node_text, re.IGNORECASE):
            return True

    # 检查是否在用户输入函数附近
    node_line = node.start_point[0] + 1
    for user_input in user_inputs:
        if abs(node_line - user_input['line']) <= 3:
            return True

    return False


def contains_path_traversal(text):
    """检查文本是否包含路径遍历模式"""
    if not text:
        return False

    text_lower = text.lower()

    # 检查路径遍历模式
    traversal_patterns = [
        r'\.\./', r'\.\.\\', r'~/', r'//', r'\\\\',
        r'/etc/passwd', r'/etc/shadow', r'/proc/self'
    ]

    for pattern in traversal_patterns:
        if re.search(pattern, text_lower):
            return True

    return False


def contains_dangerous_command(text):
    """检查文本是否包含危险命令模式"""
    if not text:
        return False

    text_lower = text.lower()

    for pattern in RESOURCE_PATTERNS['dangerous_commands']:
        if re.search(pattern, text_lower):
            return True

    return False


def extract_malicious_pattern(text):
    """提取恶意模式"""
    if not text:
        return "无参数"

    text_lower = text.lower()

    for pattern in RESOURCE_PATTERNS['sensitive_paths']:
        if re.search(pattern, text_lower):
            return pattern

    return "未知恶意模式"


def extract_dangerous_command(text):
    """提取危险命令"""
    if not text:
        return "无命令"

    text_lower = text.lower()

    for pattern in RESOURCE_PATTERNS['dangerous_commands']:
        match = re.search(pattern, text_lower)
        if match:
            return match.group(0)

    return "未知危险命令"


def is_same_node(node1, node2):
    """检查两个节点是否相同"""
    if not node1 or not node2:
        return False

    return (node1.start_point == node2.start_point and
            node1.end_point == node2.end_point)


def get_function_arguments(call_node):
    """获取函数调用的参数列表"""
    arguments = []
    if not call_node:
        return arguments

    for child in call_node.children:
        if child.type == 'argument_list':
            for arg in child.children:
                if arg.type not in ['(', ')', ',']:
                    try:
                        arguments.append(arg.text.decode('utf8'))
                    except:
                        continue
    return arguments


def remove_duplicate_vulnerabilities(vulnerabilities):
    """去除重复的漏洞报告"""
    unique_vulns = []
    seen = set()

    for vuln in vulnerabilities:
        # 基于行号和代码片段创建唯一标识
        vuln_id = f"{vuln['line']}:{vuln['code_snippet'][:50]}"
        if vuln_id not in seen:
            seen.add(vuln_id)
            unique_vulns.append(vuln)

    return sorted(unique_vulns, key=lambda x: x['line'])


def analyze_c_resource_injection(code_string):
    """
    分析C代码字符串中的资源注入漏洞
    """
    return detect_c_resource_injection(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>

// 资源注入漏洞示例
void resource_injection_examples(int argc, char* argv[]) {
    char buffer[256];
    char command[512];

    // 漏洞1: 直接使用用户输入作为文件名
    FILE* file1 = fopen(argv[1], "r");  // 路径遍历风险

    // 漏洞2: 命令注入
    sprintf(command, "ls -la %s", argv[1]);
    system(command);  // 命令注入风险

    // 漏洞3: 动态库加载
    void* handle = dlopen(argv[1], RTLD_LAZY);  // 恶意库加载风险

    // 漏洞4: 路径遍历
    char user_path[100];
    strcpy(user_path, "/home/user/");
    strcat(user_path, argv[1]);  // 可能包含../等遍历字符
    FILE* file2 = fopen(user_path, "w");

    // 漏洞5: 进程操作
    char* args[] = {"cat", argv[1], NULL};
    execvp("cat", args);  // 任意文件读取
}

// 相对安全的示例
void safe_resource_examples() {
    // 安全示例1: 使用固定路径
    FILE* file = fopen("/var/log/app.log", "r");

    // 安全示例2: 使用硬编码命令
    system("ls -la /safe/directory");

    // 安全示例3: 白名单验证
    char* allowed_files[] = {"config.txt", "data.dat", NULL};
    char* user_file = "config.txt";  // 假设经过验证的文件名

    int allowed = 0;
    for (int i = 0; allowed_files[i] != NULL; i++) {
        if (strcmp(user_file, allowed_files[i]) == 0) {
            allowed = 1;
            break;
        }
    }

    if (allowed) {
        FILE* f = fopen(user_file, "r");
    }
}

int main(int argc, char* argv[]) {
    resource_injection_examples(argc, argv);
    safe_resource_examples();
    return 0;
}
"""

    print("=" * 60)
    print("C语言资源注入漏洞检测（修复版）")
    print("=" * 60)

    results = analyze_c_resource_injection(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在资源注入漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            if 'function' in vuln:
                print(f"   危险函数: {vuln['function']}")
            if 'argument' in vuln:
                print(f"   可疑参数: {vuln['argument'][:50]}...")
    else:
        print("未检测到资源注入漏洞")