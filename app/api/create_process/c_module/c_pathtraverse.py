import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 路径遍历漏洞模式
PATH_TRAVERSAL_VULNERABILITIES = {
    'c': [
        # 检测文件操作函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @path_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(fopen|open|fopen64|open64|freopen|creat|mkstemp)$',
            'message': '文件打开函数调用'
        },
        # 检测文件读取函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @filename_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(fread|read|pread|readv|fgetc|fgets|getline)$',
            'message': '文件读取函数调用'
        },
        # 检测文件写入函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @file_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(fwrite|write|pwrite|writev|fputc|fputs|puts)$',
            'message': '文件写入函数调用'
        },
        # 检测目录操作函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @dir_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(opendir|readdir|mkdir|rmdir|chdir|getcwd)$',
            'message': '目录操作函数调用'
        },
        # 检测文件信息函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @stat_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(stat|lstat|fstat|access|faccessat|realpath)$',
            'message': '文件信息函数调用'
        },
        # 检测文件删除函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @remove_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(remove|unlink|delete|rm)$',
            'message': '文件删除函数调用'
        }
    ]
}

# 路径遍历模式
PATH_TRAVERSAL_PATTERNS = {
    'c': [
        # 检测路径拼接操作
        {
            'query': '''
                (binary_expression
                    left: (string_literal) @base_path
                    operator: "+"
                    right: (identifier) @user_input
                ) @binary_expr
            ''',
            'message': '路径与用户输入拼接'
        },
        # 检测格式化路径构建
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string_literal) @format_str
                        (identifier) @path_var
                    )
                ) @call
            ''',
            'func_pattern': r'^(sprintf|snprintf|vsprintf|vsnprintf)$',
            'pattern': r'.*%s.*',
            'message': '格式化字符串构建路径'
        },
        # 检测路径复制操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (identifier) @dest_path
                        (identifier) @src_path
                    )
                ) @call
            ''',
            'func_pattern': r'^(strcpy|strncpy|strcat|strncat)$',
            'message': '字符串复制构建路径'
        }
    ]
}

# 文件操作上下文检测
FILE_OPERATION_CONTEXT = {
    'c': [
        # 检测文件相关头文件包含
        {
            'query': '''
                (preproc_include
                    path: (string_literal) @include_path
                ) @include
            ''',
            'pattern': r'.*(stdio|fcntl|unistd|sys/stat|dirent|stdlib)\.h',
            'message': '包含文件操作相关头文件'
        },
        # 检测文件相关类型
        {
            'query': '''
                (type_identifier) @type_name
            ''',
            'pattern': r'^(FILE|DIR|struct\s+stat|struct\s+dirent)$',
            'message': '使用文件操作相关类型'
        }
    ]
}

# 危险的路径模式
DANGEROUS_PATH_PATTERNS = {
    'c': [
        # 检测路径遍历序列
        {
            'query': '''
                (string_literal) @traversal_string
            ''',
            'pattern': r'\.\./|\.\.\\|~/|\./|/etc/|/proc/|/sys/|/boot/|/root/',
            'message': '字符串包含路径遍历序列'
        },
        # 检测绝对路径
        {
            'query': '''
                (string_literal) @absolute_path
            ''',
            'pattern': r'^/|^[A-Za-z]:\\',
            'message': '字符串包含绝对路径'
        },
        # 检测特殊文件引用
        {
            'query': '''
                (string_literal) @special_file
            ''',
            'pattern': r'(/etc/passwd|/etc/shadow|/proc/self|/dev/null|/dev/zero|/dev/random)',
            'message': '字符串引用特殊文件'
        }
    ]
}

# 用户输入源模式
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


def detect_c_path_traversal(code, language='c'):
    """
    检测C代码中路径遍历漏洞

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
    file_operation_calls = []  # 存储文件操作函数调用
    path_traversal_patterns = []  # 存储路径遍历模式
    file_operation_context = []  # 存储文件操作上下文信息
    dangerous_path_patterns = []  # 存储危险的路径模式
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集文件操作函数调用
    for query_info in PATH_TRAVERSAL_VULNERABILITIES[language]:
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
                        current_capture['func_node'] = node

                elif tag in ['path_arg', 'filename_arg', 'file_arg', 'dir_arg', 'stat_arg', 'remove_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag in ['call'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    file_operation_calls.append({
                        'type': 'file_operation',
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
            print(f"文件操作函数查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第二步：收集路径遍历模式
    for query_info in PATH_TRAVERSAL_PATTERNS[language]:
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

                elif tag in ['base_path', 'format_str']:
                    current_capture['base'] = node.text.decode('utf8')
                    current_capture['base_node'] = node
                    # 检查格式模式
                    format_pattern = query_info.get('pattern', '')
                    if format_pattern and re.search(format_pattern, current_capture['base'], re.IGNORECASE):
                        current_capture['format_match'] = True

                elif tag in ['user_input', 'path_var', 'src_path']:
                    current_capture['user_var'] = node.text.decode('utf8')
                    current_capture['user_node'] = node

                elif tag in ['dest_path']:
                    current_capture['dest_var'] = node.text.decode('utf8')
                    current_capture['dest_node'] = node

                elif tag in ['binary_expr', 'call'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    path_traversal_patterns.append({
                        'type': 'path_building',
                        'line': current_capture['line'],
                        'function': current_capture.get('func', ''),
                        'base_path': current_capture.get('base', ''),
                        'user_variable': current_capture.get('user_var', ''),
                        'destination': current_capture.get('dest_var', ''),
                        'code_snippet': code_snippet,
                        'node': node,
                        'format_match': current_capture.get('format_match', False),
                        'message': query_info.get('message', '')
                    })
                    current_capture = {}

        except Exception as e:
            print(f"路径遍历模式查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第三步：收集文件操作上下文信息
    for query_info in FILE_OPERATION_CONTEXT[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                text = node.text.decode('utf8')

                if tag in ['include_path']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        file_operation_context.append({
                            'type': 'file_include',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

                elif tag in ['type_name']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        file_operation_context.append({
                            'type': 'file_type',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"文件操作上下文查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第四步：收集危险的路径模式
    for query_info in DANGEROUS_PATH_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['traversal_string', 'absolute_path', 'special_file']:
                    text = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')

                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        dangerous_path_patterns.append({
                            'type': 'dangerous_path',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'pattern_match': True,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"危险路径模式查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第五步：收集用户输入源
    try:
        query = LANGUAGES[language].query(C_USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
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
                        break

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第六步：分析路径遍历漏洞
    vulnerabilities.extend(analyze_path_traversal_vulnerabilities(
        file_operation_calls, path_traversal_patterns, file_operation_context,
        dangerous_path_patterns, user_input_sources
    ))

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_path_traversal_vulnerabilities(file_calls, path_patterns, file_context, dangerous_paths,
                                           user_input_sources):
    """
    分析路径遍历漏洞
    """
    vulnerabilities = []

    # 分析文件操作函数调用漏洞
    for call in file_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '路径遍历',
            'severity': '高危'
        }

        # 检查是否包含用户输入
        if call.get('arg_node') and is_user_input_related(call['arg_node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入直接传递给文件操作函数: {call['function']}"
            is_vulnerable = True

        # 检查在文件操作上下文中的潜在风险
        elif is_in_file_context(call['node'], file_context):
            vulnerability_details['message'] = f"文件操作上下文中的函数调用: {call['function']}"
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    # 分析路径遍历模式漏洞
    for pattern in path_patterns:
        is_vulnerable = False
        vulnerability_details = {
            'line': pattern['line'],
            'code_snippet': pattern['code_snippet'],
            'vulnerability_type': '路径遍历',
            'severity': '高危'
        }

        if pattern.get('user_variable') and is_user_input_variable(pattern['user_variable'], user_input_sources):
            vulnerability_details['message'] = f"用户输入用于路径构建: {pattern['message']}"
            is_vulnerable = True

        elif pattern.get('format_match', False):
            vulnerability_details['message'] = f"格式化字符串构建路径: {pattern['function']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    # 分析危险的路径模式
    for dangerous in dangerous_paths:
        is_vulnerable = False
        vulnerability_details = {
            'line': dangerous['line'],
            'code_snippet': dangerous['code_snippet'],
            'vulnerability_type': '路径遍历',
            'severity': '高危'
        }

        if dangerous.get('pattern_match', False) and has_user_input_nearby(dangerous['node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入附近的危险路径模式: {dangerous['message']}"
            is_vulnerable = True

        elif dangerous.get('pattern_match', False) and is_in_file_context(dangerous['node'], file_context):
            vulnerability_details['message'] = f"文件上下文中的危险路径模式: {dangerous['message']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return vulnerabilities


def is_user_input_related(arg_node, user_input_sources):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'file', 'path', 'filename']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_in_file_context(node, file_context):
    """
    检查节点是否在文件操作上下文中
    """
    node_line = node.start_point[0] + 1

    for context in file_context:
        context_line = context['line']
        # 如果文件操作上下文在调用之前或同一区域
        if context_line <= node_line and (node_line - context_line) < 50:
            return True

    return False


def is_user_input_variable(var_name, user_input_sources):
    """
    检查变量名是否与用户输入相关
    """
    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'file', 'path']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', var_name, re.IGNORECASE):
            return True

    return False


def has_user_input_nearby(node, user_input_sources):
    """
    检查节点附近是否有用户输入
    """
    node_line = node.start_point[0] + 1

    for source in user_input_sources:
        source_line = source['line']
        # 如果用户输入在节点附近
        if abs(source_line - node_line) < 10:
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


def analyze_path_traversal(code_string):
    """
    分析C代码字符串中的路径遍历漏洞
    """
    return detect_c_path_traversal(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - 路径遍历场景
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

// 危险示例 - 路径遍历漏洞
void vulnerable_path_functions(int argc, char* argv[]) {
    FILE* fp;
    int fd;
    char buffer[1024];

    // 漏洞1: 直接使用用户输入作为文件路径
    char* user_file = argv[1];
    fp = fopen(user_file, "r");  // 路径遍历漏洞

    // 漏洞2: 路径拼接未过滤
    char base_path[] = "/home/user/files/";
    char full_path[200];
    sprintf(full_path, "%s%s", base_path, argv[2]);  // 路径遍历漏洞
    fp = fopen(full_path, "r");

    // 漏洞3: 字符串拼接构建路径
    char user_dir[100];
    strcpy(user_dir, argv[3]);
    char config_path[200] = "/etc/";
    strcat(config_path, user_dir);  // 路径遍历漏洞
    strcat(config_path, "/config.conf");
    fp = fopen(config_path, "r");

    // 漏洞4: 格式化字符串构建路径
    char template[] = "/var/www/html/%s";
    char web_path[200];
    snprintf(web_path, sizeof(web_path), template, argv[4]);  // 路径遍历漏洞
    fp = fopen(web_path, "r");

    // 漏洞5: 使用相对路径遍历
    char relative_path[] = "../../../etc/passwd";
    fp = fopen(relative_path, "r");  // 直接路径遍历

    // 漏洞6: 网络数据作为路径
    char network_path[256];
    // recv(socket_fd, network_path, sizeof(network_path), 0);
    fp = fopen(network_path, "w");  // 潜在路径遍历

    // 漏洞7: 环境变量作为路径
    char* env_path = getenv("USER_FILE");
    if (env_path) {
        fp = fopen(env_path, "r");  // 路径遍历漏洞
    }

    // 漏洞8: 目录遍历
    char* user_input = argv[5];
    char dir_path[200];
    sprintf(dir_path, "/home/users/%s/documents", user_input);  // 路径遍历漏洞
    // opendir(dir_path);

    if (fp != NULL) {
        fclose(fp);
    }
}

// 相对安全的示例
void safe_path_functions() {
    FILE* fp;

    // 安全1: 硬编码路径
    fp = fopen("/etc/secure_config", "r");  // 安全

    // 安全2: 路径规范化检查
    char user_input[100];
    // 路径验证逻辑...
    // if (is_valid_path(user_input)) {
    //     fp = fopen(user_input, "r");
    // }

    // 安全3: 使用basename限制路径
    char safe_path[200];
    char* base_name = basename(argv[1]);  // 获取文件名部分
    sprintf(safe_path, "/safe/directory/%s", base_name);
    fp = fopen(safe_path, "r");  // 相对安全

    // 安全4: 路径白名单
    char* allowed_paths[] = {"/tmp/file1", "/tmp/file2", NULL};
    // if (is_in_whitelist(user_path, allowed_paths)) {
    //     fp = fopen(user_path, "r");
    // }

    // 安全5: 使用绝对路径限制
    char absolute_path[PATH_MAX];
    if (realpath(user_input, absolute_path) != NULL) {
        // 检查路径是否在允许的目录内
        if (strncmp(absolute_path, "/allowed/directory/", 19) == 0) {
            fp = fopen(absolute_path, "r");  // 相对安全
        }
    }

    if (fp != NULL) {
        fclose(fp);
    }
}

// Web服务器文件服务示例
void webserver_file_example(int argc, char* argv[]) {
    // 模拟Web服务器文件下载
    char* requested_file = argv[1];  // 来自HTTP请求的文件名

    // 危险: 直接使用请求的文件名
    char dangerous_path[300];
    sprintf(dangerous_path, "/var/www/files/%s", requested_file);  // 路径遍历漏洞
    FILE* fp = fopen(dangerous_path, "rb");

    // 相对安全: 路径过滤
    char safe_path[300];
    // 过滤路径遍历序列
    char* filtered_name = filter_path_traversal(requested_file);
    sprintf(safe_path, "/var/www/files/%s", filtered_name);
    fp = fopen(safe_path, "rb");
}

// 配置文件读取示例
void config_reader_example(int argc, char* argv[]) {
    // 危险: 用户控制配置文件路径
    char* config_file = argv[1];
    FILE* fp = fopen(config_file, "r");  // 路径遍历漏洞

    // 相对安全: 限制配置文件位置
    char config_path[200];
    sprintf(config_path, "/etc/myapp/%s.conf", argv[1]);
    // 还需要进一步验证文件名合法性
    fp = fopen(config_path, "r");
}

int main(int argc, char* argv[]) {
    vulnerable_path_functions(argc, argv);
    safe_path_functions();
    webserver_file_example(argc, argv);
    config_reader_example(argc, argv);
    return 0;
}
"""

    print("=" * 60)
    print("C语言路径遍历漏洞检测")
    print("=" * 60)

    results = analyze_path_traversal(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在路径遍历漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到路径遍历漏洞")