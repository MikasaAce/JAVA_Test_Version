import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 定义C语言动态代码注入漏洞模式（优化版）
DYNAMIC_CODE_VULNERABILITIES = {
    'c': [
        # 检测system函数调用（带参数分析）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @first_arg)
                ) @call
            ''',
            'func_pattern': r'^(system|popen|execl|execlp|execle|execv|execvp|execvpe|execve)$',
            'message': '系统命令执行函数调用',
            'severity': '高危'
        },
        # 检测动态库加载函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @lib_path)
                ) @call
            ''',
            'func_pattern': r'^(dlopen|LoadLibraryA|LoadLibraryW|LoadLibraryExA|LoadLibraryExW)$',
            'message': '动态库加载函数',
            'severity': '高危'
        },
        # 检测动态符号解析
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @sym_name (_)?)
                ) @call
            ''',
            'func_pattern': r'^(dlsym|GetProcAddress)$',
            'message': '动态符号解析函数',
            'severity': '高危'
        },
        # 检测函数指针调用（更精确的匹配）
        {
            'query': '''
                (call_expression
                    function: (pointer_expression) @func_ptr
                ) @call
            ''',
            'message': '函数指针动态调用',
            'severity': '高危'
        },
        # 检测eval类函数（通过动态库）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @code_str)
                ) @call
            ''',
            'func_pattern': r'^(eval|exec|compile)$',
            'message': '动态代码执行函数',
            'severity': '高危'
        }
    ]
}

# 用户输入源模式（优化版）
USER_INPUT_SOURCES = {
    'c': [
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(scanf|fscanf|sscanf|gets|fgets|getchar|fgetc|getc|read|getline)$',
            'message': '标准输入函数',
            'arg_index': 0  # 第一个参数通常是缓冲区
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(recv|recvfrom|recvmsg)$',
            'message': '网络输入函数',
            'arg_index': 1  # 第二个参数是缓冲区
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(fread)$',
            'message': '文件输入函数',
            'arg_index': 0  # 第一个参数是缓冲区
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(getenv)$',
            'message': '环境变量获取'
        },
        # 命令行参数（main函数的参数）
        {
            'query': '''
                (function_definition
                    declarator: (function_declarator
                        declarator: (identifier) @func_name
                        parameters: (parameter_list (_)* @param)
                    )
                ) @func_def
            ''',
            'func_pattern': r'^(main)$',
            'message': '命令行参数'
        }
    ]
}

# 危险数据流模式（优化版）
DANGEROUS_DATA_FLOWS = {
    'c': [
        # 用户输入直接传递给系统命令
        {
            'query': '''
                (call_expression
                    function: (identifier) @sys_func
                    arguments: (argument_list (identifier) @input_var)
                ) @call
            ''',
            'sys_pattern': r'^(system|popen|execl|execv)$',
            'message': '用户输入直接传递给系统命令'
        },
        # 字符串拼接后传递给危险函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @danger_func
                    arguments: (argument_list (call_expression
                        function: (identifier) @concat_func
                    ) @concat_call)
                ) @call
            ''',
            'danger_pattern': r'^(system|popen|dlopen|dlsym)$',
            'concat_pattern': r'^(sprintf|strcat|strncat|vsprintf)$',
            'message': '拼接字符串传递给危险函数'
        }
    ]
}

# 安全模式（白名单，用于减少误报）
SAFE_PATTERNS = {
    'c': [
        # 硬编码路径的dlopen
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (string_literal) @path)
                ) @call
            ''',
            'func_pattern': r'^(dlopen|LoadLibrary)$',
            'path_pattern': r'^"(/usr/lib|/lib|/System/Library|C:\\Windows\\System32)[^"]*"',
            'message': '系统库加载，相对安全'
        },
        # 硬编码命令的system调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (string_literal) @cmd)
                ) @call
            ''',
            'func_pattern': r'^(system|popen)$',
            'cmd_pattern': r'^"(echo|ls|dir|pwd|cd\s+|mkdir\s+[A-Za-z0-9_]+|rmdir\s+[A-Za-z0-9_]+)"',
            'message': '简单命令执行，相对安全'
        }
    ]
}


def detect_c_dynamic_code_injection(code, language='c'):
    """
    检测C代码中动态代码注入漏洞（优化版）

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

    # 收集所有相关信息
    dangerous_calls = collect_dangerous_calls(root, language)
    user_inputs = collect_user_inputs(root, language)
    safe_calls = collect_safe_patterns(root, language)

    # 分析漏洞
    vulnerabilities.extend(analyze_dynamic_code_injection(
        dangerous_calls, user_inputs, safe_calls
    ))

    return sorted(vulnerabilities, key=lambda x: x['line'])


def collect_dangerous_calls(root, language):
    """收集危险函数调用"""
    dangerous_calls = []

    for pattern in DYNAMIC_CODE_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(pattern['query'])
            captures = query.captures(root)

            current_call = {}
            for node, tag in captures:
                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    if re.match(pattern.get('func_pattern', ''), func_name, re.IGNORECASE):
                        current_call['function'] = func_name
                        current_call['func_node'] = node
                        current_call['line'] = node.start_point[0] + 1

                elif tag in ['first_arg', 'lib_path', 'sym_name', 'code_str']:
                    current_call['argument'] = node.text.decode('utf8')
                    current_call['arg_node'] = node

                elif tag == 'func_ptr':
                    current_call['is_function_pointer'] = True
                    current_call['node'] = node.parent
                    current_call['line'] = node.start_point[0] + 1

                elif tag in ['call', 'func_def'] and current_call:
                    # 完成捕获
                    code_snippet = node.text.decode('utf8')[:200]  # 限制长度

                    call_info = {
                        'type': 'dangerous_call',
                        'line': current_call['line'],
                        'function': current_call.get('function', ''),
                        'argument': current_call.get('argument', ''),
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': pattern.get('message', ''),
                        'severity': pattern.get('severity', '中危'),
                        'is_function_pointer': current_call.get('is_function_pointer', False)
                    }

                    dangerous_calls.append(call_info)
                    current_call = {}

        except Exception as e:
            print(f"危险调用收集错误: {e}")
            continue

    return dangerous_calls


def collect_user_inputs(root, language):
    """收集用户输入源"""
    user_inputs = []

    for pattern in USER_INPUT_SOURCES[language]:
        try:
            query = LANGUAGES[language].query(pattern['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    if re.match(pattern.get('func_pattern', ''), func_name, re.IGNORECASE):
                        input_info = {
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8')[:200],
                            'node': node.parent,
                            'message': pattern.get('message', ''),
                            'arg_index': pattern.get('arg_index')
                        }
                        user_inputs.append(input_info)

                elif tag == 'param' and pattern.get('func_pattern') == r'^(main)$':
                    # 处理main函数的参数
                    param_text = node.text.decode('utf8')
                    if 'argv' in param_text or 'argc' in param_text:
                        input_info = {
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'function': 'main',
                            'code_snippet': param_text,
                            'node': node,
                            'message': '命令行参数'
                        }
                        user_inputs.append(input_info)

        except Exception as e:
            print(f"用户输入收集错误: {e}")
            continue

    return user_inputs


def collect_safe_patterns(root, language):
    """收集安全模式（用于减少误报）"""
    safe_calls = []

    for pattern in SAFE_PATTERNS.get(language, []):
        try:
            query = LANGUAGES[language].query(pattern['query'])
            captures = query.captures(root)

            current_call = {}
            for node, tag in captures:
                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    if re.match(pattern.get('func_pattern', ''), func_name, re.IGNORECASE):
                        current_call['function'] = func_name
                        current_call['line'] = node.start_point[0] + 1

                elif tag in ['path', 'cmd']:
                    arg_text = node.text.decode('utf8')
                    path_pattern = pattern.get('path_pattern') or pattern.get('cmd_pattern')
                    if path_pattern and re.match(path_pattern, arg_text, re.IGNORECASE):
                        current_call['is_safe'] = True
                        current_call['safe_reason'] = pattern.get('message', '')

                elif tag == 'call' and current_call.get('is_safe'):
                    safe_calls.append({
                        'function': current_call['function'],
                        'line': current_call['line'],
                        'safe_reason': current_call.get('safe_reason', ''),
                        'node': node
                    })
                    current_call = {}

        except Exception as e:
            print(f"安全模式收集错误: {e}")
            continue

    return safe_calls


def analyze_dynamic_code_injection(dangerous_calls, user_inputs, safe_calls):
    """分析动态代码注入漏洞"""
    vulnerabilities = []

    for call in dangerous_calls:
        # 检查是否在安全白名单中
        if is_safe_call(call, safe_calls):
            continue

        vulnerability = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '动态代码注入',
            'severity': call['severity'],
            'message': call['message']
        }

        # 分析具体风险
        if call['is_function_pointer']:
            vulnerability['message'] = f"函数指针动态调用: {call['message']}"
            vulnerability['risk_factors'] = ['动态函数调用', '难以静态分析']

        elif call['function'] and call.get('argument'):
            arg_text = call['argument']

            # 检查参数是否包含用户输入特征
            if is_user_input_like(arg_text):
                vulnerability['message'] = f"用户输入用于动态代码执行: {call['function']}"
                vulnerability['risk_factors'] = ['用户输入依赖', '动态代码执行']
                vulnerability['severity'] = '高危'

            # 检查参数是否包含动态内容
            elif is_dynamic_content(arg_text):
                vulnerability['message'] = f"动态内容用于代码执行: {call['function']}"
                vulnerability['risk_factors'] = ['动态内容', '潜在代码注入']

            # 检查是否与已知用户输入相关
            elif is_related_to_user_input(call, user_inputs):
                vulnerability['message'] = f"可能受用户输入影响: {call['function']}"
                vulnerability['risk_factors'] = ['数据流依赖', '潜在注入']

        vulnerabilities.append(vulnerability)

    return vulnerabilities


def is_safe_call(call, safe_calls):
    """检查调用是否安全"""
    for safe_call in safe_calls:
        if (safe_call['line'] == call['line'] and
                safe_call['function'] == call.get('function', '')):
            return True
    return False


def is_user_input_like(text):
    """检查文本是否类似用户输入"""
    user_input_indicators = [
        r'.*%s.*',  # 格式化字符串
        r'.*\$.+',  # 变量引用
        r'.*argv.*',  # 命令行参数
        r'.*scanf.*',  # 输入函数
        r'.*getenv.*',  # 环境变量
    ]

    for pattern in user_input_indicators:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def is_dynamic_content(text):
    """检查是否包含动态内容"""
    dynamic_indicators = [
        r'.*\.(so|dll|dylib).*',  # 动态库
        r'.*(python|perl|php|ruby|bash|sh).*',  # 解释器
        r'.*(eval|exec|compile).*',  # 动态执行
        r'.*(\$\(|`).*',  # 命令替换
    ]

    for pattern in dynamic_indicators:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def is_related_to_user_input(call, user_inputs):
    """检查调用是否与用户输入相关"""
    call_text = call['code_snippet'].lower()

    # 检查代码片段中是否包含用户输入相关的变量名
    input_vars = ['argv', 'argc', 'input', 'buffer', 'user', 'data', 'param', 'cmd']
    for var in input_vars:
        if re.search(rf'\b{var}\b', call_text):
            return True

    # 检查是否在同一区域有用户输入操作
    for user_input in user_inputs:
        if abs(user_input['line'] - call['line']) < 10:  # 相近的行号
            return True

    return False


def analyze_c_code(code_string):
    """
    分析C代码字符串中的动态代码注入漏洞
    """
    return detect_c_dynamic_code_injection(code_string, 'c')


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
    system("ls -la");  // 直接命令执行（相对安全）

    char command[100];
    sprintf(command, "echo %s", argv[1]);
    system(command);  // 命令注入（高危）

    // 动态库加载
    void* handle = dlopen("malicious.so", RTLD_LAZY);  // 动态库加载（高危）
    void* safe_handle = dlopen("/usr/lib/libc.so.6", RTLD_LAZY);  // 系统库（安全）

    // 函数指针动态调用
    void (*func_ptr)() = NULL;
    func_ptr();  // 危险的函数指针调用（高危）

    // 用户输入直接使用
    char user_input[100];
    scanf("%s", user_input);  // 直接用户输入
    system(user_input);  // 高危！
}

// 相对安全的示例
void safe_functions() {
    // 安全的硬编码命令
    system("echo 'Hello World'");  // 安全

    // 安全的动态库加载
    void* handle = dlopen("/usr/lib/libc.so.6", RTLD_LAZY);  // 安全

    // 安全的系统调用
    system("pwd");  // 安全
}

int main(int argc, char* argv[]) {
    vulnerable_functions(argc, argv);
    safe_functions();
    return 0;
}
"""

    print("=" * 60)
    print("C语言动态代码注入漏洞检测（优化版）")
    print("=" * 60)

    results = analyze_c_code(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            if 'risk_factors' in vuln:
                print(f"   风险因素: {', '.join(vuln['risk_factors'])}")
    else:
        print("未检测到动态代码注入漏洞")