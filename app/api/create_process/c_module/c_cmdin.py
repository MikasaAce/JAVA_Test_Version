import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 命令注入漏洞检测模式
COMMAND_INJECTION_VULNERABILITIES = {
    'c': [
        # 检测system函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string_literal) @arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(system|popen|exec[lv]p?e?)$',
            'message': '系统命令执行函数调用'
        },
        # 检测system函数调用（变量参数）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (identifier) @arg_var
                    )
                ) @call
            ''',
            'func_pattern': r'^(system|popen|exec[lv]p?e?)$',
            'message': '系统命令执行函数调用（变量参数）'
        },
        # 检测system函数调用（复杂表达式参数）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (call_expression) @nested_call
                    )
                ) @call
            ''',
            'func_pattern': r'^(system|popen|exec[lv]p?e?)$',
            'message': '系统命令执行函数调用（嵌套调用参数）'
        },
        # 检测Windows系统命令执行
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(_?system|_wsystem|CreateProcess|ShellExecute|WinExec)$',
            'message': 'Windows系统命令执行函数'
        },
        # 检测命令字符串构建模式
        {
            'query': '''
                (call_expression
                    function: (identifier) @str_func
                    arguments: (argument_list (_)* @args)
                ) @str_call
            ''',
            'func_pattern': r'^(sprintf|snprintf|vsprintf|strcat|strncat|strcpy|strncpy)$',
            'message': '命令字符串构建函数'
        },
        # 检测环境变量相关函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(getenv|_wgetenv|_dupenv_s)$',
            'message': '环境变量获取函数'
        }
    ]
}

# 用户输入源模式（专门针对命令注入）
COMMAND_INJECTION_INPUT_SOURCES = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(scanf|fscanf|sscanf|gets|fgets|getchar|fgetc|getc|read|getline)$',
            'message': '标准输入函数',
            'risk_level': 'high'
        },
        {
            'func_pattern': r'^(recv|recvfrom|recvmsg)$',
            'message': '网络输入函数',
            'risk_level': 'high'
        },
        {
            'func_pattern': r'^(fread|fgetc|fgets)$',
            'message': '文件输入函数',
            'risk_level': 'medium'
        },
        {
            'func_pattern': r'^(getenv|_wgetenv)$',
            'message': '环境变量获取',
            'risk_level': 'medium'
        },
        # main函数参数
        {
            'query': '''
                (function_definition
                    declarator: (function_declarator
                        declarator: (identifier) @func_name
                        parameters: (parameter_list) @params
                    )
                ) @func_def
            ''',
            'func_pattern': r'^main$',
            'message': 'main函数命令行参数',
            'risk_level': 'high'
        }
    ]
}

# 危险字符和模式检测
DANGEROUS_PATTERNS = {
    'shell_metacharacters': r'[|&;`$<>(){}!]',
    'command_concatenation': r'\$\(|\`|&&|\|\|',
    'path_traversal': r'\.\./|\.\\',
    'dangerous_commands': r'\b(rm\s+-rf|del\s+/q|format|shutdown|mkfs)\b',
    'script_indicators': r'\.(sh|bat|cmd|ps1|py|pl)\b'
}


def detect_command_injection_vulnerabilities(code, language='c'):
    """
    检测C代码中的命令注入漏洞

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
    dangerous_calls = []  # 存储危险函数调用
    user_input_sources = []  # 存储用户输入源
    string_operations = []  # 存储字符串操作

    # 第一步：收集危险函数调用
    for query_info in COMMAND_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'str_func']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['func_node'] = node

                elif tag in ['arg', 'arg_var', 'nested_call']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node
                    current_capture['arg_type'] = tag

                elif tag in ['call', 'str_call'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    dangerous_call = {
                        'type': 'dangerous_function',
                        'line': current_capture['line'],
                        'function': current_capture.get('func', ''),
                        'argument': current_capture.get('arg', ''),
                        'arg_node': current_capture.get('arg_node'),
                        'arg_type': current_capture.get('arg_type', ''),
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    }

                    # 分析参数内容
                    if 'arg' in current_capture:
                        dangerous_call['arg_analysis'] = analyze_argument_content(
                            current_capture['arg'],
                            current_capture['arg_type']
                        )

                    dangerous_calls.append(dangerous_call)
                    current_capture = {}

        except Exception as e:
            print(f"命令注入查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        # 处理函数调用类型的输入源
        query = LANGUAGES[language].query(COMMAND_INJECTION_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern_info in COMMAND_INJECTION_INPUT_SOURCES['patterns']:
                    if 'func_pattern' in pattern_info:
                        func_pattern = pattern_info.get('func_pattern', '')
                        if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                            code_snippet = node.parent.text.decode('utf8')
                            user_input_sources.append({
                                'type': 'user_input_call',
                                'line': node.start_point[0] + 1,
                                'function': func_name,
                                'code_snippet': code_snippet,
                                'node': node.parent,
                                'risk_level': pattern_info.get('risk_level', 'medium'),
                                'message': pattern_info.get('message', '')
                            })
                            break

        # 处理main函数参数定义
        for pattern_info in COMMAND_INJECTION_INPUT_SOURCES['patterns']:
            if 'query' in pattern_info and pattern_info.get('func_pattern') == r'^main$':
                try:
                    query = LANGUAGES[language].query(pattern_info['query'])
                    captures = query.captures(root)

                    for node, tag in captures:
                        if tag == 'func_name':
                            func_name = node.text.decode('utf8')
                            if func_name == 'main':
                                user_input_sources.append({
                                    'type': 'main_parameters',
                                    'line': node.start_point[0] + 1,
                                    'function': 'main',
                                    'code_snippet': node.parent.text.decode('utf8'),
                                    'node': node.parent,
                                    'risk_level': 'high',
                                    'message': 'main函数命令行参数'
                                })

                except Exception as e:
                    print(f"main函数参数查询错误: {e}")

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：分析数据流和漏洞
    vulnerabilities = analyze_command_injection_flow(dangerous_calls, user_input_sources, root, code)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_argument_content(argument, arg_type):
    """
    分析参数内容，检测潜在的危险模式
    """
    analysis = {
        'has_metacharacters': False,
        'has_concatenation': False,
        'has_user_input_indicators': False,
        'is_static_string': False,
        'risk_score': 0
    }

    # 清理参数文本（去除引号等）
    clean_arg = argument.strip()
    if arg_type == 'arg' and clean_arg.startswith('"') and clean_arg.endswith('"'):
        clean_arg = clean_arg[1:-1]
        analysis['is_static_string'] = True

    # 检查shell元字符
    if re.search(DANGEROUS_PATTERNS['shell_metacharacters'], clean_arg):
        analysis['has_metacharacters'] = True
        analysis['risk_score'] += 2

    # 检查命令连接符
    if re.search(DANGEROUS_PATTERNS['command_concatenation'], clean_arg):
        analysis['has_concatenation'] = True
        analysis['risk_score'] += 2

    # 检查用户输入指示器
    user_input_indicators = ['argv', 'argc', 'input', 'buffer', 'user', 'cmd', 'param']
    for indicator in user_input_indicators:
        if re.search(rf'\b{indicator}\b', clean_arg, re.IGNORECASE):
            analysis['has_user_input_indicators'] = True
            analysis['risk_score'] += 1
            break

    # 检查危险命令
    if re.search(DANGEROUS_PATTERNS['dangerous_commands'], clean_arg, re.IGNORECASE):
        analysis['risk_score'] += 1

    return analysis


def analyze_command_injection_flow(dangerous_calls, user_input_sources, root, code):
    """
    分析命令注入的数据流
    """
    vulnerabilities = []

    for call in dangerous_calls:
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': '命令注入',
            'function': call['function'],
            'severity': '待评估'
        }

        is_vulnerable = False
        risk_factors = []

        # 分析1：参数内容分析
        if 'arg_analysis' in call:
            analysis = call['arg_analysis']

            if analysis['has_metacharacters'] and not analysis['is_static_string']:
                risk_factors.append("参数包含shell元字符")
                is_vulnerable = True

            if analysis['has_concatenation']:
                risk_factors.append("参数包含命令连接符")
                is_vulnerable = True

            if analysis['has_user_input_indicators']:
                risk_factors.append("参数名暗示用户输入")
                is_vulnerable = True

            if analysis['risk_score'] >= 3:
                is_vulnerable = True

        # 分析2：数据流分析
        if call.get('arg_node'):
            # 检查参数是否来自用户输入源
            if is_argument_from_user_input(call['arg_node'], user_input_sources, root):
                risk_factors.append("参数可能来自用户输入")
                is_vulnerable = True

            # 检查参数是否经过字符串操作
            if is_argument_manipulated(call['arg_node'], root, code):
                risk_factors.append("参数经过字符串拼接操作")
                is_vulnerable = True

        # 分析3：函数类型分析
        if call['function'].lower() in ['system', 'popen']:
            risk_factors.append("使用高危命令执行函数")
            is_vulnerable = True

        # 确定严重程度
        if is_vulnerable:
            if len(risk_factors) >= 2 or any('用户输入' in factor for factor in risk_factors):
                vulnerability_details['severity'] = '高危'
            else:
                vulnerability_details['severity'] = '中危'

            vulnerability_details['message'] = f"命令注入风险: {call['function']}调用"
            vulnerability_details['risk_factors'] = risk_factors
            vulnerability_details['recommendation'] = get_remediation_recommendation(call)

            vulnerabilities.append(vulnerability_details)

    return vulnerabilities


def is_argument_from_user_input(arg_node, user_input_sources, root):
    """
    检查参数是否来自用户输入
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查变量名是否匹配用户输入源
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'user', 'cmd']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查数据流关系
    for source in user_input_sources:
        if is_data_flow_related(arg_node, source['node'], root):
            return True

    return False


def is_argument_manipulated(arg_node, root, code):
    """
    检查参数是否经过字符串操作
    """
    # 简单的文本分析：检查附近是否有字符串操作函数
    node_text = arg_node.text.decode('utf8')

    string_operations = ['sprintf', 'strcat', 'strcpy', 'snprintf', 'vsprintf']
    for op in string_operations:
        if op in code[max(0, arg_node.start_byte - 100):arg_node.end_byte + 100]:
            return True

    return False


def is_data_flow_related(node1, node2, root):
    """
    简化的数据流关系检查
    """
    # 在实际实现中，这里应该进行更复杂的数据流分析
    # 这里使用简单的文本和位置关系作为近似
    return (node1.start_point[0] > node2.start_point[0] and
            abs(node1.start_point[0] - node2.start_point[0]) < 50)


def get_remediation_recommendation(vulnerability):
    """
    根据漏洞类型提供修复建议
    """
    func = vulnerability.get('function', '').lower()

    recommendations = {
        'system': '使用安全的API替代system函数，如使用exec系列函数并正确转义参数',
        'popen': '使用popen时应对命令参数进行严格验证和转义',
        'sprintf': '使用snprintf替代sprintf，避免缓冲区溢出',
        'getenv': '对环境变量值进行严格验证'
    }

    for key, recommendation in recommendations.items():
        if key in func:
            return recommendation

    return '对用户输入进行严格验证，使用白名单机制，避免直接拼接命令字符串'


def analyze_c_code_for_command_injection(code_string):
    """
    分析C代码字符串中的命令注入漏洞
    """
    return detect_command_injection_vulnerabilities(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 危险示例 - 命令注入漏洞
void vulnerable_examples(int argc, char* argv[]) {
    char command[100];
    char user_input[100];

    // 直接使用用户输入
    system(argv[1]);  // 高危: 直接使用命令行参数

    // 字符串拼接命令
    sprintf(command, "ls %s", argv[1]);  // 中危: 拼接用户输入
    system(command);

    // 环境变量使用
    char* path = getenv("USER_INPUT");
    if (path) {
        system(path);  // 高危: 使用环境变量作为命令
    }

    // 从文件读取命令
    FILE* f = fopen("command.txt", "r");
    fgets(user_input, sizeof(user_input), f);
    fclose(f);
    system(user_input);  // 高危: 使用文件内容作为命令

    // 网络数据直接使用
    char buffer[1024];
    read(0, buffer, sizeof(buffer));  // 从标准输入读取
    system(buffer);  // 高危: 使用网络数据作为命令

    // 复杂的字符串构建
    char cmd[200];
    char* base_cmd = "echo ";
    strcpy(cmd, base_cmd);
    strcat(cmd, argv[1]);  // 中危: 字符串拼接
    strcat(cmd, " | sort");
    system(cmd);
}

// 相对安全的示例
void safe_examples() {
    // 硬编码命令
    system("ls -la");  // 安全: 硬编码命令

    // 使用白名单验证
    char* valid_commands[] = {"list", "status", "help"};
    char user_choice[10];
    scanf("%9s", user_choice);

    // 白名单检查
    int valid = 0;
    for (int i = 0; i < 3; i++) {
        if (strcmp(user_choice, valid_commands[i]) == 0) {
            valid = 1;
            break;
        }
    }

    if (valid) {
        char safe_cmd[50];
        snprintf(safe_cmd, sizeof(safe_cmd), "echo %s", user_choice);
        system(safe_cmd);  // 相对安全: 经过白名单验证
    }

    // 使用参数化执行
    char* args[] = {"ls", "-la", NULL};
    execvp("ls", args);  // 较安全: 参数化执行
}

int main(int argc, char* argv[]) {
    vulnerable_examples(argc, argv);
    safe_examples();
    return 0;
}
"""

    print("=" * 60)
    print("C语言命令注入漏洞检测")
    print("=" * 60)

    results = analyze_c_code_for_command_injection(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在命令注入漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   函数: {vuln['function']}")
            print(f"   代码片段: {vuln['code_snippet'][:80]}...")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   风险因素: {', '.join(vuln.get('risk_factors', []))}")
            print(f"   修复建议: {vuln.get('recommendation', '')}")
    else:
        print("未检测到命令注入漏洞")

    # 统计信息
    if results:
        high_severity = sum(1 for vuln in results if vuln['severity'] == '高危')
        medium_severity = sum(1 for vuln in results if vuln['severity'] == '中危')
        print(f"\n统计信息: 高危 {high_severity}个, 中危 {medium_severity}个")