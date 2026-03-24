import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# SMTP标头操纵漏洞模式
SMTP_HEADER_INJECTION_VULNERABILITIES = {
    'c': [
        # 检测SMTP相关函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(smtp_send|smtp_command|send_mail|smtp_write|smtp_printf)$',
            'message': 'SMTP发送函数调用'
        },
        # 检测邮件头设置函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @header_name (_) @header_value)
                ) @call
            ''',
            'func_pattern': r'^(smtp_set_header|smtp_add_header|set_header|add_header)$',
            'message': '邮件头设置函数'
        },
        # 检测收件人/发件人设置函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @recipient_arg)
                ) @call
            ''',
            'func_pattern': r'^(smtp_set_recipient|smtp_set_from|set_recipient|set_from)$',
            'message': '收件人/发件人设置函数'
        },
        # 检测主题设置函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @subject_arg)
                ) @call
            ''',
            'func_pattern': r'^(smtp_set_subject|set_subject)$',
            'message': '邮件主题设置函数'
        },
        # 检测邮件内容设置函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @body_arg)
                ) @call
            ''',
            'func_pattern': r'^(smtp_set_body|set_body|smtp_set_content)$',
            'message': '邮件内容设置函数'
        },
        # 检测SMTP命令发送
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @command_arg)
                ) @call
            ''',
            'func_pattern': r'^(smtp_command|send_command)$',
            'message': 'SMTP命令发送函数'
        },
        # 检测字符串连接操作（可能用于构建SMTP命令）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @str_args)
                ) @call
            ''',
            'func_pattern': r'^(strcat|strncat|sprintf|snprintf|vsprintf)$',
            'message': '字符串连接函数，可能用于构建SMTP命令'
        }
    ]
}

# SMTP相关头字段模式
SMTP_HEADER_PATTERNS = {
    'headers': [
        r'To:',
        r'From:',
        r'Subject:',
        r'Cc:',
        r'Bcc:',
        r'Reply-To:',
        r'Date:',
        r'Content-Type:',
        r'Content-Transfer-Encoding:',
        r'MIME-Version:'
    ],
    'smtp_commands': [
        r'MAIL FROM:',
        r'RCPT TO:',
        r'DATA',
        r'QUIT',
        r'HELO',
        r'EHLO',
        r'RSET',
        r'VRFY',
        r'EXPN'
    ],
    'injection_indicators': [
        r'\\r\\n',  # CRLF序列
        r'\\n',  # LF序列
        r'%0d%0a',  # URL编码的CRLF
        r'%0a',  # URL编码的LF
        r'\\r',  # CR字符
    ]
}

# 用户输入源模式（用于SMTP上下文）
SMTP_USER_INPUT_SOURCES = {
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
        },
        {
            'func_pattern': r'^(strcpy|strncpy|strcat|strncat|sprintf|snprintf)$',
            'message': '字符串处理函数（可能处理用户输入）'
        }
    ]
}


def detect_c_smtp_header_injection(code, language='c'):
    """
    检测C代码中SMTP标头操纵漏洞

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
    smtp_related_calls = []  # 存储SMTP相关函数调用
    user_input_sources = []  # 存储用户输入源
    suspicious_strings = []  # 存储可疑字符串

    # 第一步：收集SMTP相关函数调用
    for query_info in SMTP_HEADER_INJECTION_VULNERABILITIES[language]:
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
                        current_capture[
                            'node_id'] = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"

                elif tag in ['args', 'header_name', 'header_value', 'recipient_arg',
                             'subject_arg', 'body_arg', 'command_arg', 'str_args']:
                    arg_text = node.text.decode('utf8')
                    if 'args' not in current_capture:
                        current_capture['args'] = []
                    current_capture['args'].append({
                        'text': arg_text,
                        'node': node,
                        'tag': tag,
                        'node_id': f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"
                    })

                elif tag in ['call']:
                    if current_capture:
                        code_snippet = node.text.decode('utf8')

                        # 处理函数调用
                        smtp_related_calls.append({
                            'type': 'smtp_function',
                            'line': current_capture.get('line', node.start_point[0] + 1),
                            'function': current_capture.get('func', ''),
                            'args': current_capture.get('args', []),
                            'code_snippet': code_snippet,
                            'node': node,
                            'node_id': current_capture.get('node_id',
                                                           f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"),
                            'message': query_info.get('message', '')
                        })

                        current_capture = {}

        except Exception as e:
            print(f"SMTP头注入查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(SMTP_USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                # 检查是否匹配任何用户输入模式
                for pattern_info in SMTP_USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')

                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        code_snippet = node.parent.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'node_id': f"{node.parent.start_point[0]}:{node.parent.start_point[1]}:{node.parent.end_point[0]}:{node.parent.end_point[1]}",
                            'arg_index': pattern_info.get('arg_index', None)
                        })
                        break

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：收集可疑字符串（单独查询，避免重复）
    try:
        string_query = LANGUAGES[language].query('''
            (string_literal) @string_lit
        ''')
        string_captures = string_query.captures(root)

        for node, tag in string_captures:
            if tag == 'string_lit':
                string_text = node.text.decode('utf8')
                if contains_crlf_pattern(string_text):
                    suspicious_strings.append({
                        'type': 'string_literal',
                        'line': node.start_point[0] + 1,
                        'text': string_text,
                        'code_snippet': node.text.decode('utf8'),
                        'node': node,
                        'node_id': f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"
                    })
    except Exception as e:
        print(f"字符串查询错误: {e}")

    # 第四步：分析SMTP标头操纵漏洞（使用智能去重）
    vulnerabilities = analyze_and_deduplicate_vulnerabilities(
        smtp_related_calls, suspicious_strings, user_input_sources, root
    )

    return vulnerabilities


def analyze_and_deduplicate_vulnerabilities(smtp_calls, suspicious_strings, user_input_sources, root_node):
    """
    分析漏洞并进行智能去重
    """
    all_vulnerabilities = []

    # 分析SMTP函数调用
    for call in smtp_calls:
        vulnerability_details = analyze_smtp_call_vulnerability(call, user_input_sources, root_node)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 分析可疑字符串
    for string_info in suspicious_strings:
        vulnerability_details = analyze_string_vulnerability(string_info, user_input_sources, root_node)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 智能去重
    return intelligent_smtp_deduplication(all_vulnerabilities)


def intelligent_smtp_deduplication(vulnerabilities):
    """
    智能去重：基于代码上下文和语义合并相似漏洞
    """
    if not vulnerabilities:
        return []

    # 按行号分组
    line_groups = {}
    for vuln in vulnerabilities:
        line = vuln['line']
        if line not in line_groups:
            line_groups[line] = []
        line_groups[line].append(vuln)

    # 对每行的漏洞进行智能合并
    deduplicated = []
    for line, vulns in line_groups.items():
        if len(vulns) == 1:
            deduplicated.append(vulns[0])
        else:
            # 多个漏洞，选择最准确的一个或合并信息
            best_vuln = select_best_smtp_vulnerability(vulns)
            deduplicated.append(best_vuln)

    return sorted(deduplicated, key=lambda x: x['line'])


def select_best_smtp_vulnerability(vulns):
    """
    从同一行的多个漏洞中选择最准确的一个
    """
    if len(vulns) == 1:
        return vulns[0]

    # 优先级：明确的注入 > 潜在风险 > 字符串模式
    priority_order = {
        'SMTP标头注入': 1,
        'SMTP命令注入': 1,
        '邮件头操纵': 2,
        'CRLF注入模式': 3,
        '潜在的SMTP头操纵': 4,
        '潜在的CRLF注入模式': 5
    }

    # 按优先级排序
    sorted_vulns = sorted(vulns, key=lambda x: priority_order.get(x['vulnerability_type'], 6))

    # 选择优先级最高的漏洞
    best_vuln = sorted_vulns[0]

    # 如果存在更具体的证据，合并信息
    for vuln in sorted_vulns[1:]:
        if 'evidence' in vuln and ('CRLF' in vuln['evidence'] or '注入' in vuln['evidence']):
            # 如果其他漏洞有更具体的注入证据，更新消息
            if 'CRLF注入' in vuln['evidence'] and 'CRLF注入' not in best_vuln['message']:
                best_vuln['message'] += f" | 检测到CRLF注入模式: {vuln['evidence'][:50]}"
                best_vuln['severity'] = max_severity(best_vuln['severity'], vuln['severity'])

    return best_vuln


def max_severity(sev1, sev2):
    """
    返回两个严重程度中较高的一个
    """
    severity_order = {'低危': 1, '中危': 2, '高危': 3}
    return sev1 if severity_order.get(sev1, 0) >= severity_order.get(sev2, 0) else sev2


def analyze_smtp_call_vulnerability(call, user_input_sources, root_node):
    """
    分析SMTP函数调用是否存在标头操纵漏洞
    """
    vulnerability_details = None

    # 检查参数是否包含用户输入
    user_input_args = []
    for arg in call.get('args', []):
        if is_user_input_related(arg['node'], user_input_sources, root_node):
            user_input_args.append(arg)

    if user_input_args:
        # 检查是否包含SMTP头字段或命令
        for arg in user_input_args:
            arg_text = arg['text']

            # 检查是否包含CRLF注入模式
            if contains_crlf_injection(arg_text):
                vulnerability_details = {
                    'line': call['line'],
                    'code_snippet': call['code_snippet'],
                    'vulnerability_type': 'SMTP标头注入',
                    'severity': '高危',
                    'message': f"SMTP函数 {call['function']} 参数包含CRLF注入风险",
                    'evidence': f"参数内容: {arg_text[:100]}..."
                }
                break

            # 检查是否直接使用用户输入构建SMTP命令
            elif is_smtp_command_building(call['function'], arg_text):
                vulnerability_details = {
                    'line': call['line'],
                    'code_snippet': call['code_snippet'],
                    'vulnerability_type': 'SMTP命令注入',
                    'severity': '高危',
                    'message': f"SMTP函数 {call['function']} 使用用户输入构建命令",
                    'evidence': f"参数内容: {arg_text[:100]}..."
                }
                break

            # 检查邮件头字段是否使用用户输入
            elif is_header_field_vulnerable(call['function'], arg):
                vulnerability_details = {
                    'line': call['line'],
                    'code_snippet': call['code_snippet'],
                    'vulnerability_type': '邮件头操纵',
                    'severity': '中危',
                    'message': f"邮件头设置函数 {call['function']} 使用未验证的用户输入",
                    'evidence': f"头字段内容: {arg_text[:100]}..."
                }
                break
        else:
            # 如果没有找到具体的注入模式，但使用了用户输入，报告为潜在风险
            if user_input_args:
                vulnerability_details = {
                    'line': call['line'],
                    'code_snippet': call['code_snippet'],
                    'vulnerability_type': '潜在的SMTP头操纵',
                    'severity': '中危',
                    'message': f"SMTP函数 {call['function']} 使用用户输入但未检测到明显注入模式",
                    'evidence': f"用户输入参数数量: {len(user_input_args)}"
                }

    return vulnerability_details


def analyze_string_vulnerability(string_info, user_input_sources, root_node):
    """
    分析字符串字面量是否存在SMTP注入风险
    """
    vulnerability_details = None
    string_text = string_info['text']

    # 检查字符串是否包含CRLF模式
    if contains_crlf_pattern(string_text):
        # 检查这个字符串是否与用户输入相关
        if is_user_input_related(string_info['node'], user_input_sources, root_node):
            vulnerability_details = {
                'line': string_info['line'],
                'code_snippet': string_info['code_snippet'],
                'vulnerability_type': 'CRLF注入模式',
                'severity': '中危',
                'message': "字符串包含CRLF模式且可能与用户输入相关",
                'evidence': f"字符串内容: {string_text[:100]}..."
            }
        else:
            # 即使不是直接用户输入，包含CRLF的模式也值得注意
            vulnerability_details = {
                'line': string_info['line'],
                'code_snippet': string_info['code_snippet'],
                'vulnerability_type': '潜在的CRLF注入模式',
                'severity': '低危',
                'message': "字符串包含CRLF注入模式",
                'evidence': f"字符串内容: {string_text[:100]}..."
            }

    return vulnerability_details


def contains_crlf_injection(text):
    """
    检查文本是否包含CRLF注入模式
    """
    injection_patterns = SMTP_HEADER_PATTERNS['injection_indicators']

    for pattern in injection_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    # 检查实际的CRLF字符（非转义）
    if '\r' in text or '\n' in text:
        return True

    return False


def contains_crlf_pattern(text):
    """
    检查文本是否包含CRLF模式（包括转义序列）
    """
    patterns = [
        r'\\r\\n',  # 转义的CRLF
        r'\\n',  # 转义的LF
        r'\\r',  # 转义的CR
        r'%0d%0a',  # URL编码
        r'%0a',
        r'%0d'
    ]

    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


def is_smtp_command_building(func_name, arg_text):
    """
    检查是否使用用户输入构建SMTP命令
    """
    smtp_commands = SMTP_HEADER_PATTERNS['smtp_commands']

    # 检查函数名是否与SMTP命令构建相关
    smtp_building_funcs = ['sprintf', 'snprintf', 'strcat', 'strncat']
    if func_name.lower() in smtp_building_funcs:
        # 检查参数中是否包含SMTP命令模式
        for command in smtp_commands:
            if re.search(command, arg_text, re.IGNORECASE):
                return True

    return False


def is_header_field_vulnerable(func_name, arg_info):
    """
    检查邮件头字段是否易受攻击
    """
    header_funcs = ['smtp_set_header', 'smtp_add_header', 'set_header', 'add_header']
    recipient_funcs = ['smtp_set_recipient', 'smtp_set_from', 'set_recipient', 'set_from']
    subject_funcs = ['smtp_set_subject', 'set_subject']
    body_funcs = ['smtp_set_body', 'set_body', 'smtp_set_content']

    if func_name.lower() in header_funcs:
        # 对于头设置函数，第二个参数（头值）是关键的
        if arg_info['tag'] == 'header_value':
            return True
    elif func_name.lower() in recipient_funcs + subject_funcs + body_funcs:
        # 这些函数的第一个参数就是关键参数
        return True

    return False


def is_user_input_related(node, user_input_sources, root_node):
    """
    检查节点是否与用户输入相关
    """
    node_text = node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user',
                       'email', 'subject', 'body', 'recipient', 'from_addr', 'to_addr']

    for var in user_input_vars:
        if re.search(rf'\b{var}\b', node_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        source_node_id = f"{source['node'].start_point[0]}:{source['node'].start_point[1]}:{source['node'].end_point[0]}:{source['node'].end_point[1]}"
        current_node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"

        if source_node_id == current_node_id or is_child_node(node, source['node']):
            return True

    # 检查变量是否来自输入函数
    if is_variable_from_input(node, root_node):
        return True

    return False


def is_variable_from_input(node, root_node):
    """
    检查变量是否来自输入函数（简单的数据流分析）
    """
    node_text = node.text.decode('utf8')

    # 简单的模式匹配：如果变量名包含输入相关的关键词
    input_keywords = ['input', 'read', 'scan', 'get', 'recv', 'argv']
    for keyword in input_keywords:
        if re.search(rf'\b\w*{keyword}\w*\b', node_text, re.IGNORECASE):
            return True

    return False


def is_child_node(child, parent):
    """
    检查一个节点是否是另一个节点的子节点
    """
    node = child
    while node:
        if (node.start_point[0] == parent.start_point[0] and
                node.start_point[1] == parent.start_point[1] and
                node.end_point[0] == parent.end_point[0] and
                node.end_point[1] == parent.end_point[1]):
            return True
        node = node.parent
    return False


def analyze_smtp_header_injection(code_string):
    """
    分析C代码字符串中的SMTP标头操纵漏洞
    """
    return detect_c_smtp_header_injection(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

// 危险的SMTP实现示例
void vulnerable_smtp_functions(int argc, char* argv[]) {
    char email[256];
    char subject[256];
    char body[1024];

    // 直接从命令行参数获取邮件内容（危险！）
    if (argc > 1) {
        strcpy(email, argv[1]);  // 可能包含CRLF注入
    }
    if (argc > 2) {
        strcpy(subject, argv[2]); // 可能包含恶意主题
    }
    if (argc > 3) {
        strcpy(body, argv[3]);   // 可能包含恶意内容
    }

    // 危险的SMTP头设置
    smtp_set_header("To", email);      // 直接使用用户输入
    smtp_set_header("From", "sender@example.com");
    smtp_set_header("Subject", subject); // 用户控制的主题

    // 构建SMTP命令（危险！）
    char command[512];
    sprintf(command, "RCPT TO: %s", email);  // 命令注入风险

    // 发送SMTP命令
    smtp_command(command);

    // 更危险的例子：直接拼接CRLF
    char malicious_header[512];
    sprintf(malicious_header, "To: %s\\r\\nBcc: attacker@evil.com", email);
    smtp_send(malicious_header);

    // 使用未验证的用户输入作为邮件体
    smtp_set_body(body);
}

// 相对安全的SMTP实现
void safe_smtp_functions() {
    // 使用硬编码或验证过的值
    smtp_set_header("To", "recipient@example.com");
    smtp_set_header("From", "sender@example.com");
    smtp_set_header("Subject", "Safe Subject");

    // 安全的命令构建
    char safe_command[256];
    snprintf(safe_command, sizeof(safe_command), "RCPT TO: %s", "recipient@example.com");

    // 输入验证和清理
    char user_input[256];
    fgets(user_input, sizeof(user_input), stdin);

    // 移除可能的CRLF字符
    char *crlf = strchr(user_input, '\\r');
    if (crlf) *crlf = '\\0';
    crlf = strchr(user_input, '\\n');
    if (crlf) *crlf = '\\0';

    // 长度限制
    if (strlen(user_input) < 100) {
        smtp_set_header("Reply-To", user_input);
    }
}

// SMTP命令构建函数
void build_smtp_commands(char* recipient) {
    // 危险的命令构建
    char cmd1[100];
    strcpy(cmd1, "MAIL FROM: sender@example.com");

    char cmd2[200];
    sprintf(cmd2, "RCPT TO: %s", recipient);  // 注入风险

    char cmd3[300];
    strcat(cmd3, "DATA\\r\\n");
    strcat(cmd3, "Subject: Test\\r\\n");
    strcat(cmd3, "\\r\\n");
    strcat(cmd3, "This is a test message\\r\\n");
    strcat(cmd3, ".\\r\\n");
}

int main(int argc, char* argv[]) {
    vulnerable_smtp_functions(argc, argv);
    safe_smtp_functions();
    return 0;
}
"""

    print("=" * 60)
    print("C语言SMTP标头操纵漏洞检测（智能去重版）")
    print("=" * 60)

    results = analyze_smtp_header_injection(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            if 'evidence' in vuln:
                print(f"   证据: {vuln['evidence']}")
    else:
        print("未检测到SMTP标头操纵漏洞")