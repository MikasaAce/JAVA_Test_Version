import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# HTTP重定向相关模式
REDIRECT_PATTERNS = {
    'redirect_keywords': [
        r'location:', r'location\s*:', r'redirect', r'redirect_to', r'redirect_uri',
        r'url=', r'return_url', r'return_to', r'next', r'goto', r'target',
        r'forward', r'jump', r'dest', r'destination', r'link', r'href'
    ],
    'http_status_codes': [
        r'301', r'302', r'303', r'307', r'308'  # 重定向状态码
    ],
    'redirect_functions': [
        r'send', r'printf', r'sprintf', r'write', r'fwrite', r'fprintf'
    ],
    'url_schemes': [
        r'http://', r'https://', r'ftp://', r'file://', r'javascript:',
        r'data:', r'mailto:', r'tel:'
    ],
    'dangerous_redirect_patterns': [
        r'//.*\..*/',  # 包含域名的URL
        r'https?://[^/]*[.,]',  # 外部域名
        r'\.(com|org|net|cn|ru|tk|ml|ga|cf)[^/]*'  # 常见顶级域名
    ]
}


def detect_c_open_redirection(code, language='c'):
    """
    检测C代码中的Open重定向漏洞
    """
    if language not in LANGUAGES:
        return []

    parser = Parser()
    parser.set_language(LANGUAGES[language])
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    vulnerabilities = []

    # 收集所有相关信息
    redirect_operations = find_redirect_operations(root)
    user_input_sources = find_user_input_sources(root)
    url_operations = find_url_operations(root)
    http_operations = find_http_operations(root)

    # 分析漏洞模式
    vuln_list = []
    vuln_list.extend(analyze_redirect_with_user_input(redirect_operations, user_input_sources))
    vuln_list.extend(analyze_unsafe_url_redirects(url_operations, user_input_sources))
    vuln_list.extend(analyze_http_redirects(http_operations, user_input_sources))
    vuln_list.extend(analyze_dynamic_redirects(root, user_input_sources))

    # 智能去重：基于代码上下文和语义
    vulnerabilities = intelligent_deduplication(vuln_list)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def intelligent_deduplication(vuln_list):
    """智能去重：合并相同代码位置的相似漏洞"""
    if not vuln_list:
        return []

    # 按行号分组
    line_groups = {}
    for vuln in vuln_list:
        line = vuln['line']
        if line not in line_groups:
            line_groups[line] = []
        line_groups[line].append(vuln)

    # 对每行的漏洞进行合并
    deduplicated = []
    for line, vulns in line_groups.items():
        if len(vulns) == 1:
            # 只有一个漏洞，直接添加
            deduplicated.append(vulns[0])
        else:
            # 多个漏洞，选择最准确的一个
            best_vuln = select_best_vulnerability(vulns)
            deduplicated.append(best_vuln)

    return deduplicated


def select_best_vulnerability(vulns):
    """从同一行的多个漏洞中选择最准确的一个"""
    if len(vulns) == 1:
        return vulns[0]

    # 优先级：HTTP输出 > URL构造 > 字符串检测 > 动态赋值
    priority_order = {
        'Open重定向-HTTP输出': 1,
        'Open重定向-URL构造': 2,
        'Open重定向-字符串检测': 3,
        'Open重定向-动态赋值': 4
    }

    # 按优先级排序
    sorted_vulns = sorted(vulns, key=lambda x: priority_order.get(x['vulnerability_type'], 5))

    # 选择优先级最高的，如果消息不够详细，尝试合并信息
    best_vuln = sorted_vulns[0]

    # 如果存在更详细的消息，优先使用
    for vuln in sorted_vulns:
        if len(vuln['message']) > len(best_vuln['message']):
            best_vuln = vuln

    return best_vuln


def find_redirect_operations(root):
    """查找重定向相关操作"""
    redirect_ops = []
    processed_positions = set()

    # 查找包含重定向关键词的字符串
    try:
        query = LANGUAGES['c'].query('(string_literal) @string_lit')
        captures = query.captures(root)

        for node, tag in captures:
            node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"
            if node_id in processed_positions:
                continue

            content = node.text.decode('utf8')
            line = node.start_point[0] + 1

            # 检查是否包含重定向模式
            redirect_info = extract_redirect_info(content, line)
            if redirect_info:
                redirect_info.update({
                    'node': node,
                    'content': content,
                    'code_snippet': node.text.decode('utf8'),
                    'node_id': node_id
                })
                redirect_ops.append(redirect_info)
                processed_positions.add(node_id)

    except Exception as e:
        print(f"查找重定向字符串错误: {e}")

    return redirect_ops


def extract_redirect_info(content, line):
    """从字符串内容中提取重定向信息"""
    content_lower = content.lower()

    # 检测Location头（最高优先级）
    location_match = re.search(r'location\s*:', content_lower)
    if location_match:
        return {
            'line': line,
            'type': 'location_header',
            'keyword': 'location:',
            'priority': 1
        }

    # 检测其他重定向关键词
    for keyword in REDIRECT_PATTERNS['redirect_keywords']:
        if re.search(keyword, content_lower, re.IGNORECASE):
            return {
                'line': line,
                'type': 'redirect_keyword',
                'keyword': keyword,
                'priority': 2
            }

    # 检测HTTP状态码
    for status_code in REDIRECT_PATTERNS['http_status_codes']:
        if status_code in content:
            return {
                'line': line,
                'type': 'http_status',
                'status_code': status_code,
                'priority': 3
            }

    return None


def find_user_input_sources(root):
    """查找用户输入源"""
    user_inputs = []
    processed_positions = set()

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

        current_call = None
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
                node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"
                if node_id not in processed_positions:
                    args = get_function_arguments(node)
                    user_inputs.append({
                        'node': node,
                        'func_name': current_call['func_name'],
                        'line': node.start_point[0] + 1,
                        'arguments': args,
                        'code_snippet': node.text.decode('utf8'),
                        'type': 'user_input_function',
                        'node_id': node_id
                    })
                    processed_positions.add(node_id)
                current_call = None

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
                node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"
                if node_id not in processed_positions:
                    user_inputs.append({
                        'node': node.parent,
                        'func_name': 'main',
                        'line': node.start_point[0] + 1,
                        'arguments': ['argv'],
                        'code_snippet': node.parent.text.decode('utf8')[:100],
                        'type': 'main_argv',
                        'node_id': node_id
                    })
                    processed_positions.add(node_id)
                break

    except Exception as e:
        print(f"查找main函数错误: {e}")

    return user_inputs


def find_url_operations(root):
    """查找URL相关操作"""
    url_ops = []
    processed_positions = set()

    try:
        query = LANGUAGES['c'].query('''
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list (_)* @args)
            ) @call
        ''')
        captures = query.captures(root)

        current_call = None
        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                if re.match(r'^(sprintf|snprintf|strcpy|strncpy|strcat|strncat)$', func_name, re.IGNORECASE):
                    current_call = {
                        'func_name': func_name,
                        'func_node': node
                    }

            elif tag == 'call' and current_call:
                node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"
                if node_id not in processed_positions:
                    args = get_function_arguments(node)
                    url_info = extract_url_info(args, node.start_point[0] + 1)
                    if url_info:
                        url_info.update({
                            'node': node,
                            'func_name': current_call['func_name'],
                            'arguments': args,
                            'code_snippet': node.text.decode('utf8'),
                            'type': 'url_construction',
                            'node_id': node_id
                        })
                        url_ops.append(url_info)
                    processed_positions.add(node_id)
                current_call = None

    except Exception as e:
        print(f"查找URL操作错误: {e}")

    # 查找包含URL的字符串字面量
    try:
        query = LANGUAGES['c'].query('(string_literal) @string_lit')
        captures = query.captures(root)

        for node, tag in captures:
            node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"
            if node_id not in processed_positions:
                content = node.text.decode('utf8')
                url_info = extract_url_info([content], node.start_point[0] + 1)
                if url_info:
                    url_info.update({
                        'node': node,
                        'content': content,
                        'code_snippet': content,
                        'type': 'url_string',
                        'node_id': node_id
                    })
                    url_ops.append(url_info)
                processed_positions.add(node_id)

    except Exception as e:
        print(f"查找URL字符串错误: {e}")

    return url_ops


def extract_url_info(args, line):
    """从参数中提取URL信息"""
    for arg in args:
        for scheme in REDIRECT_PATTERNS['url_schemes']:
            if scheme in arg.lower():
                return {
                    'line': line,
                    'url_scheme': scheme
                }
    return None


def find_http_operations(root):
    """查找HTTP相关操作"""
    http_ops = []
    processed_positions = set()

    try:
        query = LANGUAGES['c'].query('''
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list) @args
            ) @call
        ''')
        captures = query.captures(root)

        current_call = None
        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                if func_name.lower() in ['send', 'write', 'printf', 'fprintf', 'sprintf']:
                    current_call = {
                        'func_name': func_name,
                        'func_node': node
                    }

            elif tag == 'call' and current_call:
                node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"
                if node_id not in processed_positions:
                    http_ops.append({
                        'node': node,
                        'func_name': current_call['func_name'],
                        'line': node.start_point[0] + 1,
                        'code_snippet': node.text.decode('utf8'),
                        'type': 'http_output',
                        'node_id': node_id
                    })
                    processed_positions.add(node_id)
                current_call = None

    except Exception as e:
        print(f"查找HTTP操作错误: {e}")

    return http_ops


def analyze_redirect_with_user_input(redirect_ops, user_inputs):
    """分析重定向操作与用户输入的关联"""
    vulnerabilities = []
    processed_lines = set()

    for redirect_op in redirect_ops:
        line = redirect_op['line']
        if line in processed_lines:
            continue

        # 检查重定向操作附近是否有用户输入
        for user_input in user_inputs:
            if abs(line - user_input['line']) <= 5:  # 5行范围内
                vulnerabilities.append({
                    'line': line,
                    'code_snippet': redirect_op['code_snippet'],
                    'vulnerability_type': 'Open重定向-字符串检测',
                    'severity': '中危' if redirect_op.get('priority', 0) > 1 else '高危',
                    'message': f"重定向字符串附近发现用户输入: {redirect_op.get('keyword', redirect_op.get('type', '重定向'))}",
                    'related_line': user_input['line'],
                    'related_code': user_input['code_snippet'][:50]
                })
                processed_lines.add(line)
                break

    return vulnerabilities


def analyze_unsafe_url_redirects(url_ops, user_inputs):
    """分析不安全的URL重定向"""
    vulnerabilities = []
    processed_lines = set()

    for url_op in url_ops:
        line = url_op['line']
        if line in processed_lines:
            continue

        # 检查URL操作是否涉及用户输入
        if is_user_input_related(url_op['node'], user_inputs):
            # 检查URL是否包含外部域名模式
            content = url_op.get('content', url_op['code_snippet'])
            if contains_external_url(content):
                vulnerabilities.append({
                    'line': line,
                    'code_snippet': url_op['code_snippet'],
                    'vulnerability_type': 'Open重定向-URL构造',
                    'severity': '高危',
                    'message': f"用户输入用于构造外部URL重定向: {url_op['func_name'] if 'func_name' in url_op else '字符串操作'}",
                    'url_scheme': url_op.get('url_scheme', '未知')
                })
                processed_lines.add(line)

    return vulnerabilities


def analyze_http_redirects(http_ops, user_inputs):
    """分析HTTP重定向"""
    vulnerabilities = []
    processed_lines = set()

    for http_op in http_ops:
        line = http_op['line']
        if line in processed_lines:
            continue

        code = http_op['code_snippet'].lower()

        # 检查是否包含Location头
        if 'location:' in code:
            # 检查是否涉及用户输入
            if is_user_input_related(http_op['node'], user_inputs):
                vulnerabilities.append({
                    'line': line,
                    'code_snippet': http_op['code_snippet'],
                    'vulnerability_type': 'Open重定向-HTTP输出',
                    'severity': '高危',
                    'message': f"用户输入用于构造HTTP Location重定向头: {http_op['func_name']}"
                })
                processed_lines.add(line)

    return vulnerabilities


def analyze_dynamic_redirects(root, user_inputs):
    """分析动态重定向"""
    vulnerabilities = []
    processed_lines = set()

    try:
        query = LANGUAGES['c'].query('''
            (assignment_expression
                left: (_) @left
                right: (_) @right
            ) @assign
        ''')
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'assign':
                line = node.start_point[0] + 1
                if line in processed_lines:
                    continue

                assign_text = node.text.decode('utf8').lower()
                # 检查是否包含重定向关键词和URL模式
                has_redirect = any(keyword in assign_text for keyword in REDIRECT_PATTERNS['redirect_keywords'])
                has_url = any(scheme in assign_text for scheme in REDIRECT_PATTERNS['url_schemes'])

                if has_redirect and has_url:
                    # 检查是否涉及用户输入
                    if is_user_input_related(node, user_inputs):
                        vulnerabilities.append({
                            'line': line,
                            'code_snippet': node.text.decode('utf8'),
                            'vulnerability_type': 'Open重定向-动态赋值',
                            'severity': '中危',
                            'message': "动态赋值可能用于构造不安全的重定向URL"
                        })
                        processed_lines.add(line)

    except Exception as e:
        print(f"分析动态重定向错误: {e}")

    return vulnerabilities


def is_user_input_related(node, user_inputs):
    """检查节点是否与用户输入相关"""
    node_text = node.text.decode('utf8').lower()
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'query', 'url']

    for var in user_input_vars:
        if re.search(rf'\b{var}\b', node_text):
            return True

    node_line = node.start_point[0] + 1
    for user_input in user_inputs:
        if abs(node_line - user_input['line']) <= 3:
            return True

    return False


def contains_external_url(text):
    """检查文本是否包含外部URL模式"""
    text_lower = text.lower()

    for pattern in REDIRECT_PATTERNS['dangerous_redirect_patterns']:
        if re.search(pattern, text_lower):
            return True

    if re.search(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', text_lower):
        return True

    return False


def get_function_arguments(call_node):
    """获取函数调用的参数列表"""
    arguments = []
    for child in call_node.children:
        if child.type == 'argument_list':
            for arg in child.children:
                if arg.type not in ['(', ')', ',']:
                    arguments.append(arg.text.decode('utf8'))
    return arguments


def analyze_c_open_redirect(code_string):
    """分析C代码字符串中的Open重定向漏洞"""
    return detect_c_open_redirection(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    test_c_code = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void insecure_redirect_examples(int argc, char* argv[]) {
    char buffer[1024];
    char response[2048];

    // 漏洞1: 直接使用用户输入进行重定向
    char* redirect_url = argv[1];
    sprintf(response, "HTTP/1.1 302 Found\\r\\nLocation: %s\\r\\n\\r\\n", redirect_url);

    // 漏洞2: 从查询参数获取重定向URL
    char query_string[] = "url=http://evil.com";
    char url[256];
    sscanf(query_string, "url=%s", url);
    sprintf(response, "Location: %s\\r\\n", url);

    // 漏洞3: 不安全的URL拼接
    char base_url[] = "http://example.com/redirect?target=";
    char user_target[100];
    strcpy(user_target, argv[1]);
    char full_url[200];
    sprintf(full_url, "%s%s", base_url, user_target);
}

void secure_redirect_examples() {
    char response[1024];
    sprintf(response, "HTTP/1.1 302 Found\\r\\nLocation: /dashboard\\r\\n\\r\\n");
}

int main(int argc, char* argv[]) {
    insecure_redirect_examples(argc, argv);
    secure_redirect_examples();
    return 0;
}
"""

    print("=" * 60)
    print("C语言Open重定向漏洞检测（智能去重版）")
    print("=" * 60)

    results = analyze_c_open_redirect(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在Open重定向漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            if 'related_line' in vuln:
                print(f"   关联行号: {vuln['related_line']}")
    else:
        print("未检测到Open重定向漏洞")