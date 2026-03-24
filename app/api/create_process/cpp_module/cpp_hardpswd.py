import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义硬编码密码检测模式
HARDCODED_PASSWORD_VULNERABILITIES = {
    'cpp': [
        # 检测字符串字面量中的密码
        {
            'query': '''
                (string_literal) @string_literal
            ''',
            'message': '字符串字面量中可能包含硬编码密码'
        },
        # 检测字符数组初始化中的密码
        {
            'query': '''
                (init_declarator
                    declarator: (_) @declarator
                    value: (initializer_list
                        (string_literal) @string_literal
                    )
                ) @init
            ''',
            'message': '字符数组初始化中可能包含硬编码密码'
        },
        # 检测赋值语句中的密码
        {
            'query': '''
                (assignment_expression
                    left: (_) @left
                    right: (string_literal) @string_literal
                ) @assignment
            ''',
            'message': '赋值语句中可能包含硬编码密码'
        },
        # 检测函数调用参数中的密码
        {
            'query': '''
                (call_expression
                    function: (_) @func
                    arguments: (argument_list
                        (string_literal) @string_literal
                    )
                ) @call
            ''',
            'message': '函数调用参数中可能包含硬编码密码'
        },
        # 检测宏定义中的密码
        {
            'query': '''
                (preproc_def
                    name: (_) @name
                    value: (string_literal) @string_literal
                ) @macro
            ''',
            'message': '宏定义中可能包含硬编码密码'
        }
    ]
}

# 密码相关函数模式（用于减少误报）
PASSWORD_RELATED_FUNCTIONS = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    ''',
    'patterns': [
        r'^(strcmp|strncmp|memcmp|strcpy|strncpy|strcat|strncat)$',
        r'^(wcscmp|wcsncmp|wcscpy|wcsncpy|wcscat|wcsncat)$',
        r'^(printf|sprintf|snprintf|fprintf|vprintf|vsprintf)$',
        r'^(malloc|calloc|realloc|free|memset|memcpy|memmove)$',
        r'^(CryptEncrypt|CryptDecrypt|CryptHashData|CryptDeriveKey)$',
        r'^(EVP_EncryptInit|EVP_DecryptInit|EVP_CipherInit)$',
        r'^(RSA_public_encrypt|RSA_private_decrypt)$',
        r'^(AES_encrypt|AES_decrypt|DES_encrypt|DES_decrypt)$',
        r'^(SSL_connect|SSL_accept|SSL_read|SSL_write)$',
        r'^(setpassword|setpasswd|setcredential|setauth)$'
    ]
}

# 密码相关变量名模式（用于减少误报）
PASSWORD_RELATED_VARIABLES = {
    'query': '''
        [
            (declaration
                declarator: (_) @declarator
            )
            (assignment_expression
                left: (identifier) @var_name
            )
        ] @stmt
    ''',
    'patterns': [
        r'^(password|passwd|pwd|pass|secret|key|token|credential|auth)$',
        r'^(db_pass|db_password|db_pwd|db_secret)$',
        r'^(api_key|api_token|access_key|access_token)$',
        r'^(encryption_key|decryption_key|private_key|public_key)$',
        r'^(login_pass|user_pass|admin_pass|root_pass)$'
    ]
}

# 需要排除的上下文函数（这些函数中的字符串参数不是硬编码密码）
EXCLUDED_CONTEXT_FUNCTIONS = [
    # getenv的参数是环境变量名，不是密码值
    r'^getenv$',
    r'^_wgetenv$',
    r'^SecureZeroMemory$',
]

# 非密码字符串的额外模式
NON_PASSWORD_STRING_PATTERNS = [
    r'^%[sd]$',           # 格式字符串 "%s", "%d"
    r'^%\.\d+[sf]$ ',     # 精度格式 "%.*s", "%.2f"
    r'^%0?\d*[dxX]$ ',    # 十六进制/十进制 "%02x", "%d"
    r'^%[0-9]*\*?[sd]$ ', # 动态宽度格式
    r'^\.$',              # 单个点
    r'^\.\.$',            # 双点
    r'^\s+$',             # 纯空白
    r'^[\-/]$',           # 单个破折号或斜杠
    r'^[a-z]$',           # 单个字母
    r'^[0-9]+$',          # 纯数字（短）
    r'^[A-Z_]+$',         # 全大写下划线（常量名风格如 "SQLITE_OK"）
    r'^SELECT\b',         # SQL语句开头
    r'^INSERT\b',
    r'^UPDATE\b',
    r'^DELETE\b',
    r'^CREATE\b',
    r'^ALTER\b',
    r'^DROP\b',
    r'^BEGIN RSA',        # 证书头
    r'^-----',            # PEM标记
    r'^\w+=\w+',          # 简单键值对如 "password="
    r'^\w+,',             # 逗号分隔的简单词
    r'^\d+\.\d+\.\d+',    # 版本号或IP
    r'^0x[0-9a-fA-F]+$',  # 十六进制数
    r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # IPv4
]

# 演示/说明性文本（不应报告为密码）
DEMO_TEXT_PATTERNS = [
    r'^password=\s',
    r'^passwd=\s',
    r'^pwd=\s',
    r'^api_key,\s',
    r'^apikey,\s',
    r'^api-key,\s',
    r'^secret,\s',
    r'^secret_key,\s',
    r'^private_key,\s',
    r'^token,\s',
    r'^credential,\s',
    r'^credentials,\s',
    r'^password=,',
    r'^passwd=,',
]


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


def detect_hardcoded_passwords(code, language='cpp'):
    """
    检测C++代码中硬编码密码漏洞

    Args:
        code: C++源代码字符串
        language: 语言类型，默认为'cpp'

    Returns:
        list: 检测结果列表
    """
    if language not in LANGUAGES:
        return []

    # 预处理
    comment_lines = _parse_comment_lines(code)

    # 初始化解析器
    parser = Parser()
    parser.set_language(LANGUAGES[language])

    # 解析代码
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    safe_func_ranges = _collect_safe_function_ranges(LANGUAGES[language], root)

    vulnerabilities = []
    password_related_functions = []
    password_related_variables = []

    # 第一步：收集所有密码相关函数调用
    try:
        query = LANGUAGES[language].query(PASSWORD_RELATED_FUNCTIONS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in PASSWORD_RELATED_FUNCTIONS['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        password_related_functions.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break
    except Exception as e:
        print(f"密码相关函数查询错误: {e}")

    # 第二步：收集密码相关变量
    try:
        query = LANGUAGES[language].query(PASSWORD_RELATED_VARIABLES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['declarator', 'var_name']:
                var_name = node.text.decode('utf8')
                for pattern in PASSWORD_RELATED_VARIABLES['patterns']:
                    if re.match(pattern, var_name, re.IGNORECASE):
                        current_capture['var_name'] = var_name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1
                        break

            elif tag == 'stmt' and current_capture:
                password_related_variables.append({
                    'line': current_capture['line'],
                    'variable': current_capture['var_name'],
                    'code_snippet': node.text.decode('utf8'),
                    'node': node
                })
                current_capture = {}

    except Exception as e:
        print(f"密码相关变量查询错误: {e}")

    # 第三步：检测硬编码密码
    for query_info in HARDCODED_PASSWORD_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag == 'string_literal':
                    line_number = node.start_point[0] + 1

                    # 跳过注释中的代码
                    if line_number in comment_lines:
                        continue

                    # 跳过 safe_* 函数内的字符串
                    if _is_in_safe_function(line_number, safe_func_ranges):
                        continue

                    string_content = node.text.decode('utf8').strip('"\'')

                    # 检查字符串是否包含密码特征
                    if is_potential_password(string_content):
                        # 检查上下文，减少误报
                        if not is_false_positive(
                                node, password_related_functions,
                                password_related_variables, root, code):
                            code_snippet = get_code_snippet_with_context(node, code)

                            vulnerabilities.append({
                                'line': line_number,
                                'code_snippet': code_snippet,
                                'vulnerability_type': '硬编码密码',
                                'severity': '高危',
                                'message': query_info['message'],
                                'string_content': string_content
                            })

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def _is_in_safe_function(line_num, safe_func_ranges):
    """检查给定行号是否在 safe_* 函数的作用域内"""
    for start, end in safe_func_ranges:
        if start <= line_num <= end:
            return True
    return False


def is_potential_password(string_content):
    """
    检查字符串是否可能包含密码（更严格版本）
    """
    # 空字符串或过短字符串
    if len(string_content) < 4:
        return False

    # 排除明显的非密码字符串
    non_password_patterns = [
        r'^https?://',
        r'^www\.',
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',  # 邮箱
        r'^\d+$',  # 纯数字
        r'^[a-z]+$',  # 纯小写字母
        r'^[A-Z_]+$',  # 全大写下划线（常量名）
        r'^\s*$',  # 空白字符串
        r'^[!@#$%^&*()_+\-=\[\]{};:\\|,.<>/?]+$',  # 纯符号
    ]

    for pattern in non_password_patterns:
        if re.search(pattern, string_content):
            return False

    # 排除额外的非密码模式
    for pattern in NON_PASSWORD_STRING_PATTERNS:
        if re.search(pattern, string_content, re.IGNORECASE):
            return False

    # 排除演示/说明性文本
    for pattern in DEMO_TEXT_PATTERNS:
        if re.search(pattern, string_content, re.IGNORECASE):
            return False

    # 密码语义特征（核心关键词 - 必须至少含一个才可能是密码）
    semantic_keywords = [
        r'password', r'passwd', r'pwd', r'secret', r'key', r'token',
        r'credential', r'auth', r'login',
    ]

    has_semantic = any(re.search(p, string_content, re.IGNORECASE)
                      for p in semantic_keywords)

    # 字符多样性特征
    diversity_features = [
        r'[0-9]',   # 包含数字
        r'[A-Z]',   # 包含大写字母
        r'[a-z]',   # 包含小写字母
        r'[!@#$%^&*()_+\-=\[\]{};:\\|,.<>/?]',  # 包含特殊字符
    ]

    diversity_score = sum(1 for p in diversity_features
                          if re.search(p, string_content))

    # 判定逻辑：
    # 1. 含语义关键词且字符多样性>=2 → 可能是密码
    # 2. 不含语义关键词但字符多样性>=3且长度>=8 → 可能是密码
    # 3. 含语义关键词但纯小写/纯数字 → 仅当长度>=6时可能是密码
    if has_semantic:
        return diversity_score >= 1 or len(string_content) >= 6
    else:
        return diversity_score >= 3 and len(string_content) >= 8


def is_false_positive(string_node, password_related_functions,
                      password_related_variables, root_node, code):
    """
    检查是否是误报（密码相关上下文）
    """
    # 新增：检查是否在排除的上下文函数中（如getenv参数）
    if is_in_excluded_context(string_node, root_node, code):
        return True

    # 检查是否在密码相关函数调用中
    for func_call in password_related_functions:
        func_name = func_call['function']
        if is_node_in_function_argument(string_node, func_call['node']):
            # strcmp/strncmp中的字符串是比较值，不是硬编码密码
            if re.match(r'^(strcmp|strncmp|memcmp)$', func_name, re.IGNORECASE):
                return True
            # printf/sprintf/fprintf中的格式字符串不是密码
            if re.match(r'^(printf|sprintf|snprintf|fprintf)$', func_name, re.IGNORECASE):
                # 检查是否是第一个参数（格式字符串）
                if is_first_argument(string_node, func_call['node']):
                    return True
            # strncpy/strcpy中的源参数（第二个参数）不应重复报告
            if re.match(r'^(strcpy|strncpy)$', func_name, re.IGNORECASE):
                if is_second_argument(string_node, func_call['node']):
                    return True
            return True

    # 检查是否是明显的非密码字符串（URL、文件路径等）
    string_content = string_node.text.decode('utf8').strip('"\'')
    if is_obvious_non_password(string_content):
        return True

    return False


def is_in_excluded_context(string_node, root_node, code):
    """
    检查字符串节点是否在排除的上下文函数中
    例如：getenv("DB_PASSWORD") 中的 "DB_PASSWORD" 不应报告
    """
    parent = string_node.parent
    # 向上遍历AST找到call_expression
    while parent:
        if parent.type == 'call_expression':
            # 找到函数名
            for child in parent.children:
                if child.type == 'identifier':
                    func_name = child.text.decode('utf8')
                    for pattern in EXCLUDED_CONTEXT_FUNCTIONS:
                        if re.match(pattern, func_name, re.IGNORECASE):
                            return True
                    break
            break
        parent = parent.parent
    return False


def is_first_argument(string_node, call_node):
    """检查字符串节点是否是函数调用的第一个参数"""
    args_node = None
    for child in call_node.children:
        if child.type == 'argument_list':
            args_node = child
            break

    if args_node:
        for i, child in enumerate(args_node.children):
            if child == string_node:
                return i == 0  # 第一个参数（跳过逗号/括号等）
    return False


def is_second_argument(string_node, call_node):
    """检查字符串节点是否是函数调用的第二个参数"""
    args_node = None
    for child in call_node.children:
        if child.type == 'argument_list':
            args_node = child
            break

    if args_node:
        arg_index = 0
        for child in args_node.children:
            if child.type in ('string_literal', 'identifier',
                              'number_literal', 'call_expression'):
                if child == string_node:
                    return arg_index == 1
                arg_index += 1
    return False


def is_node_in_function_argument(target_node, function_node):
    """
    检查目标节点是否在函数调用的参数中
    """
    def traverse_children(node):
        if node == target_node:
            return True
        for child in node.children:
            if traverse_children(child):
                return True
        return False

    return traverse_children(function_node)


def is_node_assigned_to_variable(target_node, variable_node):
    """
    检查目标节点是否赋值给变量
    """
    parent = target_node.parent
    while parent:
        if parent.type == 'assignment_expression':
            for child in parent.children:
                if child == variable_node:
                    return True
        parent = parent.parent
    return False


def is_obvious_non_password(string_content):
    """
    检查是否是明显的非密码字符串
    """
    obvious_non_passwords = [
        # 常见文件扩展名
        r'\.(cpp|h|hpp|c|cc|java|py|js|html|css|xml|json|txt|md)$',
        # 常见协议
        r'^(http|https|ftp|file|ssh|telnet)://',
        # 常见路径
        r'^/(usr|bin|lib|etc|var|home|tmp|dev)/',
        r'^[A-Z]:\\(Windows|Program Files|Users|System32)\\',
        # 常见常量
        r'^(true|false|null|NULL|TRUE|FALSE)$',
        r'^(std|cout|cin|cerr|endl|printf|scanf)$',
        # 版本信息
        r'^v?(\d+\.)+\d+$',
        # UUID格式
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        # AWS密钥前缀（不是密码值本身）
        r'^AKIA[0-9A-Z]{16}$',
        # PEM证书标记
        r'^-----',
    ]

    for pattern in obvious_non_passwords:
        if re.search(pattern, string_content, re.IGNORECASE):
            return True

    return False


def get_code_snippet_with_context(node, code):
    """
    获取带上下文的代码片段
    """
    lines = code.split('\n')
    line_num = node.start_point[0]

    start_line = max(0, line_num - 2)
    end_line = min(len(lines), line_num + 3)

    context_lines = []
    for i in range(start_line, end_line):
        prefix = '>>> ' if i == line_num else '    '
        context_lines.append(f"{prefix}{lines[i]}")

    return '\n'.join(context_lines)


def analyze_cpp_code(code_string):
    """
    分析C++代码字符串中的硬编码密码漏洞
    """
    return detect_hardcoded_passwords(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <string>
#include <cstring>

using namespace std;

void vulnerable_function() {
    // 硬编码密码 - 高危
    const char* db_password = "Admin@123";
    string api_key = "sk_test_51abc123def456";

    // 连接字符串中的密码
    char connection_string[] = "Server=localhost;Database=test;User=admin;Password=P@ssw0rd!";

    // 加密密钥
    unsigned char encryption_key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

    // 函数调用中的密码
    connect_to_database("localhost", "admin", "secret123");

    // 认证令牌
    string auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
}

void safe_env_credentials() {
    // 安全: 从环境变量读取 - getenv参数不应报为密码
    const char* password = getenv("DB_PASSWORD");
    if (password == NULL) {
        printf("DB_PASSWORD environment variable not set\\n");
        return;
    }
}

void safe_function() {
    // 安全的做法 - 从环境变量获取
    const char* db_pass = getenv("DB_PASSWORD");

    // 明显的非密码字符串 - 不应报警
    string file_path = "/usr/local/bin/program";
    string url = "https://api.example.com/v1/data";
    string version = "1.2.3";

    // 密码比较函数 - 不应报警
    if (strcmp(input_password, "default") == 0) {
    }
}

int main() {
    vulnerable_function();
    safe_env_credentials();
    safe_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++硬编码密码漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   字符串内容: {vuln['string_content']}")
            print(f"   代码片段:\n{vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到硬编码密码漏洞")
