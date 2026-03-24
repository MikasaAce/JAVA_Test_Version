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

    # 初始化解析器
    parser = Parser()
    parser.set_language(LANGUAGES[language])

    # 解析代码
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    vulnerabilities = []
    password_related_functions = []  # 存储密码相关函数调用
    password_related_variables = []  # 存储密码相关变量

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
                    string_content = node.text.decode('utf8').strip('"\'')

                    # 检查字符串是否包含密码特征
                    if is_potential_password(string_content):
                        # 检查上下文，减少误报
                        if not is_false_positive(node, password_related_functions, password_related_variables, root):
                            line_number = node.start_point[0] + 1
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


def is_potential_password(string_content):
    """
    检查字符串是否可能包含密码
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
        r'^[a-zA-Z]+$',  # 纯字母
        r'^\s*$',  # 空白字符串
        r'^[!@#$%^&*()_+\-=\[\]{};:\\|,.<>/?]+$',  # 纯符号
    ]

    for pattern in non_password_patterns:
        if re.search(pattern, string_content):
            return False

    # 密码特征模式
    password_patterns = [
        r'password', r'passwd', r'pwd', r'secret', r'key', r'token',
        r'credential', r'auth', r'login', r'admin', r'root',
        r'[0-9]',  # 包含数字
        r'[A-Z]',  # 包含大写字母
        r'[a-z]',  # 包含小写字母
        r'[!@#$%^&*()_+\-=\[\]{};:\\|,.<>/?]',  # 包含特殊字符
    ]

    score = 0
    for pattern in password_patterns:
        if re.search(pattern, string_content, re.IGNORECASE):
            score += 1

    # 至少匹配3个密码特征，且长度适中
    return score >= 3 and 6 <= len(string_content) <= 64


def is_false_positive(string_node, password_related_functions, password_related_variables, root_node):
    """
    检查是否是误报（密码相关上下文）
    """
    # 检查是否在密码相关函数调用中
    for func_call in password_related_functions:
        if is_node_in_function_argument(string_node, func_call['node']):
            return True

    # 检查是否赋值给密码相关变量
    for var in password_related_variables:
        if is_node_assigned_to_variable(string_node, var['node']):
            return True

    # 检查是否是明显的非密码字符串（URL、文件路径等）
    string_content = string_node.text.decode('utf8').strip('"\'')
    if is_obvious_non_password(string_content):
        return True

    return False


def is_node_in_function_argument(target_node, function_node):
    """
    检查目标节点是否在函数调用的参数中
    """

    # 遍历函数节点的子节点，检查是否包含目标节点
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
    # 简单的实现：检查变量节点和目标节点是否在同一赋值语句中
    parent = target_node.parent
    while parent:
        if parent.type == 'assignment_expression':
            # 检查赋值语句的左侧是否包含变量节点
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
        r'^[A-Z]:\\\\(Windows|Program Files|Users|System32)\\\\',
        # 常见常量
        r'^(true|false|null|NULL|TRUE|FALSE)$',
        r'^(std|cout|cin|cerr|endl|printf|scanf)$',
        # 版本信息
        r'^v?(\d+\.)+\d+$',
        # UUID格式
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
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

    # 获取前后各2行的上下文
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

void safe_function() {
    // 安全的做法 - 从环境变量获取
    const char* db_pass = getenv("DB_PASSWORD");

    // 明显的非密码字符串 - 不应报警
    string file_path = "/usr/local/bin/program";
    string url = "https://api.example.com/v1/data";
    string version = "1.2.3";

    // 密码比较函数 - 不应报警（上下文相关）
    if (strcmp(input_password, "default") == 0) {
        // 重置密码
    }

    // 密码哈希函数 - 不应报警
    hash_password("salted_hash_input");
}

int main() {
    vulnerable_function();
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