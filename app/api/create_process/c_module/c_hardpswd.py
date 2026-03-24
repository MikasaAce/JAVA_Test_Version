import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 硬编码密码漏洞模式
HARDCODED_PASSWORD_VULNERABILITIES = {
    'c': [
        # 检测字符串字面量中的密码
        {
            'id': 'string_literal_password',
            'query': '''
                (string_literal) @string_literal
            ''',
            'message': '字符串字面量可能包含硬编码密码'
        },
        # 检测字符数组初始化中的密码
        {
            'id': 'array_init_password',
            'query': '''
                (init_declarator
                    declarator: (array_declarator)
                    value: (initializer_list (_)* @string_init)
                ) @array_init
            ''',
            'message': '字符数组初始化可能包含硬编码密码'
        },
        # 检测strcpy类函数中的硬编码密码
        {
            'id': 'strcpy_password',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (_) @dest_arg
                        . (string_literal) @password_arg
                    )
                ) @strcpy_call
            ''',
            'func_pattern': r'^(strcpy|strncpy|memcpy|sprintf|strcat)$',
            'message': '字符串复制函数中的硬编码密码'
        },
        # 检测赋值表达式中的密码
        {
            'id': 'assignment_password',
            'query': '''
                (assignment_expression
                    left: (_) @left_side
                    right: (string_literal) @password_value
                ) @assignment
            ''',
            'message': '赋值操作中的硬编码密码'
        },
        # 检测比较函数中的硬编码密码
        {
            'id': 'compare_password',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (_) @input_arg
                        . (string_literal) @hardcoded_arg
                    )
                ) @compare_call
            ''',
            'func_pattern': r'^(strcmp|strncmp|memcmp|strcasecmp|strncasecmp)$',
            'message': '比较函数中的硬编码密码'
        },
        # 检测认证函数调用
        {
            'id': 'auth_function',
            'query': '''
                (call_expression
                    function: (identifier) @auth_func
                    arguments: (argument_list (_)* @auth_args)
                ) @auth_call
            ''',
            'func_pattern': r'^(authenticate|login|check_password|verify_password|validate_credential)$',
            'message': '认证函数可能包含硬编码密码'
        },
        # 检测网络连接中的硬编码凭据
        {
            'id': 'connection_credentials',
            'query': '''
                (call_expression
                    function: (identifier) @conn_func
                    arguments: (argument_list (_)* @conn_args)
                ) @conn_call
            ''',
            'func_pattern': r'^(connect|ftp_login|mysql_real_connect|PQconnectdb|SQLConnect)$',
            'message': '网络连接函数可能包含硬编码凭据'
        },
        # 检测加密密钥硬编码
        {
            'id': 'crypto_keys',
            'query': '''
                (call_expression
                    function: (identifier) @crypto_func
                    arguments: (argument_list (_)* @key_args)
                ) @crypto_call
            ''',
            'func_pattern': r'^(AES_set_encrypt_key|DES_set_key|EVP_BytesToKey|RSA_generate_key)$',
            'message': '加密函数可能包含硬编码密钥'
        },
        # 检测URL中的硬编码凭据
        {
            'id': 'url_credentials',
            'query': '''
                (string_literal) @url_string
            ''',
            'url_pattern': r'^(http|https|ftp|sftp)://[^:]+:[^@]+@',
            'message': 'URL中包含硬编码凭据'
        },
        # 检测数据库连接字符串
        {
            'id': 'db_connection_string',
            'query': '''
                (string_literal) @db_string
            ''',
            'db_pattern': r'(password|pwd|passwd)=[^;&]+',
            'message': '数据库连接字符串包含硬编码密码'
        }
    ]
}

# 密码相关关键词模式
PASSWORD_KEYWORDS = [
    r'password', r'pwd', r'passwd', r'pass', r'secret', r'key', r'token',
    r'credential', r'auth', r'login', r'encrypt', r'decrypt', r'cipher',
    r'private', r'certificate', r'signature', r'hash', r'salt'
]

# 常见密码模式
COMMON_PASSWORD_PATTERNS = [
    r'^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$',  # 基本密码格式
    r'^[A-Fa-f0-9]{16,}$',  # 十六进制密钥
    r'^[A-Za-z0-9+/]{20,}={0,2}$',  # Base64编码
    r'^\$2[aby]\$\d+\$[A-Za-z0-9+/\.]{53}$',  # bcrypt哈希
    r'^\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}$',  # MD5 crypt
    r'^\$5\$rounds=\d+\$[A-Za-z0-9./]{16}\$[A-Za-z0-9./]{43}$',  # SHA-256 crypt
    r'^\$6\$rounds=\d+\$[A-Za-z0-9./]{16}\$[A-Za-z0-9./]{86}$',  # SHA-512 crypt
]

# 上下文分析配置
CONTEXT_ANALYSIS = {
    'variable_patterns': [
        r'.*pass(word)?.*', r'.*pwd.*', r'.*secret.*', r'.*key.*',
        r'.*token.*', r'.*auth.*', r'.*credential.*'
    ],
    'function_patterns': [
        r'.*auth.*', r'.*login.*', r'.*password.*', r'.*encrypt.*',
        r'.*decrypt.*', r'.*verify.*', r'.*check.*', r'.*validate.*'
    ]
}

# 明确排除的模式（明显不是密码的字符串）
EXCLUDED_PATTERNS = [
    r'^[\s\t\n]*$',  # 空白字符
    r'^[0-9\.:]+$',  # 版本号、IP地址等
    r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # 简单的标识符
    r'^[A-Z][a-zA-Z0-9_]*$',  # 首字母大写的标识符
    r'^https?://[^:]+$',  # 不包含凭据的URL
    r'^\w+\.(c|h|cpp|hpp|txt|json|xml)$',  # 文件名
    r'^\d{4}-\d{2}-\d{2}$',  # 日期格式
    r'^[\d\s\-+:]+$',  # 主要是数字和分隔符
    r'^[A-Za-z\s]+$',  # 纯字母和空格
    r'^%.*%$',  # 格式化字符串
    r'^[\x20-\x7E]{1,20}$',  # 短的可打印字符串
]


def get_node_id(node):
    """获取节点的唯一标识符"""
    return f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"


def detect_hardcoded_passwords(code, language='c'):
    """
    检测C代码中硬编码密码漏洞

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
    password_candidates = []
    processed_nodes = set()  # 记录已处理的节点ID

    # 第一步：收集所有可能的密码候选
    for query_info in HARDCODED_PASSWORD_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                node_id = get_node_id(node)
                if node_id in processed_nodes:
                    continue

                node_text = node.text.decode('utf8').strip('"\'')

                # 首先检查是否应该排除
                if is_excluded_string(node_text):
                    continue

                if tag in ['string_literal', 'password_arg', 'hardcoded_arg',
                           'password_value', 'url_string', 'db_string']:

                    # 特殊模式检查（URL凭据、数据库连接字符串等）
                    if has_special_pattern(node_text, query_info):
                        password_candidates.append({
                            'id': query_info['id'],
                            'node': node,
                            'text': node_text,
                            'type': 'string_literal',
                            'line': node.start_point[0] + 1,
                            'code_snippet': get_code_snippet(code, node),
                            'context': get_node_context(node, root),
                            'message': query_info.get('message', '')
                        })
                        processed_nodes.add(node_id)
                    # 检查是否是密码相关
                    elif is_password_related(node, node_text, root):
                        password_candidates.append({
                            'id': query_info['id'],
                            'node': node,
                            'text': node_text,
                            'type': 'string_literal',
                            'line': node.start_point[0] + 1,
                            'code_snippet': get_code_snippet(code, node),
                            'context': get_node_context(node, root),
                            'message': query_info.get('message', '')
                        })
                        processed_nodes.add(node_id)

                elif tag in ['func_name', 'auth_func', 'conn_func', 'crypto_func']:
                    # 检查函数名是否匹配密码相关模式
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, node_text, re.IGNORECASE):
                        parent_node = node.parent
                        parent_id = get_node_id(parent_node)
                        if parent_id not in processed_nodes:
                            password_candidates.append({
                                'id': query_info['id'],
                                'node': parent_node,
                                'text': node_text,
                                'type': 'function_call',
                                'line': node.start_point[0] + 1,
                                'code_snippet': get_code_snippet(code, parent_node),
                                'context': get_node_context(parent_node, root),
                                'message': query_info.get('message', '')
                            })
                            processed_nodes.add(parent_id)

        except Exception as e:
            print(f"密码检测查询错误 {query_info.get('id', 'unknown')}: {e}")
            continue

    # 第二步：分析密码候选，减少误报
    processed_vulnerabilities = set()

    for candidate in password_candidates:
        vulnerability_key = f"{candidate['line']}:{candidate['id']}"
        if vulnerability_key in processed_vulnerabilities:
            continue

        if is_likely_password(candidate):
            vulnerability_details = {
                'line': candidate['line'],
                'code_snippet': candidate['code_snippet'],
                'vulnerability_type': '硬编码密码',
                'severity': '高危',
                'message': candidate['message'],
                'evidence': candidate['text'][:50] + '...' if len(candidate['text']) > 50 else candidate['text'],
                'rule_id': candidate['id']
            }

            # 根据上下文调整严重程度
            if is_in_authentication_context(candidate, root):
                vulnerability_details['severity'] = '严重'
                vulnerability_details['message'] += ' (认证上下文)'

            vulnerabilities.append(vulnerability_details)
            processed_vulnerabilities.add(vulnerability_key)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_excluded_string(text):
    """检查字符串是否应该被排除（明显不是密码）"""
    for pattern in EXCLUDED_PATTERNS:
        if re.match(pattern, text, re.IGNORECASE):
            return True
    return False


def has_special_pattern(text, query_info):
    """检查是否有特殊模式匹配（URL凭据、数据库连接字符串等）"""
    url_pattern = query_info.get('url_pattern', '')
    db_pattern = query_info.get('db_pattern', '')

    if url_pattern and re.search(url_pattern, text, re.IGNORECASE):
        return True

    if db_pattern and re.search(db_pattern, text, re.IGNORECASE):
        return True

    return False


def is_password_related(node, text, root_node):
    """
    检查节点是否与密码相关
    """
    # 检查文本内容是否像密码
    if looks_like_password(text):
        return True

    # 检查变量名或函数名是否密码相关
    parent = node.parent
    while parent:
        if parent.type in ['declaration', 'assignment_expression', 'call_expression']:
            parent_text = parent.text.decode('utf8')
            for pattern in PASSWORD_KEYWORDS:
                if re.search(pattern, parent_text, re.IGNORECASE):
                    return True
        parent = parent.parent

    return False


def looks_like_password(text):
    """
    判断文本是否看起来像密码
    """
    if len(text) < 6:  # 太短的文本不太可能是密码
        return False

    # 密码可能性评分
    score = 0

    # 基于内容特征
    if re.search(r'[a-zA-Z]', text) and re.search(r'\d', text):
        score += 2  # 包含字母和数字

    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', text):
        score += 2  # 包含特殊字符

    if 8 <= len(text) <= 128:
        score += 1  # 合理长度

    # 基于常见密码模式
    for pattern in COMMON_PASSWORD_PATTERNS:
        if re.match(pattern, text):
            score += 5  # 匹配已知密码模式

    return score >= 4  # 阈值可调整


def is_likely_password(candidate):
    """
    综合判断是否很可能是硬编码密码
    """
    text = candidate['text']

    # 绝对排除的情况
    if len(text) == 0:
        return False

    # 密码可能性评分
    score = 0

    # 基于内容特征
    if re.search(r'[a-zA-Z]', text) and re.search(r'\d', text):
        score += 2  # 包含字母和数字

    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', text):
        score += 2  # 包含特殊字符

    if 8 <= len(text) <= 128:
        score += 1  # 合理长度

    # 基于上下文
    context = candidate.get('context', '').lower()
    for keyword in PASSWORD_KEYWORDS:
        if re.search(keyword, context):
            score += 3  # 在密码相关上下文中

    # 基于常见密码模式
    for pattern in COMMON_PASSWORD_PATTERNS:
        if re.match(pattern, text):
            score += 5  # 匹配已知密码模式

    return score >= 5  # 阈值可调整


def is_in_authentication_context(candidate, root_node):
    """
    检查是否在认证相关的上下文中
    """
    context = candidate.get('context', '').lower()

    auth_keywords = ['login', 'auth', 'password', 'verify', 'authenticate',
                     'credential', 'check', 'validate']

    for keyword in auth_keywords:
        if keyword in context:
            return True

    # 检查父节点是否是认证相关函数调用
    node = candidate['node']
    while node:
        if node.type == 'call_expression':
            func_text = node.text.decode('utf8').lower()
            for keyword in auth_keywords:
                if keyword in func_text:
                    return True
        node = node.parent

    return False


def get_code_snippet(full_code, node):
    """
    从完整代码中提取节点对应的代码片段
    """
    start_byte = node.start_byte
    end_byte = node.end_byte
    return full_code[start_byte:end_byte]


def get_node_context(node, root_node, context_lines=2):
    """
    获取节点的上下文信息
    """
    context_parts = []

    # 获取变量声明信息
    current = node
    while current and current != root_node:
        if current.type in ['declaration', 'function_definition']:
            context_parts.append(current.text.decode('utf8'))
            break
        current = current.parent

    # 获取周围的代码行
    line_start = max(0, node.start_point[0] - context_lines)
    line_end = node.end_point[0] + context_lines + 1

    code_lines = root_node.text.decode('utf8').split('\n')
    context_lines_code = '\n'.join(code_lines[line_start:line_end])
    context_parts.append(context_lines_code)

    return '\n'.join(context_parts)


def analyze_c_code_for_passwords(code_string):
    """
    分析C代码字符串中的硬编码密码漏洞
    """
    return detect_hardcoded_passwords(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码
    test_c_code = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 硬编码密码示例
void insecure_authentication() {
    // 明显的硬编码密码
    char* password = "MySecret123!";  // 高危：硬编码密码
    char* db_password = "Admin@2024"; // 高危：数据库密码
    char* api_key = "sk_test_51abc123def456"; // 高危：API密钥

    // 加密密钥
    unsigned char encryption_key[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef};
    char* ssl_key = "-----BEGIN PRIVATE KEY-----\\nMIIEvQ..."; // 高危：SSL私钥

    // 认证函数中的硬编码密码
    if (strcmp(input_password, "DefaultPass123") == 0) {  // 高危：比较中的硬编码密码
        printf("Login successful\\n");
    }

    // 数据库连接字符串
    char* conn_str = "Server=db;Database=test;User=admin;Password=P@ssw0rd!;"; // 高危

    // URL中的凭据
    char* api_url = "https://user:password123@api.example.com/data"; // 高危

    // 使用硬编码密码的函数调用
    connect_to_database("localhost", "admin", "Admin123!"); // 高危
}

// 相对安全的示例
void secure_authentication() {
    // 从环境变量获取密码
    char* password = getenv("DB_PASSWORD");

    // 从配置文件读取
    char* config_password = read_config("password");

    // 非密码的字符串（应该被排除）
    char* username = "admin";  // 低危：用户名
    char* hostname = "localhost"; // 低危：主机名
    char* version = "1.0.0"; // 低危：版本号

    // 简单的非密码文本
    char* message = "Hello World"; // 应该被排除
    char* format_str = "Connecting to %s as %s\\n"; // 应该被排除
    int port = 3306; // 应该被排除
}

// 网络连接函数
void connect_to_database(char* host, char* user, char* pass) {
    // 连接逻辑
    printf("Connecting to %s as %s\\n", host, user);
}

int main() {
    insecure_authentication();
    secure_authentication();
    return 0;
}
"""

    print("=" * 60)
    print("C语言硬编码密码漏洞检测")
    print("=" * 60)

    results = analyze_c_code_for_passwords(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在硬编码密码漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   证据: {vuln.get('evidence', 'N/A')}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   规则ID: {vuln.get('rule_id', 'N/A')}")
    else:
        print("未检测到硬编码密码漏洞")