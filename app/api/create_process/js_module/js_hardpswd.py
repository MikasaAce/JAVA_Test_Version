import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义硬编码密码检测模式
PASSWORD_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (variable_declarator
                    name: (identifier) @var_name
                    value: (string) @string_value
                ) @var_decl
            ''',
            'name_pattern': r'(?i)(password|passwd|pwd|secret|key|token|credential)',
            'value_pattern': r'.{8,}',  # 至少8个字符的字符串
            'message': '疑似硬编码密码的变量声明'
        },
        {
            'query': '''
                (assignment_expression
                    left: (identifier) @var_name
                    right: (string) @string_value
                ) @assignment
            ''',
            'name_pattern': r'(?i)(password|passwd|pwd|secret|key|token|credential)',
            'value_pattern': r'.{8,}',
            'message': '疑似硬编码密码的赋值操作'
        },
        {
            'query': '''
                (object
                    (pair
                        key: (property_identifier) @key_name
                        value: (string) @string_value
                    ) @pair
                ) @object
            ''',
            'name_pattern': r'(?i)(password|passwd|pwd|secret|key|token|credential)',
            'value_pattern': r'.{8,}',
            'message': '疑似硬编码密码的对象属性'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments
                        (string) @string_value
                    )
                ) @call
            ''',
            'name_pattern': r'(?i)(connect|login|authenticate|authorize|config)',
            'value_pattern': r'.{8,}',
            'message': '疑似包含硬编码密码的函数调用'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression) @member_func
                    arguments: (arguments
                        (string) @string_value
                    )
                ) @call
            ''',
            'name_pattern': r'(?i)(password|passwd|pwd|secret|key|token|credential)',
            'value_pattern': r'.{8,}',
            'message': '疑似包含硬编码密码的方法调用'
        }
    ]
}

# 常见密码模式的黑名单（减少误报）
PASSWORD_BLACKLIST = [
    r'^(https?|ftp|file)://',  # URL
    r'^[a-f0-9]{32}$',  # MD5哈希
    r'^[a-f0-9]{40}$',  # SHA-1哈希
    r'^[a-f0-9]{64}$',  # SHA-256哈希
    r'^[A-Za-z0-9+/]{20,}={0,2}$',  # Base64编码数据
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',  # UUID
    r'^[0-9]{4,8}$',  # 纯数字（可能只是端口号或简单数字）
    r'^test|demo|example|placeholder|changeme|default$',  # 常见占位符
]


def is_likely_password(string_value, var_name=None):
    """
    判断字符串值是否可能是硬编码密码

    Args:
        string_value: 字符串值
        var_name: 变量名（可选）

    Returns:
        bool: 是否可能是密码
    """
    if not string_value or len(string_value) < 8:
        return False

    # 检查黑名单模式
    for pattern in PASSWORD_BLACKLIST:
        if re.search(pattern, string_value, re.IGNORECASE):
            return False

    # 检查是否包含多种字符类型（密码的常见特征）
    has_upper = bool(re.search(r'[A-Z]', string_value))
    has_lower = bool(re.search(r'[a-z]', string_value))
    has_digit = bool(re.search(r'[0-9]', string_value))
    has_special = bool(re.search(r'[^A-Za-z0-9]', string_value))

    # 如果包含多种字符类型，更可能是密码
    char_type_count = sum([has_upper, has_lower, has_digit, has_special])
    if char_type_count >= 2:
        return True

    # 如果变量名明确指示这是密码，即使字符类型单一也认为是密码
    if var_name and re.search(r'(?i)(password|passwd|pwd)', var_name):
        return True

    return False


def detect_hardcoded_passwords(code, language='javascript'):
    """
    检测JavaScript代码中的硬编码密码

    Args:
        code: JavaScript源代码字符串
        language: 语言类型，默认为'javascript'

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

    # 遍历所有检测模式
    for query_info in PASSWORD_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['var_name', 'key_name', 'func_name']:
                    name = node.text.decode('utf8')
                    name_pattern = query_info.get('name_pattern', '')
                    if name_pattern and re.search(name_pattern, name, re.IGNORECASE):
                        current_capture['name'] = name
                        current_capture['name_node'] = node

                elif tag == 'string_value':
                    string_value = node.text.decode('utf8').strip('"\'')
                    value_pattern = query_info.get('value_pattern', '')

                    # 移除字符串引号后检查
                    if (not value_pattern or
                        re.search(value_pattern, string_value)) and \
                            is_likely_password(string_value, current_capture.get('name')):
                        current_capture['string_value'] = string_value
                        current_capture['value_node'] = node

                elif tag in ['var_decl', 'assignment', 'pair', 'call'] and current_capture:
                    if 'string_value' in current_capture:
                        # 获取行号和代码片段
                        line_number = current_capture['value_node'].start_point[0] + 1
                        code_snippet = node.text.decode('utf8')

                        vulnerabilities.append({
                            'line': line_number,
                            'message': query_info['message'],
                            'code_snippet': code_snippet,
                            'variable_name': current_capture.get('name', 'N/A'),
                            'string_value': current_capture['string_value'],
                            'vulnerability_type': '硬编码密码',
                            'severity': '高危'
                        })

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的硬编码密码

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_hardcoded_passwords(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 明显的硬编码密码
const password = "MySuperSecretPassword123!";
var dbPassword = "DB@Admin#2024";
let apiKey = "sk_live_51HJdR2Kb6YJ8x7z4q3w2e1r9t5y0u4i6o7p8";

// 对象中的硬编码密码
const config = {
    username: "admin",
    password: "AdminPass123!",
    host: "localhost"
};

// 赋值操作
let secretToken;
secretToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

// 函数调用中的硬编码密码
connectToDatabase("localhost", "admin", "DbPassword!234");

// 方法调用
db.authenticate("user", "UserPass456!");

// 可能的误报情况（应该被过滤）
const md5Hash = "e10adc3949ba59abbe56e057f20f883e";  // MD5哈希
const url = "https://api.example.com/v1/login";  // URL
const port = "8080";  // 端口号
const uuid = "550e8400-e29b-41d4-a716-446655440000";  // UUID
const base64Data = "SGVsbG8gV29ybGQ=";  // Base64编码

// 占位符值（应该被过滤）
const demoPassword = "changeme";
const exampleToken = "placeholder";

// 边缘情况
const shortPassword = "short";  // 太短，不应该检测
const simpleNumber = "12345678";  // 纯数字，应该被过滤

// 变量名不包含密码相关词汇但值像密码
const connectionString = "Server=myServer;Database=myDB;Uid=user;Pwd=P@ssw0rd;";
"""

    print("=" * 60)
    print("JavaScript硬编码密码检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   变量名: {vuln['variable_name']}")
            print(f"   字符串值: {vuln['string_value']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到硬编码密码漏洞")