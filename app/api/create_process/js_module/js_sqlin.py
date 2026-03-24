import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义SQL注入漏洞检测模式
SQL_INJECTION_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @db_object
                        property: (property_identifier) @db_method
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'object_pattern': r'^(mysql|pg|sqlite|db|database|connection|pool|query|request)$',
            'method_pattern': r'^(query|execute|exec|run|all|get|each|prepare|statement)$',
            'message': '数据库查询方法调用'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(query|execute|sql|mysqlQuery|pgQuery|databaseQuery)$',
            'message': 'SQL查询函数调用'
        },
        {
            'query': '''
                (template_string) @template
            ''',
            'message': '模板字符串可能包含SQL查询'
        }
    ]
}

# 常见的SQL关键字模式，用于识别潜在的SQL查询
SQL_KEYWORDS = [
    r'SELECT\s+.+\s+FROM',
    r'INSERT\s+INTO',
    r'UPDATE\s+.+\s+SET',
    r'DELETE\s+FROM',
    r'DROP\s+(TABLE|DATABASE)',
    r'CREATE\s+(TABLE|DATABASE)',
    r'ALTER\s+TABLE',
    r'WHERE\s+.+=',
    r'JOIN\s+.+\s+ON',
    r'UNION\s+ALL',
    r'EXEC\s+',
    r'EXECUTE\s+'
]


def detect_js_sql_injection(code, language='javascript'):
    """
    检测JavaScript代码中的SQL注入漏洞

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
    sql_operations = []  # 存储所有SQL操作

    # 第一步：收集所有可能的SQL操作
    for query_info in SQL_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['db_object', 'func_name']:
                    obj_name = node.text.decode('utf8')
                    pattern = query_info.get('object_pattern') or query_info.get('pattern', '')
                    if pattern and re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'db_method':
                    method_name = node.text.decode('utf8')
                    method_pattern = query_info.get('method_pattern', '')
                    if method_pattern and re.match(method_pattern, method_name, re.IGNORECASE):
                        current_capture['method'] = method_name

                elif tag == 'args' and current_capture:
                    # 获取参数节点
                    args_text = node.text.decode('utf8')
                    current_capture['arguments'] = args_text
                    current_capture['full_code'] = node.parent.text.decode('utf8') if node.parent else ''

                elif tag in ['call', 'template'] and current_capture:
                    # 完成一个完整的捕获
                    if ('object' in current_capture or 'func_name' in query_info.get('query',
                                                                                     '')) and 'arguments' in current_capture:
                        sql_operations.append({
                            'type': 'sql_operation',
                            'line': current_capture['line'],
                            'object': current_capture.get('object', ''),
                            'method': current_capture.get('method', ''),
                            'arguments': current_capture['arguments'],
                            'full_code': current_capture['full_code'],
                            'node': current_capture.get('node')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：分析每个SQL操作的潜在漏洞
    for operation in sql_operations:
        args_text = operation['arguments']
        full_code = operation['full_code']
        line = operation['line']

        # 检查是否包含SQL关键字（表明这是真正的SQL操作）
        is_sql_operation = False
        for sql_pattern in SQL_KEYWORDS:
            if re.search(sql_pattern, full_code, re.IGNORECASE):
                is_sql_operation = True
                break

        if not is_sql_operation:
            continue

        # 检查参数中是否包含潜在的注入点
        vulnerabilities_found = analyze_sql_arguments(args_text, full_code, line)

        if vulnerabilities_found:
            vulnerabilities.extend(vulnerabilities_found)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_sql_arguments(args_text, full_code, line):
    """
    分析SQL操作的参数，检测潜在的注入漏洞

    Args:
        args_text: 参数字符串
        full_code: 完整代码片段
        line: 行号

    Returns:
        list: 漏洞列表
    """
    vulnerabilities = []

    # 检查是否使用字符串拼接构造SQL查询
    if is_string_concatenation(args_text):
        vulnerabilities.append({
            'line': line,
            'message': 'SQL注入风险: 使用字符串拼接构造SQL查询',
            'code_snippet': full_code[:200] + '...' if len(full_code) > 200 else full_code,
            'vulnerability_type': 'SQL注入漏洞',
            'severity': '高危',
            'details': '避免使用字符串拼接构造SQL查询，应使用参数化查询或预处理语句'
        })

    # 检查是否包含用户输入变量而没有适当的转义或验证
    if contains_user_input_without_sanitization(args_text):
        vulnerabilities.append({
            'line': line,
            'message': 'SQL注入风险: 用户输入未经过适当验证或转义',
            'code_snippet': full_code[:200] + '...' if len(full_code) > 200 else full_code,
            'vulnerability_type': 'SQL注入漏洞',
            'severity': '高危',
            'details': '用户输入应进行严格的验证和适当的转义处理'
        })

    # 检查模板字符串中的SQL注入风险
    if '${' in args_text and any(
            sql_keyword in args_text.upper() for sql_keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
        vulnerabilities.append({
            'line': line,
            'message': 'SQL注入风险: 模板字符串中直接插值可能导致SQL注入',
            'code_snippet': full_code[:200] + '...' if len(full_code) > 200 else full_code,
            'vulnerability_type': 'SQL注入漏洞',
            'severity': '高危',
            'details': '避免在模板字符串中直接插入用户输入到SQL查询中'
        })

    return vulnerabilities


def is_string_concatenation(text):
    """
    检查文本是否包含字符串拼接模式

    Args:
        text: 要检查的文本

    Returns:
        bool: 是否包含字符串拼接
    """
    # 检查 + 操作符连接字符串和变量
    if re.search(r'["\'][^"\']*["\']\s*\+\s*[a-zA-Z_$][\w$]*', text):
        return True

    # 检查模板字符串中的变量插值
    if '${' in text and any(sql_keyword in text.upper() for sql_keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
        return True

    return False


def contains_user_input_without_sanitization(text):
    """
    检查文本是否包含用户输入而没有适当的清理

    Args:
        text: 要检查的文本

    Returns:
        bool: 是否包含未清理的用户输入
    """
    # 常见的用户输入来源
    user_input_patterns = [
        r'req\.(query|params|body|headers)\.[\w$]+',
        r'window\.location\.(search|hash|href)',
        r'document\.(cookie|location|referrer)',
        r'localStorage\.getItem',
        r'sessionStorage\.getItem',
        r'URLSearchParams',
        r'formData\.get',
        r'event\.target\.value'
    ]

    # 常见的清理/转义函数
    sanitization_patterns = [
        r'escapeSql',
        r'mysql\.escape',
        r'pg\.escape',
        r'connection\.escape',
        r'validator\.escape',
        r'sanitize',
        r'encodeURIComponent',
        r'encodeURI',
        r'escape'
    ]

    # 检查是否包含用户输入
    has_user_input = any(re.search(pattern, text, re.IGNORECASE) for pattern in user_input_patterns)

    # 检查是否包含清理函数
    has_sanitization = any(re.search(pattern, text, re.IGNORECASE) for pattern in sanitization_patterns)

    return has_user_input and not has_sanitization


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的SQL注入漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_sql_injection(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 安全的SQL查询示例
const safeQuery = db.query('SELECT * FROM users WHERE id = ?', [userId]);
const safeExecute = pool.execute('INSERT INTO table VALUES (?, ?)', [value1, value2]);

// 存在SQL注入风险的示例
const unsafeQuery1 = db.query('SELECT * FROM users WHERE name = "' + userName + '"');
const unsafeQuery2 = connection.execute(\`SELECT * FROM products WHERE category = \${category}\`);
const unsafeQuery3 = mysql.query('UPDATE users SET status = ' + userInput);

// 使用req参数直接构造查询
app.get('/users', (req, res) => {
    const query = 'SELECT * FROM users WHERE name = "' + req.query.name + '"';
    db.query(query, (err, results) => {
        // 处理结果
    });
});

// 模板字符串中的SQL注入风险
function getUserData(userId) {
    return db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
}

// 看似安全但实际上不安全的查询
const partiallySafe = db.query('SELECT * FROM table WHERE id = ' + parseInt(userInput)); // parseInt不能防止所有SQL注入

// 使用预处理语句的安全示例
const safeExample = db.prepare('SELECT * FROM users WHERE email = ? AND active = ?');
safeExample.execute([email, true]);

// 使用ORM的安全示例
const ormSafe = User.findAll({
    where: {
        email: email,
        active: true
    }
});
"""

    print("=" * 60)
    print("JavaScript SQL注入漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   详细信息: {vuln.get('details', '无额外信息')}")
    else:
        print("未检测到SQL注入漏洞")