import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义MyBatis SQL注入漏洞模式
MYBATIS_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (template_string) @template
            ''',
            'message': '模板字符串发现，可能包含SQL查询'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @method
                    )
                    arguments: (arguments (template_string) @sql_template)
                ) @call
            ''',
            'pattern': r'^(query|execute|sql|db|connection|pool|mysql|pg|sqlite)$',
            'method_pattern': r'^(query|execute|run|all|get|select|insert|update|delete)$',
            'message': '数据库查询方法调用包含模板字符串'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (template_string) @sql_template)
                ) @call
            ''',
            'pattern': r'^(query|executeSql|runQuery|dbQuery|sql|mysqlQuery|pgQuery)$',
            'message': 'SQL查询函数调用包含模板字符串'
        },
        {
            'query': '''
                (variable_declarator
                    name: (identifier) @var_name
                    value: (template_string) @sql_template
                ) @declaration
            ''',
            'pattern': r'^(sql|query|stmt|statement|cmd|command)$',
            'message': 'SQL查询字符串赋值给变量'
        },
        {
            'query': '''
                (assignment_expression
                    left: (identifier) @var_name
                    right: (template_string) @sql_template
                ) @assignment
            ''',
            'pattern': r'^(sql|query|stmt|statement|cmd|command)$',
            'message': 'SQL查询字符串赋值'
        },
        {
            'query': '''
                (binary_expression
                    left: (identifier) @left_var
                    operator: "+"
                    right: (_) @right_expr
                ) @concat
            ''',
            'pattern': r'^(sql|query|stmt|statement|cmd|command)$',
            'message': 'SQL字符串拼接操作'
        }
    ]
}


def detect_mybatis_sql_injection(code, language='javascript'):
    """
    检测JavaScript代码中MyBatis风格的SQL注入漏洞

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
    sql_operations = []

    # 收集所有可能的SQL操作
    for query_info in MYBATIS_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['object', 'func_name', 'var_name', 'left_var']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture[tag] = name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'method':
                    method_name = node.text.decode('utf8')
                    method_pattern = query_info.get('method_pattern', '')
                    if (not method_pattern or
                            re.match(method_pattern, method_name, re.IGNORECASE)):
                        current_capture['method'] = method_name

                elif tag in ['template', 'sql_template', 'right_expr', 'concat']:
                    if tag == 'template' and 'sql_template' not in current_capture:
                        current_capture['sql_template'] = node.text.decode('utf8')
                    elif tag == 'sql_template':
                        current_capture['sql_template'] = node.text.decode('utf8')
                    elif tag == 'right_expr':
                        current_capture['right_expr'] = node.text.decode('utf8')

                    # 完成捕获
                    if current_capture:
                        # 检查是否包含SQL注入特征
                        sql_content = current_capture.get('sql_template', '') or current_capture.get('right_expr', '')

                        if is_potential_sql_injection(sql_content):
                            sql_operations.append({
                                'type': query_info['message'],
                                'line': current_capture['line'],
                                'code_snippet': node.text.decode('utf8'),
                                'sql_content': sql_content,
                                'node': node,
                                'pattern_matched': current_capture.get('object') or
                                                   current_capture.get('func_name') or
                                                   current_capture.get('var_name') or
                                                   current_capture.get('left_var')
                            })
                        current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 分析漏洞
    for operation in sql_operations:
        sql_content = operation['sql_content']

        # 检查是否包含${}占位符（MyBatis动态SQL注入点）
        if contains_dynamic_placeholder(sql_content):
            vulnerabilities.append({
                'line': operation['line'],
                'message': f'Potential MyBatis SQL Injection: {operation["type"]}',
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'SQL注入漏洞',
                'severity': '高危',
                'details': f'检测到动态SQL拼接: {sql_content[:100]}...'
            })

        # 检查字符串拼接导致的SQL注入
        elif is_string_concatenation_vulnerable(operation):
            vulnerabilities.append({
                'line': operation['line'],
                'message': f'Potential SQL Injection via string concatenation: {operation["type"]}',
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'SQL注入漏洞',
                'severity': '高危',
                'details': f'检测到不安全的字符串拼接: {sql_content[:100]}...'
            })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_dynamic_placeholder(sql_content):
    """
    检查SQL内容是否包含MyBatis风格的${}占位符

    Args:
        sql_content: SQL字符串内容

    Returns:
        bool: 是否包含动态占位符
    """
    # 匹配${...}模式
    pattern = r'\$\{[^}]+\}'
    return bool(re.search(pattern, sql_content))


def is_potential_sql_injection(content):
    """
    检查内容是否可能包含SQL查询

    Args:
        content: 字符串内容

    Returns:
        bool: 是否可能包含SQL
    """
    if not content:
        return False

    content_lower = content.lower()

    # SQL关键词检测
    sql_keywords = [
        'select', 'insert', 'update', 'delete', 'from', 'where',
        'join', 'inner', 'outer', 'left', 'right', 'set', 'values',
        'into', 'create', 'alter', 'drop', 'table', 'database'
    ]

    return any(keyword in content_lower for keyword in sql_keywords)


def is_string_concatenation_vulnerable(operation):
    """
    检查字符串拼接操作是否可能导致SQL注入

    Args:
        operation: SQL操作信息

    Returns:
        bool: 是否可能存在漏洞
    """
    if operation['type'] != 'SQL字符串拼接操作':
        return False

    # 检查右侧表达式是否包含用户输入特征
    right_expr = operation.get('right_expr', '')
    user_input_patterns = [
        r'req\.', r'request\.', r'params\.', r'query\.', r'body\.',
        r'input', r'userInput', r'userInput', r'formData',
        r'localStorage', r'sessionStorage', r'cookie'
    ]

    return any(re.search(pattern, right_expr, re.IGNORECASE)
               for pattern in user_input_patterns)


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的MyBatis SQL注入漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_mybatis_sql_injection(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// MyBatis风格SQL注入示例
const userId = req.params.id;
const sql = `SELECT * FROM users WHERE id = ${userId}`;  // 漏洞: 使用${}

// 另一种动态SQL拼接
const userName = req.body.name;
const dynamicSql = `SELECT * FROM users WHERE name = '${userName}'`;  // 漏洞: 直接拼接

// 数据库查询调用
db.query(`INSERT INTO logs (message) VALUES (${req.body.message})`);  // 漏洞

// 字符串拼接方式
const unsafeQuery = "SELECT * FROM products WHERE category = '" + req.query.category + "'";  // 漏洞

// 使用函数调用
executeQuery(`UPDATE settings SET value = ${userInput} WHERE id = 1`);  // 漏洞

// 安全的参数化查询示例
const safeSql = "SELECT * FROM users WHERE id = ?";
db.query(safeSql, [userId]);  // 安全: 使用参数化查询

// 安全的模板字符串使用（不包含用户输入）
const staticSql = `SELECT * FROM config WHERE environment = 'production'`;  // 安全: 静态SQL

// 变量赋值但不包含SQL
const message = `Hello, ${userName}!`;  // 安全: 非SQL上下文

// 包含${}但不是SQL
const template = `User: ${userName}, Time: ${new Date()}`;  // 安全: 非SQL
"""

    print("=" * 60)
    print("JavaScript MyBatis SQL注入漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   详情: {vuln['details']}")
    else:
        print("未检测到MyBatis SQL注入漏洞")