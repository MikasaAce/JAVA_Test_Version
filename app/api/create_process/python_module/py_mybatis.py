import os
import re
import sys
from tree_sitter import Language, Parser

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义MyBatis SQL注入漏洞模式
MYBATIS_SQL_INJECTION_VULNERABILITIES = {
    'python': [
        # 检测字符串拼接的SQL查询
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @obj
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list 
                        (binary_expression
                            left: (string) @sql_left
                            operator: "+"
                            right: (_) @sql_right
                        ) @concat_sql
                    )
                ) @call
            ''',
            'method_pattern': r'^(execute|executemany|fetchall|fetchone|fetchmany)$',
            'message': '字符串拼接的SQL查询'
        },
        # 检测f-string格式化的SQL查询
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @obj
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list 
                        (interpolation) @fstring_sql
                    )
                ) @call
            ''',
            'method_pattern': r'^(execute|executemany|fetchall|fetchone|fetchmany)$',
            'message': 'f-string格式化的SQL查询'
        },
        # 检测format方法格式化的SQL查询
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @obj
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list 
                        (call
                            function: (attribute
                                object: (string) @sql_string
                                attribute: (identifier) @format_method
                            )
                            arguments: (argument_list (_)* @format_args)
                        ) @format_call
                    )
                ) @call
            ''',
            'method_pattern': r'^(execute|executemany|fetchall|fetchone|fetchmany)$',
            'format_pattern': r'^format$',
            'message': 'format方法格式化的SQL查询'
        },
        # 检测%s占位符的SQL查询
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @obj
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list 
                        (string) @sql_string
                    )
                ) @call
            ''',
            'method_pattern': r'^(execute|executemany|fetchall|fetchone|fetchmany)$',
            'sql_pattern': r'%[sd]',
            'message': '使用%s占位符的SQL查询'
        },
        # 检测直接变量拼接的SQL
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @obj
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @sql_left
                            operator: "+"
                            right: (identifier) @var_right
                        ) @var_concat
                    )
                ) @call
            ''',
            'method_pattern': r'^(execute|executemany|fetchall|fetchone|fetchmany)$',
            'message': '变量直接拼接的SQL查询'
        },
        # 检测游标execute方法调用
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @cursor_var
                        attribute: (identifier) @method_name
                    )
                    arguments: (argument_list (_)* @sql_args)
                ) @call
            ''',
            'method_pattern': r'^(execute|executemany)$',
            'cursor_pattern': r'^(cursor|cur|db_cursor)$',
            'message': '游标execute方法调用'
        }
    ]
}

# MyBatis相关数据库操作模式
MYBATIS_DATABASE_OPERATIONS = {
    'query': '''
        [
            (call
                function: (attribute
                    object: (_) @obj
                    attribute: (identifier) @method_name
                )
                arguments: (argument_list (_)* @args)
            )
            (call
                function: (identifier) @func_name
                arguments: (argument_list (_)* @args)
            )
        ] @call
    ''',
    'patterns': [
        {
            'obj_pattern': r'^(session|db|connection|conn|sqlite3|mysql|psycopg2|pymysql)$',
            'method_pattern': r'^(execute|executemany|fetchall|fetchone|fetchmany|commit|rollback)$',
            'message': '数据库操作调用'
        },
        {
            'func_pattern': r'^(execute_sql|run_query|query_db)$',
            'message': '自定义SQL执行函数'
        },
        {
            'obj_pattern': r'^(cursor|cur)$',
            'method_pattern': r'^(execute|executemany|fetchall|fetchone|fetchmany)$',
            'message': '游标操作'
        }
    ]
}

# SQL查询字符串构建模式
SQL_STRING_BUILDING_PATTERNS = {
    'query': '''
        [
            (assignment
                left: (identifier) @var_name
                right: (binary_expression
                    left: (_) @left_expr
                    operator: "+"
                    right: (_) @right_expr
                ) @concat_expr
            )
            (assignment
                left: (identifier) @var_name
                right: (interpolation) @fstring_expr
            )
            (assignment
                left: (identifier) @var_name
                right: (call
                    function: (attribute
                        object: (string) @base_string
                        attribute: (identifier) @format_method
                    )
                    arguments: (argument_list (_)* @format_args)
                ) @format_call
            )
        ] @assignment
    ''',
    'patterns': [
        {
            'var_pattern': r'^(sql|query|stmt|statement|command|sql_cmd)$',
            'message': 'SQL查询字符串构建'
        },
        {
            'base_string_pattern': r'^(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)',
            'message': 'SQL语句字符串构建'
        }
    ]
}

# 用户输入源模式（与SQL注入相关）
SQL_USER_INPUT_SOURCES = {
    'query': '''
        [
            (call
                function: (identifier) @func_name
                arguments: (argument_list) @args
            )
            (call
                function: (attribute
                    object: (_) @obj
                    attribute: (identifier) @attr
                )
                arguments: (argument_list) @args
            )
        ] @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(input|raw_input)$',
            'message': '标准输入'
        },
        {
            'obj_pattern': r'^(flask|django)\.request$',
            'attr_pattern': r'^(args|form|values|data|json|files|headers|cookies|get|post)$',
            'message': 'Web请求参数'
        },
        {
            'obj_pattern': r'^(sys)$',
            'attr_pattern': r'^(argv)$',
            'message': '命令行参数'
        },
        {
            'obj_pattern': r'^os\.environ$',
            'attr_pattern': r'^(get|__getitem__)$',
            'message': '环境变量'
        }
    ]
}


def detect_python_mybatis_sql_injection(code, language='python'):
    """
    检测Python代码中MyBatis相关的SQL注入漏洞

    Args:
        code: Python源代码字符串
        language: 语言类型，默认为'python'

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
    dangerous_sql_calls = []  # 存储危险的SQL调用
    sql_string_buildings = []  # 存储SQL字符串构建
    user_input_sources = []  # 存储用户输入源
    database_operations = []  # 存储数据库操作

    # 第一步：收集所有危险的SQL调用
    for query_info in MYBATIS_SQL_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['method_name', 'obj', 'cursor_var']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['sql_string', 'sql_left', 'sql_right', 'fstring_sql', 'concat_sql']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['format_method', 'format_call']:
                    current_capture[tag] = node.text.decode('utf8')

                elif tag == 'call' and current_capture:
                    # 检查方法名是否匹配模式
                    method_pattern = query_info.get('method_pattern', '')
                    cursor_pattern = query_info.get('cursor_pattern', '')
                    sql_pattern = query_info.get('sql_pattern', '')
                    format_pattern = query_info.get('format_pattern', '')

                    method_match = True
                    cursor_match = True
                    sql_match = True
                    format_match = True

                    if method_pattern and 'method_name' in current_capture:
                        method_match = re.match(method_pattern, current_capture['method_name'], re.IGNORECASE)

                    if cursor_pattern and 'cursor_var' in current_capture:
                        cursor_match = re.match(cursor_pattern, current_capture['cursor_var'], re.IGNORECASE)

                    if sql_pattern and 'sql_string' in current_capture:
                        sql_match = re.search(sql_pattern, current_capture['sql_string'], re.IGNORECASE)

                    if format_pattern and 'format_method' in current_capture:
                        format_match = re.match(format_pattern, current_capture['format_method'], re.IGNORECASE)

                    if method_match and cursor_match and sql_match and format_match:
                        code_snippet = node.text.decode('utf8')

                        dangerous_sql_calls.append({
                            'type': 'dangerous_sql_call',
                            'line': current_capture['line'],
                            'method': current_capture.get('method_name', ''),
                            'object': current_capture.get('obj', ''),
                            'cursor_var': current_capture.get('cursor_var', ''),
                            'sql_fragment': current_capture.get('sql_string', '') or 
                                          current_capture.get('sql_left', '') or
                                          current_capture.get('fstring_sql', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'vulnerability_type': query_info.get('message', 'SQL注入风险')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"SQL注入查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集SQL字符串构建
    try:
        query = LANGUAGES[language].query(SQL_STRING_BUILDING_PATTERNS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['var_name', 'format_method']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['base_string', 'left_expr', 'right_expr', 'fstring_expr']:
                current_capture[tag] = node.text.decode('utf8')

            elif tag == 'assignment' and current_capture:
                # 检查是否匹配SQL字符串构建模式
                for pattern_info in SQL_STRING_BUILDING_PATTERNS['patterns']:
                    var_pattern = pattern_info.get('var_pattern', '')
                    base_string_pattern = pattern_info.get('base_string_pattern', '')

                    var_match = False
                    base_match = True  # 如果没有base_string_pattern，默认为True

                    if var_pattern and 'var_name' in current_capture:
                        var_match = re.match(var_pattern, current_capture['var_name'], re.IGNORECASE)

                    if base_string_pattern and 'base_string' in current_capture:
                        base_match = re.match(base_string_pattern, current_capture['base_string'], re.IGNORECASE)

                    if var_match and base_match:
                        code_snippet = node.text.decode('utf8')
                        sql_string_buildings.append({
                            'type': 'sql_string_building',
                            'line': current_capture['line'],
                            'variable': current_capture.get('var_name', ''),
                            'base_string': current_capture.get('base_string', ''),
                            'expression': current_capture.get('left_expr', '') + ' + ' + current_capture.get('right_expr', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"SQL字符串构建查询错误: {e}")

    # 第三步：收集用户输入源
    try:
        query = LANGUAGES[language].query(SQL_USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'obj', 'attr']:
                name = node.text.decode('utf8')
                current_capture[tag] = name
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'call' and current_capture:
                # 检查是否匹配用户输入模式
                for pattern_info in SQL_USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    obj_pattern = pattern_info.get('obj_pattern', '')
                    attr_pattern = pattern_info.get('attr_pattern', '')

                    match = False
                    if func_pattern and 'func_name' in current_capture:
                        if re.match(func_pattern, current_capture['func_name'], re.IGNORECASE):
                            match = True
                    elif obj_pattern and attr_pattern and 'obj' in current_capture and 'attr' in current_capture:
                        if (re.match(obj_pattern, current_capture['obj'], re.IGNORECASE) and
                                re.match(attr_pattern, current_capture['attr'], re.IGNORECASE)):
                            match = True

                    if match:
                        code_snippet = node.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': current_capture['line'],
                            'function': current_capture.get('func_name', ''),
                            'object': current_capture.get('obj', ''),
                            'attribute': current_capture.get('attr', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第四步：收集数据库操作
    try:
        query = LANGUAGES[language].query(MYBATIS_DATABASE_OPERATIONS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'obj', 'method_name']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'call' and current_capture:
                # 检查是否匹配数据库操作模式
                for pattern_info in MYBATIS_DATABASE_OPERATIONS['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    obj_pattern = pattern_info.get('obj_pattern', '')
                    method_pattern = pattern_info.get('method_pattern', '')

                    match = False
                    if func_pattern and 'func_name' in current_capture:
                        if re.match(func_pattern, current_capture['func_name'], re.IGNORECASE):
                            match = True
                    elif obj_pattern and method_pattern and 'obj' in current_capture and 'method_name' in current_capture:
                        if (re.match(obj_pattern, current_capture['obj'], re.IGNORECASE) and
                                re.match(method_pattern, current_capture['method_name'], re.IGNORECASE)):
                            match = True

                    if match:
                        code_snippet = node.text.decode('utf8')
                        database_operations.append({
                            'type': 'database_operation',
                            'line': current_capture['line'],
                            'function': current_capture.get('func_name', ''),
                            'object': current_capture.get('obj', ''),
                            'method': current_capture.get('method_name', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"数据库操作查询错误: {e}")

    # 第五步：分析SQL注入漏洞
    for sql_call in dangerous_sql_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': sql_call['line'],
            'code_snippet': sql_call['code_snippet'],
            'vulnerability_type': sql_call['vulnerability_type'],
            'severity': '高危'
        }

        # 情况1: 字符串拼接的SQL
        if 'concat_sql' in sql_call.get('sql_fragment', ''):
            vulnerability_details['message'] = f"字符串拼接的SQL查询: {sql_call['method']} 方法使用字符串拼接构建SQL"
            is_vulnerable = True

        # 情况2: f-string格式化的SQL
        elif 'fstring_sql' in sql_call:
            vulnerability_details['message'] = f"f-string格式化的SQL查询: {sql_call['method']} 方法使用f-string构建SQL"
            is_vulnerable = True

        # 情况3: format方法格式化的SQL
        elif 'format_call' in sql_call:
            vulnerability_details['message'] = f"format方法格式化的SQL查询: {sql_call['method']} 方法使用format构建SQL"
            is_vulnerable = True

        # 情况4: %s占位符的SQL
        elif re.search(r'%[sd]', sql_call.get('sql_fragment', '')):
            vulnerability_details['message'] = f"使用%s占位符的SQL查询: {sql_call['method']} 方法使用字符串格式化"
            is_vulnerable = True

        # 情况5: 检查SQL是否包含用户输入
        elif is_sql_user_input_related(sql_call, user_input_sources):
            vulnerability_details['message'] = f"用户输入直接拼接到SQL: {sql_call['method']} 方法"
            is_vulnerable = True

        # 情况6: 检查是否使用参数化查询
        elif not is_parameterized_query(sql_call):
            vulnerability_details['message'] = f"未使用参数化查询: {sql_call['method']} 方法"
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_sql_user_input_related(sql_call, user_input_sources):
    """
    检查SQL调用是否与用户输入相关
    """
    sql_fragment = sql_call.get('sql_fragment', '')
    
    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'data', 'param', 'args', 'kwargs', 
                      'request', 'query', 'form', 'argv']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', sql_fragment, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == sql_call['node'] or is_child_node(sql_call['node'], source['node']):
            return True

    return False


def is_parameterized_query(sql_call):
    """
    检查是否使用参数化查询
    """
    code_snippet = sql_call['code_snippet']
    
    # 参数化查询的迹象
    parameterized_patterns = [
        r'%s.*%\(.*\)',  # 命名参数
        r'execute.*\(.*,.*\)',  # 带参数的execute
        r'executemany',  # executemany通常使用参数
        r'SELECT.*FROM.*WHERE.*=\?',  # 问号占位符
        r'INSERT.*VALUES.*\(.*%s.*\)',  # 值列表使用%s
    ]
    
    for pattern in parameterized_patterns:
        if re.search(pattern, code_snippet, re.IGNORECASE | re.DOTALL):
            return True
    
    return False


def is_child_node(child, parent):
    """
    检查一个节点是否是另一个节点的子节点
    """
    node = child
    while node:
        if node == parent:
            return True
        node = node.parent
    return False


def analyze_python_mybatis_sql_injection(code_string):
    """
    分析Python代码字符串中的MyBatis SQL注入漏洞
    """
    return detect_python_mybatis_sql_injection(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import sqlite3
import MySQLdb
import psycopg2
from flask import request
import sys

def vulnerable_mybatis_operations():
    # 字符串拼接的SQL - 高危
    user_id = input("Enter user ID: ")
    sql = "SELECT * FROM users WHERE id = " + user_id  # SQL注入
    cursor.execute(sql)
    
    # f-string格式化的SQL - 高危
    username = request.args.get('username')
    sql = f"SELECT * FROM users WHERE username = '{username}'"  # SQL注入
    cursor.execute(sql)
    
    # format方法格式化的SQL - 高危
    table_name = request.form.get('table')
    sql = "SELECT * FROM {} WHERE 1=1".format(table_name)  # SQL注入
    cursor.execute(sql)
    
    # %s占位符错误使用 - 高危
    condition = "1=1 OR 1=1"
    sql = "DELETE FROM products WHERE %s" % condition  # SQL注入
    cursor.execute(sql)
    
    # 直接变量拼接 - 高危
    order_by = request.args.get('order', 'id')
    sql = "SELECT * FROM logs ORDER BY " + order_by  # SQL注入
    cursor.execute(sql)
    
    # 多部分字符串拼接 - 高危
    base_sql = "SELECT * FROM users WHERE "
    filter_condition = request.args.get('filter', '1=1')
    final_sql = base_sql + filter_condition  # SQL注入
    cursor.execute(final_sql)

def safe_mybatis_operations():
    # 参数化查询 - 安全
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    
    # 命名参数 - 安全
    username = request.form.get('username')
    cursor.execute("SELECT * FROM users WHERE username = %(name)s", {'name': username})
    
    # 安全的executemany - 安全
    data = [('user1', 'pass1'), ('user2', 'pass2')]
    cursor.executemany("INSERT INTO users (username, password) VALUES (?, ?)", data)
    
    # 硬编码SQL - 相对安全
    cursor.execute("SELECT * FROM config WHERE key = 'version'")
    
    # 白名单验证 - 安全
    valid_columns = ['id', 'name', 'email']
    sort_by = request.args.get('sort', 'id')
    if sort_by in valid_columns:
        cursor.execute(f"SELECT * FROM users ORDER BY {sort_by}")  # 相对安全

def mixed_operations():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # 危险：用户输入直接拼接
    search_term = input("Search: ")
    cursor.execute("SELECT * FROM products WHERE name LIKE '%" + search_term + "%'")
    
    # 安全：参数化查询
    user_input = request.args.get('category')
    cursor.execute("SELECT * FROM products WHERE category = ?", (user_input,))
    
    # 危险：字符串格式化
    limit = request.form.get('limit', '10')
    sql = "SELECT * FROM logs LIMIT %s" % limit
    cursor.execute(sql)
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    vulnerable_mybatis_operations()
    safe_mybatis_operations()
    mixed_operations()
"""

    print("=" * 60)
    print("Python MyBatis SQL注入漏洞检测")
    print("=" * 60)

    results = analyze_python_mybatis_sql_injection(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个潜在SQL注入漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到MyBatis SQL注入漏洞")