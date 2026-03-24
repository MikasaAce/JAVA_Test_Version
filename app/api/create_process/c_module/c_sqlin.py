import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# SQL注入漏洞模式 - 修复查询语法
SQL_INJECTION_VULNERABILITIES = {
    'c': [
        # 检测数据库执行函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @sql_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(mysql_query|mysqli_query|pg_query|sqlite3_exec|PQexec|SQLExecDirect|OCIStmtExecute)$',
            'message': '数据库查询函数调用'
        },
        # 检测SQL准备和执行函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @stmt_arg
                        (_) @sql_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(mysql_real_query|mysqli_real_query|sqlite3_prepare|sqlite3_prepare_v2|PQprepare|OCIStmtPrepare)$',
            'message': 'SQL准备函数调用'
        },
        # 检测字符串构建函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @dest_arg
                        (_) @src_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(sprintf|snprintf|vsprintf|vsnprintf|strcat|strncat|strcpy|strncpy)$',
            'message': '字符串构建函数可能用于SQL查询'
        },
        # 检测SQL连接和执行组合
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @conn_arg
                        (_) @sql_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(mysql_real_query|mysqli_query|PQexec|SQLExecDirect)$',
            'message': '数据库连接和执行函数'
        }
    ]
}

# SQL查询字符串模式 - 修复查询语法
SQL_QUERY_PATTERNS = {
    'c': [
        # 检测包含SQL关键字的字符串
        {
            'query': '''
                (string_literal) @sql_string
            ''',
            'pattern': r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|WHERE|FROM|JOIN|AND|OR)\b',
            'message': '字符串包含SQL关键字'
        },
        # 检测字符串拼接构建SQL
        {
            'query': '''
                (binary_expression
                    left: (string_literal) @left_str
                    operator: "+"
                    right: (identifier) @right_var
                ) @binary_expr
            ''',
            'message': '字符串与变量拼接可能用于构建SQL查询'
        },
        # 检测格式化字符串构建SQL
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string_literal) @format_str
                    )
                ) @call
            ''',
            'func_pattern': r'^(sprintf|snprintf)$',
            'pattern': r'.*\b(SELECT|INSERT|UPDATE|DELETE).*%s.*',
            'message': '格式化字符串可能用于构建SQL查询'
        }
    ]
}

# 数据库上下文检测 - 修复查询语法
DATABASE_CONTEXT = {
    'c': [
        # 检测数据库头文件包含
        {
            'query': '''
                (preproc_include
                    path: (string_literal) @include_path
                ) @include
            ''',
            'pattern': r'.*(mysql|postgresql|sqlite|oci|odbc|db)\.h',
            'message': '包含数据库相关头文件'
        },
        # 检测数据库连接函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(mysql_init|mysqli_init|mysql_real_connect|mysqli_connect|PQconnectdb|sqlite3_open|SQLConnect|OCILogon)$',
            'message': '数据库连接函数'
        },
        # 检测数据库相关类型
        {
            'query': '''
                (type_identifier) @type_name
            ''',
            'pattern': r'^(MYSQL|MYSQL_RES|MYSQL_ROW|PGconn|PGresult|sqlite3|OCIEnv|OCIStmt|SQLHANDLE)$',
            'message': '使用数据库相关类型'
        }
    ]
}

# 用户输入源模式
C_USER_INPUT_SOURCES = {
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
        }
    ]
}


def detect_c_sql_injection(code, language='c'):
    """
    检测C代码中SQL注入漏洞

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
    sql_function_calls = []  # 存储SQL相关函数调用
    sql_query_patterns = []  # 存储SQL查询模式
    database_context = []  # 存储数据库上下文信息
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集SQL相关函数调用
    for query_info in SQL_INJECTION_VULNERABILITIES[language]:
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

                elif tag in ['sql_arg', 'stmt_arg', 'dest_arg', 'src_arg', 'conn_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node
                    # 检查参数模式
                    arg_pattern = query_info.get('pattern', '')
                    if arg_pattern and re.search(arg_pattern, current_capture['arg'], re.IGNORECASE):
                        current_capture['arg_match'] = True

                elif tag in ['call'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    sql_function_calls.append({
                        'type': 'sql_function',
                        'line': current_capture['line'],
                        'function': current_capture.get('func', ''),
                        'argument': current_capture.get('arg', ''),
                        'arg_node': current_capture.get('arg_node'),
                        'code_snippet': code_snippet,
                        'node': node,
                        'arg_match': current_capture.get('arg_match', False),
                        'message': query_info.get('message', '')
                    })
                    current_capture = {}

        except Exception as e:
            print(f"SQL函数查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第二步：收集SQL查询模式
    for query_info in SQL_QUERY_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['sql_string', 'left_str', 'format_str']:
                    text = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')

                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        sql_query_patterns.append({
                            'type': 'sql_pattern',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'pattern_match': True,
                            'message': query_info.get('message', '')
                        })

                elif tag in ['right_var', 'func_name']:
                    var_text = node.text.decode('utf8')
                    code_snippet = node.parent.text.decode('utf8')
                    sql_query_patterns.append({
                        'type': 'sql_building',
                        'line': node.start_point[0] + 1,
                        'variable': var_text,
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    })

        except Exception as e:
            print(f"SQL模式查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第三步：收集数据库上下文信息
    for query_info in DATABASE_CONTEXT[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                text = node.text.decode('utf8')

                # 根据不同的查询类型使用不同的模式匹配
                if tag in ['include_path']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        database_context.append({
                            'type': 'database_include',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

                elif tag in ['func_name']:
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, text, re.IGNORECASE):
                        code_snippet = node.parent.text.decode('utf8')
                        database_context.append({
                            'type': 'database_function',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'message': query_info.get('message', '')
                        })

                elif tag in ['type_name']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        database_context.append({
                            'type': 'database_type',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"数据库上下文查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第四步：收集用户输入源
    try:
        query = LANGUAGES[language].query(C_USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                # 检查是否匹配任何用户输入模式
                for pattern_info in C_USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')

                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        code_snippet = node.parent.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'arg_index': pattern_info.get('arg_index', None)
                        })
                        break

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第五步：分析SQL注入漏洞
    vulnerabilities.extend(analyze_sql_injection_vulnerabilities(
        sql_function_calls, sql_query_patterns, database_context, user_input_sources
    ))

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_sql_injection_vulnerabilities(sql_calls, sql_patterns, db_context, user_input_sources):
    """
    分析SQL注入漏洞
    """
    vulnerabilities = []

    # 分析SQL函数调用漏洞
    for call in sql_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': 'SQL注入',
            'severity': '高危'
        }

        # 检查是否包含用户输入
        if call.get('arg_node') and is_user_input_related(call['arg_node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入直接传递给SQL函数: {call['function']}"
            is_vulnerable = True

        # 检查是否包含SQL关键字且可能动态构建
        elif call.get('arg_match', False):
            vulnerability_details['message'] = f"SQL函数包含动态SQL内容: {call['function']}"
            is_vulnerable = True

        # 检查字符串构建函数在数据库上下文中
        elif call['function'] in ['sprintf', 'snprintf', 'strcat', 'strcpy'] and is_in_database_context(call['node'],
                                                                                                        db_context):
            vulnerability_details['message'] = f"数据库上下文中的字符串构建: {call['function']}"
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    # 分析SQL模式漏洞
    for pattern in sql_patterns:
        is_vulnerable = False
        vulnerability_details = {
            'line': pattern['line'],
            'code_snippet': pattern['code_snippet'],
            'vulnerability_type': 'SQL注入',
            'severity': '中危'
        }

        if pattern.get('pattern_match', False) and pattern.get('variable'):
            vulnerability_details['message'] = f"SQL查询与变量拼接: {pattern['message']}"
            is_vulnerable = True

        elif pattern.get('variable') and is_user_input_variable(pattern.get('variable', ''), user_input_sources):
            vulnerability_details['message'] = f"用户输入变量用于SQL构建: {pattern['message']}"
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True

        elif pattern.get('pattern_match', False):
            vulnerability_details['message'] = f"检测到SQL查询模式: {pattern['message']}"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return vulnerabilities


def is_user_input_related(arg_node, user_input_sources):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'query', 'username',
                       'password']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_in_database_context(node, db_context):
    """
    检查节点是否在数据库上下文中
    """
    node_line = node.start_point[0] + 1

    for context in db_context:
        context_line = context['line']
        # 如果数据库上下文在调用之前或同一区域
        if context_line <= node_line and (node_line - context_line) < 50:
            return True

    return False


def is_user_input_variable(var_name, user_input_sources):
    """
    检查变量名是否与用户输入相关
    """
    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'query']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', var_name, re.IGNORECASE):
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


def analyze_sql_injection(code_string):
    """
    分析C代码字符串中的SQL注入漏洞
    """
    return detect_c_sql_injection(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - SQL注入场景
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>

// 危险示例 - SQL注入漏洞
void vulnerable_sql_functions(int argc, char* argv[]) {
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;

    char *server = "localhost";
    char *user = "root";
    char *password = "password";
    char *database = "test";

    conn = mysql_init(NULL);

    // 连接数据库
    if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)) {
        fprintf(stderr, "%s\\n", mysql_error(conn));
        return;
    }

    // 漏洞1: 直接使用用户输入构建SQL
    char* user_input = argv[1];
    char query1[200];
    sprintf(query1, "SELECT * FROM users WHERE username = '%s'", user_input);
    mysql_query(conn, query1);  // SQL注入漏洞

    // 漏洞2: 字符串拼接构建SQL
    char username[100];
    strcpy(username, argv[1]);
    char query2[200] = "SELECT * FROM users WHERE username = '";
    strcat(query2, username);
    strcat(query2, "'");
    mysql_query(conn, query2);  // SQL注入漏洞

    // 漏洞3: 直接执行用户输入
    if (argc > 2) {
        mysql_query(conn, argv[2]);  // 直接执行用户输入的SQL
    }

    // 漏洞4: 格式化字符串构建动态SQL
    char table_name[50] = "users";
    char condition[100];
    sprintf(condition, "age > %s", argv[3]);
    char query4[300];
    sprintf(query4, "SELECT * FROM %s WHERE %s", table_name, condition);
    mysql_query(conn, query4);  // SQL注入漏洞

    mysql_close(conn);
}

// 相对安全的示例 - 使用参数化查询
void safe_sql_functions() {
    MYSQL *safe_conn = mysql_init(NULL);
    MYSQL_STMT *stmt;

    // 安全1: 使用预处理语句
    stmt = mysql_stmt_init(safe_conn);
    const char *safe_query = "SELECT * FROM users WHERE username = ? AND password = ?";
    mysql_stmt_prepare(stmt, safe_query, strlen(safe_query));

    // 安全2: 硬编码SQL查询
    mysql_query(safe_conn, "SELECT * FROM products WHERE category = 'electronics'");

    mysql_close(safe_conn);
}

int main(int argc, char* argv[]) {
    vulnerable_sql_functions(argc, argv);
    safe_sql_functions();
    return 0;
}
"""

    print("=" * 60)
    print("C语言SQL注入漏洞检测")
    print("=" * 60)

    results = analyze_sql_injection(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在SQL注入漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SQL注入漏洞")