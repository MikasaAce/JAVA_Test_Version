import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# SQL注入漏洞模式（C语言版本）
SQL_INJECTION_VULNERABILITIES = {
    'c': [
        # 检测SQL执行函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @sql_args)
                ) @call
            ''',
            'func_pattern': r'^(mysql_query|sqlite3_exec|PQexec|OCIStmtExecute|db_query|sql_exec)$',
            'message': 'SQL执行函数调用'
        },
        # 检测字符串拼接构建SQL
        {
            'query': '''
                (call_expression
                    function: (identifier) @concat_func
                    arguments: (argument_list (_)* @concat_args)
                ) @concat_call
            ''',
            'func_pattern': r'^(sprintf|snprintf|strcat|strncat)$',
            'message': '字符串拼接可能用于构建SQL语句'
        },
        # 检测用户输入直接插入SQL
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        . (string_literal) @sql_template
                        . (identifier) @user_input
                    )
                ) @call
            ''',
            'func_pattern': r'^(sprintf|snprintf|printf|fprintf)$',
            'template_pattern': r'^.*SELECT|INSERT|UPDATE|DELETE.*%s.*$',
            'message': '用户输入直接插入SQL模板'
        },
        # 检测SQL字符串字面量
        {
            'query': '''
                (string_literal) @sql_string
            ''',
            'sql_pattern': r'^.*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR).*$',
            'message': 'SQL语句字符串字面量'
        },
        # 检测预处理语句使用
        {
            'query': '''
                (call_expression
                    function: (identifier) @prepare_func
                    arguments: (argument_list (_)* @prepare_args)
                ) @call
            ''',
            'func_pattern': r'^(mysql_stmt_prepare|sqlite3_prepare|PQprepare|OCIStmtPrepare)$',
            'message': 'SQL预处理语句函数'
        },
        # 检测参数绑定操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @bind_func
                    arguments: (argument_list (_)* @bind_args)
                ) @call
            ''',
            'func_pattern': r'^(mysql_stmt_bind_param|sqlite3_bind|PQbind|OCIBindByName)$',
            'message': 'SQL参数绑定函数'
        },
        # 检测动态SQL构建
        {
            'query': '''
                (assignment_expression
                    left: (identifier) @sql_var
                    right: (string_literal) @sql_fragment
                ) @assignment
            ''',
            'message': 'SQL片段赋值操作'
        },
        # 检测数据库连接函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @conn_func
                    arguments: (argument_list (_)* @conn_args)
                ) @call
            ''',
            'func_pattern': r'^(mysql_real_connect|sqlite3_open|PQconnectdb|OCILogon)$',
            'message': '数据库连接函数'
        }
    ]
}

# SQL注入检测配置
SQL_INJECTION_CONFIG = {
    'sql_keywords': [
        'select', 'insert', 'update', 'delete', 'from', 'where', 'and', 'or',
        'union', 'join', 'like', 'order by', 'group by', 'having', 'limit'
    ],
    'dangerous_patterns': [
        r'.*%s.*',  # 直接字符串格式化
        r'.*\"\s*\+\s*.*',  # 字符串连接
        r'.*strcat.*',  # 字符串连接函数
        r'.*sprintf.*',  # 格式化字符串
        r'SELECT.*FROM.*WHERE.*=.*\'.*\'.*',  # 单引号包裹的变量
        r'SELECT.*FROM.*WHERE.*=.*".*"',  # 双引号包裹的变量
    ],
    'safe_patterns': [
        r'.*prepare.*',  # 预处理语句
        r'.*bind.*',  # 参数绑定
        r'.*\\?.*',  # 参数占位符
        r'.*:.*',  # 命名参数
    ],
    'prepared_statement_functions': [
        'mysql_stmt_prepare', 'sqlite3_prepare', 'PQprepare',
        'mysql_stmt_bind_param', 'sqlite3_bind', 'PQbind'
    ],
    'validation_functions': [
        'mysql_real_escape_string', 'sqlite3_escape_string',
        'addslashes', 'htmlspecialchars', 'filter_var'
    ]
}


def detect_mybatis_sql_injection(code, language='c'):
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
    sql_operations = []  # 存储SQL相关操作
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集用户输入源
    user_input_sources = collect_user_input_sources(root, code)

    # 第二步：收集所有SQL相关操作
    for query_info in SQL_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                node_text = node.text.decode('utf8').strip('"\'')

                if tag in ['func_name', 'concat_func', 'prepare_func', 'bind_func', 'conn_func']:
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, node_text, re.IGNORECASE):
                        current_capture['func'] = node_text
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['sql_template']:
                    template_pattern = query_info.get('template_pattern', '')
                    if template_pattern and re.match(template_pattern, node_text, re.IGNORECASE):
                        current_capture['sql_template'] = node_text
                        current_capture['template_node'] = node

                elif tag in ['user_input']:
                    if is_user_input_variable(node_text, user_input_sources):
                        current_capture['user_input'] = node_text
                        current_capture['input_node'] = node

                elif tag in ['sql_string']:
                    sql_pattern = query_info.get('sql_pattern', '')
                    if sql_pattern and re.search(sql_pattern, node_text, re.IGNORECASE):
                        current_capture['sql_string'] = node_text
                        current_capture['string_node'] = node

                elif tag in ['sql_var']:
                    if is_sql_related_variable(node_text):
                        current_capture['sql_var'] = node_text
                        current_capture['var_node'] = node

                elif tag in ['sql_fragment']:
                    if is_sql_fragment(node_text):
                        current_capture['sql_fragment'] = node_text
                        current_capture['fragment_node'] = node

                elif tag in ['call', 'assignment'] and current_capture:
                    # 完成捕获
                    code_snippet = node.text.decode('utf8')
                    capture_data = {
                        'type': query_info.get('message', 'unknown'),
                        'line': current_capture.get('line', node.start_point[0] + 1),
                        'code_snippet': code_snippet,
                        'node': node,
                        'message': query_info.get('message', '')
                    }

                    # 添加特定信息
                    for key in ['func', 'sql_template', 'user_input', 'sql_string',
                                'sql_var', 'sql_fragment']:
                        if key in current_capture:
                            capture_data[key] = current_capture[key]

                    sql_operations.append(capture_data)
                    current_capture = {}

        except Exception as e:
            print(f"SQL注入检测查询错误 {query_info.get('message')}: {e}")
            continue

    # 第三步：分析SQL注入漏洞
    vulnerabilities = analyze_sql_injection(
        sql_operations, user_input_sources, code, root
    )

    return sorted(vulnerabilities, key=lambda x: x['line'])


def collect_user_input_sources(root, code):
    """
    收集用户输入源
    """
    user_input_sources = []

    input_functions = [
        'scanf', 'fscanf', 'sscanf', 'gets', 'fgets', 'getchar',
        'fgetc', 'getc', 'read', 'getline', 'recv', 'recvfrom',
        'recvmsg', 'getenv'
    ]

    query_pattern = '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    '''

    try:
        query = LANGUAGES['c'].query(query_pattern)
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                if func_name in input_functions:
                    user_input_sources.append({
                        'function': func_name,
                        'node': node.parent,
                        'line': node.start_point[0] + 1,
                        'code_snippet': node.parent.text.decode('utf8')
                    })
    except Exception as e:
        print(f"用户输入源收集错误: {e}")

    return user_input_sources


def analyze_sql_injection(sql_operations, user_input_sources, code, root):
    """
    分析SQL注入漏洞
    """
    vulnerabilities = []
    processed_locations = set()

    # 分析直接用户输入插入SQL
    for operation in sql_operations:
        location_key = f"{operation['line']}:direct_insertion"
        if location_key in processed_locations:
            continue
        processed_locations.add(location_key)

        vuln = analyze_direct_sql_insertion(operation, user_input_sources, code, root)
        if vuln:
            vulnerabilities.append(vuln)

    # 分析字符串拼接构建SQL
    for operation in sql_operations:
        if 'func' in operation and operation['func'] in ['sprintf', 'snprintf', 'strcat']:
            location_key = f"{operation['line']}:concat_build"
            if location_key in processed_locations:
                continue
            processed_locations.add(location_key)

            vuln = analyze_concat_sql_build(operation, user_input_sources, code, root)
            if vuln:
                vulnerabilities.append(vuln)

    # 分析预处理语句使用情况
    for operation in sql_operations:
        if 'func' in operation and 'prepare' in operation['func'].lower():
            location_key = f"{operation['line']}:prepared_stmt"
            if location_key in processed_locations:
                continue
            processed_locations.add(location_key)

            vuln = analyze_prepared_statement_usage(operation, code, root)
            if vuln:
                vulnerabilities.append(vuln)

    # 分析缺少预处理语句的情况
    missing_prepared_vulns = analyze_missing_prepared_statements(sql_operations, code, root)
    vulnerabilities.extend(missing_prepared_vulns)

    return vulnerabilities


def analyze_direct_sql_insertion(operation, user_input_sources, code, root):
    """
    分析直接用户输入插入SQL的漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    if 'user_input' in operation and 'sql_template' in operation:
        template = operation['sql_template']

        # 检查是否缺少输入验证和使用预处理语句
        if not has_sql_input_validation(operation, user_input_sources, code, root):
            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': 'SQL注入',
                'severity': '严重',
                'message': '用户输入未经验证直接插入SQL模板'
            }

    return None


def analyze_concat_sql_build(operation, user_input_sources, code, root):
    """
    分析字符串拼接构建SQL的漏洞
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    # 检查是否用于构建SQL
    if is_sql_construction(operation, code, root):
        # 检查是否包含用户输入且缺少预处理语句
        if contains_user_input(operation, user_input_sources) and not uses_prepared_statements(operation, code, root):
            return {
                'line': line,
                'code_snippet': code_snippet,
                'vulnerability_type': 'SQL注入',
                'severity': '严重',
                'message': '字符串拼接构建SQL，未使用预处理语句'
            }

    return None


def analyze_prepared_statement_usage(operation, code, root):
    """
    分析预处理语句使用情况
    """
    line = operation['line']
    code_snippet = operation['code_snippet']
    func_name = operation.get('func', '')

    # 检查预处理语句是否正确使用（有对应的绑定操作）
    if not has_proper_binding(operation, code, root):
        return {
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SQL注入',
            'severity': '中危',
            'message': f'预处理语句 {func_name} 可能缺少参数绑定'
        }

    return None


def analyze_missing_prepared_statements(sql_operations, code, root):
    """
    分析缺少预处理语句的情况
    """
    vulnerabilities = []

    # 查找所有SQL执行操作
    sql_exec_operations = [op for op in sql_operations if
                           'func' in op and any(f in op['func'].lower()
                                                for f in ['query', 'exec'])]

    for operation in sql_exec_operations:
        # 检查是否使用了预处理语句
        if not uses_prepared_statements(operation, code, root):
            vulnerabilities.append({
                'line': operation['line'],
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'SQL注入',
                'severity': '高危',
                'message': 'SQL执行操作未使用预处理语句'
            })

    return vulnerabilities


def is_user_input_variable(var_name, user_input_sources):
    """
    检查变量名是否与用户输入相关
    """
    input_var_patterns = [
        r'.*input.*', r'.*user.*', r'.*param.*', r'.*arg.*',
        r'.*data.*', r'.*buffer.*', r'.*query.*', r'.*post.*',
        r'.*get.*', r'.*request.*'
    ]

    for pattern in input_var_patterns:
        if re.search(pattern, var_name, re.IGNORECASE):
            return True

    # 检查是否在用户输入源中
    for source in user_input_sources:
        if var_name in source['code_snippet']:
            return True

    return False


def is_sql_related_variable(var_name):
    """
    检查变量名是否与SQL相关
    """
    sql_var_patterns = [
        r'.*sql.*', r'.*query.*', r'.*stmt.*', r'.*db.*',
        r'.*select.*', r'.*insert.*', r'.*update.*', r'.*delete.*'
    ]

    for pattern in sql_var_patterns:
        if re.search(pattern, var_name, re.IGNORECASE):
            return True

    return False


def is_sql_fragment(text):
    """
    检查文本是否类似SQL片段
    """
    if not text:
        return False

    sql_indicators = SQL_INJECTION_CONFIG['sql_keywords']

    for indicator in sql_indicators:
        if indicator.lower() in text.lower():
            return True

    return False


def has_sql_input_validation(operation, user_input_sources, code, root):
    """
    检查SQL输入是否有验证或使用预处理语句
    """
    # 检查是否使用预处理语句
    if uses_prepared_statements(operation, code, root):
        return True

    # 检查是否有输入验证
    line = operation['line']
    input_var = operation.get('user_input', '')

    # 查找SQL转义或验证函数
    validation_functions = SQL_INJECTION_CONFIG['validation_functions']

    # 检查操作之前的代码是否有验证
    node = operation['node']
    current = node.prev_sibling

    while current and current.start_point[0] >= max(0, line - 10):
        if current.type == 'call_expression':
            call_text = current.text.decode('utf8')
            for val_func in validation_functions:
                if val_func in call_text and input_var in call_text:
                    return True
        current = current.prev_sibling

    return False


def is_sql_construction(operation, code, root):
    """
    检查操作是否用于SQL构建
    """
    code_snippet = operation['code_snippet']

    # 检查是否包含SQL关键词
    sql_indicators = SQL_INJECTION_CONFIG['sql_keywords']

    for indicator in sql_indicators:
        if indicator.lower() in code_snippet.lower():
            return True

    return False


def contains_user_input(operation, user_input_sources):
    """
    检查操作是否包含用户输入
    """
    code_snippet = operation['code_snippet']

    # 检查用户输入变量名模式
    input_patterns = [
        r'argv', r'argc', r'input', r'user', r'param', r'data',
        r'buffer', r'query', r'post', r'get'
    ]

    for pattern in input_patterns:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True

    # 检查用户输入函数
    input_functions = ['scanf', 'fgets', 'getenv', 'recv']
    for func in input_functions:
        if func in code_snippet:
            return True

    return False


def uses_prepared_statements(operation, code, root):
    """
    检查是否使用预处理语句
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    # 检查是否包含预处理语句函数
    prepared_funcs = SQL_INJECTION_CONFIG['prepared_statement_functions']

    for func in prepared_funcs:
        if func in code_snippet:
            return True

    # 检查附近是否有预处理语句
    node = operation['node']

    # 检查之前的代码
    current = node.prev_sibling
    while current and current.start_point[0] >= max(0, line - 10):
        if current.type == 'call_expression':
            call_text = current.text.decode('utf8')
            for func in prepared_funcs:
                if func in call_text:
                    return True
        current = current.prev_sibling

    return False


def has_proper_binding(operation, code, root):
    """
    检查预处理语句是否有正确的参数绑定
    """
    line = operation['line']
    code_snippet = operation['code_snippet']

    # 查找绑定函数调用
    binding_funcs = [f for f in SQL_INJECTION_CONFIG['prepared_statement_functions']
                     if 'bind' in f.lower()]

    # 检查之后的代码是否有绑定操作
    node = operation['node']
    current = node.next_sibling

    while current and current.start_point[0] <= line + 10:
        if current.type == 'call_expression':
            call_text = current.text.decode('utf8')
            for bind_func in binding_funcs:
                if bind_func in call_text:
                    return True
        current = current.next_sibling

    return False


def analyze_c_code_for_sql_injection(code_string):
    """
    分析C代码字符串中的SQL注入漏洞
    """
    return detect_mybatis_sql_injection(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - SQL注入示例
    test_c_code = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mysql.h>

// 存在SQL注入漏洞的示例
void vulnerable_sql_operations() {
    char* user_input = getenv("USER_ID");

    // 漏洞1: 直接拼接用户输入到SQL
    char sql_query[256];
    sprintf(sql_query, "SELECT * FROM users WHERE id = %s", user_input);  // 高风险

    MYSQL* conn = mysql_init(NULL);
    mysql_query(conn, sql_query);  // 执行易受攻击的查询

    // 漏洞2: 字符串拼接构建SQL
    char* username = getenv("USERNAME");
    char dynamic_sql[512];
    strcpy(dynamic_sql, "SELECT * FROM users WHERE username = '");
    strcat(dynamic_sql, username);  // 直接拼接
    strcat(dynamic_sql, "'");

    mysql_query(conn, dynamic_sql);  // 严重风险

    // 漏洞3: 多个条件拼接
    char* condition = getenv("CONDITION");
    sprintf(sql_query, "SELECT * FROM products WHERE category = 'electronics' AND %s", condition);
    mysql_query(conn, sql_query);
}

// 相对安全的SQL操作示例
void secure_sql_operations() {
    char* user_input = getenv("USER_ID");

    // 安全示例1: 使用预处理语句
    MYSQL* conn = mysql_init(NULL);
    MYSQL_STMT* stmt = mysql_stmt_init(conn);

    const char* prepared_sql = "SELECT * FROM users WHERE id = ?";
    mysql_stmt_prepare(stmt, prepared_sql, strlen(prepared_sql));

    // 参数绑定
    int user_id = atoi(user_input);  // 输入验证
    MYSQL_BIND bind_param;
    memset(&bind_param, 0, sizeof(bind_param));
    bind_param.buffer_type = MYSQL_TYPE_LONG;
    bind_param.buffer = &user_id;

    mysql_stmt_bind_param(stmt, &bind_param);
    mysql_stmt_execute(stmt);

    // 安全示例2: 输入验证和转义
    if (is_valid_number(user_input)) {
        char safe_sql[256];
        sprintf(safe_sql, "SELECT * FROM users WHERE id = %d", atoi(user_input));
        mysql_query(conn, safe_sql);
    }

    // 安全示例3: 使用存储过程或ORM
    call_stored_procedure("get_user_by_id", user_input);
}

// 输入验证函数
int is_valid_number(const char* input) {
    for (int i = 0; input[i] != '\\0'; i++) {
        if (!isdigit(input[i])) {
            return 0;
        }
    }
    return 1;
}

// 存储过程调用
void call_stored_procedure(const char* proc_name, const char* param) {
    char call_sql[256];
    sprintf(call_sql, "CALL %s('%s')", proc_name, mysql_real_escape_string(param));
    // 执行存储过程调用
}

// 存在风险的登录验证函数
void vulnerable_login(char* username, char* password) {
    MYSQL* conn = mysql_init(NULL);
    char login_sql[512];

    // 漏洞: 用户名和密码直接插入SQL
    sprintf(login_sql, "SELECT * FROM users WHERE username = '%s' AND password = '%s'", 
            username, password);

    mysql_query(conn, login_sql);  // 严重SQL注入风险
}

// 安全登录验证
void secure_login(char* username, char* password) {
    MYSQL* conn = mysql_init(NULL);
    MYSQL_STMT* stmt = mysql_stmt_init(conn);

    const char* prepared_sql = "SELECT * FROM users WHERE username = ? AND password = ?";
    mysql_stmt_prepare(stmt, prepared_sql, strlen(prepared_sql));

    // 参数绑定
    MYSQL_BIND bind_params[2];
    memset(bind_params, 0, sizeof(bind_params));

    bind_params[0].buffer_type = MYSQL_TYPE_STRING;
    bind_params[0].buffer = username;
    bind_params[0].buffer_length = strlen(username);

    bind_params[1].buffer_type = MYSQL_TYPE_STRING;
    bind_params[1].buffer = password;
    bind_params[1].buffer_length = strlen(password);

    mysql_stmt_bind_param(stmt, bind_params);
    mysql_stmt_execute(stmt);
}

int main() {
    vulnerable_sql_operations();
    secure_sql_operations();

    // 测试风险函数
    char* malicious_input = "1 OR 1=1; DROP TABLE users; --";
    vulnerable_login("admin", "password");

    return 0;
}
"""

    print("=" * 60)
    print("C语言SQL注入漏洞检测")
    print("=" * 60)

    results = analyze_c_code_for_sql_injection(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在SQL注入漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SQL注入漏洞")