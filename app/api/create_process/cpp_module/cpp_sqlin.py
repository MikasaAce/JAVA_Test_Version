import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++ SQL注入漏洞模式
SQL_INJECTION_VULNERABILITIES = {
    'cpp': [
        # 检测字符串拼接构建SQL查询
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (call_expression
                            function: (identifier) @method_name
                            arguments: (argument_list) @method_args
                        ) @method_call
                    )
                ) @call
                (#match? @method_name "^(c_str|data)$")
            ''',
            'func_pattern': r'^(sqlite3_exec|mysql_query|mysql_real_query|PQexec|PQexecParams|SQLExecDirect)$',
            'message': '字符串对象转换为C字符串后执行SQL'
        },
        # 检测直接使用用户输入构建SQL
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (identifier) @arg_var
                    )
                ) @call
            ''',
            'func_pattern': r'^(sqlite3_exec|mysql_query|mysql_real_query|PQexec|PQexecParams|SQLExecDirect)$',
            'message': 'SQL执行函数直接使用变量'
        },
        # 检测ODBC SQL执行函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(SQLExecDirect|SQLPrepare|SQLExecute)$',
            'message': 'ODBC SQL执行函数调用'
        },
        # 检测PostgreSQL libpq函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(PQexec|PQexecParams|PQprepare|PQexecPrepared)$',
            'message': 'PostgreSQL SQL执行函数调用'
        },
        # 检测MySQL C API函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(mysql_query|mysql_real_query|mysql_stmt_execute|mysql_stmt_prepare)$',
            'message': 'MySQL SQL执行函数调用'
        },
        # 检测SQLite函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(sqlite3_exec|sqlite3_prepare|sqlite3_prepare_v2|sqlite3_prepare_v3)$',
            'message': 'SQLite SQL执行函数调用'
        }
    ]
}

# 用户输入源模式
USER_INPUT_SOURCES = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    ''',
    'patterns': [
        r'^(cin|getline|gets|fgets|scanf|sscanf|fscanf|getc|getchar|read)$',
        r'^(recv|recvfrom|recvmsg|ReadFile)$',
        r'^(fread|fgetc|fgets|getline)$',
        r'^(getenv|_wgetenv)$',
        r'^(GetCommandLine|GetCommandLineW)$'
    ]
}

# 危险字符串函数模式
DANGEROUS_STRING_FUNCTIONS = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    ''',
    'patterns': [
        r'^strcat$',
        r'^strcpy$',
        r'^wcscat$',
        r'^wcscpy$',
        r'^sprintf$',
        r'^swprintf$',
        r'^vsprintf$',
        r'^vswprintf$',
        r'^snprintf$',
        r'^vsnprintf$'
    ]
}

# 参数化查询安全函数模式
SAFE_SQL_FUNCTIONS = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    ''',
    'patterns': [
        r'^sqlite3_bind_',
        r'^mysql_stmt_bind_',
        r'^PQbind$',
        r'^SQLBindParameter$',
        r'^SQLSetParam$'
    ]
}


def detect_cpp_sql_injection(code, language='cpp'):
    """
    检测C++代码中SQL注入漏洞
    """
    if language not in LANGUAGES:
        return []

    parser = Parser()
    parser.set_language(LANGUAGES[language])
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    vulnerabilities = []
    sql_calls = []
    user_input_sources = []
    dangerous_string_ops = []
    safe_sql_operations = []

    # 第一步：收集SQL函数调用
    for query_info in SQL_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, func_name, re.IGNORECASE):
                        sql_calls.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
        except Exception as e:
            print(f"SQL查询错误: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in USER_INPUT_SOURCES['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        user_input_sources.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break
    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：收集危险字符串操作
    try:
        query = LANGUAGES[language].query(DANGEROUS_STRING_FUNCTIONS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in DANGEROUS_STRING_FUNCTIONS['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        dangerous_string_ops.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break
    except Exception as e:
        print(f"危险字符串函数查询错误: {e}")

    # 第四步：收集安全SQL操作
    try:
        query = LANGUAGES[language].query(SAFE_SQL_FUNCTIONS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in SAFE_SQL_FUNCTIONS['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        safe_sql_operations.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break
    except Exception as e:
        print(f"安全SQL函数查询错误: {e}")

    # 第五步：分析漏洞
    for call in sql_calls:
        is_vulnerable = False
        code_snippet = call['code_snippet']

        vulnerability_details = {
            'line': call['line'],
            'code_snippet': code_snippet,
            'vulnerability_type': 'SQL注入',
            'severity': '高危',
            'function': call['function']
        }

        # 检查是否包含用户输入特征
        if contains_user_input_patterns(code_snippet):
            vulnerability_details['message'] = f"SQL函数调用包含用户输入特征: {call['function']}"
            is_vulnerable = True

        # 检查是否使用危险字符串函数
        elif contains_dangerous_functions(code_snippet, dangerous_string_ops):
            vulnerability_details['message'] = f"SQL函数调用前使用危险字符串操作: {call['function']}"
            is_vulnerable = True

        # 检查是否使用字符串拼接
        elif contains_string_concatenation(code_snippet):
            vulnerability_details['message'] = f"使用字符串拼接构建SQL查询: {call['function']}"
            is_vulnerable = True

        if is_vulnerable:
            # 检查是否有安全措施
            if uses_parameterized_queries(call, safe_sql_operations):
                vulnerability_details['severity'] = '中危'
                vulnerability_details['message'] += ' (但使用了参数化措施)'

            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_user_input_patterns(code_snippet):
    """检查代码片段是否包含用户输入特征"""
    user_input_patterns = [
        r'\bargv\b',
        r'\bcin\b',
        r'\bscanf\b',
        r'\bgetenv\b',
        r'\bfgets\b',
        r'\bgetline\b',
        r'\brecv\b',
        r'\bReadFile\b',
        r'%s', r'%d', r'%f'  # printf格式符
    ]

    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in user_input_patterns)


def contains_dangerous_functions(code_snippet, dangerous_string_ops):
    """检查代码片段是否包含危险字符串函数"""
    dangerous_patterns = [op['function'] for op in dangerous_string_ops]
    return any(func in code_snippet for func in dangerous_patterns)


def contains_string_concatenation(code_snippet):
    """检查代码片段是否包含字符串拼接"""
    return '+' in code_snippet and ('"' in code_snippet or "'" in code_snippet)


def uses_parameterized_queries(sql_call, safe_sql_operations):
    """检查是否使用了参数化查询"""
    # 简单的行号接近检查
    for safe_op in safe_sql_operations:
        if abs(sql_call['line'] - safe_op['line']) < 10:
            return True
    return False


def analyze_cpp_code(code_string):
    """分析C++代码字符串中的SQL注入漏洞"""
    return detect_cpp_sql_injection(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 更简单的测试代码
    test_cpp_code = """
#include <iostream>
#include <cstring>
#include <sqlite3.h>

void test_vulnerable(int argc, char* argv[]) {
    sqlite3* db;

    // 明显的SQL注入漏洞
    char sql[100];
    sprintf(sql, "SELECT * FROM users WHERE name='%s'", argv[1]);
    sqlite3_exec(db, sql, 0, 0, 0);

    // 字符串拼接
    std::string query = "DELETE FROM products WHERE id = " + std::string(argv[2]);
    sqlite3_exec(db, query.c_str(), 0, 0, 0);

    // 直接使用用户输入
    sqlite3_exec(db, argv[3], 0, 0, 0);
}

void test_safe() {
    sqlite3* db;
    // 安全的硬编码查询
    sqlite3_exec(db, "SELECT * FROM config", 0, 0, 0);
}

int main(int argc, char* argv[]) {
    test_vulnerable(argc, argv);
    test_safe();
    return 0;
}
"""

    print("=" * 60)
    print("C++ SQL注入漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   函数: {vuln['function']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SQL注入漏洞")