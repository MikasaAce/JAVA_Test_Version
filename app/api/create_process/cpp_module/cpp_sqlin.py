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
            'func_pattern': r'^(SQLExecDirect|SQLExecute)$',
            'message': 'ODBC SQL执行函数调用'
        },
        # 检测PostgreSQL libpq执行函数（排除prepare）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(PQexec|PQexecParams|PQexecPrepared)$',
            'message': 'PostgreSQL SQL执行函数调用'
        },
        # 检测MySQL C API执行函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(mysql_query|mysql_real_query|mysql_stmt_execute)$',
            'message': 'MySQL SQL执行函数调用'
        },
        # 检测SQLite执行函数（仅exec，排除prepare/bind/step/column）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                ) @call
            ''',
            'func_pattern': r'^(sqlite3_exec)$',
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

# SQL结果读取函数（不应报告为SQL注入）
SQL_RESULT_FUNCTIONS = [
    r'^sqlite3_column_', r'^sqlite3_step$', r'^sqlite3_finalize$',
    r'^sqlite3_prepare', r'^sqlite3_bind_', r'^sqlite3_errmsg$',
    r'^mysql_fetch_', r'^mysql_num_', r'^mysql_field_', r'^mysql_store_',
    r'^PQgetvalue$', r'^PQntuples$', r'^PQnfields$', r'^PQresultStatus$'
]


def _parse_comment_lines(code):
    """
    解析源码，返回所有属于注释的行号集合（1-based）。
    支持 // 行注释和 /* */ 块注释。
    """
    lines = code.split('\n')
    comment_lines = set()
    in_block_comment = False
    for i, line in enumerate(lines):
        line_num = i + 1
        if in_block_comment:
            comment_lines.add(line_num)
            end_idx = line.find('*/')
            if end_idx != -1:
                in_block_comment = False
        else:
            # 检查块注释开始
            stripped = line.lstrip()
            # 查找该行中非字符串内的 /* 和 //
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
                        end_idx = line.find('*/', idx + 2)
                        if end_idx != -1:
                            in_block_comment = False
                        else:
                            in_block_comment = True
                        break
                idx += 1
    return comment_lines


def _is_sql_result_function(func_name):
    """检查函数名是否为SQL结果读取/准备/辅助函数"""
    for pattern in SQL_RESULT_FUNCTIONS:
        if re.match(pattern, func_name, re.IGNORECASE):
            return True
    return False


def _is_in_safe_function(line_num, safe_func_ranges):
    """检查给定行号是否在 safe_* 函数的作用域内"""
    for start, end in safe_func_ranges:
        if start <= line_num <= end:
            return True
    return False


def _collect_safe_function_ranges(parser, root, language):
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


def detect_cpp_sql_injection(code, language='cpp'):
    """
    检测C++代码中SQL注入漏洞
    """
    if language not in LANGUAGES:
        return []

    # 预处理：收集注释行和safe函数范围
    comment_lines = _parse_comment_lines(code)

    parser = Parser()
    parser.set_language(LANGUAGES[language])
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    safe_func_ranges = _collect_safe_function_ranges(parser, root, LANGUAGES[language])

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
                    line = node.start_point[0] + 1

                    # 跳过注释中的代码
                    if line in comment_lines:
                        continue

                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, func_name, re.IGNORECASE):
                        sql_calls.append({
                            'line': line,
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

    # 第四步：收集安全SQL操作（bind函数）
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
        line = call['line']
        code_snippet = call['code_snippet']

        # 跳过 safe_* 函数内的调用
        if _is_in_safe_function(line, safe_func_ranges):
            continue

        # 跳过SQL结果读取/辅助函数
        if _is_sql_result_function(call['function']):
            continue

        is_vulnerable = False

        vulnerability_details = {
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SQL注入',
            'severity': '高危',
            'function': call['function']
        }

        # 检查是否包含用户输入特征（不含格式符）
        if contains_user_input_patterns(code_snippet):
            vulnerability_details['message'] = f"SQL函数调用包含用户输入特征: {call['function']}"
            is_vulnerable = True

        # 检查是否使用危险字符串函数且参数包含用户输入变量
        elif contains_dangerous_functions_with_user_input(code_snippet, dangerous_string_ops):
            vulnerability_details['message'] = f"SQL函数调用前使用危险字符串操作: {call['function']}"
            is_vulnerable = True

        # 检查是否使用字符串拼接（仅当参数含用户输入变量时）
        elif contains_user_input_concatenation(code_snippet):
            vulnerability_details['message'] = f"使用字符串拼接构建SQL查询: {call['function']}"
            is_vulnerable = True

        if is_vulnerable:
            # 检查是否有安全措施（参数化查询）
            if uses_parameterized_queries(call, safe_sql_operations):
                continue  # 使用了参数化查询，完全排除

            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_user_input_patterns(code_snippet):
    """检查代码片段是否包含用户输入特征（不包含格式符）"""
    user_input_patterns = [
        r'\bargv\b',
        r'\bcin\b',
        r'\bscanf\b',
        r'\bgetenv\b',
        r'\bfgets\b',
        r'\bgetline\b',
        r'\brecv\b',
        r'\bReadFile\b',
    ]
    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in user_input_patterns)


def contains_dangerous_functions_with_user_input(code_snippet, dangerous_string_ops):
    """检查代码片段是否包含危险字符串函数且参数涉及用户输入"""
    for op in dangerous_string_ops:
        func = op['function']
        if func in code_snippet:
            # 检查该函数调用的参数是否包含用户输入变量
            # 匹配 func(user_var) 或 func(buf, user_var) 模式
            user_var_patterns = [
                r'(?:argv|username|password|user_id|user_input|sort_column|search_term|'
                r'limit|offset|input|param|filename)\b'
            ]
            for pattern in user_var_patterns:
                if re.search(pattern, code_snippet, re.IGNORECASE):
                    return True
    return False


def contains_user_input_concatenation(code_snippet):
    """检查代码片段是否使用字符串拼接且拼接了用户输入变量"""
    if '+' not in code_snippet:
        return False
    if '"' not in code_snippet and "'" not in code_snippet:
        return False
    # 检查拼接中是否包含用户输入变量名
    user_var_patterns = [
        r'\bargv\b',
        r'\busername\b',
        r'\bpassword\b',
        r'\buser_id\b',
        r'\buser_input\b',
        r'\bsort_column\b',
        r'\bsearch_term\b',
        r'\binput\b',
    ]
    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in user_var_patterns)


def uses_parameterized_queries(sql_call, safe_sql_operations):
    """检查是否使用了参数化查询 - 基于同一函数作用域内的bind调用"""
    for safe_op in safe_sql_operations:
        # bind操作必须在sql_call之后（行号更大）且在合理范围内
        if 0 < (safe_op['line'] - sql_call['line']) <= 30:
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
