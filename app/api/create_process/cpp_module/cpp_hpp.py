import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经定义在config_path中
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义HTTP参数污染漏洞模式
HTTP_PARAMETER_POLLUTION_VULNERABILITIES = {
    'cpp': [
        # 检测从HTTP请求中获取参数的函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(cgi|CGI|getenv|_getenv|GetEnvironmentVariable|getParameter|getQueryString|getHeader|getCookies)$',
            'message': 'HTTP参数获取函数调用'
        },
        # 检测Web框架特定的参数获取函数
        {
            'query': '''
                (call_expression
                    function: (field_expression
                        object: (_) @obj
                        field: (_) @field
                    )
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'obj_pattern': r'^(request|req|http_request|HttpRequest)$',
            'field_pattern': r'^(getParameter|getQueryString|getHeader|getCookies|operator\[\])$',
            'message': 'Web框架参数获取方法'
        },
        # 检测参数直接用于关键操作（如数据库查询、文件操作等）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @param_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(sqlite3_exec|mysql_query|pqexec|system|popen|fopen|open|create|ifstream|ofstream|fstream)$',
            'message': '参数直接用于关键操作'
        },
        # 检测参数拼接后用于关键操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @left
                            operator: "+"
                            right: (_) @right
                        ) @concat_arg
                    )
                ) @call
            ''',
            'func_pattern': r'^(sqlite3_exec|mysql_query|pqexec|system|popen|fopen|open)$',
            'message': '参数拼接后用于关键操作'
        }
    ]
}

# HTTP参数获取函数模式
HTTP_PARAMETER_SOURCES = {
    'query': '''
        [
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list) @args
            )
            (call_expression
                function: (field_expression
                    object: (_) @obj
                    field: (_) @field
                )
                arguments: (argument_list) @args
            )
        ] @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(cgi|CGI|getenv|_getenv|GetEnvironmentVariable)$',
            'message': '环境变量获取函数'
        },
        {
            'func_pattern': r'^(getParameter|getQueryString|getHeader|getCookies)$',
            'message': 'HTTP参数获取函数'
        },
        {
            'obj_pattern': r'^(request|req|http_request|HttpRequest)$',
            'field_pattern': r'^(getParameter|getQueryString|getHeader|getCookies|operator\[\])$',
            'message': 'Web框架参数获取方法'
        },
        {
            'func_pattern': r'^(QUERY_STRING|HTTP_.*)$',
            'message': 'CGI环境变量'
        }
    ]
}

# 关键操作函数模式
CRITICAL_OPERATIONS = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list (_)* @args)
        ) @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(sqlite3_exec|mysql_query|pqexec|mysql_real_query)$',
            'message': '数据库查询操作'
        },
        {
            'func_pattern': r'^(system|popen|execl|execlp|execle|execv|execvp|execvpe|WinExec|ShellExecute)$',
            'message': '命令执行操作'
        },
        {
            'func_pattern': r'^(fopen|open|create|ifstream|ofstream|fstream|fread|fwrite)$',
            'message': '文件操作'
        },
        {
            'func_pattern': r'^(printf|sprintf|snprintf|fprintf|vprintf|vsprintf|vfprintf)$',
            'message': '格式化输出操作'
        }
    ]
}


def detect_cpp_hpp_vulnerabilities(code, language='cpp'):
    """
    检测C++代码中HTTP参数污染漏洞

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
    parameter_sources = []  # 存储HTTP参数获取点
    critical_operations = []  # 存储关键操作点

    # 第一步：收集所有HTTP参数获取点
    try:
        query = LANGUAGES[language].query(HTTP_PARAMETER_SOURCES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                current_capture['func'] = func_name
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['obj', 'field']:
                name = node.text.decode('utf8')
                if tag == 'obj':
                    current_capture['object'] = name
                else:
                    current_capture['field'] = name

            elif tag == 'call' and current_capture:
                # 检查是否匹配任何HTTP参数源模式
                for pattern_info in HTTP_PARAMETER_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    obj_pattern = pattern_info.get('obj_pattern', '')
                    field_pattern = pattern_info.get('field_pattern', '')

                    match = False
                    if func_pattern and 'func' in current_capture:
                        if re.match(func_pattern, current_capture['func'], re.IGNORECASE):
                            match = True
                    elif obj_pattern and field_pattern and 'object' in current_capture and 'field' in current_capture:
                        if (re.match(obj_pattern, current_capture['object'], re.IGNORECASE) and
                                re.match(field_pattern, current_capture['field'], re.IGNORECASE)):
                            match = True

                    if match:
                        code_snippet = node.text.decode('utf8')
                        parameter_sources.append({
                            'type': 'parameter_source',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'object': current_capture.get('object', ''),
                            'field': current_capture.get('field', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"HTTP参数源查询错误: {e}")

    # 第二步：收集所有关键操作点
    try:
        query = LANGUAGES[language].query(CRITICAL_OPERATIONS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern_info in CRITICAL_OPERATIONS['patterns']:
                    pattern = pattern_info['func_pattern']
                    if re.match(pattern, func_name, re.IGNORECASE):
                        critical_operations.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent,
                            'operation_type': pattern_info['message']
                        })
                        break

    except Exception as e:
        print(f"关键操作查询错误: {e}")

    # 第三步：分析漏洞 - 检查参数是否直接用于关键操作
    for operation in critical_operations:
        # 获取操作的所有参数
        op_node = operation['node']

        # 查找参数节点
        arg_nodes = []
        for child in op_node.children:
            if child.type == 'argument_list':
                for arg in child.children:
                    if arg.type != '(' and arg.type != ')':
                        arg_nodes.append(arg)

        # 检查每个参数是否来自HTTP参数源
        for i, arg_node in enumerate(arg_nodes):
            arg_text = arg_node.text.decode('utf8')

            # 检查参数是否直接来自HTTP参数源
            for source in parameter_sources:
                if is_parameter_used(arg_node, source, root):
                    vulnerability_details = {
                        'line': operation['line'],
                        'code_snippet': operation['code_snippet'],
                        'vulnerability_type': 'HTTP参数污染',
                        'severity': '中危',
                        'message': f"HTTP参数直接用于{operation['operation_type']}: {operation['function']}"
                    }
                    vulnerabilities.append(vulnerability_details)
                    break

            # 检查参数是否包含明显的HTTP参数名
            http_param_patterns = [
                r'\b(query|param|parameter|id|name|user|username|password|email|token|session|cookie)\b',
                r'\b(QUERY_STRING|REQUEST_METHOD|HTTP_.*)\b'
            ]

            for pattern in http_param_patterns:
                if re.search(pattern, arg_text, re.IGNORECASE):
                    vulnerability_details = {
                        'line': operation['line'],
                        'code_snippet': operation['code_snippet'],
                        'vulnerability_type': 'HTTP参数污染',
                        'severity': '中危',
                        'message': f"疑似HTTP参数用于{operation['operation_type']}: {operation['function']}"
                    }
                    vulnerabilities.append(vulnerability_details)
                    break

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_parameter_used(arg_node, parameter_source, root_node):
    """
    检查参数节点是否使用了来自HTTP参数源的值
    """
    # 简单实现：检查参数节点是否包含参数源中的变量名
    arg_text = arg_node.text.decode('utf8')
    source_text = parameter_source['node'].text.decode('utf8')

    # 提取变量名
    var_pattern = r'[a-zA-Z_][a-zA-Z0-9_]*'
    arg_vars = re.findall(var_pattern, arg_text)
    source_vars = re.findall(var_pattern, source_text)

    # 检查是否有共同的变量
    common_vars = set(arg_vars) & set(source_vars)
    if common_vars:
        return True

    # 更复杂的实现可以在这里添加数据流分析

    return False


def analyze_cpp_code(code_string):
    """
    分析C++代码字符串中的HTTP参数污染漏洞
    """
    return detect_cpp_hpp_vulnerabilities(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cgi/Cgi.h>

using namespace std;

void vulnerable_cgi_function() {
    // CGI示例 - 获取查询参数
    cgi::Cgi request;
    string query = request.getParameter("query");

    // 直接用于系统命令 - 高危
    system(("search " + query).c_str());

    // 直接用于数据库查询 - 高危
    string sql = "SELECT * FROM users WHERE name = '" + query + "'";
    mysql_query(connection, sql.c_str());

    // 直接用于文件操作 - 高危
    string filename = "/tmp/" + query;
    FILE* file = fopen(filename.c_str(), "r");
}

void vulnerable_env_function() {
    // 从环境变量获取参数
    char* query_str = getenv("QUERY_STRING");
    if (query_str) {
        // 直接用于命令执行 - 高危
        system(("process " + string(query_str)).c_str());
    }
}

void safe_function() {
    // 相对安全的做法 - 参数验证和清理
    cgi::Cgi request;
    string query = request.getParameter("query");

    // 参数验证
    if (is_valid_input(query)) {
        // 使用参数化查询
        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name = ?", -1, &stmt, 0);
        sqlite3_bind_text(stmt, 1, query.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
    }
}

bool is_valid_input(const string& input) {
    // 简单的输入验证
    return input.find_first_of(";|&`$()") == string::npos;
}

int main() {
    vulnerable_cgi_function();
    vulnerable_env_function();
    safe_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++ HTTP参数污染漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到HTTP参数污染漏洞")