import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义Spring表达式注入漏洞模式（修复版）
SPRING_EXPRESSION_INJECTION_VULNERABILITIES = {
    'cpp': [
        # 检测SpEL表达式解析函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list . (_) @expr_arg)
                ) @call
            ''',
            'func_pattern': r'^(parseExpression|evaluate|getValue|setValue|createExpression)$',
            'message': 'Spring表达式解析函数调用'
        },
        # 检测ExpressionParser相关调用
        {
            'query': '''
                (call_expression
                    function: (field_expression
                        field: (identifier) @field_name
                    )
                    arguments: (argument_list . (_) @expr_arg)
                ) @call
            ''',
            'field_pattern': r'^(parseExpression|evaluate|getValue)$',
            'message': 'ExpressionParser表达式解析调用'
        },
        # 检测StandardEvaluationContext的使用
        {
            'query': '''
                (new_expression
                    type: (type_identifier) @type_name
                ) @new_expr
            ''',
            'type_pattern': r'^(StandardEvaluationContext|SpelExpressionParser|ExpressionParser)$',
            'message': 'Spring表达式上下文创建'
        },
        # 检测变量声明中的Spring类型
        {
            'query': '''
                (declaration
                    type: (type_identifier) @type_name
                    declarator: (init_declarator
                        declarator: (identifier) @var_name
                    )
                ) @decl
            ''',
            'type_pattern': r'^(StandardEvaluationContext|SpelExpressionParser|ExpressionParser|EvaluationContext)$',
            'message': 'Spring表达式相关类型声明'
        }
    ]
}

# C++用户输入源模式（修复版）
USER_INPUT_SOURCES = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(cin|getline|gets|fgets|scanf|sscanf|fscanf|getc|getchar|read)$',
            'message': '标准输入函数'
        },
        {
            'func_pattern': r'^(recv|recvfrom|recvmsg|ReadFile)$',
            'message': '网络输入函数'
        },
        {
            'func_pattern': r'^(fread|fgetc|fgets|getline)$',
            'message': '文件输入函数'
        },
        {
            'func_pattern': r'^(getenv|_wgetenv)$',
            'message': '环境变量获取'
        },
        {
            'func_pattern': r'^(GetCommandLine|GetCommandLineW)$',
            'message': '命令行参数获取'
        }
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
        r'^vswprintf$'
    ]
}

# 字符串拼接模式
STRING_CONCATENATION_PATTERNS = {
    'query': '''
        (binary_expression
            left: (_) @left
            operator: "+"
            right: (_) @right
        ) @concat_expr
    ''',
    'message': '字符串拼接操作'
}


def detect_cpp_spring_expression_injection(code, language='cpp'):
    """
    检测C++代码中Spring表达式注入漏洞

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
    spring_expr_calls = []  # 存储Spring表达式相关调用
    user_input_sources = []  # 存储用户输入源
    dangerous_string_ops = []  # 存储危险字符串操作
    string_concatenations = []  # 存储字符串拼接操作

    # 第一步：收集所有Spring表达式相关调用
    for query_info in SPRING_EXPRESSION_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'field_name', 'type_name']:
                    name = node.text.decode('utf8')

                    # 检查函数名模式
                    func_pattern = query_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                    # 检查字段模式
                    field_pattern = query_info.get('field_pattern', '')
                    if field_pattern and re.match(field_pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                    # 检查类型模式
                    type_pattern = query_info.get('type_pattern', '')
                    if type_pattern and re.match(type_pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['expr_arg', 'var_name']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag in ['call', 'new_expr', 'decl'] and current_capture:
                    # 完成一个完整的捕获
                    if 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')

                        spring_expr_calls.append({
                            'type': 'spring_expr',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有用户输入源
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                # 检查是否匹配任何用户输入模式
                for pattern_info in USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        code_snippet = node.parent.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': code_snippet,
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

    # 第四步：收集字符串拼接操作
    try:
        query = LANGUAGES[language].query(STRING_CONCATENATION_PATTERNS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'concat_expr':
                code_snippet = node.text.decode('utf8')
                string_concatenations.append({
                    'line': node.start_point[0] + 1,
                    'code_snippet': code_snippet,
                    'node': node
                })

    except Exception as e:
        print(f"字符串拼接查询错误: {e}")

    # 第五步：分析Spring表达式注入漏洞
    for call in spring_expr_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': 'Spring表达式注入',
            'severity': '高危'
        }

        # 情况1: 检查参数是否来自用户输入
        if call.get('arg_node') and is_user_input_related(call['arg_node'], user_input_sources, root):
            vulnerability_details['message'] = f"用户输入直接传递给Spring表达式解析函数: {call['function']}"
            is_vulnerable = True

        # 情况2: 检查参数是否经过危险字符串操作
        elif call.get('arg_node') and is_dangerous_string_operation(call['arg_node'], dangerous_string_ops, root):
            vulnerability_details['message'] = f"经过危险字符串操作后传递给Spring表达式解析函数: {call['function']}"
            is_vulnerable = True

        # 情况3: 检查表达式是否包含危险模式
        elif call.get('argument') and contains_dangerous_expression(call['argument']):
            vulnerability_details['message'] = f"表达式包含可能危险的模式: {call['function']}"
            is_vulnerable = True

        # 情况4: 检查是否使用不安全的上下文类型
        elif call['function'] in ['StandardEvaluationContext']:
            vulnerability_details['message'] = f"使用StandardEvaluationContext - 可能不安全的表达式上下文"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_dangerous_expression(argument):
    """
    检查参数是否包含危险的Spring表达式模式
    """
    dangerous_patterns = [
        r'T\([^)]*\)',  # 类型引用
        r'#\{[^}]*\}',  # SpEL表达式
        r'\$\\\{[^}]*\\\}',  # 属性占位符
        r'new\s+\w+\(',  # 对象创建
        r'@\w+\(',  # Bean引用
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, argument, re.IGNORECASE):
            return True

    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'env', 'input', 'buffer', 'cmd', 'command', 'param',
                       'request', 'response', 'session', 'header', 'parameter']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_dangerous_string_operation(arg_node, dangerous_string_ops, root_node):
    """
    检查参数是否经过危险字符串操作
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查是否直接使用了危险字符串函数的缓冲区
    for op in dangerous_string_ops:
        if op['function'] in arg_text:
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


def analyze_cpp_spring_expression_injection(code_string):
    """
    分析C++代码字符串中的Spring表达式注入漏洞
    """
    return detect_cpp_spring_expression_injection(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <string>
#include <spring/expression/ExpressionParser.h>
#include <spring/expression/spel/standard/StandardEvaluationContext.h>

using namespace std;
using namespace Spring;

void vulnerable_spring_function(int argc, char* argv[]) {
    // 创建表达式解析器
    SpelExpressionParser parser;

    // 用户输入直接传递给表达式解析 - 高危
    if (argc > 1) {
        Expression expr = parser.parseExpression(argv[1]); // Spring表达式注入漏洞
        cout << expr.getValue() << endl;
    }

    // 使用StandardEvaluationContext - 高危
    StandardEvaluationContext context;
    context.setVariable("userInput", "dangerousInput");

    // 环境变量直接使用 - 高危
    char* path = getenv("PATH");
    Expression expr2 = parser.parseExpression(path);
    cout << expr2.getValue(context) << endl;

    // 字符串拼接后解析表达式 - 高危
    string userTemplate = "#{";
    string userData;
    cin >> userData;
    userTemplate += userData + "}";
    Expression expr3 = parser.parseExpression(userTemplate);
    cout << expr3.getValue() << endl;

    // 危险字符串操作
    char buffer[100];
    sprintf(buffer, "#{%s}", argv[1]);
    Expression expr4 = parser.parseExpression(buffer);
}

void safe_spring_function() {
    // 安全的硬编码表达式
    SpelExpressionParser parser;
    Expression expr = parser.parseExpression("1 + 2");
    cout << expr.getValue() << endl;
}

int main(int argc, char* argv[]) {
    vulnerable_spring_function(argc, argv);
    safe_spring_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++ Spring表达式注入漏洞检测")
    print("=" * 60)

    results = analyze_cpp_spring_expression_injection(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Spring表达式注入漏洞")