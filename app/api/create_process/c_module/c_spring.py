import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# Spring表达式注入漏洞模式 - 优化后的查询
SPRING_EXPRESSION_INJECTION_VULNERABILITIES = {
    'c': [
        # 主要检测：Spring表达式解析函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @first_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(SpelExpressionParser_parseExpression|spel_parser_parse|spring_expression_parse|SpEL_eval|spel_evaluate|parseExpression|evaluate|evalExpression|parseSpel|evaluateExpression|getValue|setValue)$',
            'message': 'Spring表达式解析函数调用'
        },
        # 检测包含"spel"或"expression"的函数名（更严格的模式）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @first_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(.*[Ss]pel.*|.*[Ee]xpression.*|.*[Ss]pEL.*)$',
            'message': '可能涉及Spring表达式处理的函数',
            'severity': '中危'  # 降低严重性
        }
    ]
}

# Spring表达式相关危险模式 - 优化查询
SPRING_EXPRESSION_DANGEROUS_PATTERNS = {
    'c': [
        # 检测包含Spring表达式语法的字符串
        {
            'query': '''
                (string_literal) @string_lit
            ''',
            'pattern': r'#\{.*\}|\$\{.*\}|T\([^)]*\)|\bnew\s+\w+\([^)]*\)|\.\w+\([^)]*\)',
            'message': '字符串包含Spring表达式语法'
        },
        # 检测表达式模板构建（更具体的模式）
        {
            'query': '''
                (binary_expression
                    left: (string_literal) @left_str
                    operator: "+"
                    right: (identifier) @right_var
                ) @binary_expr
            ''',
            'message': '字符串与变量拼接可能用于构建表达式模板'
        }
    ]
}

# Spring表达式上下文检测 - 优化查询
SPRING_EXPRESSION_CONTEXT = {
    'c': [
        # 检测Spring相关头文件包含
        {
            'query': '''
                (preproc_include
                    path: (string_literal) @include_path
                ) @include
            ''',
            'pattern': r'.*(spring|spel|expression)\.h',
            'message': '包含Spring表达式相关头文件'
        },
        # 检测Spring相关类型定义
        {
            'query': '''
                (type_identifier) @type_name
            ''',
            'pattern': r'^(SpelExpressionParser|Expression|SpelParser|EvaluationContext)$',
            'message': '使用Spring表达式相关类型'
        }
    ]
}


def detect_c_spring_expression_injection(code, language='c'):
    """
    检测C代码中Spring表达式注入漏洞 - 修复重复报告问题

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

    # 使用集合来跟踪已处理的节点，避免重复
    processed_nodes = set()
    vulnerabilities = []

    # 收集所有相关信息
    spring_expression_calls = collect_spring_expression_calls(root, language, processed_nodes)
    dangerous_patterns = collect_dangerous_patterns(root, language, processed_nodes)
    spring_context = collect_spring_context(root, language)
    user_input_sources = collect_user_input_sources(root, language)

    # 分析漏洞
    vulnerabilities.extend(analyze_spring_injection_vulnerabilities(
        spring_expression_calls, dangerous_patterns, spring_context, user_input_sources
    ))

    return sorted(vulnerabilities, key=lambda x: x['line'])


def collect_spring_expression_calls(root, language, processed_nodes):
    """
    收集Spring表达式相关调用 - 避免重复
    """
    spring_expression_calls = []

    for query_info in SPRING_EXPRESSION_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                # 跳过已处理的节点
                if node.id in processed_nodes:
                    continue

                if tag in ['func_name']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['func_node'] = node
                        current_capture['severity'] = query_info.get('severity', '高危')

                elif tag in ['first_arg']:
                    arg_text = node.text.decode('utf8')
                    current_capture['arg'] = arg_text
                    current_capture['arg_node'] = node

                elif tag in ['call'] and current_capture:
                    # 标记节点为已处理
                    processed_nodes.add(node.id)

                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    spring_expression_calls.append({
                        'type': 'spring_expression_call',
                        'line': current_capture['line'],
                        'function': current_capture.get('func', ''),
                        'argument': current_capture.get('arg', ''),
                        'arg_node': current_capture.get('arg_node'),
                        'code_snippet': code_snippet,
                        'node': node,
                        'severity': current_capture.get('severity', '高危'),
                        'message': query_info.get('message', '')
                    })
                    current_capture = {}

        except Exception as e:
            print(f"Spring表达式查询错误 {query_info.get('message')}: {e}")
            continue

    return spring_expression_calls


def collect_dangerous_patterns(root, language, processed_nodes):
    """
    收集危险模式 - 避免重复
    """
    dangerous_patterns = []

    for query_info in SPRING_EXPRESSION_DANGEROUS_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                # 跳过已处理的节点
                if node.id in processed_nodes:
                    continue

                if tag in ['string_lit', 'left_str']:
                    text = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')

                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        # 标记节点为已处理
                        processed_nodes.add(node.id)

                        code_snippet = node.text.decode('utf8')
                        dangerous_patterns.append({
                            'type': 'dangerous_pattern',
                            'line': node.start_point[0] + 1,
                            'pattern_match': True,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

                elif tag in ['binary_expr']:
                    # 标记节点为已处理
                    if node.id not in processed_nodes:
                        processed_nodes.add(node.id)

                        code_snippet = node.text.decode('utf8')
                        dangerous_patterns.append({
                            'type': 'expression_building',
                            'line': node.start_point[0] + 1,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"危险模式查询错误 {query_info.get('message')}: {e}")
            continue

    return dangerous_patterns


def collect_spring_context(root, language):
    """
    收集Spring上下文信息
    """
    spring_context = []

    for query_info in SPRING_EXPRESSION_CONTEXT[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag in ['include_path', 'type_name']:
                    text = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')

                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        spring_context.append({
                            'type': 'spring_context',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"Spring上下文查询错误 {query_info.get('message')}: {e}")
            continue

    return spring_context


def collect_user_input_sources(root, language):
    """
    收集用户输入源
    """
    user_input_sources = []

    user_input_query = '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        ) @call
    '''

    user_input_patterns = [
        {'func_pattern': r'^(scanf|fscanf|sscanf|gets|fgets|getchar|fgetc|getc|read|getline)$',
         'message': '标准输入函数'},
        {'func_pattern': r'^(recv|recvfrom|recvmsg|read)$', 'message': '网络输入函数'},
        {'func_pattern': r'^(fread|fgetc|fgets)$', 'message': '文件输入函数'},
        {'func_pattern': r'^(getenv)$', 'message': '环境变量获取'},
        {'func_pattern': r'^(main)$', 'arg_index': 1, 'message': '命令行参数'}
    ]

    try:
        query = LANGUAGES[language].query(user_input_query)
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern_info in user_input_patterns:
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
        print(f"用户输入源收集错误: {e}")

    return user_input_sources


def analyze_spring_injection_vulnerabilities(expression_calls, dangerous_patterns, spring_context, user_input_sources):
    """
    分析Spring表达式注入漏洞 - 改进的去重逻辑
    """
    vulnerabilities = []
    reported_locations = set()  # 用于跟踪已报告的位置

    # 分析Spring表达式调用
    for call in expression_calls:
        location_key = f"{call['line']}:{call['function']}"

        # 检查是否已报告过相同位置
        if location_key in reported_locations:
            continue

        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vulnerability_type': 'Spring表达式注入',
            'severity': call.get('severity', '高危')
        }

        is_vulnerable = False

        # 检查是否包含用户输入
        if call.get('arg_node') and is_user_input_related(call['arg_node'], user_input_sources):
            vulnerability_details['message'] = f"用户输入直接传递给Spring表达式函数: {call['function']}"
            is_vulnerable = True

        # 检查是否在Spring上下文中且有潜在风险
        elif is_in_spring_context(call['node'], spring_context) and has_potential_risk(call):
            vulnerability_details['message'] = f"Spring上下文中的潜在危险表达式调用: {call['function']}"
            vulnerability_details['severity'] = '中危'
            is_vulnerable = True

        # 对于低风险模式，只在有明确危险信号时报告
        elif call['severity'] == '中危' and has_explicit_danger_signs(call):
            vulnerability_details['message'] = f"检测到可能的Spring表达式处理: {call['function']}"
            vulnerability_details['severity'] = '低危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)
            reported_locations.add(location_key)

    # 分析危险模式 - 只报告未在调用中覆盖的模式
    for pattern in dangerous_patterns:
        location_key = f"{pattern['line']}:pattern"

        if location_key in reported_locations:
            continue

        # 检查这个模式是否已经被任何调用覆盖
        if not is_pattern_covered_by_call(pattern, expression_calls):
            vulnerability_details = {
                'line': pattern['line'],
                'code_snippet': pattern['code_snippet'],
                'vulnerability_type': 'Spring表达式注入',
                'severity': '中危'
            }

            if pattern.get('pattern_match', False):
                vulnerability_details['message'] = f"检测到Spring表达式语法: {pattern['message']}"
            else:
                vulnerability_details['message'] = f"动态构建表达式模板: {pattern['message']}"

            vulnerabilities.append(vulnerability_details)
            reported_locations.add(location_key)

    return vulnerabilities


def is_user_input_related(arg_node, user_input_sources):
    """检查参数节点是否与用户输入相关"""
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'request', 'query']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_in_spring_context(node, spring_context):
    """检查节点是否在Spring上下文中"""
    node_line = node.start_point[0] + 1

    for context in spring_context:
        context_line = context['line']
        # 如果Spring上下文在调用之前或同一区域
        if context_line <= node_line and (node_line - context_line) < 50:
            return True

    return False


def has_potential_risk(call):
    """检查调用是否有潜在风险"""
    # 检查参数是否包含动态内容
    if call.get('argument'):
        arg_text = call['argument']
        risk_indicators = ['argv', 'sprintf', 'strcat', 'fgets', 'scanf']
        for indicator in risk_indicators:
            if indicator in arg_text:
                return True
    return False


def has_explicit_danger_signs(call):
    """检查是否有明确的危险信号"""
    if call.get('argument'):
        arg_text = call['argument']
        danger_signs = ['exec', 'Runtime', 'System', 'Process', 'eval']
        for sign in danger_signs:
            if sign in arg_text:
                return True
    return False


def is_pattern_covered_by_call(pattern, expression_calls):
    """检查模式是否已经被调用覆盖"""
    pattern_line = pattern['line']
    pattern_code = pattern['code_snippet']

    for call in expression_calls:
        # 如果调用在同一行或附近，并且代码片段相似，则认为已覆盖
        if abs(call['line'] - pattern_line) <= 2 and pattern_code in call['code_snippet']:
            return True

    return False


def is_child_node(child, parent):
    """检查一个节点是否是另一个节点的子节点"""
    node = child
    while node:
        if node == parent:
            return True
        node = node.parent
    return False


def analyze_spring_expression_injection(code_string):
    """分析C代码字符串中的Spring表达式注入漏洞"""
    return detect_c_spring_expression_injection(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - Spring表达式注入场景
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spring_expression.h"

// 危险示例 - Spring表达式注入漏洞
void vulnerable_spring_functions(int argc, char* argv[]) {
    // Spring表达式解析器
    SpelExpressionParser* parser = createSpelExpressionParser();

    // 漏洞1: 直接使用用户输入
    char* user_input = argv[1];
    Expression* expr1 = SpelExpressionParser_parseExpression(parser, user_input); // 直接注入漏洞
    evaluateExpression(expr1, NULL);

    // 漏洞2: 字符串拼接构建表达式
    char expression_template[200];
    sprintf(expression_template, "T(java.lang.Runtime).getRuntime().exec('%s')", argv[1]);
    Expression* expr2 = SpelExpressionParser_parseExpression(parser, expression_template); // 命令注入

    // 漏洞3: 动态构建表达式
    char dynamic_expr[100];
    strcpy(dynamic_expr, "#{");
    strcat(dynamic_expr, argv[1]);
    strcat(dynamic_expr, "}");
    Expression* expr3 = parseSpelExpression(parser, dynamic_expr); // 表达式注入

    // 漏洞4: 从文件读取表达式
    char file_content[1024];
    FILE* fp = fopen("expression.txt", "r");
    fgets(file_content, sizeof(file_content), fp);
    fclose(fp);
    Expression* expr4 = SpelExpressionParser_parseExpression(parser, file_content); // 文件内容注入
}

// 相对安全的示例
void safe_spring_functions() {
    SpelExpressionParser* safe_parser = createSpelExpressionParser();

    // 安全1: 硬编码表达式
    Expression* safe_expr1 = SpelExpressionParser_parseExpression(safe_parser, "2 + 2"); // 安全

    // 安全2: 常量表达式
    const char* safe_expression = "systemProperties['user.name']";
    Expression* safe_expr2 = SpelExpressionParser_parseExpression(safe_parser, safe_expression); // 相对安全

    // 安全3: 经过验证的输入
    char validated_input[100];
    // 输入验证逻辑...
    Expression* safe_expr3 = SpelExpressionParser_parseExpression(safe_parser, validated_input); // 经过验证
}

int main(int argc, char* argv[]) {
    vulnerable_spring_functions(argc, argv);
    safe_spring_functions();
    return 0;
}
"""

    print("=" * 60)
    print("C语言Spring表达式注入漏洞检测（修复重复报告）")
    print("=" * 60)

    results = analyze_spring_expression_injection(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在Spring表达式注入漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Spring表达式注入漏洞")