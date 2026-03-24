import os
import re
from tree_sitter import Language, Parser

# 加载C语言
from .config_path import language_path

LANGUAGES = {
    'c': Language(language_path, 'c'),
}

# 服务端模板注入（SSTI）漏洞模式
SSTI_VULNERABILITIES = {
    'c': [
        # 检测模板引擎函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @template_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(template_render|template_parse|template_eval|mustache_render|handlebars_compile|jinja_render|django_render)$',
            'message': '模板引擎函数调用'
        },
        # 检测动态字符串构建用于模板
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @dest_arg
                        (_) @src_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(sprintf|snprintf|vsprintf|vsnprintf|strcat|strncat|strcpy|strncpy)$',
            'message': '字符串构建函数可能用于模板'
        },
        # 检测模板相关函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @template_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(render|compile|evaluate|execute|process_template|parse_template)$',
            'message': '模板处理函数调用'
        },
        # 检测脚本执行函数可能用于模板
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @script_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(eval|exec|system|popen)$',
            'message': '脚本执行函数可能用于模板处理'
        }
    ]
}

# 模板语法模式
TEMPLATE_SYNTAX_PATTERNS = {
    'c': [
        # 检测模板语法字符串
        {
            'query': '''
                (string_literal) @template_string
            ''',
            'pattern': r'\{\{.*\}\}|\{%.*%\}|\$?\{.*\}|#\{.*\}|\[\[.*\]\]',
            'message': '字符串包含模板语法'
        },
        # 检测模板变量语法
        {
            'query': '''
                (string_literal) @template_var
            ''',
            'pattern': r'\{\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\}\}|\{%.*[a-zA-Z_][a-zA-Z0-9_].*%\}|\$?\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\}|#\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\}|\[\[\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\]\]',
            'message': '字符串包含模板变量语法'
        },
        # 检测模板控制结构
        {
            'query': '''
                (string_literal) @template_control
            ''',
            'pattern': r'\{%\s*(if|for|while|foreach|endfor|endif)\s*.*%\}|\{\{.*\|.*\}\}',
            'message': '字符串包含模板控制结构'
        },
        # 检测模板拼接操作
        {
            'query': '''
                (binary_expression
                    left: (string_literal) @base_template
                    operator: "+"
                    right: (identifier) @user_input
                ) @binary_expr
            ''',
            'message': '模板与用户输入拼接'
        }
    ]
}

# 模板引擎上下文检测
TEMPLATE_ENGINE_CONTEXT = {
    'c': [
        # 检测模板引擎头文件包含
        {
            'query': '''
                (preproc_include
                    path: (string_literal) @include_path
                ) @include
            ''',
            'pattern': r'.*(template|mustache|handlebars|jinja|django|ctemplate|inja|template_engine)\.h',
            'message': '包含模板引擎相关头文件'
        },
        # 检测模板引擎相关类型
        {
            'query': '''
                (type_identifier) @type_name
            ''',
            'pattern': r'^(TemplateEngine|Template|Mustache|Handlebars|Jinja|DjangoTemplate|CTemplate|Inja)$',
            'message': '使用模板引擎相关类型'
        },
        # 检测模板引擎初始化函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'func_pattern': r'^(template_init|mustache_init|handlebars_init|jinja_init|template_engine_create)$',
            'message': '模板引擎初始化函数'
        }
    ]
}

# 危险模板函数模式
DANGEROUS_TEMPLATE_PATTERNS = {
    'c': [
        # 检测危险的模板函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @template_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(eval_template|exec_template|compile_and_exec|unsafe_render|raw_render)$',
            'message': '危险的模板函数调用'
        },
        # 检测文件读取用于模板
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @file_arg
                        (_)*
                    )
                ) @call
            ''',
            'func_pattern': r'^(fopen|open|fread|read|load_file|read_file)$',
            'pattern': r'.*\.(html|htm|tpl|template|mustache|hbs)$',
            'message': '文件读取可能用于模板加载'
        }
    ]
}

# 用户输入源模式（复用之前的定义）
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


def detect_c_ssti_vulnerabilities(code, language='c'):
    """
    检测C代码中服务端模板注入（SSTI）漏洞

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
    template_function_calls = []  # 存储模板相关函数调用
    template_syntax_patterns = []  # 存储模板语法模式
    template_engine_context = []  # 存储模板引擎上下文信息
    dangerous_template_patterns = []  # 存储危险模板模式
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集模板相关函数调用
    for query_info in SSTI_VULNERABILITIES[language]:
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

                elif tag in ['template_arg', 'dest_arg', 'src_arg', 'script_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node
                    # 检查参数模式
                    arg_pattern = query_info.get('pattern', '')
                    if arg_pattern and re.search(arg_pattern, current_capture['arg'], re.IGNORECASE):
                        current_capture['arg_match'] = True

                elif tag in ['call'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    template_function_calls.append({
                        'type': 'template_function',
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
            print(f"模板函数查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第二步：收集模板语法模式（使用节点ID去重）
    processed_string_nodes = set()  # 用于记录已处理的字符串节点

    for query_info in TEMPLATE_SYNTAX_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                # 使用节点位置作为唯一标识
                node_id = f"{node.start_point[0]}:{node.start_point[1]}:{node.end_point[0]}:{node.end_point[1]}"

                if node_id in processed_string_nodes:
                    continue

                if tag in ['template_string', 'template_var', 'template_control', 'base_template']:
                    text = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')

                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        template_syntax_patterns.append({
                            'type': 'template_syntax',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'node_id': node_id,
                            'pattern_match': True,
                            'message': query_info.get('message', ''),
                            'pattern_type': tag  # 记录检测到的模式类型
                        })
                        processed_string_nodes.add(node_id)

                elif tag in ['user_input']:
                    var_text = node.text.decode('utf8')
                    code_snippet = node.parent.text.decode('utf8')
                    template_syntax_patterns.append({
                        'type': 'template_building',
                        'line': node.start_point[0] + 1,
                        'variable': var_text,
                        'code_snippet': code_snippet,
                        'node': node,
                        'node_id': node_id,
                        'message': query_info.get('message', '')
                    })
                    processed_string_nodes.add(node_id)

        except Exception as e:
            print(f"模板语法模式查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第三步：收集模板引擎上下文信息
    for query_info in TEMPLATE_ENGINE_CONTEXT[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                text = node.text.decode('utf8')

                if tag in ['include_path']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        template_engine_context.append({
                            'type': 'template_include',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node,
                            'message': query_info.get('message', '')
                        })

                elif tag in ['type_name']:
                    pattern = query_info.get('pattern', '')
                    if pattern and re.search(pattern, text, re.IGNORECASE):
                        code_snippet = node.text.decode('utf8')
                        template_engine_context.append({
                            'type': 'template_type',
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
                        template_engine_context.append({
                            'type': 'template_function',
                            'line': node.start_point[0] + 1,
                            'text': text,
                            'code_snippet': code_snippet,
                            'node': node.parent,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"模板引擎上下文查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第四步：收集危险模板模式
    for query_info in DANGEROUS_TEMPLATE_PATTERNS[language]:
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

                elif tag in ['template_arg', 'file_arg']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node
                    # 检查参数模式
                    arg_pattern = query_info.get('pattern', '')
                    if arg_pattern and re.search(arg_pattern, current_capture['arg'], re.IGNORECASE):
                        current_capture['arg_match'] = True

                elif tag in ['call'] and current_capture:
                    # 完成一个完整的捕获
                    code_snippet = node.text.decode('utf8')

                    dangerous_template_patterns.append({
                        'type': 'dangerous_template',
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
            print(f"危险模板模式查询错误 {query_info.get('message', '未知')}: {e}")
            continue

    # 第五步：收集用户输入源
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

    # 第六步：分析SSTI漏洞（使用智能去重）
    vulnerabilities = analyze_ssti_vulnerabilities_with_deduplication(
        template_function_calls, template_syntax_patterns, template_engine_context,
        dangerous_template_patterns, user_input_sources
    )

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_ssti_vulnerabilities_with_deduplication(template_calls, syntax_patterns, template_context,
                                                    dangerous_patterns,
                                                    user_input_sources):
    """
    分析SSTI漏洞并进行智能去重
    """
    all_vulnerabilities = []

    # 分析模板函数调用漏洞
    for call in template_calls:
        vulnerability_details = analyze_template_function_vulnerability(call, user_input_sources, template_context)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 分析模板语法模式漏洞
    for pattern in syntax_patterns:
        vulnerability_details = analyze_template_syntax_vulnerability(pattern, user_input_sources, template_context)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 分析危险模板模式
    for dangerous in dangerous_patterns:
        vulnerability_details = analyze_dangerous_template_vulnerability(dangerous, user_input_sources)
        if vulnerability_details:
            all_vulnerabilities.append(vulnerability_details)

    # 智能去重
    return intelligent_ssti_deduplication(all_vulnerabilities)


def intelligent_ssti_deduplication(vulnerabilities):
    """
    智能去重：基于代码上下文和语义合并相似漏洞
    """
    if not vulnerabilities:
        return []

    # 按行号分组
    line_groups = {}
    for vuln in vulnerabilities:
        line = vuln['line']
        if line not in line_groups:
            line_groups[line] = []
        line_groups[line].append(vuln)

    # 对每行的漏洞进行智能合并
    deduplicated = []
    for line, vulns in line_groups.items():
        if len(vulns) == 1:
            deduplicated.append(vulns[0])
        else:
            # 多个漏洞，选择最准确的一个
            best_vuln = select_best_ssti_vulnerability(vulns)
            deduplicated.append(best_vuln)

    return deduplicated


def select_best_ssti_vulnerability(vulns):
    """
    从同一行的多个漏洞中选择最准确的一个
    """
    if len(vulns) == 1:
        return vulns[0]

    # 优先级：函数调用漏洞 > 危险模式 > 语法模式
    priority_order = {
        'template_function': 1,
        'dangerous_template': 2,
        'template_syntax': 3,
        'template_building': 4
    }

    # 按优先级排序
    sorted_vulns = sorted(vulns, key=lambda x: priority_order.get(
        x.get('detection_type', 'template_syntax'), 5
    ))

    # 选择优先级最高的漏洞
    best_vuln = sorted_vulns[0]

    # 如果存在更具体的证据，更新消息
    for vuln in sorted_vulns[1:]:
        if '用户输入' in vuln['message'] and '用户输入' not in best_vuln['message']:
            best_vuln['message'] += f" | 检测到用户输入关联"
            best_vuln['severity'] = max_severity(best_vuln['severity'], vuln['severity'])

    return best_vuln


def max_severity(sev1, sev2):
    """
    返回两个严重程度中较高的一个
    """
    severity_order = {'低危': 1, '中危': 2, '高危': 3}
    return sev1 if severity_order.get(sev1, 0) >= severity_order.get(sev2, 0) else sev2


def analyze_template_function_vulnerability(call, user_input_sources, template_context):
    """
    分析模板函数调用漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': call['line'],
        'code_snippet': call['code_snippet'],
        'vulnerability_type': '服务端模板注入(SSTI)',
        'severity': '高危',
        'detection_type': 'template_function'
    }

    # 检查是否包含用户输入
    if call.get('arg_node') and is_user_input_related(call['arg_node'], user_input_sources):
        vulnerability_details['message'] = f"用户输入直接传递给模板函数: {call['function']}"
        is_vulnerable = True

    # 检查是否包含模板语法且可能动态构建
    elif call.get('arg_match', False):
        vulnerability_details['message'] = f"模板函数包含动态模板内容: {call['function']}"
        is_vulnerable = True

    # 检查字符串构建函数在模板上下文中
    elif call['function'] in ['sprintf', 'snprintf', 'strcat', 'strcpy'] and is_in_template_context(call['node'],
                                                                                                    template_context):
        vulnerability_details['message'] = f"模板上下文中的字符串构建: {call['function']}"
        vulnerability_details['severity'] = '中危'
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def analyze_template_syntax_vulnerability(pattern, user_input_sources, template_context):
    """
    分析模板语法模式漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': pattern['line'],
        'code_snippet': pattern['code_snippet'],
        'vulnerability_type': '服务端模板注入(SSTI)',
        'severity': '中危',
        'detection_type': 'template_syntax'
    }

    # 检查模板拼接操作
    if pattern.get('variable') and is_user_input_variable(pattern.get('variable', ''), user_input_sources):
        vulnerability_details['message'] = f"用户输入变量用于模板构建: {pattern['message']}"
        vulnerability_details['severity'] = '高危'
        is_vulnerable = True

    # 检查模板语法在模板上下文中
    elif pattern.get('pattern_match', False) and is_in_template_context(pattern['node'], template_context):
        # 合并多个模式类型的描述
        pattern_type = pattern.get('pattern_type', '')
        if pattern_type == 'template_control':
            desc = "控制结构"
        elif pattern_type == 'template_var':
            desc = "变量语法"
        else:
            desc = "模板语法"

        vulnerability_details['message'] = f"模板上下文中的{desc}: {pattern['text'][:50]}..."
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def analyze_dangerous_template_vulnerability(dangerous, user_input_sources):
    """
    分析危险模板模式漏洞
    """
    is_vulnerable = False
    vulnerability_details = {
        'line': dangerous['line'],
        'code_snippet': dangerous['code_snippet'],
        'vulnerability_type': '服务端模板注入(SSTI)',
        'severity': '高危',
        'detection_type': 'dangerous_template'
    }

    if dangerous.get('arg_match', False):
        vulnerability_details['message'] = f"危险模板函数调用: {dangerous['function']}"
        is_vulnerable = True

    elif dangerous.get('arg_node') and is_user_input_related(dangerous['arg_node'], user_input_sources):
        vulnerability_details['message'] = f"用户输入传递给危险模板函数: {dangerous['function']}"
        is_vulnerable = True

    return vulnerability_details if is_vulnerable else None


def is_user_input_related(arg_node, user_input_sources):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'template', 'content', 'html']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_in_template_context(node, template_context):
    """
    检查节点是否在模板上下文中
    """
    node_line = node.start_point[0] + 1

    for context in template_context:
        context_line = context['line']
        # 如果模板上下文在调用之前或同一区域
        if context_line <= node_line and (node_line - context_line) < 50:
            return True

    return False


def is_user_input_variable(var_name, user_input_sources):
    """
    检查变量名是否与用户输入相关
    """
    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'argc', 'input', 'buffer', 'data', 'param', 'user', 'cmd', 'template']
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


def analyze_ssti(code_string):
    """
    分析C代码字符串中的服务端模板注入(SSTI)漏洞
    """
    return detect_c_ssti_vulnerabilities(code_string, 'c')


# 示例使用
if __name__ == "__main__":
    # 测试C代码 - SSTI场景
    test_c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <template_engine.h>

// 危险示例 - SSTI漏洞
void vulnerable_ssti_functions(int argc, char* argv[]) {
    TemplateEngine* engine;
    char* result;

    // 初始化模板引擎
    engine = template_init();

    // 漏洞1: 直接使用用户输入构建模板
    char* user_template = argv[1];
    char template1[200];
    sprintf(template1, "Hello {{%s}}", user_template);

    result = template_render(engine, template1, NULL);  // SSTI漏洞

    // 漏洞2: 直接使用用户输入的模板
    if (argc > 2) {
        result = template_render(engine, argv[2], NULL);  // 直接SSTI漏洞
    }

    // 漏洞3: 字符串拼接构建模板
    char username[100];
    strcpy(username, argv[1]);
    char template2[200] = "Welcome {{";
    strcat(template2, username);
    strcat(template2, "}}!";
    result = template_render(engine, template2, NULL);  // SSTI漏洞

    // 漏洞4: 从文件读取模板内容
    char template_content[1024];
    FILE* fp = fopen("template.tpl", "r");
    if (fp) {
        fgets(template_content, sizeof(template_content), fp);
        fclose(fp);
        // 用户可能控制文件内容
        result = template_render(engine, template_content, NULL);  // 潜在SSTI
    }

    // 漏洞5: 使用危险的模板函数
    char dangerous_template[200];
    sprintf(dangerous_template, "{%s}", argv[3]);
    result = eval_template(engine, dangerous_template);  // 危险函数

    // 漏洞6: Mustache模板引擎
    Mustache* mustache = mustache_init();
    char mustache_template[200];
    sprintf(mustache_template, "{{#%s}}...{{/%s}}", argv[4], argv[4]);
    result = mustache_render(mustache, mustache_template, NULL);  // SSTI漏洞

    // 漏洞7: 模板控制结构注入
    char control_template[300];
    sprintf(control_template, "{% if %s %}Admin{% endif %}", argv[5]);
    result = template_render(engine, control_template, NULL);  // 控制结构注入

    template_cleanup(engine);
}

// 相对安全的示例
void safe_template_functions() {
    TemplateEngine* safe_engine = template_init();
    char* result;

    // 安全1: 硬编码模板
    result = template_render(safe_engine, "Hello {{name}}", NULL);  // 安全

    // 安全2: 经过验证的模板内容
    char validated_template[200];
    // 模板验证逻辑...
    // if (validate_template(user_input)) {
    //     strcpy(validated_template, user_input);
    // }

    // 安全3: 使用转义函数
    char escaped_input[100];
    // 输入转义逻辑...
    // html_escape(user_input, escaped_input);
    char safe_template[200];
    sprintf(safe_template, "Hello %s", escaped_input);
    result = template_render(safe_engine, safe_template, NULL);

    template_cleanup(safe_engine);
}

// 其他模板引擎示例
void jinja_example(int argc, char* argv[]) {
    Jinja* jinja = jinja_init();

    // 危险: 用户控制模板
    char jinja_template[200];
    sprintf(jinja_template, "{{ %s }}", argv[1]);
    char* result = jinja_render(jinja, jinja_template, NULL);  // SSTI漏洞

    jinja_cleanup(jinja);
}

void handlebars_example(int argc, char* argv[]) {
    Handlebars* hbs = handlebars_init();

    // 危险: 用户控制模板
    char hbs_template[200];
    sprintf(hbs_template, "{{{ %s }}}", argv[1]);
    char* result = handlebars_compile(hbs, hbs_template);  // SSTI漏洞

    handlebars_cleanup(hbs);
}

int main(int argc, char* argv[]) {
    vulnerable_ssti_functions(argc, argv);
    safe_template_functions();
    jinja_example(argc, argv);
    handlebars_example(argc, argv);
    return 0;
}
"""

    print("=" * 60)
    print("C语言服务端模板注入(SSTI)漏洞检测（智能去重版）")
    print("=" * 60)

    results = analyze_ssti(test_c_code)

    if results:
        print(f"检测到 {len(results)} 个潜在SSTI漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SSTI漏洞")