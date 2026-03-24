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

# 定义反射型XSS漏洞模式
REFLECTED_XSS_VULNERABILITIES = {
    'python': [
        # 检测直接返回用户输入
        {
            'query': '''
                (return_statement
                    value: (_) @return_value
                ) @return_stmt
            ''',
            'message': '直接返回用户输入'
        },
        # 检测字符串拼接的响应
        {
            'query': '''
                (return_statement
                    value: (binary_expression
                        left: (_) @left_part
                        operator: "+"
                        right: (_) @right_part
                    ) @concat_expr
                ) @return_stmt
            ''',
            'message': '字符串拼接的响应'
        },
        # 检测format格式化的响应
        {
            'query': '''
                (return_statement
                    value: (call
                        function: (attribute
                            object: (string) @base_string
                            attribute: (identifier) @format_method
                        )
                        arguments: (argument_list (_)* @format_args)
                    ) @format_call
                ) @return_stmt
            ''',
            'message': 'format格式化的响应'
        },
        # 检测f-string响应
        {
            'query': '''
                (return_statement
                    value: (interpolation) @fstring_expr
                ) @return_stmt
            ''',
            'message': 'f-string响应'
        },
        # 检测Flask响应返回
        {
            'query': '''
                (return_statement
                    value: (call
                        function: (identifier) @response_func
                        arguments: (argument_list (_) @response_content)
                    ) @return_stmt
                ) @return_call
            ''',
            'func_pattern': r'^(make_response|Response|jsonify)$',
            'message': 'Flask响应返回'
        },
        # 检测Django HttpResponse
        {
            'query': '''
                (return_statement
                    value: (call
                        function: (identifier) @http_response
                        arguments: (argument_list (_) @response_content)
                    ) @return_stmt
                ) @return_call
            ''',
            'func_pattern': r'^(HttpResponse|JsonResponse|HttpResponseRedirect)$',
            'message': 'Django HTTP响应'
        },
        # 检测模板渲染中的用户输入
        {
            'query': '''
                (return_statement
                    value: (call
                        function: (identifier) @render_func
                        arguments: (argument_list 
                            (_) @template_name
                            (_)? @template_context
                        )
                    ) @return_stmt
                ) @return_call
            ''',
            'func_pattern': r'^(render_template|render|render_to_response)$',
            'message': '模板渲染返回'
        },
        # 检测字符串构建赋值后返回
        {
            'query': '''
                (assignment
                    left: (identifier) @var_name
                    right: (binary_expression
                        left: (_) @left_expr
                        operator: "+"
                        right: (_) @right_expr
                    ) @concat_expr
                ) @assignment
                (return_statement
                    value: (identifier) @return_var
                ) @return_stmt
            ''',
            'message': '字符串构建后返回'
        }
    ]
}

# 用户输入源模式（XSS相关）
XSS_USER_INPUT_SOURCES = {
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
            'obj_pattern': r'^(flask|django|bottle|tornado)\.request$',
            'attr_pattern': r'^(args|form|values|data|json|files|get|post|cookies|headers)$',
            'message': 'Web请求参数'
        },
        {
            'obj_pattern': r'^request$',
            'attr_pattern': r'^(args|form|values|data|json|files|get|post|cookies|headers)$',
            'message': '请求对象参数'
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

# HTML构建模式
HTML_BUILDING_PATTERNS = {
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
            'var_pattern': r'^(html|content|response|output|result|message|error|success|data)$',
            'message': 'HTML内容构建'
        },
        {
            'base_string_pattern': r'^(<[a-zA-Z][^>]*>|</[a-zA-Z]+>|<script|javascript:)',
            'message': 'HTML标签构建'
        }
    ]
}

# 危险XSS模式
DANGEROUS_XSS_PATTERNS = {
    'script_patterns': [
        r'<script[^>]*>',
        r'javascript:',
        r'onclick=',
        r'onload=',
        r'onerror=',
        r'onmouseover=',
        r'alert\(',
        r'document\.cookie',
        r'window\.location',
        r'eval\(',
        r'setTimeout\(',
        r'setInterval\(',
        r'Function\(',
        r'innerHTML',
        r'outerHTML',
        r'document\.write',
        r'document\.writeln'
    ],
    'html_entities': [
        r'&lt;',
        r'&gt;',
        r'&amp;',
        r'&quot;',
        r'&#x27;',
        r'&#x2F;'
    ]
}

def analyze_reflected_xss(code, language='python'):
    """
    检测Python代码中反射型XSS漏洞

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
    return_operations = []  # 存储返回操作
    user_input_sources = []  # 存储用户输入源
    html_buildings = []  # 存储HTML构建操作

    # 第一步：收集所有返回操作
    for query_info in REFLECTED_XSS_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['return_value', 'left_part', 'right_part', 'base_string', 
                          'fstring_expr', 'response_func', 'http_response', 
                          'render_func', 'var_name', 'return_var']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['format_method', 'format_call', 'template_name', 
                           'template_context', 'response_content']:
                    current_capture[tag] = node.text.decode('utf8')

                elif tag in ['return_stmt', 'assignment'] and current_capture:
                    # 检查函数名是否匹配模式
                    func_pattern = query_info.get('func_pattern', '')
                    
                    func_match = True
                    if func_pattern and 'response_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['response_func'], re.IGNORECASE)
                    elif func_pattern and 'http_response' in current_capture:
                        func_match = re.match(func_pattern, current_capture['http_response'], re.IGNORECASE)
                    elif func_pattern and 'render_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['render_func'], re.IGNORECASE)

                    if func_match:
                        code_snippet = node.text.decode('utf8')

                        return_operations.append({
                            'type': 'return_operation',
                            'line': current_capture['line'],
                            'return_value': current_capture.get('return_value', '') or 
                                          current_capture.get('left_part', '') or
                                          current_capture.get('fstring_expr', '') or
                                          current_capture.get('response_content', '') or
                                          current_capture.get('return_var', ''),
                            'function': current_capture.get('response_func', '') or
                                      current_capture.get('http_response', '') or
                                      current_capture.get('render_func', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'vulnerability_type': query_info.get('message', '反射型XSS风险')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"反射型XSS查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(XSS_USER_INPUT_SOURCES['query'])
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
                for pattern_info in XSS_USER_INPUT_SOURCES['patterns']:
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

    # 第三步：收集HTML构建操作
    try:
        query = LANGUAGES[language].query(HTML_BUILDING_PATTERNS['query'])
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
                # 检查是否匹配HTML构建模式
                for pattern_info in HTML_BUILDING_PATTERNS['patterns']:
                    var_pattern = pattern_info.get('var_pattern', '')
                    base_string_pattern = pattern_info.get('base_string_pattern', '')

                    var_match = False
                    base_match = True  # 如果没有base_string_pattern，默认为True

                    if var_pattern and 'var_name' in current_capture:
                        var_match = re.match(var_pattern, current_capture['var_name'], re.IGNORECASE)

                    if base_string_pattern and 'base_string' in current_capture:
                        base_match = re.search(base_string_pattern, current_capture['base_string'], re.IGNORECASE)

                    if var_match and base_match:
                        code_snippet = node.text.decode('utf8')
                        html_buildings.append({
                            'type': 'html_building',
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
        print(f"HTML构建查询错误: {e}")

    # 第四步：分析反射型XSS漏洞
    for return_op in return_operations:
        vulnerability_details = analyze_return_operation(return_op, user_input_sources, html_buildings)
        if vulnerability_details:
            vulnerabilities.extend(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_return_operation(return_op, user_input_sources, html_buildings):
    """
    分析单个返回操作的安全问题
    """
    vulnerabilities = []
    code_snippet = return_op['code_snippet']
    line = return_op['line']
    return_value = return_op['return_value']
    function_name = return_op.get('function', 'return')

    # 检查直接用户输入
    if is_direct_user_input(return_op, user_input_sources):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '反射型XSS',
            'severity': '高危',
            'message': f"{function_name} 直接返回用户输入，存在XSS风险"
        })

    # 检查字符串拼接
    elif is_string_concatenation(return_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '反射型XSS',
            'severity': '高危',
            'message': f"{function_name} 使用字符串拼接构建响应，存在XSS风险"
        })

    # 检查危险XSS模式
    elif contains_dangerous_xss_patterns(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '反射型XSS',
            'severity': '严重',
            'message': f"{function_name} 包含危险的XSS攻击模式"
        })

    # 检查HTML转义缺失
    elif not has_html_escaping(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '反射型XSS',
            'severity': '中危',
            'message': f"{function_name} 缺少HTML转义处理"
        })

    return vulnerabilities


def is_direct_user_input(return_op, user_input_sources):
    """
    检查返回值是否直接来自用户输入
    """
    return_value = return_op['return_value']
    
    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'request', 'args', 'form', 'get', 
                      'post', 'data', 'json', 'query', 'param', 'value']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', return_value, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == return_op['node'] or is_child_node(return_op['node'], source['node']):
            return True

    return False


def is_string_concatenation(return_op):
    """
    检查是否使用字符串拼接构建响应
    """
    code_snippet = return_op['code_snippet']
    return '+' in code_snippet and any(keyword in code_snippet for keyword in 
                                     ['return', 'make_response', 'HttpResponse', 'jsonify'])


def contains_dangerous_xss_patterns(code_snippet):
    """
    检查是否包含危险的XSS模式
    """
    # 检查脚本标签和事件处理器
    for pattern in DANGEROUS_XSS_PATTERNS['script_patterns']:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True
            
    return False


def has_html_escaping(code_snippet):
    """
    检查代码片段是否包含HTML转义处理
    """
    escaping_patterns = [
        r'escape\(',
        r'html\.escape',
        r'cgi\.escape',
        r'markupsafe\.escape',
        r'flask\.escape',
        r'jinja2\.escape',
        r'render_template',  # 模板引擎通常自动转义
        r'autoescape=True',
        r'Markup',
        r'bleach',
        r'html_sanitizer',
        r'xss_filter',
        r'sanitize_html'
    ]
    
    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in escaping_patterns)


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


def analyze_reflected_xss_main(code_string):
    """
    主函数：分析Python代码字符串中的反射型XSS漏洞
    """
    return analyze_reflected_xss(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
from flask import Flask, request, make_response, Response, jsonify, render_template_string
from django.http import HttpResponse, JsonResponse
import html
from markupsafe import escape
import json

app = Flask(__name__)

# 不安全的反射型XSS示例
def insecure_xss_examples():
    # 直接返回用户输入 - 高危
    user_input = request.args.get('q')
    return user_input  # 高危: 反射型XSS
    
    # 字符串拼接响应 - 高危
    search_term = request.form.get('search')
    return f"<h1>Search results for: {search_term}</h1>"  # 高危
    
    # format格式化响应 - 高危
    username = request.json.get('username')
    response = "Welcome, {}!".format(username)  # 高危
    return response
    
    # 直接字符串拼接 - 高危
    error_msg = request.args.get('error')
    html_response = "<div class='error'>" + error_msg + "</div>"  # 高危
    return html_response
    
    # Flask make_response - 高危
    message = request.form.get('message')
    return make_response(message)  # 高危
    
    # Django HttpResponse - 高危
    content = request.GET.get('content')
    return HttpResponse(content)  # 高危
    
    # JSON响应中的XSS - 中危
    user_data = request.args.get('data')
    return jsonify({"result": user_data})  # 中危: 如果前端不转义
    
    # 模板字符串渲染 - 高危
    template_str = request.args.get('template')
    return render_template_string(template_str)  # 高危

# 相对安全的响应示例
def safe_response_examples():
    # 转义用户输入 - 安全
    user_input = request.args.get('q')
    safe_input = html.escape(user_input)
    return f"<h1>Search: {safe_input}</h1>"  # 安全
    
    # 使用markupsafe - 安全
    from markupsafe import Markup
    user_content = request.form.get('content')
    safe_content = escape(user_content)
    return f"<div>{safe_content}</div>"  # 安全
    
    # 硬编码响应 - 安全
    return "<h1>Hello World</h1>"  # 安全
    
    # 使用模板文件 - 安全
    return render_template('search.html', query=request.args.get('q'))  # 安全
    
    # JSON响应安全使用 - 安全
    data = {"status": "success", "message": "Operation completed"}
    return jsonify(data)  # 安全
    
    # 白名单验证 - 安全
    allowed_messages = ['success', 'error', 'warning']
    message_type = request.args.get('type')
    if message_type in allowed_messages:
        return f"<div class='{message_type}'>Message</div>"  # 相对安全

# 混合示例
def mixed_examples():
    # 部分转义 - 中危
    user_input = request.args.get('input')
    partially_escaped = user_input.replace('<', '&lt;').replace('>', '&gt;')  # 不完整转义
    return f"<div>{partially_escaped}</div>"  # 中危
    
    # 条件性转义 - 中危
    user_content = request.form.get('content')
    if needs_escaping(user_content):
        safe_content = html.escape(user_content)
    else:
        safe_content = user_content  # 可能不安全
    return safe_content
    
    # 属性中的XSS - 高危
    user_class = request.args.get('class')
    return f"<div class='{user_class}'>Content</div>"  # 高危

# 上下文相关的XSS
def context_specific_xss():
    # HTML属性上下文 - 高危
    user_url = request.args.get('url')
    return f"<a href='{user_url}'>Click me</a>"  # 高危: javascript: URL
    
    # CSS上下文 - 中危
    user_style = request.form.get('style')
    return f"<div style='color: {user_style}'>Text</div>"  # 中危
    
    # JavaScript上下文 - 高危
    user_data = request.json.get('data')
    return f"<script>var data = '{user_data}';</script>"  # 高危
    
    # URL参数上下文 - 高危
    redirect_url = request.args.get('redirect')
    return f"<meta http-equiv='refresh' content='0;url={redirect_url}'>"  # 高危

# 辅助函数
def needs_escaping(content):
    \"\"\"检查内容是否需要转义\"\"\"
    dangerous_chars = ['<', '>', '"', "'", '&']
    return any(char in content for char in dangerous_chars)

def safe_html_response(content):
    \"\"\"创建安全的HTML响应\"\"\"
    escaped_content = html.escape(content)
    return f"<div>{escaped_content}</div>"

def build_safe_url(user_input):
    \"\"\"构建安全的URL\"\"\"
    # 验证URL协议
    if user_input and user_input.startswith(('http://', 'https://')):
        return user_input
    else:
        return '#'  # 安全的默认值

# 高级XSS攻击示例
def advanced_xss_attacks():
    # DOM-based XSS - 高危
    user_fragment = request.args.get('fragment')
    return f\"\"\"<script>
        document.write('<div>{user_fragment}</div>');
    </script>\"\"\"  # 高危
    
    # 事件处理器注入 - 高危
    user_event = request.form.get('event')
    return f"<div {user_event}=\"alert('xss')\">Content</div>"  # 高危
    
    # 样式注入 - 中危
    user_style = request.args.get('style')
    return f"<div style=\"{user_style}\">Content</div>"  # 中危

if __name__ == "__main__":
    insecure_xss_examples()
    safe_response_examples()
    mixed_examples()
    context_specific_xss()
    advanced_xss_attacks()
"""

    print("=" * 60)
    print("Python 反射型XSS漏洞检测")
    print("=" * 60)

    results = analyze_reflected_xss_main(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个反射型XSS漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到反射型XSS漏洞")