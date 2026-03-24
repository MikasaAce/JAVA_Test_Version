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

# 定义SSTI漏洞模式
SSTI_VULNERABILITIES = {
    'python': [
        # 检测Jinja2模板渲染
        {
            'query': '''
                (call
                    function: (identifier) @render_func
                    arguments: (argument_list 
                        (_) @template_name
                        (_)? @template_context
                    )
                ) @call
            ''',
            'func_pattern': r'^(render_template|render_template_string)$',
            'message': 'Jinja2模板渲染'
        },
        # 检测Flask的render_template
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @flask_obj
                        attribute: (identifier) @render_method
                    )
                    arguments: (argument_list 
                        (_) @template_name
                        (_)? @template_context
                    )
                ) @call
            ''',
            'obj_pattern': r'^(flask|current_app)$',
            'method_pattern': r'^(render_template|render_template_string)$',
            'message': 'Flask模板渲染'
        },
        # 检测Django模板渲染
        {
            'query': '''
                (call
                    function: (identifier) @django_func
                    arguments: (argument_list 
                        (_) @request_obj
                        (_) @template_name
                        (_)? @template_context
                    )
                ) @call
            ''',
            'func_pattern': r'^(render|render_to_response)$',
            'message': 'Django模板渲染'
        },
        # 检测Template类实例化
        {
            'query': '''
                (call
                    function: (identifier) @template_class
                    arguments: (argument_list 
                        (_) @template_content
                    )
                ) @call
            ''',
            'class_pattern': r'^(Template|Environment|TemplateSyntax)$',
            'message': '模板类实例化'
        },
        # 检测字符串拼接的模板内容
        {
            'query': '''
                (call
                    function: (identifier) @template_func
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @template_left
                            operator: "+"
                            right: (_) @template_right
                        ) @concat_template
                    )
                ) @call
            ''',
            'func_pattern': r'^(render_template_string|Template|render)$',
            'message': '字符串拼接的模板内容'
        },
        # 检测format格式化的模板
        {
            'query': '''
                (call
                    function: (identifier) @template_func
                    arguments: (argument_list 
                        (call
                            function: (attribute
                                object: (string) @base_template
                                attribute: (identifier) @format_method
                            )
                            arguments: (argument_list (_)* @format_args)
                        ) @format_call
                    )
                ) @call
            ''',
            'func_pattern': r'^(render_template_string|Template|render)$',
            'message': 'format格式化的模板内容'
        },
        # 检测f-string模板
        {
            'query': '''
                (call
                    function: (identifier) @template_func
                    arguments: (argument_list 
                        (interpolation) @fstring_template
                    )
                ) @call
            ''',
            'func_pattern': r'^(render_template_string|Template|render)$',
            'message': 'f-string模板内容'
        },
        # 检测模板渲染方法调用
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @template_obj
                        attribute: (identifier) @render_method
                    )
                    arguments: (argument_list 
                        (_)? @render_context
                    )
                ) @call
            ''',
            'method_pattern': r'^(render|generate|stream)$',
            'message': '模板对象渲染方法'
        },
        # 检测Mako模板
        {
            'query': '''
                (call
                    function: (identifier) @mako_func
                    arguments: (argument_list 
                        (_) @mako_template
                    )
                ) @call
            ''',
            'func_pattern': r'^(Template|TemplateLookup)$',
            'message': 'Mako模板渲染'
        },
        # 检测Tornado模板
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @tornado_obj
                        attribute: (identifier) @render_method
                    )
                    arguments: (argument_list 
                        (_) @tornado_template
                    )
                ) @call
            ''',
            'obj_pattern': r'^(RequestHandler|tornado\.web)$',
            'method_pattern': r'^(render|render_string)$',
            'message': 'Tornado模板渲染'
        }
    ]
}

# 用户输入源模式（SSTI相关）
SSTI_USER_INPUT_SOURCES = {
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

# 模板构建模式
TEMPLATE_BUILDING_PATTERNS = {
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
            'var_pattern': r'^(template|tpl|html|content|body|message|output|response)$',
            'message': '模板内容构建'
        },
        {
            'base_string_pattern': r'(\{\{.*\}\}|\{%.*%\}|\{#.*#\})',
            'message': '模板语法字符串构建'
        }
    ]
}

# 危险模板模式
DANGEROUS_TEMPLATE_PATTERNS = {
    'jinja2_dangerous': [
        r'\{\{.*__class__.*\}\}',
        r'\{\{.*__mro__.*\}\}',
        r'\{\{.*__subclasses__.*\}\}',
        r'\{\{.*__globals__.*\}\}',
        r'\{\{.*__init__.*\}\}',
        r'\{\{.*config.*\}\}',
        r'\{\{.*request.*\}\}',
        r'\{\{.*os\.*\}\}',
        r'\{\{.*subprocess.*\}\}',
        r'\{\{.*import.*\}\}',
        r'\{\{.*eval.*\}\}',
        r'\{\{.*exec.*\}\}',
        r'\{\{.*open.*\}\}',
        r'\{\{.*file.*\}\}',
        r'\{%.*import.*%\}',
        r'\{%.*include.*%\}',
        r'\{%.*from.*import.*%\}'
    ],
    'django_dangerous': [
        r'\{\{.*\._meta\.*\}\}',
        r'\{\{.*\.objects\.*\}\}',
        r'\{\{.*config.*\}\}',
        r'\{\{.*settings.*\}\}',
        r'\{\{.*request.*\}\}',
        r'\{\{.*__dict__.*\}\}',
        r'\{\{.*\.delete.*\}\}',
        r'\{\{.*\.save.*\}\}'
    ],
    'mako_dangerous': [
        r'\$\{.*__import__.*\}',
        r'\$\{.*eval.*\}',
        r'\$\{.*exec.*\}',
        r'\$\{.*open.*\}',
        r'\$\{.*file.*\}',
        r'\$\{.*os\.*\}',
        r'\$\{.*subprocess.*\}'
    ],
    'tornado_dangerous': [
        r'\{\{.*__import__.*\}\}',
        r'\{\{.*eval.*\}\}',
        r'\{\{.*exec.*\}\}',
        r'\{\{.*open.*\}\}',
        r'\{\{.*file.*\}\}'
    ]
}

def analyze_ssti(code, language='python'):
    """
    检测Python代码中服务器端模板注入漏洞

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
    template_operations = []  # 存储模板操作
    user_input_sources = []  # 存储用户输入源
    template_buildings = []  # 存储模板构建操作

    # 第一步：收集所有模板操作
    for query_info in SSTI_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['render_func', 'flask_obj', 'render_method', 'django_func', 
                          'template_class', 'template_func', 'template_obj', 'mako_func',
                          'tornado_obj']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['template_name', 'template_content', 'template_context', 
                           'template_left', 'template_right', 'base_template', 
                           'fstring_template', 'render_context', 'mako_template',
                           'tornado_template']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['format_method', 'format_call']:
                    current_capture[tag] = node.text.decode('utf8')

                elif tag == 'call' and current_capture:
                    # 检查方法名是否匹配模式
                    func_pattern = query_info.get('func_pattern', '')
                    obj_pattern = query_info.get('obj_pattern', '')
                    method_pattern = query_info.get('method_pattern', '')
                    class_pattern = query_info.get('class_pattern', '')

                    func_match = True
                    obj_match = True
                    method_match = True
                    class_match = True

                    if func_pattern and 'render_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['render_func'], re.IGNORECASE)
                    elif func_pattern and 'django_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['django_func'], re.IGNORECASE)
                    elif func_pattern and 'template_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['template_func'], re.IGNORECASE)
                    elif func_pattern and 'mako_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['mako_func'], re.IGNORECASE)

                    if obj_pattern and 'flask_obj' in current_capture:
                        obj_match = re.match(obj_pattern, current_capture['flask_obj'], re.IGNORECASE)
                    elif obj_pattern and 'tornado_obj' in current_capture:
                        obj_match = re.match(obj_pattern, current_capture['tornado_obj'], re.IGNORECASE)

                    if method_pattern and 'render_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['render_method'], re.IGNORECASE)

                    if class_pattern and 'template_class' in current_capture:
                        class_match = re.match(class_pattern, current_capture['template_class'], re.IGNORECASE)

                    if func_match and obj_match and method_match and class_match:
                        code_snippet = node.text.decode('utf8')

                        template_operations.append({
                            'type': 'template_operation',
                            'line': current_capture['line'],
                            'function': current_capture.get('render_func', '') or 
                                       current_capture.get('render_method', '') or
                                       current_capture.get('django_func', '') or
                                       current_capture.get('template_class', '') or
                                       current_capture.get('template_func', '') or
                                       current_capture.get('mako_func', ''),
                            'object': current_capture.get('flask_obj', '') or 
                                     current_capture.get('template_obj', '') or
                                     current_capture.get('tornado_obj', ''),
                            'template_content': current_capture.get('template_name', '') or 
                                              current_capture.get('template_content', '') or
                                              current_capture.get('template_left', '') or
                                              current_capture.get('fstring_template', '') or
                                              current_capture.get('mako_template', '') or
                                              current_capture.get('tornado_template', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'vulnerability_type': query_info.get('message', 'SSTI风险')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"SSTI查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(SSTI_USER_INPUT_SOURCES['query'])
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
                for pattern_info in SSTI_USER_INPUT_SOURCES['patterns']:
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

    # 第三步：收集模板构建操作
    try:
        query = LANGUAGES[language].query(TEMPLATE_BUILDING_PATTERNS['query'])
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
                # 检查是否匹配模板构建模式
                for pattern_info in TEMPLATE_BUILDING_PATTERNS['patterns']:
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
                        template_buildings.append({
                            'type': 'template_building',
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
        print(f"模板构建查询错误: {e}")

    # 第四步：分析SSTI漏洞
    for template_op in template_operations:
        vulnerability_details = analyze_template_operation(template_op, user_input_sources, template_buildings)
        if vulnerability_details:
            vulnerabilities.extend(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_template_operation(template_op, user_input_sources, template_buildings):
    """
    分析单个模板操作的安全问题
    """
    vulnerabilities = []
    code_snippet = template_op['code_snippet']
    line = template_op['line']
    function_name = template_op['function']
    template_content = template_op['template_content']

    # 检查直接用户输入
    if is_direct_user_input(template_op, user_input_sources):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSTI',
            'severity': '高危',
            'message': f"{function_name} 操作直接使用用户输入作为模板内容"
        })

    # 检查字符串拼接
    elif is_string_concatenation(template_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSTI',
            'severity': '高危',
            'message': f"{function_name} 操作使用字符串拼接构建模板内容"
        })

    # 检查危险模板模式
    elif contains_dangerous_template_patterns(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSTI',
            'severity': '严重',
            'message': f"{function_name} 操作包含危险的模板注入模式"
        })

    # 检查模板验证缺失
    elif not has_template_validation(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SSTI',
            'severity': '中危',
            'message': f"{function_name} 操作缺少模板验证逻辑"
        })

    return vulnerabilities


def is_direct_user_input(template_op, user_input_sources):
    """
    检查模板内容是否直接来自用户输入
    """
    template_content = template_op['template_content']
    
    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'request', 'args', 'form', 'get', 
                      'post', 'template', 'content', 'html', 'body']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', template_content, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == template_op['node'] or is_child_node(template_op['node'], source['node']):
            return True

    return False


def is_string_concatenation(template_op):
    """
    检查是否使用字符串拼接构建模板
    """
    code_snippet = template_op['code_snippet']
    return '+' in code_snippet and any(keyword in code_snippet for keyword in 
                                     ['render_template', 'Template', 'render'])


def contains_dangerous_template_patterns(code_snippet):
    """
    检查是否包含危险的模板模式
    """
    # 检查Jinja2危险模式
    for pattern in DANGEROUS_TEMPLATE_PATTERNS['jinja2_dangerous']:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True
            
    # 检查Django危险模式
    for pattern in DANGEROUS_TEMPLATE_PATTERNS['django_dangerous']:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True
            
    # 检查Mako危险模式
    for pattern in DANGEROUS_TEMPLATE_PATTERNS['mako_dangerous']:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True
            
    # 检查Tornado危险模式
    for pattern in DANGEROUS_TEMPLATE_PATTERNS['tornado_dangerous']:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True
            
    return False


def has_template_validation(code_snippet):
    """
    检查代码片段是否包含模板验证逻辑
    """
    validation_patterns = [
        r'sanitize',
        r'escape',
        r'validate',
        r'check',
        r'whitelist',
        r'allowed',
        r'safe',
        r'Markup',
        r'escape_html',
        r'clean_html',
        r'bleach',
        r'html_sanitizer'
    ]
    
    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in validation_patterns)


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


def analyze_ssti_main(code_string):
    """
    主函数：分析Python代码字符串中的SSTI漏洞
    """
    return analyze_ssti(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
from flask import Flask, render_template, render_template_string, request
from django.shortcuts import render
from jinja2 import Template, Environment
from mako.template import Template as MakoTemplate
import tornado.web
import os

app = Flask(__name__)

# 不安全的SSTI示例
def insecure_ssti_examples():
    # 直接用户输入模板 - 高危
    user_template = request.args.get('template')
    return render_template_string(user_template)  # 高危: SSTI
    
    # 字符串拼接模板 - 高危
    base_template = \"\"\"<h1>Welcome {{ name }}</h1>\"\"\"
    user_content = request.form.get('content')
    full_template = base_template + user_content  # 高危
    return render_template_string(full_template)
    
    # format格式化模板 - 高危
    user_name = request.json.get('name')
    template = \"\"\"Hello {{ %s }}!\"\"\" % user_name  # 高危
    return render_template_string(template)
    
    # f-string模板 - 高危
    user_input = request.args.get('input')
    template = f\"\"\"<div>{{ {user_input} }}</div>\"\"\"  # 高危
    return render_template_string(template)
    
    # Jinja2 Template类 - 高危
    user_template = request.form.get('template')
    tpl = Template(user_template)  # 高危
    return tpl.render()
    
    # 包含危险表达式的模板 - 严重
    malicious_template = \"\"\"{{ ''.__class__.__mro__[1].__subclasses__() }}\"\"\"
    render_template_string(malicious_template)  # 严重
    
    # Django模板注入 - 高危
    return render(request, request.GET.get('template'), {})  # 高危

# 相对安全的模板操作示例
def safe_template_examples():
    # 硬编码模板 - 安全
    return render_template_string('<h1>Hello World</h1>')  # 安全
    
    # 经过验证的用户输入 - 安全
    user_template = request.args.get('template', '')
    if is_safe_template(user_template):
        return render_template_string(user_template)  # 安全
    
    # 转义用户输入 - 安全
    from markupsafe import escape
    user_input = request.form.get('name', '')
    safe_template = f\"\"\"<h1>Hello {escape(user_input)}!</h1>\"\"\"  # 安全
    return render_template_string(safe_template)
    
    # 使用模板文件 - 安全
    return render_template('index.html', name=request.args.get('name'))  # 安全
    
    # 白名单验证 - 安全
    allowed_templates = ['welcome.html', 'error.html', 'success.html']
    template_name = request.args.get('template')
    if template_name in allowed_templates:
        return render_template(template_name)  # 安全

# 不同模板引擎示例
def different_template_engines():
    # Mako模板 - 高危
    user_template = request.args.get('mako_template')
    tpl = MakoTemplate(user_template)  # 高危
    return tpl.render()
    
    # Tornado模板 - 高危
    class MainHandler(tornado.web.RequestHandler):
        def get(self):
            template_content = self.get_argument('template', '')
            self.render(template_content)  # 高危
    
    # Jinja2环境 - 高危
    env = Environment()
    user_template = request.form.get('template')
    template = env.from_string(user_template)  # 高危
    return template.render()

# 混合示例
def mixed_examples():
    # 部分验证
    user_template = request.args.get('template')
    if user_template:  # 验证不充分
        return render_template_string(user_template)  # 高危
    
    # 使用安全函数
    safe_render = create_safe_template(request.form.get('content'))
    return safe_render  # 相对安全
    
    # 直接构造模板上下文
    context = {
        'user_input': request.args.get('input')  # 可能不安全
    }
    return render_template('page.html', **context)  # 需要检查上下文内容

# 模板验证辅助函数
def is_safe_template(template_content):
    \"\"\"检查模板内容是否安全\"\"\"
    if not template_content:
        return False
        
    # 检查危险表达式
    dangerous_patterns = [
        r'\{\{.*__class__.*\}\}',
        r'\{\{.*__mro__.*\}\}',
        r'\{\{.*__subclasses__.*\}\}',
        r'\{\{.*__globals__.*\}\}',
        r'\{\{.*__init__.*\}\}',
        r'\{\{.*import.*\}\}',
        r'\{\{.*eval.*\}\}',
        r'\{\{.*exec.*\}\}',
        r'\{\{.*open.*\}\}',
        r'\{%.*import.*%\}',
        r'\{%.*include.*%\}'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, template_content, re.IGNORECASE):
            return False
            
    return True

def create_safe_template(user_content):
    \"\"\"创建安全的模板\"\"\"
    from markupsafe import escape
    
    # 转义所有用户输入
    safe_content = escape(user_content)
    
    # 使用固定的模板结构
    template = f\"\"\"<div class=\"content\">{safe_content}</div>\"\"\"
    
    return render_template_string(template)

# 高级SSTI攻击示例
def advanced_ssti_attacks():
    # 通过上下文注入 - 高危
    user_ctx = request.get_json()
    return render_template_string('{{ config }}', **user_ctx)  # 高危
    
    # 过滤器滥用 - 高危
    user_filter = request.args.get('filter')
    template = f\"\"\"{{{{ ''|{user_filter} }}}}\"\"\"  # 高危
    return render_template_string(template)
    
    # 全局函数调用 - 严重
    malicious_template = \"\"\"{{ lipsum.__globals__['os'].popen('id').read() }}\"\"\"
    render_template_string(malicious_template)  # 严重

if __name__ == "__main__":
    insecure_ssti_examples()
    safe_template_examples()
    different_template_engines()
    mixed_examples()
    advanced_ssti_attacks()
"""

    print("=" * 60)
    print("Python SSTI漏洞检测")
    print("=" * 60)

    results = analyze_ssti_main(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个SSTI漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SSTI漏洞")