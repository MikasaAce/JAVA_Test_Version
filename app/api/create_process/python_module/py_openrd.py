import os
import re
import sys
from tree_sitter import Language, Parser
from urllib.parse import urlparse

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义Open Redirect漏洞模式
OPEN_REDIRECT_VULNERABILITIES = {
    'python': [
        # 检测redirect函数调用 - 直接用户输入
        {
            'query': '''
                (call
                    function: (identifier) @redirect_func
                    arguments: (argument_list 
                        (_) @redirect_url
                    )
                ) @call
            ''',
            'func_pattern': r'^(redirect|redirect_to|redirect_to_url)$',
            'message': '重定向函数调用'
        },
        # 检测Flask的redirect函数
        {
            'query': '''
                (call
                    function: (identifier) @redirect_func
                    arguments: (argument_list 
                        (_) @redirect_url
                    )
                ) @call
            ''',
            'func_pattern': r'^(redirect)$',
            'message': 'Flask重定向函数调用'
        },
        # 检测Django的redirect函数
        {
            'query': '''
                (call
                    function: (identifier) @redirect_func
                    arguments: (argument_list 
                        (_) @redirect_url
                    )
                ) @call
            ''',
            'func_pattern': r'^(redirect|HttpResponseRedirect|HttpResponsePermanentRedirect)$',
            'message': 'Django重定向函数调用'
        },
        # 检测redirect函数调用 - 属性访问
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @module_obj
                        attribute: (identifier) @redirect_func
                    )
                    arguments: (argument_list 
                        (_) @redirect_url
                    )
                ) @call
            ''',
            'module_pattern': r'^(flask|django\.shortcuts|django\.http)$',
            'func_pattern': r'^(redirect|redirect_to|HttpResponseRedirect|HttpResponsePermanentRedirect)$',
            'message': '模块重定向函数调用'
        },
        # 检测字符串拼接的重定向URL
        {
            'query': '''
                (call
                    function: (identifier) @redirect_func
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @url_left
                            operator: "+"
                            right: (_) @url_right
                        ) @concat_url
                    )
                ) @call
            ''',
            'func_pattern': r'^(redirect|redirect_to|HttpResponseRedirect)$',
            'message': '字符串拼接的重定向URL'
        },
        # 检测format格式化的重定向URL
        {
            'query': '''
                (call
                    function: (identifier) @redirect_func
                    arguments: (argument_list 
                        (call
                            function: (attribute
                                object: (string) @base_url
                                attribute: (identifier) @format_method
                            )
                            arguments: (argument_list (_)* @format_args)
                        ) @format_call
                    )
                ) @call
            ''',
            'func_pattern': r'^(redirect|redirect_to|HttpResponseRedirect)$',
            'message': 'format格式化的重定向URL'
        },
        # 检测f-string重定向URL
        {
            'query': '''
                (call
                    function: (identifier) @redirect_func
                    arguments: (argument_list 
                        (interpolation) @fstring_url
                    )
                ) @call
            ''',
            'func_pattern': r'^(redirect|redirect_to|HttpResponseRedirect)$',
            'message': 'f-string重定向URL'
        },
        # 检测URL构建函数调用
        {
            'query': '''
                (call
                    function: (identifier) @url_func
                    arguments: (argument_list (_)* @url_args)
                ) @call
            ''',
            'func_pattern': r'^(url_for|reverse|build_absolute_uri|full_url)$',
            'message': 'URL构建函数调用'
        }
    ]
}

# 用户输入源模式（Open Redirect相关）
REDIRECT_USER_INPUT_SOURCES = {
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
            'obj_pattern': r'^(flask|django)\.request$',
            'attr_pattern': r'^(args|form|values|data|json|get|post)$',
            'message': 'Web请求参数'
        },
        {
            'obj_pattern': r'^request$',
            'attr_pattern': r'^(args|form|values|data|json|get|post)$',
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

# 重定向URL构建模式
REDIRECT_URL_BUILDING_PATTERNS = {
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
            'var_pattern': r'^(url|redirect_url|next|target|return_url|redirect_to|location)$',
            'message': '重定向URL构建'
        },
        {
            'base_string_pattern': r'^(https?://|/|\.\./)',
            'message': 'URL字符串构建'
        }
    ]
}

# 安全的域名和URL模式
SAFE_DOMAINS = {
    'whitelist_domains': [
        r'example\.com',
        r'localhost',
        r'127\.0\.0\.1',
        r'::1',
        r'\.internal$',
        r'\.local$',
        r'^/',
        r'^\./',
        r'^\.\./'
    ],
    'safe_schemes': ['http', 'https', '']
}

def analyze_open_redirects(code, language='python'):
    """
    检测Python代码中Open Redirect漏洞

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
    redirect_calls = []  # 存储重定向调用
    user_input_sources = []  # 存储用户输入源
    url_buildings = []  # 存储URL构建操作

    # 第一步：收集所有重定向调用
    for query_info in OPEN_REDIRECT_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['redirect_func', 'module_obj', 'url_func']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['redirect_url', 'url_left', 'url_right', 'base_url', 'fstring_url']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['format_method', 'format_call']:
                    current_capture[tag] = node.text.decode('utf8')

                elif tag == 'call' and current_capture:
                    # 检查函数名是否匹配模式
                    func_pattern = query_info.get('func_pattern', '')
                    module_pattern = query_info.get('module_pattern', '')

                    func_match = True
                    module_match = True

                    if func_pattern and 'redirect_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['redirect_func'], re.IGNORECASE)
                    elif func_pattern and 'url_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['url_func'], re.IGNORECASE)

                    if module_pattern and 'module_obj' in current_capture:
                        module_match = re.match(module_pattern, current_capture['module_obj'], re.IGNORECASE)

                    if func_match and module_match:
                        code_snippet = node.text.decode('utf8')

                        redirect_calls.append({
                            'type': 'redirect_call',
                            'line': current_capture['line'],
                            'function': current_capture.get('redirect_func', '') or current_capture.get('url_func', ''),
                            'module': current_capture.get('module_obj', ''),
                            'redirect_url': current_capture.get('redirect_url', '') or 
                                          current_capture.get('url_left', '') or
                                          current_capture.get('fstring_url', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'vulnerability_type': query_info.get('message', 'Open Redirect风险')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"Open Redirect查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(REDIRECT_USER_INPUT_SOURCES['query'])
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
                for pattern_info in REDIRECT_USER_INPUT_SOURCES['patterns']:
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

    # 第三步：收集URL构建操作
    try:
        query = LANGUAGES[language].query(REDIRECT_URL_BUILDING_PATTERNS['query'])
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
                # 检查是否匹配URL构建模式
                for pattern_info in REDIRECT_URL_BUILDING_PATTERNS['patterns']:
                    var_pattern = pattern_info.get('var_pattern', '')
                    base_string_pattern = pattern_info.get('base_string_pattern', '')

                    var_match = False
                    base_match = True  # 如果没有base_string_pattern，默认为True

                    if var_pattern and 'var_name' in current_capture:
                        var_match = re.match(var_pattern, current_capture['var_name'], re.IGNORECASE)

                    if base_string_pattern and 'base_string' in current_capture:
                        base_match = re.match(base_string_pattern, current_capture['base_string'], re.IGNORECASE)

                    if var_match and base_match:
                        code_snippet = node.text.decode('utf8')
                        url_buildings.append({
                            'type': 'url_building',
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
        print(f"URL构建查询错误: {e}")

    # 第四步：分析Open Redirect漏洞
    for redirect_call in redirect_calls:
        vulnerability_details = analyze_redirect_call(redirect_call, user_input_sources, url_buildings)
        if vulnerability_details:
            vulnerabilities.extend(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_redirect_call(redirect_call, user_input_sources, url_buildings):
    """
    分析单个重定向调用的安全问题
    """
    vulnerabilities = []
    code_snippet = redirect_call['code_snippet']
    line = redirect_call['line']
    function_name = redirect_call['function']
    redirect_url = redirect_call['redirect_url']

    # 检查直接用户输入
    if is_direct_user_input(redirect_call, user_input_sources):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Open Redirect',
            'severity': '高危',
            'message': f"{function_name} 函数直接使用用户输入作为重定向URL"
        })

    # 检查字符串拼接
    elif is_string_concatenation(redirect_call):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Open Redirect',
            'severity': '高危',
            'message': f"{function_name} 函数使用字符串拼接构建重定向URL"
        })

    # 检查format格式化
    elif is_format_operation(redirect_call):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Open Redirect',
            'severity': '高危',
            'message': f"{function_name} 函数使用format方法构建重定向URL"
        })

    # 检查f-string格式化
    elif is_fstring_operation(redirect_call):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Open Redirect',
            'severity': '高危',
            'message': f"{function_name} 函数使用f-string构建重定向URL"
        })

    # 检查外部URL重定向
    elif is_external_url_redirect(redirect_call):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Open Redirect',
            'severity': '中危',
            'message': f"{function_name} 函数可能重定向到外部域名"
        })

    # 检查URL验证缺失
    elif not has_url_validation(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'Open Redirect',
            'severity': '中危',
            'message': f"{function_name} 函数缺少URL验证逻辑"
        })

    return vulnerabilities


def is_direct_user_input(redirect_call, user_input_sources):
    """
    检查重定向URL是否直接来自用户输入
    """
    redirect_url = redirect_call['redirect_url']
    
    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'request', 'args', 'form', 'get', 
                      'post', 'next', 'target', 'return_url', 'redirect_to']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', redirect_url, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == redirect_call['node'] or is_child_node(redirect_call['node'], source['node']):
            return True

    return False


def is_string_concatenation(redirect_call):
    """
    检查是否使用字符串拼接构建URL
    """
    code_snippet = redirect_call['code_snippet']
    return '+' in code_snippet and 'redirect' in code_snippet


def is_format_operation(redirect_call):
    """
    检查是否使用format方法构建URL
    """
    return 'format' in redirect_call.get('format_method', '')


def is_fstring_operation(redirect_call):
    """
    检查是否使用f-string构建URL
    """
    return 'fstring_url' in redirect_call


def is_external_url_redirect(redirect_call):
    """
    检查是否可能重定向到外部URL
    """
    code_snippet = redirect_call['code_snippet']
    
    # 检查常见的外部URL模式
    external_url_patterns = [
        r'https?://[^\s\']+',
        r'//[^\s\']+',
        r'www\.[^\s\']+',
        r'\.(com|org|net|io)[^\s\']*'
    ]
    
    for pattern in external_url_patterns:
        if re.search(pattern, code_snippet):
            return True
    
    return False


def has_url_validation(code_snippet):
    """
    检查代码片段是否包含URL验证逻辑
    """
    validation_patterns = [
        r'startswith\([\'"]/[\'"]\)',
        r'urlparse\..*hostname',
        r'\.(example\.com|localhost)',
        r'whitelist',
        r'safe_redirect',
        r'is_safe_url',
        r'validate_redirect',
        r'allowed_domains'
    ]
    
    return any(re.search(pattern, code_snippet, re.IGNORECASE) for pattern in validation_patterns)


def is_safe_domain(url):
    """
    检查URL是否指向安全域名
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        
        for domain_pattern in SAFE_DOMAINS['whitelist_domains']:
            if re.search(domain_pattern, hostname, re.IGNORECASE):
                return True
        
        return False
    except:
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


def analyze_open_redirects_main(code_string):
    """
    主函数：分析Python代码字符串中的Open Redirect漏洞
    """
    return analyze_open_redirects(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
from flask import Flask, redirect, request, url_for
from django.http import HttpResponseRedirect
from django.shortcuts import redirect as django_redirect
import urllib.parse

app = Flask(__name__)

# 不安全的Open Redirect示例
def insecure_redirect_examples():
    # 直接用户输入重定向 - 高危
    next_url = request.args.get('next')
    return redirect(next_url)  # 高危: Open Redirect
    
    # 字符串拼接重定向 - 高危
    base_url = "https://example.com"
    user_path = request.form.get('path')
    redirect_url = base_url + user_path  # 高危
    return redirect(redirect_url)
    
    # format格式化重定向 - 高危
    domain = request.args.get('domain', 'evil.com')
    url = "https://{}/login".format(domain)  # 高危
    return redirect(url)
    
    # f-string重定向 - 高危
    user_domain = request.json.get('domain')
    url = f"https://{user_domain}/dashboard"  # 高危
    return redirect(url)
    
    # 没有验证的重定向 - 中危
    return_url = request.args.get('return_url', '/')
    return redirect(return_url)  # 中危: 缺少验证

# 相对安全的重定向示例
def safe_redirect_examples():
    # 相对URL重定向 - 安全
    return redirect('/dashboard')  # 安全: 相对URL
    
    # 命名路由重定向 - 安全
    return redirect(url_for('login'))  # 安全: 命名路由
    
    # 硬编码URL重定向 - 相对安全
    return redirect('https://example.com/home')  # 相对安全
    
    # 经过验证的重定向 - 安全
    next_url = request.args.get('next', '/')
    if is_safe_url(next_url):
        return redirect(next_url)  # 安全: 经过验证
    else:
        return redirect('/')
    
    # 白名单域名重定向 - 安全
    domain = request.args.get('domain')
    if domain in ['example.com', 'trusted-site.org']:
        return redirect(f"https://{domain}/")
    else:
        return redirect('/error')

# Django中的重定向示例  
def django_redirect_examples():
    # 不安全的Django重定向
    target = request.GET.get('target')
    return HttpResponseRedirect(target)  # 高危
    
    # 字符串拼接
    path = request.POST.get('path')
    full_url = "https://example.com" + path  # 高危
    return django_redirect(full_url)
    
    # 安全的Django重定向
    return django_redirect('/home')  # 安全
    return HttpResponseRedirect('/profile')  # 安全

# URL验证函数
def is_safe_url(url):
    \"\"\"检查URL是否安全\"\"\"
    if not url:
        return False
        
    parsed = urllib.parse.urlparse(url)
    
    # 只允许相对URL或特定域名
    if not parsed.netloc:  # 相对URL
        return True
        
    # 白名单域名检查
    safe_domains = ['example.com', 'localhost', '127.0.0.1']
    return parsed.hostname in safe_domains

# 混合示例
def mixed_examples():
    # 部分验证的重定向
    url = request.args.get('url')
    if url and url.startswith('/'):  # 只验证了相对URL
        return redirect(url)  # 中危: 验证不充分
    
    # 使用内置安全函数
    from django.utils.http import is_safe_url
    next_url = request.GET.get('next')
    if is_safe_url(next_url, allowed_hosts={'example.com'}):
        return redirect(next_url)  # 安全
    
    # 直接重定向到用户输入
    return redirect(request.args.get('redirect_to'))  # 高危

if __name__ == "__main__":
    insecure_redirect_examples()
    safe_redirect_examples()
    django_redirect_examples()
    mixed_examples()
"""

    print("=" * 60)
    print("Python Open Redirect漏洞检测")
    print("=" * 60)

    results = analyze_open_redirects_main(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个Open Redirect漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Open Redirect漏洞")