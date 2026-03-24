import os
import re
from urllib.parse import urlparse
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JavaScript的Open重定向漏洞模式
OPEN_REDIRECT_VULNERABILITIES = {
    'javascript': [
        {
            'name': 'window_location_assignment',
            'query': '''
                (assignment_expression
                    left: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    right: (_) @redirect_url
                ) @assignment
            ''',
            'object_pattern': r'^(window\.location|location|window|document\.location)$',
            'property_pattern': r'^(href|replace|assign)$',
            'message': 'window.location重定向操作'
        },
        {
            'name': 'window_location_method_call',
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (_) @redirect_url)
                ) @call
            ''',
            'object_pattern': r'^(window\.location|location|window|document\.location)$',
            'property_pattern': r'^(replace|assign)$',
            'message': 'window.location方法调用重定向'
        },
        {
            'name': 'response_redirect',
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (_) @redirect_url)
                ) @call
            ''',
            'object_pattern': r'^(response|res|ctx|context|reply|h)$',
            'property_pattern': r'^(redirect|redirected|location|writeHead|setHeader)$',
            'message': 'HTTP响应重定向操作'
        },
        {
            'name': 'express_redirect',
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (_) @redirect_url (_)?)
                ) @call
            ''',
            'pattern': r'^(redirect|res\.redirect|res\.location|res\.writeHead)$',
            'message': 'Express框架重定向函数'
        },
        {
            'name': 'url_parameter_extraction',
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (call_expression
                            function: (identifier) @url_func
                            arguments: (arguments (_) @url_param)
                        )
                        property: (property_identifier) @url_property
                    )
                ) @url_call
            ''',
            'url_func_pattern': r'^(URL|new URL|url\.parse)$',
            'url_property_pattern': r'^(searchParams|query|pathname|search|href)$',
            'message': 'URL参数提取操作'
        },
        {
            'name': 'user_input_sources',
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @req_object
                        property: (property_identifier) @req_property
                    )
                ) @req_call
            ''',
            'req_object_pattern': r'^(req|request|ctx\.request|context\.request|query|params|body)$',
            'req_property_pattern': r'^(query|url|originalUrl|path|params|body|headers\.referer|headers\.referrer)$',
            'message': '用户输入源访问'
        }
    ]
}


def is_user_controlled_variable(node, root_node, code):
    """
    判断变量是否可能受用户控制

    Args:
        node: 变量节点
        root_node: AST根节点
        code: 源代码字符串

    Returns:
        bool: 是否可能受用户控制
    """
    var_name = node.text.decode('utf8')

    # 检查是否来自请求参数、查询参数、请求体等
    user_input_patterns = [
        r'req\.(query|params|body|headers)',
        r'request\.(query|params|body|headers)',
        r'ctx\.request\.(query|params|body|headers)',
        r'query\.',
        r'params\.',
        r'body\.',
        r'window\.location\.(search|hash)',
        r'document\.location\.(search|hash)',
        r'URLSearchParams',
    ]

    # 检查变量是否包含用户输入模式
    var_usage = find_variable_usage(root_node, var_name, code)
    for usage in var_usage:
        for pattern in user_input_patterns:
            if re.search(pattern, usage, re.IGNORECASE):
                return True

    return False


def find_variable_usage(root_node, var_name, code):
    """
    查找变量的使用情况

    Args:
        root_node: AST根节点
        var_name: 变量名
        code: 源代码字符串

    Returns:
        list: 使用该变量的代码片段列表
    """
    usages = []

    # 简单的查询来查找变量使用
    query = f'''
        (identifier) @var
        (#eq? @var "{var_name}")
    '''

    try:
        language = LANGUAGES['javascript']
        query_obj = language.query(query)
        captures = query_obj.captures(root_node)

        for node, _ in captures:
            # 获取变量使用的上下文
            parent = node.parent
            if parent:
                usages.append(parent.text.decode('utf8'))
    except:
        pass

    return usages


def is_unsafe_redirect_url(url_value, root_node, code):
    """
    判断重定向URL是否不安全

    Args:
        url_value: URL值节点
        root_node: AST根节点
        code: 源代码字符串

    Returns:
        bool: 是否不安全
    """
    if not url_value:
        return False

    url_text = url_value.text.decode('utf8').strip()

    # 移除字符串引号
    if (url_text.startswith(('"', "'", "`")) and
            url_text.endswith(('"', "'", "`"))):
        url_text = url_text[1:-1]

    # 检查是否为变量或表达式
    if not url_text or url_text in ['""', "''", "``"]:
        return False

    # 1. 检查是否是完整的URL（可能包含用户输入）
    if re.match(r'^[a-zA-Z0-9]+:', url_text):
        # 外部URL - 需要验证是否可信
        try:
            parsed = urlparse(url_text)
            # 检查是否指向外部域或不可信域
            if parsed.netloc and not is_trusted_domain(parsed.netloc):
                return True
        except:
            pass

    # 2. 检查是否以//开头（协议相对URL）
    if url_text.startswith('//'):
        return True

    # 3. 检查是否包含用户输入模式
    user_input_indicators = [
        r'\{.*\}',  # 模板字符串
        r'\+.*\+',  # 字符串拼接
        r'req\.', r'request\.', r'query\.', r'params\.', r'body\.',
        r'window\.location', r'document\.location',
        r'URLSearchParams', r'searchParams',
    ]

    for pattern in user_input_indicators:
        if re.search(pattern, url_text):
            return True

    # 4. 检查是否是变量（需要进一步分析）
    if re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', url_text):
        return is_user_controlled_variable(url_value, root_node, code)

    # 5. 检查是否包含../或类似的路径遍历模式
    if re.search(r'(\.\./|\.\.\\|%2e%2e|\.\.%2f)', url_text, re.IGNORECASE):
        return True

    return False


def is_trusted_domain(domain):
    """
    判断域名是否可信

    Args:
        domain: 域名

    Returns:
        bool: 是否可信
    """
    if not domain:
        return False

    # 可信域名列表（可根据需要扩展）
    trusted_domains = [
        r'^localhost$',
        r'^127\.0\.0\.1$',
        r'^::1$',
        r'^\[::1\]$',
        r'^.*\.example\.com$',
        r'^.*\.mycompany\.com$',
        r'^.*\.internal$',
    ]

    domain = domain.lower()

    for pattern in trusted_domains:
        if re.match(pattern, domain):
            return True

    return False


def detect_js_open_redirect_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中的Open重定向漏洞

    Args:
        code: JavaScript源代码字符串
        language: 语言类型，默认为'javascript'

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

    # 检测所有重定向模式
    for query_info in OPEN_REDIRECT_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['object', 'func_name', 'url_func', 'req_object']:
                    obj_name = node.text.decode('utf8')
                    pattern = query_info.get('object_pattern') or query_info.get('pattern')
                    if pattern and re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['property', 'url_property', 'req_property']:
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern') or query_info.get(
                        'url_property_pattern') or query_info.get('req_property_pattern')
                    if prop_pattern and re.match(prop_pattern, prop_name, re.IGNORECASE):
                        current_capture['property'] = prop_name

                elif tag == 'redirect_url':
                    current_capture['redirect_url'] = node

                elif tag in ['assignment', 'call', 'url_call', 'req_call'] and current_capture:
                    # 完成一个完整的捕获
                    if (
                            'object' in current_capture and 'property' in current_capture) or 'func_name' in current_capture:
                        redirect_url = current_capture.get('redirect_url')

                        # 检查重定向URL是否不安全
                        if is_unsafe_redirect_url(redirect_url, root, code):
                            code_snippet = node.text.decode('utf8')

                            vulnerabilities.append({
                                'line': current_capture['line'],
                                'message': f'Open Redirect: {query_info["message"]}',
                                'code_snippet': code_snippet,
                                'vulnerability_type': 'Open重定向漏洞',
                                'severity': '中危',
                                'pattern': query_info['name']
                            })

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的Open重定向漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_open_redirect_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 存在Open重定向漏洞的代码示例

// 1. 直接从查询参数重定向
const urlParams = new URLSearchParams(window.location.search);
const redirectUrl = urlParams.get('redirect');
window.location.href = redirectUrl;  // 漏洞：直接使用用户输入

// 2. Express.js重定向漏洞
app.get('/login', (req, res) => {
    const returnUrl = req.query.returnUrl;
    res.redirect(returnUrl);  // 漏洞：未验证重定向URL
});

// 3. 字符串拼接漏洞
app.get('/auth', (req, res) => {
    const domain = req.query.domain;
    res.redirect('https://' + domain + '/callback');  // 漏洞：用户控制域名
});

// 4. 模板字符串漏洞
app.get('/sso', (req, res) => {
    const host = req.headers['x-forwarded-host'];
    res.redirect(`https://${host}/auth`);  // 漏洞：用户控制主机头
});

// 5. 路径遍历漏洞
app.get('/file', (req, res) => {
    const filePath = req.query.path;
    res.redirect('/static/' + filePath);  // 漏洞：可能包含../遍历
});

// 6. 协议相对URL漏洞
const userRedirect = req.body.redirect;
window.location.href = '//' + userRedirect;  // 漏洞：协议相对URL

// 安全的重定向示例
app.get('/safe-login', (req, res) => {
    const returnUrl = req.query.returnUrl;
    // 白名单验证
    const allowedDomains = ['example.com', 'myapp.com'];
    try {
        const parsedUrl = new URL(returnUrl);
        if (allowedDomains.includes(parsedUrl.hostname)) {
            res.redirect(returnUrl);  // 安全：已验证域名
        } else {
            res.redirect('/default');
        }
    } catch {
        res.redirect('/default');
    }
});

// 7. 使用replace方法的重定向
const maliciousUrl = req.query.url;
window.location.replace(maliciousUrl);  // 漏洞：用户控制URL

// 8. 通过assign方法的重定向
const userUrl = req.body.url;
window.location.assign(userUrl);  // 漏洞：用户控制URL

// 9. 设置响应头重定向
app.get('/header-redirect', (req, res) => {
    const redirectTo = req.query.redirect;
    res.setHeader('Location', redirectTo);  // 漏洞：用户控制Location头
    res.statusCode = 302;
    res.end();
});

// 10. writeHead重定向
app.get('/writehead-redirect', (req, res) => {
    const target = req.query.target;
    res.writeHead(302, { 'Location': target });  // 漏洞：用户控制Location头
    res.end();
});

// 安全的URL构建示例
app.get('/safe-redirect', (req, res) => {
    const path = req.query.path;
    // 验证路径是否安全
    if (path && /^[a-zA-Z0-9_\\-/]+$/.test(path)) {
        res.redirect('/safe/' + path);  // 相对安全：已验证路径格式
    } else {
        res.redirect('/error');
    }
});
"""

    print("=" * 60)
    print("JavaScript Open重定向漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   模式: {vuln['pattern']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Open重定向漏洞")