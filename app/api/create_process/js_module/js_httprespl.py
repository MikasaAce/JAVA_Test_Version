import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义HTTP响应拆分漏洞的检测模式
HTTP_RESPONSE_SPLITTING_VULNERABILITIES = {
    'javascript': [
        # 检测所有setHeader调用
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments) @args
                ) @call
            ''',
            'object_pattern': r'^(res|response|reply|httpResponse)$',
            'property_pattern': r'^(setHeader|append|set|cookie|writeHead)$',
            'message': 'HTTP头设置调用'
        },
        # 检测headers赋值
        {
            'query': '''
                (assignment_expression
                    left: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    right: (_) @value
                ) @assignment
            ''',
            'object_pattern': r'^(res|response|reply|httpResponse|headers)$',
            'property_pattern': r'^(headers|header|statusCode|statusMessage|cookie)$',
            'message': 'HTTP头赋值操作'
        }
    ]
}


def detect_http_response_splitting(code, language='javascript'):
    """
    检测JavaScript代码中的HTTP响应拆分漏洞
    """
    if language not in LANGUAGES:
        return []

    parser = Parser()
    parser.set_language(LANGUAGES[language])
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    vulnerabilities = []

    # 1. 首先收集所有可能的用户输入源
    user_input_sources = find_user_input_sources(root, code)

    # 2. 检测HTTP头操作
    for query_info in HTTP_RESPONSE_SPLITTING_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag == 'object':
                    obj_name = node.text.decode('utf8')
                    pattern = query_info.get('object_pattern', '')
                    if pattern and re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern', '')
                    if prop_pattern and re.match(prop_pattern, prop_name, re.IGNORECASE):
                        current_capture['property'] = prop_name

                elif tag in ['args', 'value'] and current_capture:
                    current_capture['target_node'] = node
                    # 分析这个节点是否包含用户输入
                    analyze_node_for_vulnerability(node, current_capture, user_input_sources, vulnerabilities, code)
                    current_capture = {}

        except Exception as e:
            print(f"查询错误: {e}")
            continue

    # 3. 额外的文本级别检测（作为补充）
    text_based_detection(code, vulnerabilities)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def find_user_input_sources(root, code):
    """
    查找所有可能的用户输入源
    """
    user_input_sources = set()

    # 查找变量声明和赋值
    variable_query = LANGUAGES['javascript'].query('''
        (variable_declarator
            name: (identifier) @var_name
            value: (_) @value
        ) @declaration
    ''')

    captures = variable_query.captures(root)
    current_declaration = {}

    for node, tag in captures:
        if tag == 'var_name':
            current_declaration['name'] = node.text.decode('utf8')
            current_declaration['line'] = node.start_point[0] + 1

        elif tag == 'value' and current_declaration:
            value_text = node.text.decode('utf8')
            # 检查值是否来自用户输入
            if is_user_input_source(value_text):
                user_input_sources.add(current_declaration['name'])
            current_declaration = {}

    return user_input_sources


def is_user_input_source(text):
    """
    检查文本是否表示用户输入源
    """
    user_input_patterns = [
        r'req\.(query|params|body|headers)',
        r'request\.(query|params|body|headers)',
        r'window\.location',
        r'document\.(cookie|location|referrer)',
        r'localStorage',
        r'sessionStorage',
        r'URLSearchParams',
    ]

    for pattern in user_input_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def analyze_node_for_vulnerability(node, capture, user_input_sources, vulnerabilities, code):
    """
    分析节点是否包含漏洞
    """
    node_text = node.text.decode('utf8')
    line = capture['line']

    # 检查是否包含明显的CRLF注入
    if contains_crlf_injection(node_text):
        vulnerabilities.append({
            'line': line,
            'message': f'HTTP响应拆分漏洞: 检测到CRLF注入模式',
            'code_snippet': get_code_snippet(code, node),
            'vulnerability_type': 'HTTP响应拆分',
            'severity': '高危'
        })
        return

    # 检查是否包含用户输入变量
    for var_name in user_input_sources:
        if re.search(rf'\b{var_name}\b', node_text):
            vulnerabilities.append({
                'line': line,
                'message': f'HTTP响应拆分漏洞: 用户输入变量"{var_name}"直接用于HTTP头',
                'code_snippet': get_code_snippet(code, node),
                'vulnerability_type': 'HTTP响应拆分',
                'severity': '高危'
            })
            return

    # 检查常见的用户输入模式
    if contains_user_input_pattern(node_text):
        vulnerabilities.append({
            'line': line,
            'message': 'HTTP响应拆分漏洞: 检测到用户输入模式',
            'code_snippet': get_code_snippet(code, node),
            'vulnerability_type': 'HTTP响应拆分',
            'severity': '高危'
        })


def contains_crlf_injection(text):
    """
    检查是否包含CRLF注入模式
    """
    crlf_patterns = [
        r'\\r\\n', r'\\n\\r',  # 转义字符
        r'%0d%0a', r'%0a%0d',  # URL编码
        r'&#13;&#10;', r'&#10;&#13;',  # HTML实体
        r'\r\n', r'\n\r',  # 实际CRLF
        r'\\x0d\\x0a', r'\\x0a\\x0d',  # 十六进制
    ]

    for pattern in crlf_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    # 检查头部注入模式
    if re.search(r'[\r\n].*:', text):
        return True

    return False


def contains_user_input_pattern(text):
    """
    检查是否包含用户输入模式
    """
    patterns = [
        r'req\.(query|params|body|headers)',
        r'request\.(query|params|body|headers)',
        r'window\.location',
        r'document\.',
        r'localStorage',
        r'sessionStorage',
        r'URLSearchParams',
    ]

    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def text_based_detection(code, vulnerabilities):
    """
    文本级别的漏洞检测（补充AST检测）
    """
    lines = code.split('\n')

    for i, line in enumerate(lines, 1):
        line_lower = line.lower()

        # 检查HTTP头操作
        if any(op in line_lower for op in ['setheader', 'writehead', '.headers', '.cookie']):
            # 检查是否包含用户输入
            if any(pattern in line_lower for pattern in ['req.', 'request.', 'query.', 'params.', 'body.']):
                # 检查是否包含CRLF
                if contains_crlf_injection(line):
                    vulnerabilities.append({
                        'line': i,
                        'message': 'HTTP响应拆分漏洞: 用户输入直接用于HTTP头设置',
                        'code_snippet': line.strip(),
                        'vulnerability_type': 'HTTP响应拆分',
                        'severity': '高危'
                    })
                else:
                    vulnerabilities.append({
                        'line': i,
                        'message': '潜在的HTTP响应拆分漏洞: 用户输入用于HTTP头设置',
                        'code_snippet': line.strip(),
                        'vulnerability_type': 'HTTP响应拆分',
                        'severity': '中危'
                    })


def get_code_snippet(full_code, node):
    """
    获取代码片段
    """
    start_line = node.start_point[0]
    end_line = node.end_point[0]
    lines = full_code.split('\n')

    if start_line == end_line:
        return lines[start_line].strip()
    else:
        return ' '.join(line.strip() for line in lines[start_line:end_line + 1])


def analyze_js_code(code_string):
    """
    分析JavaScript代码
    """
    return detect_http_response_splitting(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 更明确的测试代码
    test_js_code = """
// 明显的HTTP响应拆分漏洞
const userInput = req.query.input;
res.setHeader('X-Header', userInput); // 直接使用用户输入

// CRLF注入示例
const malicious = "normal\\r\\nInjected-Header: malicious";
res.setHeader('Custom-Header', malicious);

// URL编码的CRLF
const encoded = "value%0d%0aX-Injected: bad";
res.writeHead(200, {'Header': encoded});

// 模板字符串中的用户输入
res.setHeader(`X-User-${req.params.id}`, "value");

// headers赋值
res.headers['Authorization'] = req.headers.authorization;

// Cookie中的用户输入
document.cookie = `session=${req.body.token}; path=/`;

// 多层嵌套的用户输入
const config = {
    headers: {
        'Custom': req.query.value
    }
};
res.writeHead(200, config.headers);

// 安全的示例 - 编码用户输入
const safeInput = encodeURIComponent(req.query.input);
res.setHeader('Safe-Header', safeInput);

// 安全的示例 - 验证
if (!req.query.input.includes('\\r') && !req.query.input.includes('\\n')) {
    res.setHeader('Validated-Header', req.query.input);
}

// 变量传递的用户输入
const headerValue = req.body.data;
res.setHeader('Data-Header', headerValue);

// 数组中的用户输入
const headers = ['Content-Type', 'text/html', req.query.customHeader];
res.setHeader(headers[0], headers[2]);
"""

    print("=" * 60)
    print("JavaScript HTTP响应拆分漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
    else:
        print("未检测到HTTP响应拆分漏洞")