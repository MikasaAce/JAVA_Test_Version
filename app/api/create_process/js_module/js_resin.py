import os
import re
from tree_sitter import Language, Parser
from urllib.parse import urlparse

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义资源注入漏洞模式（优化版）
RESOURCE_INJECTION_VULNERABILITIES = {
    'javascript': [
        # 1. 直接innerHTML操作（带用户输入检查）
        {
            'query': '''
                (assignment_expression
                    left: (member_expression
                        object: (_) @object
                        property: (property_identifier) @property
                    )
                    right: (_) @value
                ) @assignment
            ''',
            'object_pattern': r'^(document|element|el|div|container|content|body|window)$',
            'property_pattern': r'^(innerHTML|outerHTML|insertAdjacentHTML)$',
            'message': '直接HTML操作发现 - 可能导致XSS',
            'severity': '高危',
            'require_user_input': True  # 只有包含用户输入时才报告
        },

        # 2. document.write操作（带用户输入检查）
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (_) @arg)
                ) @call
            ''',
            'object_pattern': r'^(document|window)$',
            'property_pattern': r'^(write|writeln)$',
            'message': 'document.write操作发现 - 可能导致XSS',
            'severity': '高危',
            'require_user_input': True
        },

        # 3. location操作 (URL重定向，带用户输入检查)
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
            'object_pattern': r'^(location|window\.location)$',
            'property_pattern': r'^(href|hash|search|pathname)$',
            'message': 'Location操作发现 - 可能导致开放重定向',
            'severity': '中危',
            'require_user_input': True
        },

        # 4. eval和Function构造函数（带用户输入检查）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (_) @arg)
                ) @call
            ''',
            'pattern': r'^(eval|Function)$',
            'message': '动态代码执行发现 - 可能导致代码注入',
            'severity': '高危',
            'require_user_input': True
        },

        # 5. setTimeout/setInterval with string（带用户输入检查）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments
                        (string) @first_arg
                        (_)*
                    )
                ) @call
            ''',
            'pattern': r'^(setTimeout|setInterval)$',
            'message': '字符串参数定时器发现 - 可能导致代码注入',
            'severity': '中危',
            'require_user_input': True
        },

        # 6. 动态脚本创建（带用户输入检查）
        {
            'query': '''
                (assignment_expression
                    left: (identifier) @var_name
                    right: (call_expression
                        function: (member_expression
                            object: (identifier) @obj
                            property: (property_identifier) @prop
                        )
                        arguments: (arguments (string) @tag)
                    )
                ) @assignment
                (#match? @prop "createElement")
                (#match? @tag "script|iframe|frame|embed|object")
            ''',
            'message': '动态脚本创建发现 - 可能导致代码注入',
            'severity': '高危',
            'require_user_input': True
        },

        # 7. jQuery危险方法（带用户输入检查）
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (_) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (_) @arg)
                ) @call
            ''',
            'object_pattern': r'^(\$|jQuery)$',
            'property_pattern': r'^(html|append|prepend|before|after|replaceWith|parseHTML)$',
            'message': 'jQuery HTML操作发现 - 可能导致XSS',
            'severity': '高危',
            'require_user_input': True
        },

        # 8. URL操作与用户输入
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (_) @arg)
                ) @call
            ''',
            'object_pattern': r'^(window|URL)$',
            'property_pattern': r'^(open|assign|replace)$',
            'message': 'URL操作发现 - 可能导致开放重定向或SSRF',
            'severity': '中危',
            'require_user_input': True
        },

        # 9. 动态导入（带用户输入检查）
        {
            'query': '''
                (call_expression
                    function: (import) @import
                    arguments: (arguments (string) @module)
                ) @call
            ''',
            'message': '动态导入发现 - 可能导致模块注入',
            'severity': '中危',
            'require_user_input': True
        },

        # 10. postMessage接收器中的eval（特定模式）
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (_) @arg)
                ) @call
                (member_expression
                    object: (identifier) @event_obj
                    property: (property_identifier) @event_prop
                ) @member
                (#match? @func_name "eval")
                (#eq? @event_prop "data")
            ''',
            'message': 'postMessage接收器中的eval调用 - 高危代码注入',
            'severity': '高危'
        }
    ]
}

# 用户输入源模式（优化版）
USER_INPUT_SOURCES = [
    r'location\.', r'window\.location\.', r'document\.', r'window\.',
    r'URLSearchParams', r'req\.', r'request\.', r'params\.',
    r'query\.', r'body\.', r'cookies\.', r'headers\.', r'input\.',
    r'formData\.', r'session\.', r'localStorage\.', r'sessionStorage\.',
    r'event\.data', r'userInput', r'userContent', r'getParameter'
]

# 安全函数和模式（减少误报）
SAFE_FUNCTIONS = [
    r'encodeURI', r'encodeURIComponent', r'escape', r'textContent',
    r'innerText', r'createTextNode', r'appendChild', r'setAttribute',
    r'JSON\.stringify', r'JSON\.parse', r'parseInt', r'parseFloat',
    r'RegExp', r'String', r'Number', r'Boolean'
]


def detect_js_resource_injection(code, language='javascript'):
    """
    检测JavaScript代码中的资源注入漏洞（优化版）

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

    # 检测所有漏洞模式
    for vuln_pattern in RESOURCE_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(vuln_pattern['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['object', 'func_name']:
                    obj_name = node.text.decode('utf8')
                    pattern = vuln_pattern.get('object_pattern') or vuln_pattern.get('pattern')
                    if pattern and re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = vuln_pattern.get('property_pattern')
                    if (not prop_pattern or
                            re.match(prop_pattern, prop_name, re.IGNORECASE)):
                        current_capture['property'] = prop_name

                elif tag in ['call', 'assignment', 'arg', 'first_arg', 'var_name', 'member'] and current_capture:
                    # 完成一个完整的捕获
                    if ('object' in current_capture or 'func_name' in current_capture):
                        # 获取完整的代码片段
                        code_snippet = node.text.decode('utf8')

                        # 检查是否包含安全函数（减少误报）
                        if contains_safe_function(code_snippet):
                            current_capture = {}
                            continue

                        # 检查是否需要用户输入
                        require_user_input = vuln_pattern.get('require_user_input', False)
                        has_user_input = contains_user_input(code_snippet)

                        # 如果要求用户输入但没有找到，跳过
                        if require_user_input and not has_user_input:
                            current_capture = {}
                            continue

                        # 检查是否已经报告了类似的漏洞
                        if not is_duplicate_vulnerability(vulnerabilities, current_capture['line'],
                                                          vuln_pattern['message']):
                            vulnerabilities.append({
                                'line': current_capture['line'],
                                'message': vuln_pattern['message'],
                                'code_snippet': code_snippet[:200],  # 限制长度
                                'vulnerability_type': '资源注入',
                                'severity': vuln_pattern.get('severity', '中危'),
                                'has_user_input': has_user_input
                            })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {vuln_pattern.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_user_input(code_snippet):
    """
    检查代码片段中是否包含可能的用户输入源

    Args:
        code_snippet: 代码片段字符串

    Returns:
        bool: 是否包含用户输入
    """
    code_lower = code_snippet.lower()

    for pattern in USER_INPUT_SOURCES:
        if re.search(pattern, code_lower, re.IGNORECASE):
            return True

    return False


def contains_safe_function(code_snippet):
    """
    检查代码片段中是否包含安全函数或编码操作

    Args:
        code_snippet: 代码片段字符串

    Returns:
        bool: 是否包含安全函数
    """
    for pattern in SAFE_FUNCTIONS:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True

    # 检查编码操作
    if re.search(r'encodeURI|encodeURIComponent|escape', code_snippet, re.IGNORECASE):
        return True

    return False


def is_duplicate_vulnerability(vulnerabilities, line, message):
    """
    检查是否已经报告了相同行和类型的漏洞

    Args:
        vulnerabilities: 已发现的漏洞列表
        line: 行号
        message: 漏洞消息

    Returns:
        bool: 是否是重复漏洞
    """
    for vuln in vulnerabilities:
        if vuln['line'] == line and vuln['message'] == message:
            return True
    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的资源注入漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_resource_injection(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 各种资源注入漏洞示例

// 1. 直接innerHTML操作
document.getElementById('content').innerHTML = userInput;
element.innerHTML = '<div>' + location.hash.slice(1) + '</div>';

// 2. document.write操作
document.write('Welcome ' + document.cookie);
window.write(getParameterByName('content'));

// 3. location操作
location.href = window.name;
window.location.hash = document.referrer;

// 4. eval和Function构造函数
eval('var x = ' + localStorage.getItem('data'));
const func = new Function('return ' + event.data);

// 5. 字符串参数定时器
setTimeout("alert('" + inputValue + "')", 100);
setInterval('update(' + JSON.stringify(config) + ')', 1000);

// 6. 动态脚本创建
const script = document.createElement('script');
script.src = userProvidedURL;
document.body.appendChild(script);

// 7. jQuery危险方法
$('#container').html(userContent);
$.fn.append('<div>' + queryParam + '</div>');

// 8. URL操作
window.open('https://example.com?redirect=' + window.location.href);
const url = new URL(searchParams.get('url'));

// 9. 动态导入
import(`/api/${userEndpoint}`).then(module => module.init());

// 10. postMessage接收器
window.addEventListener('message', event => {
    eval(event.data);
});

// 安全示例
document.getElementById('safe').textContent = userInput;
location.href = '/fixed-path';
const script = document.createElement('script');
script.src = '/static/script.js';

// 安全编码示例
document.getElementById('encoded').innerHTML = encodeURIComponent(userInput);
eval(JSON.parse(safeData));
"""

    print("=" * 60)
    print("JavaScript资源注入漏洞检测（优化版）")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   包含用户输入: {'是' if vuln['has_user_input'] else '否'}")
    else:
        print("未检测到资源注入漏洞")