import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JavaScript动态代码注入漏洞模式
DYNAMIC_CODE_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (string) @code_string)
                ) @call
            ''',
            'pattern': r'^(eval|Function|setTimeout|setInterval|execScript)$',
            'message': '直接动态代码执行函数调用'
        },
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
            'pattern': r'^(window|globalThis|document|this)$',
            'property_pattern': r'^(eval|execScript|setTimeout|setInterval)$',
            'message': '成员表达式动态代码执行'
        },
        {
            'query': '''
                (new_expression
                    constructor: (identifier) @constructor
                    arguments: (arguments (string) @code_string)
                ) @new
            ''',
            'pattern': r'^(Function)$',
            'message': 'Function构造函数调用'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (_) @first_arg (_)*)
                ) @call
            ''',
            'pattern': r'^(setTimeout|setInterval)$',
            'message': 'setTimeout/setInterval调用（可能包含动态代码）'
        },
        {
            'query': '''
                (assignment_expression
                    left: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    right: (string) @code_string
                ) @assignment
            ''',
            'pattern': r'^(document|window|element|el|this)$',
            'property_pattern': r'^(innerHTML|outerHTML|insertAdjacentHTML|write|writeln)$',
            'message': 'HTML内容动态注入'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (string) @code_string)
                ) @call
            ''',
            'pattern': r'^(document|element|el|this)$',
            'property_pattern': r'^(insertAdjacentHTML|createContextualFragment)$',
            'message': 'HTML插入方法调用'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (template_string) @template_string)
                ) @call
            ''',
            'pattern': r'^(eval|Function)$',
            'message': '模板字符串动态代码执行'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (binary_expression
                        operator: "+"
                        left: (_) @left
                        right: (_) @right
                    ) @binary_expr)
                ) @call
            ''',
            'pattern': r'^(eval|Function|setTimeout|setInterval)$',
            'message': '字符串拼接动态代码执行'
        }
    ]
}


def detect_js_dynamic_code_injection(code, language='javascript'):
    """
    检测JavaScript代码中动态解析代码注入漏洞

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

    # 检测所有动态代码执行模式
    for query_info in DYNAMIC_CODE_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['func_name', 'constructor', 'object']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture[tag] = name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern', '')
                    if (not prop_pattern or
                            re.match(prop_pattern, prop_name, re.IGNORECASE)):
                        current_capture['property'] = prop_name

                elif tag in ['call', 'new', 'assignment'] and current_capture:
                    # 检查是否匹配所有必要条件
                    if ('func_name' in current_capture or
                            ('object' in current_capture and 'property' in current_capture) or
                            'constructor' in current_capture):
                        # 获取代码片段
                        code_snippet = node.text.decode('utf8')

                        # 分析风险级别
                        severity = analyze_severity(current_capture, code_snippet)

                        vulnerabilities.append({
                            'line': current_capture['line'],
                            'message': f"{query_info['message']}: {code_snippet[:50]}...",
                            'code_snippet': code_snippet,
                            'vulnerability_type': '动态代码注入漏洞',
                            'severity': severity,
                            'pattern_type': query_info['message']
                        })

                    current_capture = {}

                elif tag in ['code_string', 'template_string', 'binary_expr', 'first_arg']:
                    # 记录相关的代码字符串或表达式
                    current_capture[tag] = node.text.decode('utf8')

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_severity(capture_info, code_snippet):
    """
    分析漏洞的严重程度

    Args:
        capture_info: 捕获的信息字典
        code_snippet: 代码片段

    Returns:
        str: 严重程度（高危、中危、低危）
    """
    # 高危：直接eval/Function调用且包含用户输入特征
    if any(key in capture_info for key in ['func_name', 'constructor', 'property']):
        func_name = (capture_info.get('func_name') or
                     capture_info.get('constructor') or
                     capture_info.get('property', ''))

        if func_name.lower() in ['eval', 'function']:
            if contains_user_input_indicator(code_snippet):
                return '高危'
            return '中危'

    # 中危：setTimeout/setInterval/HTML注入
    if any(key in capture_info for key in ['func_name', 'property']):
        name = (capture_info.get('func_name') or
                capture_info.get('property', ''))

        if name.lower() in ['settimeout', 'setinterval']:
            if contains_user_input_indicator(code_snippet):
                return '高危'
            return '中危'

        if name.lower() in ['innerhtml', 'outerhtml', 'insertadjacenthtml']:
            if contains_user_input_indicator(code_snippet):
                return '高危'
            return '中危'

    # 默认中危
    return '中危'


def contains_user_input_indicator(code_snippet):
    """
    检查代码片段中是否包含用户输入的特征

    Args:
        code_snippet: 代码片段

    Returns:
        bool: 是否可能包含用户输入
    """
    # 常见的用户输入变量名模式
    user_input_patterns = [
        r'\b(user|usr|input|inp|param|argv|args|query|qry|data|dt|form|frm|'
        r'post|get|request|req|response|resp|body|bd|cookie|session|sess|'
        r'localstorage|localstore|ls|storage|store|url|uri|href|location|loc|'
        r'window\.|document\.|navigator\.|history\.|location\.|'
        r'\$[0-9]|\$\{|\bthis\.|self\.|arguments\b)',
        r'\.value\b|\.text\b|\.html\b|\.content\b|\.data\b',
        r'process\.env|process\.argv|process\.stdin',
        r'XMLHttpRequest|fetch|axios|jQuery\.ajax|\$\.ajax',
        r'URLSearchParams|FormData|Blob|FileReader'
    ]

    code_lower = code_snippet.lower()

    for pattern in user_input_patterns:
        if re.search(pattern, code_lower, re.IGNORECASE):
            return True

    # 检查变量拼接模式
    if re.search(r'\+.*[a-zA-Z_$][a-zA-Z0-9_$]*', code_snippet):
        return True

    # 检查模板字符串包含变量
    if re.search(r'\$\{[^}]+\}', code_snippet):
        return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的动态代码注入漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_dynamic_code_injection(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 高危漏洞示例
function processUserInput(userInput) {
    // 直接eval用户输入 - 高危
    eval(userInput);

    // Function构造函数 - 高危
    const dynamicFunc = new Function('x', 'return ' + userInput);

    // setTimeout动态代码 - 高危（如果包含用户输入）
    setTimeout(userInput, 1000);
}

// 中危漏洞示例
function updateContent() {
    // innerHTML注入 - 中危到高危
    document.getElementById('content').innerHTML = '<div>' + getUserData() + '</div>';

    // insertAdjacentHTML - 中危
    element.insertAdjacentHTML('beforeend', dynamicContent);
}

// 可能的误报示例（需要进一步分析）
function safeUsage() {
    // 静态字符串 - 相对安全
    eval('console.log("static")');

    // 静态HTML
    document.body.innerHTML = '<div>static content</div>';

    // 静态setTimeout
    setTimeout(() => { console.log('safe') }, 1000);
}

// 复杂情况
function complexCase(data) {
    // 字符串拼接 - 需要分析
    const code = 'console.log(' + JSON.stringify(data) + ')';
    eval(code);

    // 模板字符串
    const templateCode = `console.log(${data})`;
    eval(templateCode);
}

// 用户输入相关
function handleFormSubmit(event) {
    const userData = event.target.elements.data.value;

    // 高危：直接使用用户输入
    eval('process(' + userData + ')');

    // 高危：动态函数
    const processor = new Function('input', 'return ' + userData);
}

// 第三方库模式
function thirdPartyUsage() {
    // jQuery HTML注入
    $('#container').html(userContent);

    // React dangerouslySetInnerHTML (虽然不在AST中直接检测，但原理类似)
}
"""

    print("=" * 60)
    print("JavaScript动态代码注入漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   类型: {vuln['pattern_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
    else:
        print("未检测到动态代码注入漏洞")