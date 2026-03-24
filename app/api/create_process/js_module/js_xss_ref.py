import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义反射型XSS漏洞模式
REFLECTED_XSS_PATTERNS = {
    'javascript': [
        # 直接使用location/search/hash等URL相关属性
        {
            'query': '''
                (member_expression
                    object: (identifier) @object
                    property: (property_identifier) @property
                ) @member_expr
            ''',
            'object_pattern': r'^(location|window|document)$',
            'property_pattern': r'^(search|hash|href|location|URL)$',
            'message': '直接使用URL参数属性，可能包含用户输入'
        },
        # 使用URLSearchParams获取参数
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments) @args
                ) @call_expr
            ''',
            'object_pattern': r'^(URLSearchParams)$',
            'property_pattern': r'^(get|getAll|entries|values|keys)$',
            'message': '使用URLSearchParams获取URL参数'
        },
        # 使用document.write/innerHTML等危险DOM操作
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments) @args
                ) @call_expr
            ''',
            'object_pattern': r'^(document|element|el|div|span|p)$',
            'property_pattern': r'^(write|writeln|innerHTML|outerHTML|insertAdjacentHTML)$',
            'message': '使用危险的DOM操作方法，可能执行恶意脚本'
        },
        # jQuery的html()方法
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments) @args
                ) @call_expr
            ''',
            'object_pattern': r'^(\$|jQuery)$',
            'property_pattern': r'^(html)$',
            'message': '使用jQuery的html()方法，可能执行恶意脚本'
        },
        # eval函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func
                    arguments: (arguments) @args
                ) @call_expr
            ''',
            'pattern': r'^(eval|setTimeout|setInterval|Function)$',
            'message': '使用动态代码执行函数，可能执行恶意脚本'
        },
        # 使用innerHTML赋值
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
            'property_pattern': r'^(innerHTML|outerHTML)$',
            'message': '直接设置innerHTML/outerHTML属性，可能执行恶意脚本'
        },
        # new URLSearchParams() 调用
        {
            'query': '''
                (new_expression
                    constructor: (identifier) @constructor
                    arguments: (arguments) @args
                ) @new_expr
            ''',
            'pattern': r'^(URLSearchParams)$',
            'message': '创建URLSearchParams对象处理URL参数'
        }
    ]
}


# 辅助函数：检查节点是否包含用户输入源
def is_user_input_source(node, code):
    """检查节点是否可能包含用户输入"""
    node_text = node.text.decode('utf8') if hasattr(node, 'text') else str(node)

    # 用户输入源的关键词模式
    user_input_patterns = [
        r'location\.(search|hash|href|URL)',
        r'window\.location',
        r'document\.location',
        r'URLSearchParams',
        r'new\s+URLSearchParams',
        r'getParameter',
        r'getQueryString',
        r'request\.',
        r'req\.',
        r'query\.',
        r'params\.',
        r'body\.',
        r'form\.',
        r'input\.value',
    ]

    for pattern in user_input_patterns:
        if re.search(pattern, node_text, re.IGNORECASE):
            return True

    return False


# 辅助函数：检查节点是否包含XSS过滤函数
def has_xss_protection(node, code):
    """检查节点是否包含XSS防护措施"""
    node_text = node.text.decode('utf8') if hasattr(node, 'text') else str(node)

    # XSS防护函数模式
    protection_patterns = [
        r'encodeURIComponent',
        r'encodeURI',
        r'escape',
        r'textContent',
        r'innerText',
        r'createTextNode',
        r'DOMPurify',
        r'\.sanitize',
        r'\.escape',
        r'htmlspecialchars',
        r'strip_tags',
        r'htmlentities',
        r'text\(\)',  # jQuery的text方法
    ]

    for pattern in protection_patterns:
        if re.search(pattern, node_text, re.IGNORECASE):
            return True

    return False


# 辅助函数：检查代码片段是否包含用户输入和危险操作
def check_xss_pattern(node, code, pattern_type):
    """检查特定的XSS模式"""
    node_text = node.text.decode('utf8') if hasattr(node, 'text') else str(node)

    # 获取父节点或相关节点的代码以进行更全面的分析
    parent_text = get_parent_context(node, code)

    # 检查是否包含用户输入
    has_user_input = is_user_input_source(node, code) or is_user_input_source_from_context(parent_text)

    # 检查是否缺少防护
    has_protection = has_xss_protection(node, code) or has_xss_protection_from_context(parent_text)

    return has_user_input and not has_protection


def get_parent_context(node, code, levels=2):
    """获取父节点的上下文"""
    current = node
    context = []

    for i in range(levels):
        if hasattr(current, 'parent') and current.parent:
            current = current.parent
            context.append(current.text.decode('utf8') if hasattr(current, 'text') else str(current))
        else:
            break

    return " ".join(context)


def is_user_input_source_from_context(context):
    """从上下文中检查用户输入"""
    user_input_patterns = [
        r'location\.',
        r'URLSearchParams',
        r'getParameter',
        r'search\?',
        r'hash\#',
        r'query\.',
        r'params\.',
    ]

    for pattern in user_input_patterns:
        if re.search(pattern, context, re.IGNORECASE):
            return True

    return False


def has_xss_protection_from_context(context):
    """从上下文中检查XSS防护"""
    protection_patterns = [
        r'encodeURIComponent',
        r'encodeURI',
        r'escape',
        r'textContent',
        r'innerText',
        r'DOMPurify',
        r'sanitize',
        r'escape',
    ]

    for pattern in protection_patterns:
        if re.search(pattern, context, re.IGNORECASE):
            return True

    return False


def detect_reflected_xss_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中的反射型XSS漏洞

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

    # 检测所有可能的XSS模式
    for pattern_info in REFLECTED_XSS_PATTERNS[language]:
        try:
            query = LANGUAGES[language].query(pattern_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                # 检查是否匹配模式
                is_match = False
                node_text = node.text.decode('utf8') if hasattr(node, 'text') else str(node)

                if tag in ['object', 'func', 'constructor']:
                    pattern = pattern_info.get('pattern') or pattern_info.get('object_pattern', '')
                    if pattern and re.match(pattern, node_text, re.IGNORECASE):
                        is_match = True

                elif tag == 'property':
                    prop_pattern = pattern_info.get('property_pattern', '')
                    if prop_pattern and re.match(prop_pattern, node_text, re.IGNORECASE):
                        is_match = True

                elif tag in ['call_expr', 'member_expr', 'assignment', 'new_expr']:
                    is_match = True

                if is_match and check_xss_pattern(node, code, pattern_info['message']):
                    # 获取完整的代码片段
                    code_snippet = node.text.decode('utf8')

                    vulnerabilities.append({
                        'line': node.start_point[0] + 1,
                        'message': pattern_info['message'],
                        'code_snippet': code_snippet,
                        'vulnerability_type': '反射型XSS',
                        'severity': '高危'
                    })

        except Exception as e:
            print(f"查询错误 {pattern_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_reflected_xss_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 存在反射型XSS漏洞的代码示例

// 1. 直接从URL获取参数并插入DOM
function displaySearchResults() {
    const params = new URLSearchParams(window.location.search);
    const query = params.get('q');
    document.getElementById('results').innerHTML = "搜索结果: " + query; // 漏洞
}

// 2. 使用location.hash
function processHash() {
    const hash = window.location.hash.substring(1);
    document.write("当前哈希: " + hash); // 漏洞
}

// 3. 使用eval执行URL参数
function executeParam() {
    const param = new URLSearchParams(location.search).get('action');
    if (param) {
        eval(param); // 严重漏洞
    }
}

// 4. jQuery的html方法
function updateContent() {
    const id = new URLSearchParams(location.search).get('id');
    $('#content').html("ID: " + id); // 漏洞
}

// 5. 设置innerHTML
function setUserContent() {
    const userInput = document.getElementById('userInput').value;
    document.body.innerHTML += "<div>" + userInput + "</div>"; // 漏洞
}

// 6. 使用setTimeout执行动态代码
function delayedAction() {
    const code = location.search.split('code=')[1];
    setTimeout(code, 1000); // 漏洞
}

// 安全的使用方式示例
function safeExamples() {
    // 1. 使用textContent而不是innerHTML
    const query = new URLSearchParams(location.search).get('q');
    document.getElementById('results').textContent = "搜索结果: " + query; // 安全

    // 2. 编码用户输入
    const userInput = document.getElementById('userInput').value;
    const encodedInput = encodeURIComponent(userInput);
    document.getElementById('output').innerHTML = "<div>" + encodedInput + "</div>"; // 相对安全

    // 3. 使用DOMPurify清理HTML
    // const cleanHTML = DOMPurify.sanitize(userInput);
    // document.getElementById('output').innerHTML = cleanHTML; // 安全
}
"""

    print("=" * 60)
    print("JavaScript 反射型XSS漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到反射型XSS漏洞")