import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JavaScript的Cookie安全漏洞模式
COOKIE_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                ) @call
            ''',
            'pattern': r'^(cookie|document|cookies)$',
            'property_pattern': r'^(cookie|set|append|add)$',
            'message': 'Cookie设置调用发现'
        },
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
            'pattern': r'^(document|cookie|window|globalThis)$',
            'property_pattern': r'^(cookie)$',
            'message': 'Cookie赋值操作发现'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @call
            ''',
            'pattern': r'^(setCookie|setcookie|cookie|setHttpOnly|httponly)$',
            'message': 'Cookie相关函数调用'
        },
        {
            'query': '''
                (pair
                    key: (property_identifier) @key
                    value: (_) @value
                ) @pair
            ''',
            'pattern': r'^(httpOnly|httponly|secure|samesite|expires|max-age|domain|path)$',
            'message': 'Cookie属性设置'
        }
    ]
}


def detect_js_cookie_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中Cookie的HTTPOnly属性未设置的漏洞

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
    cookie_operations = []  # 存储所有Cookie操作
    httponly_settings = []  # 存储HTTPOnly设置

    # 第一步：收集所有Cookie设置操作
    for query_info in COOKIE_VULNERABILITIES[language][:3]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag == 'object' or tag == 'func_name':
                    obj_name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern', '')
                    if (not prop_pattern or
                            re.match(prop_pattern, prop_name, re.IGNORECASE)):
                        current_capture['property'] = prop_name

                elif tag in ['call', 'assignment'] and current_capture:
                    # 完成一个完整的捕获
                    if 'object' in current_capture and 'property' in current_capture:
                        # 获取完整的代码片段
                        code_snippet = node.text.decode('utf8')

                        cookie_operations.append({
                            'type': 'cookie_set',
                            'line': current_capture['line'],
                            'object': current_capture['object'],
                            'property': current_capture['property'],
                            'code_snippet': code_snippet,
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有HTTPOnly属性设置
    try:
        query = LANGUAGES[language].query(COOKIE_VULNERABILITIES[language][3]['query'])
        captures = query.captures(root)

        current_pair = {}
        for node, tag in captures:
            if tag == 'key':
                key_name = node.text.decode('utf8')
                pattern = COOKIE_VULNERABILITIES[language][3]['pattern']
                if re.match(pattern, key_name, re.IGNORECASE):
                    current_pair['key'] = key_name
                    current_pair['node'] = node.parent
                    current_pair['line'] = node.start_point[0] + 1

            elif tag == 'value' and current_pair:
                value_text = node.text.decode('utf8')
                current_pair['value'] = value_text

                # 检查是否为HTTPOnly相关的键
                if current_pair['key'].lower() in ['httponly', 'httponly']:
                    httponly_settings.append({
                        'line': current_pair['line'],
                        'value': value_text,
                        'code_snippet': current_pair['node'].text.decode('utf8') if current_pair['node'] else ''
                    })

                current_pair = {}

    except Exception as e:
        print(f"HTTPOnly属性查询错误: {e}")

    # 第三步：分析漏洞
    for cookie_op in cookie_operations:
        cookie_line = cookie_op['line']
        has_proper_httponly = False

        # 检查在Cookie操作附近是否有正确的HTTPOnly设置
        for httponly_setting in httponly_settings:
            httponly_line = httponly_setting['line']

            # 检查是否在合理范围内（同一函数或相近行数）
            line_diff = abs(httponly_line - cookie_line)

            if line_diff < 50:  # 放宽范围以捕获更多相关设置
                # 检查HTTPOnly值是否为真
                if is_truthy_js_value(httponly_setting['value']):
                    has_proper_httponly = True
                    break

        # 额外检查：直接检查Cookie字符串中是否包含httponly
        code_snippet = cookie_op['code_snippet'].lower()
        if 'httponly' in code_snippet or 'http-only' in code_snippet:
            # 检查是否设置为true
            if re.search(r'httponly\s*[:=]\s*true', code_snippet, re.IGNORECASE):
                has_proper_httponly = True
            elif re.search(r'httponly', code_snippet, re.IGNORECASE):
                # 如果有httponly但没有明确值，默认为安全
                has_proper_httponly = True

        # 如果没有找到有效的HTTPOnly设置，报告漏洞
        if not has_proper_httponly:
            vulnerabilities.append({
                'line': cookie_line,
                'message': 'Cookie Security: HTTPOnly not properly set',
                'code_snippet': cookie_op['code_snippet'],
                'vulnerability_type': 'Cookie安全漏洞',
                'severity': '高危'
            })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_truthy_js_value(value):
    """
    检查JavaScript中的真值

    Args:
        value: 参数值字符串

    Returns:
        bool: 是否为真值
    """
    if not value:
        return False

    # 清理值
    cleaned_value = re.sub(r'[\s\'"]', '', value.lower())

    truthy_values = ['true', '1', 'yes', 'on']
    falsy_values = ['false', '0', 'no', 'off', 'null', 'undefined', 'nan']

    if cleaned_value in truthy_values:
        return True
    elif cleaned_value in falsy_values:
        return False

    # 检查数字值
    try:
        num_value = float(cleaned_value)
        return bool(num_value)
    except ValueError:
        pass

    # 默认情况下，如果有值但不是明确假值，认为是真值
    return len(cleaned_value) > 0


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_cookie_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 存在漏洞的Cookie设置
document.cookie = "sessionid=abc123; path=/; secure";  // 缺少httponly
document.cookie = "user=john; expires=Thu, 18 Dec 2023 12:00:00 UTC";  // 完全缺少安全属性

// 看似安全但实际上不安全的Cookie设置
document.cookie = "secure_session=def456; path=/; secure";  // 有secure但缺少httponly
document.cookie = "token=ghi789; Secure; SameSite=Strict";  // 有Secure但缺少HttpOnly

// 使用函数设置Cookie但不设置httponly
function setCookie(name, value, options = {}) {
    let cookie = `${name}=${value}`;
    if (options.secure) {
        cookie += '; Secure';
    }
    // 故意不添加httponly选项
    document.cookie = cookie;
}

// 不安全的函数调用 - 没有传递httponly参数
setCookie('unsafe', 'value123', { secure: true });

// 错误的HTTPOnly设置 - 明确设置为false
document.cookie = "bad=example; httponly=false";  // 明确设置为false
document.cookie = "bad2=example; httponly=0";     // 数字0表示false

// 不完整的设置对象
const incompleteOptions = {
    secure: true
    // 故意缺少httpOnly属性
};

// 使用不安全的第三方库方式
const cookies = require('js-cookie');
cookies.set('insecure_cookie', 'value789', { secure: true });  // 缺少httpOnly

// 通过赋值方式设置cookie但不包含httponly
window.document.cookie = "assignment=test; path=/";

// 使用append方法但不设置安全属性
document.cookie.append("append_cookie", "value999");

// 边缘情况：拼写错误的httponly
document.cookie = "typo=example; httponly=true";  // 少了一个字母p
document.cookie = "typo2=example; httpOnly=true"; // 正确的应该是httponly

// 使用错误的大小写
document.cookie = "wrongcase=example; HTTPONLY=true";  // 应该是httponly而不是HTTPONLY

// 设置为空字符串或undefined
document.cookie = "empty=value; httponly=";  // 空值
document.cookie = "undefined=value; httponly=undefined";  // undefined

// 使用对象设置但不包含httponly
const unsafeOptions = {
    secure: true,
    maxAge: 3600,
    // 故意省略httpOnly
};
"""

    print("=" * 60)
    print("JavaScript Cookie安全漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Cookie安全漏洞")