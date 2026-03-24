import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义HTTP参数污染漏洞的检测模式
HPP_VULNERABILITIES = {
    'javascript': [
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
            'object_pattern': r'^(req|request|params|query|body|url|headers)$',
            'property_pattern': r'^(query|param|params|body|header|get)$',
            'message': 'HTTP参数获取调用'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments) @args
                ) @call
            ''',
            'pattern': r'^(getParameter|getParam|getQueryParam|getQueryString|getHeader|param|get)$',
            'message': 'HTTP参数获取函数调用'
        },
        {
            'query': '''
                (subscript_expression
                    object: (identifier) @object
                    index: (string) @index
                ) @subscript
            ''',
            'object_pattern': r'^(req|request|params|query|body|url|headers)$',
            'message': 'HTTP参数下标访问'
        },
        {
            'query': '''
                (member_expression
                    object: (identifier) @object
                    property: (property_identifier) @property
                ) @member
            ''',
            'object_pattern': r'^(req|request|params|query|body|url|headers)$',
            'property_pattern': r'^(query|param|params|body|header|get)$',
            'message': 'HTTP参数成员访问'
        }
    ]
}


def detect_js_hpp_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中HTTP参数污染漏洞

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
    param_accesses = []  # 存储所有参数访问操作

    # 收集所有HTTP参数访问操作
    for query_info in HPP_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['object', 'func_name']:
                    obj_name = node.text.decode('utf8')
                    pattern = query_info.get('object_pattern') or query_info.get('pattern', '')
                    if pattern and re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['type'] = 'function_call' if tag == 'func_name' else 'member_access'

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern', '')
                    if (not prop_pattern or
                            re.match(prop_pattern, prop_name, re.IGNORECASE)):
                        current_capture['property'] = prop_name

                elif tag == 'index':
                    index_value = node.text.decode('utf8')
                    current_capture['index'] = index_value

                elif tag in ['call', 'subscript', 'member'] and current_capture:
                    # 完成一个完整的捕获
                    if 'object' in current_capture:
                        # 获取完整的代码片段
                        code_snippet = node.text.decode('utf8')

                        # 检查是否涉及参数访问
                        param_name = None
                        if 'index' in current_capture:
                            # 对于下标访问，提取参数名
                            index_str = current_capture['index'].strip('"\'').strip()
                            if index_str:  # 确保不是空字符串
                                param_name = index_str
                        elif 'property' in current_capture and current_capture['property'].lower() in ['get', 'param']:
                            # 对于get/param方法，尝试提取第一个参数
                            try:
                                if tag == 'call' and node.type == 'call_expression':
                                    args_node = None
                                    for child in node.children:
                                        if child.type == 'arguments':
                                            args_node = child
                                            break
                                    if args_node and len(args_node.children) > 1:
                                        first_arg = args_node.children[1]  # 跳过开头的(
                                        if first_arg.type == 'string':
                                            param_name = first_arg.text.decode('utf8').strip('"\'').strip()
                            except:
                                pass

                        param_accesses.append({
                            'line': current_capture['line'],
                            'object': current_capture['object'],
                            'property': current_capture.get('property'),
                            'index': current_capture.get('index'),
                            'code_snippet': code_snippet,
                            'param_name': param_name,
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 分析潜在的HPP漏洞
    for access in param_accesses:
        # 检查是否直接使用参数值而没有进行适当的处理
        line = access['line']
        code_snippet = access['code_snippet']

        # 标记为潜在漏洞的条件：
        # 1. 参数访问后直接使用（没有验证、过滤或只取第一个值）
        # 2. 用于敏感操作（SQL查询、命令执行、重定向等）

        # 检查代码片段中是否包含敏感操作模式
        sensitive_patterns = [
            r'\.exec\s*\(',  # SQL执行
            r'\.query\s*\(',  # 数据库查询
            r'eval\s*\(',  # eval调用
            r'exec\s*\(',  # 命令执行
            r'redirect',  # 重定向
            r'location\.',  # 位置操作
            r'innerHTML',  # DOM操作
            r'outerHTML',  # DOM操作
            r'document\.write',  # 文档写入
            r'fetch\s*\(',  # HTTP请求
            r'axios\s*\(',  # HTTP请求
            r'\.get\s*\(',  # HTTP请求
            r'\.post\s*\(',  # HTTP请求
        ]

        is_sensitive = any(re.search(pattern, code_snippet, re.IGNORECASE)
                           for pattern in sensitive_patterns)

        # 检查是否有多值处理逻辑
        has_multi_value_handling = re.search(r'join\s*\(|split\s*\(|Array\.isArray|forEach\s*\(|map\s*\(|filter\s*\(',
                                             code_snippet, re.IGNORECASE)

        # 检查是否有参数验证或过滤
        has_validation = re.search(r'test\s*\(|match\s*\(|replace\s*\(|sanitize|validate|filter',
                                   code_snippet, re.IGNORECASE)

        # 如果用于敏感操作但没有多值处理或验证，标记为潜在漏洞
        if is_sensitive and not (has_multi_value_handling or has_validation):
            vulnerabilities.append({
                'line': line,
                'message': 'Potential HTTP Parameter Pollution vulnerability',
                'code_snippet': code_snippet,
                'vulnerability_type': 'HTTP参数污染',
                'severity': '中危',
                'details': '参数直接用于敏感操作而没有处理多值情况'
            })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的HPP漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_hpp_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 潜在的HPP漏洞示例
const express = require('express');
const app = express();

// 漏洞：直接使用查询参数
app.get('/vulnerable', (req, res) => {
    const user = req.query.user;  // 可能获取数组但当作字符串使用
    db.query('SELECT * FROM users WHERE name = ?', [user]);  // 直接用于SQL查询
});

// 漏洞：直接使用参数进行重定向
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(url);  // 可能接收数组但只使用第一个值
});

// 漏洞：使用body参数而不处理多值
app.post('/submit', (req, res) => {
    const data = req.body.data;
    eval(data);  // 危险操作
});

// 正确的处理：明确处理多值情况
app.get('/safe', (req, res) => {
    const users = req.query.user;
    if (Array.isArray(users)) {
        // 处理多值情况
        const userList = users.join(',');
        db.query('SELECT * FROM users WHERE name IN (?)', [userList]);
    } else {
        // 单值情况
        db.query('SELECT * FROM users WHERE name = ?', [users]);
    }
});

// 正确的处理：只取第一个值
app.get('/safe2', (req, res) => {
    const user = Array.isArray(req.query.user) ? req.query.user[0] : req.query.user;
    db.query('SELECT * FROM users WHERE name = ?', [user]);
});

// 使用下标访问参数
app.get('/subscript', (req, res) => {
    const param = req.query['user'];  // 下标访问
    res.send(param);
});

// 使用param方法
app.get('/param', (req, res) => {
    const user = req.param('user');  // 可能返回数组
    res.send(user);
});

// 头部参数访问
app.get('/header', (req, res) => {
    const token = req.headers['authorization'];  // 头部参数
    res.send(token);
});
"""

    print("=" * 60)
    print("JavaScript HTTP参数污染漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   详情: {vuln['details']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
    else:
        print("未检测到HTTP参数污染漏洞")