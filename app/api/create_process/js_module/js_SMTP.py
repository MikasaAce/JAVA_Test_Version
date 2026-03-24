import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义SMTP标头操纵漏洞的检测模式
SMTP_HEADER_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (string) @header_value)
                ) @call
            ''',
            'pattern': r'^(mailer|smtp|email|nodemailer|transport)$',
            'property_pattern': r'^(sendMail|send|createTransport|setHeader|addHeader|header)$',
            'message': 'SMTP标头设置调用发现'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (string) @header_value)
                ) @call
            ''',
            'pattern': r'^(sendMail|send|createTransport|setHeader|addHeader|header)$',
            'message': 'SMTP相关函数调用'
        },
        {
            'query': '''
                (assignment_expression
                    left: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    right: (string) @header_value
                ) @assignment
            ''',
            'pattern': r'^(headers|mailOptions|message|email)$',
            'property_pattern': r'^(from|to|subject|cc|bcc|replyTo|headers)$',
            'message': '邮件标头赋值操作发现'
        },
        {
            'query': '''
                (object
                    (pair
                        key: (property_identifier) @key
                        value: (string) @value
                    ) @pair
                )
            ''',
            'pattern': r'^(from|to|subject|cc|bcc|replyTo|headers)$',
            'message': '邮件标头对象属性设置'
        }
    ]
}


def detect_smtp_header_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中SMTP标头操纵漏洞

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
    header_operations = []  # 存储所有标头操作
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集所有SMTP标头设置操作
    for query_info in SMTP_HEADER_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['object', 'func_name']:
                    obj_name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern', '')
                    if (not prop_pattern or
                            re.match(prop_pattern, prop_name, re.IGNORECASE)):
                        current_capture['property'] = prop_name

                elif tag == 'key':
                    key_name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, key_name, re.IGNORECASE):
                        current_capture['key'] = key_name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['header_value', 'value'] and current_capture:
                    header_value = node.text.decode('utf8')
                    current_capture['value'] = header_value
                    current_capture['value_node'] = node

                    # 完成一个完整的捕获
                    header_operations.append({
                        'type': 'header_set',
                        'line': current_capture.get('line', node.start_point[0] + 1),
                        'object': current_capture.get('object', ''),
                        'property': current_capture.get('property', ''),
                        'key': current_capture.get('key', ''),
                        'value': header_value,
                        'code_snippet': node.parent.text.decode('utf8') if node.parent else '',
                        'node': node
                    })
                    current_capture = {}

                elif tag in ['call', 'assignment', 'pair'] and current_capture:
                    # 如果没有捕获到值，但完成了结构
                    if any(key in current_capture for key in ['object', 'key']):
                        header_operations.append({
                            'type': 'header_set',
                            'line': current_capture.get('line', node.start_point[0] + 1),
                            'object': current_capture.get('object', ''),
                            'property': current_capture.get('property', ''),
                            'key': current_capture.get('key', ''),
                            'value': '',
                            'code_snippet': node.text.decode('utf8'),
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：识别用户输入源（req.body, req.query, req.params等）
    user_input_patterns = [
        r'req\.(body|query|params|headers)\.[a-zA-Z_$][a-zA-Z_$0-9]*',
        r'window\.location\.(search|hash)',
        r'document\.(URL|location|referrer)',
        r'localStorage\.getItem|sessionStorage\.getItem',
        r'process\.env\.[a-zA-Z_$][a-zA-Z_$0-9]*'
    ]

    # 查找用户输入源
    for line_num, line in enumerate(code.split('\n'), 1):
        for pattern in user_input_patterns:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                user_input_sources.append({
                    'line': line_num,
                    'source': match.group(),
                    'code_snippet': line.strip()
                })

    # 第三步：分析漏洞
    for header_op in header_operations:
        header_line = header_op['line']
        header_value = header_op['value']

        # 检查标头值是否包含用户输入
        is_vulnerable = False

        # 1. 直接检查标头值是否包含明显的用户输入模式
        if header_value and is_user_input(header_value):
            is_vulnerable = True

        # 2. 检查标头值是否包含变量或表达式（需要进一步分析）
        elif header_value and contains_variable_or_expression(header_value):
            # 查找附近的变量赋值或函数调用
            if is_value_from_user_input(header_op, user_input_sources, code):
                is_vulnerable = True

        # 3. 检查标头操作是否在用户输入处理路径中
        if not is_vulnerable:
            # 分析代码上下文，检查是否在请求处理函数中
            if is_in_request_handler(header_op['node'], root, code):
                is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append({
                'line': header_line,
                'message': f'SMTP Header Injection: Potential header manipulation in {header_op.get("key", header_op.get("property", "unknown"))}',
                'code_snippet': header_op['code_snippet'],
                'vulnerability_type': 'SMTP标头操纵漏洞',
                'severity': '高危'
            })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_user_input(value):
    """
    检查字符串是否包含明显的用户输入模式

    Args:
        value: 要检查的字符串

    Returns:
        bool: 是否包含用户输入模式
    """
    user_input_indicators = [
        r'\$\{.*\}',  # 模板字符串
        r'\+.*\+',  # 字符串连接
        r'req\.(body|query|params|headers)',
        r'process\.env',
        r'window\.location',
        r'document\.(URL|location|referrer)',
        r'localStorage|sessionStorage'
    ]

    for pattern in user_input_indicators:
        if re.search(pattern, value, re.IGNORECASE):
            return True

    return False


def contains_variable_or_expression(value):
    """
    检查字符串是否包含变量或表达式

    Args:
        value: 要检查的字符串

    Returns:
        bool: 是否包含变量或表达式
    """
    # 检查是否包含变量名模式（不以引号包围）
    variable_patterns = [
        r'[a-zA-Z_$][a-zA-Z_$0-9]*',
        r'\$\{.*\}',
        r'\+.*\+'
    ]

    for pattern in variable_patterns:
        if re.search(pattern, value):
            return True

    return False


def is_value_from_user_input(header_op, user_input_sources, code):
    """
    检查标头值是否来自用户输入

    Args:
        header_op: 标头操作信息
        user_input_sources: 用户输入源列表
        code: 完整代码

    Returns:
        bool: 是否来自用户输入
    """
    header_line = header_op['line']

    # 检查附近行是否有用户输入源
    for source in user_input_sources:
        if abs(source['line'] - header_line) < 20:  # 在合理范围内
            return True

    return False


def is_in_request_handler(node, root, code):
    """
    检查节点是否在请求处理函数中

    Args:
        node: 当前节点
        root: AST根节点
        code: 完整代码

    Returns:
        bool: 是否在请求处理函数中
    """
    # 向上遍历查找函数定义
    current = node
    while current and current != root:
        if current.type == 'function_declaration' or current.type == 'arrow_function':
            # 检查函数参数是否包含req, request等
            func_text = current.text.decode('utf8')
            if re.search(r'\(.*(req|request|ctx).*\)', func_text, re.IGNORECASE):
                return True
        current = current.parent

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的SMTP标头操纵漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_smtp_header_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 存在漏洞的SMTP标头设置
const nodemailer = require('nodemailer');

// 漏洞示例1: 直接使用用户输入
app.post('/send-email', (req, res) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'your-email@gmail.com',
            pass: 'your-password'
        }
    });

    // 直接使用请求体中的用户输入 - 存在漏洞
    const mailOptions = {
        from: req.body.from,  // 用户可控的From头
        to: 'recipient@example.com',
        subject: req.query.subject,  // 用户可控的Subject头
        text: 'Hello world!'
    };

    transporter.sendMail(mailOptions);
});

// 漏洞示例2: 使用setHeader方法
function sendEmail(userInput) {
    const transporter = nodemailer.createTransport({/* config */});

    const mailOptions = {
        from: 'sender@example.com',
        to: 'recipient@example.com'
    };

    // 用户输入直接用于标头 - 存在漏洞
    mailOptions.setHeader('Reply-To', userInput);
    mailOptions.subject = userInput + ' - Inquiry';  // 字符串连接

    transporter.sendMail(mailOptions);
}

// 漏洞示例3: 使用模板字符串
app.get('/send', (req, res) => {
    const transporter = nodemailer.createTransport({/* config */});

    const userEmail = req.params.email;
    const mailOptions = {
        from: 'noreply@example.com',
        to: `${userEmail}`,  // 模板字符串中的用户输入
        subject: `Message from ${req.query.name}`,  // 用户输入
        text: 'Thank you for your message!'
    };

    transporter.sendMail(mailOptions);
});

// 安全示例: 使用硬编码或验证过的值
function sendSafeEmail() {
    const transporter = nodemailer.createTransport({/* config */});

    const mailOptions = {
        from: 'fixed-sender@example.com',  // 硬编码值
        to: 'fixed-recipient@example.com',
        subject: 'Fixed Subject',  // 硬编码值
        text: 'Fixed content'
    };

    transporter.sendMail(mailOptions);
}

// 边缘情况: 环境变量（可能安全也可能不安全）
function sendEmailWithEnv() {
    const transporter = nodemailer.createTransport({/* config */});

    const mailOptions = {
        from: process.env.EMAIL_FROM,  // 环境变量 - 需要进一步分析
        to: process.env.EMAIL_TO,
        subject: 'Test Email',
        text: 'Content'
    };

    transporter.sendMail(mailOptions);
}

// 使用headers对象
function sendWithHeaders() {
    const transporter = nodemailer.createTransport({/* config */});

    const mailOptions = {
        from: 'sender@example.com',
        to: 'recipient@example.com',
        headers: {
            'X-Custom-Header': req.body.customHeader,  // 用户输入 - 存在漏洞
            'Reply-To': 'fixed@example.com'  // 安全
        }
    };

    transporter.sendMail(mailOptions);
}
"""

    print("=" * 60)
    print("JavaScript SMTP标头操纵漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SMTP标头操纵漏洞")