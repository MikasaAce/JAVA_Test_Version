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

# 定义SMTP标头注入漏洞模式
SMTP_HEADER_INJECTION_VULNERABILITIES = {
    'python': [
        # 检测smtplib邮件发送
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @smtp_obj
                        attribute: (identifier) @send_method
                    )
                    arguments: (argument_list 
                        (_) @from_addr
                        (_) @to_addrs
                        (_) @msg_content
                    )
                ) @call
            ''',
            'method_pattern': r'^(sendmail|send_message)$',
            'message': 'SMTP邮件发送操作'
        },
        # 检测email.mime文本构建
        {
            'query': '''
                (call
                    function: (identifier) @mime_class
                    arguments: (argument_list 
                        (_)* @mime_args
                    )
                ) @call
            ''',
            'class_pattern': r'^(MIMEText|MIMEMultipart|MIMEBase|MIMEImage|MIMEAudio)$',
            'message': 'MIME邮件对象创建'
        },
        # 检测邮件标头设置
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @msg_obj
                        attribute: (identifier) @header_method
                    )
                    arguments: (argument_list 
                        (string) @header_name
                        (_) @header_value
                    )
                ) @call
            ''',
            'method_pattern': r'^(add_header|__setitem__)$',
            'message': '邮件标头设置操作'
        },
        # 检测标头赋值操作
        {
            'query': '''
                (assignment
                    left: (attribute
                        object: (identifier) @msg_obj
                        attribute: (identifier) @header_attr
                    )
                    right: (_) @header_value
                ) @assignment
            ''',
            'attr_pattern': r'^(Subject|From|To|Cc|Bcc|Reply-To|Date|Content-Type)$',
            'message': '邮件标头直接赋值'
        },
        # 检测字符串拼接的标头值
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @msg_obj
                        attribute: (identifier) @header_method
                    )
                    arguments: (argument_list 
                        (string) @header_name
                        (binary_expression
                            left: (_) @left_part
                            operator: "+"
                            right: (_) @right_part
                        ) @concat_value
                    )
                ) @call
            ''',
            'method_pattern': r'^(add_header|__setitem__)$',
            'message': '字符串拼接的标头值'
        },
        # 检测format格式化的标头值
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @msg_obj
                        attribute: (identifier) @header_method
                    )
                    arguments: (argument_list 
                        (string) @header_name
                        (call
                            function: (attribute
                                object: (string) @base_string
                                attribute: (identifier) @format_method
                            )
                            arguments: (argument_list (_)* @format_args)
                        ) @format_call
                    )
                ) @call
            ''',
            'method_pattern': r'^(add_header|__setitem__)$',
            'message': 'format格式化的标头值'
        },
        # 检测f-string标头值
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @msg_obj
                        attribute: (identifier) @header_method
                    )
                    arguments: (argument_list 
                        (string) @header_name
                        (interpolation) @fstring_value
                    )
                ) @call
            ''',
            'method_pattern': r'^(add_header|__setitem__)$',
            'message': 'f-string标头值'
        },
        # 检测邮件内容设置
        {
            'query': '''
                (assignment
                    left: (attribute
                        object: (identifier) @msg_obj
                        attribute: (identifier) @payload_attr
                    )
                    right: (_) @payload_value
                ) @assignment
            ''',
            'attr_pattern': r'^(_payload|payload)$',
            'message': '邮件内容设置'
        },
        # 检测smtplib连接和发送
        {
            'query': '''
                (with_statement
                    body: (block) @with_body
                    (with_clause
                        (with_item
                            value: (call
                                function: (identifier) @smtp_class
                                arguments: (argument_list (_)* @smtp_args)
                            ) @smtp_call
                        ) @with_item
                    ) @with_clause
                ) @with_stmt
            ''',
            'class_pattern': r'^(SMTP|SMTP_SSL)$',
            'message': 'SMTP连接上下文'
        }
    ]
}

# 用户输入源模式（SMTP标头注入相关）
SMTP_USER_INPUT_SOURCES = {
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
            'obj_pattern': r'^(flask|django|bottle)\.request$',
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

# 邮件标头构建模式
EMAIL_HEADER_BUILDING_PATTERNS = {
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
            'var_pattern': r'^(subject|from_addr|to_addr|cc_addr|bcc_addr|reply_to|body|content|message|header_value)$',
            'message': '邮件标头值构建'
        },
        {
            'base_string_pattern': r'^(Subject:|From:|To:|Cc:|Bcc:|Reply-To:)',
            'message': '邮件标头字符串构建'
        }
    ]
}

# 危险标头模式
DANGEROUS_HEADER_PATTERNS = {
    'header_injection_patterns': [
        r'\r\n',
        r'\n',
        r'\r',
        r'%0d%0a',  # URL编码的CRLF
        r'%0a',     # URL编码的LF
        r'%0d',     # URL编码的CR
        r'Bcc:',
        r'Cc:',
        r'To:',
        r'From:',
        r'Subject:',
        r'Content-Type:',
        r'Content-Transfer-Encoding:',
        r'Reply-To:',
        r'Return-Path:'
    ],
    'sensitive_headers': [
        'Bcc',
        'Cc',
        'To',
        'From',
        'Subject',
        'Content-Type',
        'Reply-To',
        'Return-Path'
    ]
}

def analyze_smtp_header_injection(code, language='python'):
    """
    检测Python代码中SMTP标头注入漏洞

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
    smtp_operations = []  # 存储SMTP操作
    user_input_sources = []  # 存储用户输入源
    header_buildings = []  # 存储标头构建操作

    # 第一步：收集所有SMTP操作
    for query_info in SMTP_HEADER_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['smtp_obj', 'send_method', 'mime_class', 'msg_obj', 
                          'header_method', 'header_attr', 'payload_attr', 'smtp_class']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['from_addr', 'to_addrs', 'msg_content', 'header_name', 
                           'header_value', 'left_part', 'right_part', 'payload_value',
                           'base_string', 'fstring_value']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['mime_args', 'smtp_args', 'format_args']:
                    current_capture[tag] = node.text.decode('utf8')

                elif tag in ['call', 'assignment', 'with_stmt'] and current_capture:
                    # 检查方法名是否匹配模式
                    method_pattern = query_info.get('method_pattern', '')
                    class_pattern = query_info.get('class_pattern', '')
                    attr_pattern = query_info.get('attr_pattern', '')

                    method_match = True
                    class_match = True
                    attr_match = True

                    if method_pattern and 'send_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['send_method'], re.IGNORECASE)
                    elif method_pattern and 'header_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['header_method'], re.IGNORECASE)

                    if class_pattern and 'mime_class' in current_capture:
                        class_match = re.match(class_pattern, current_capture['mime_class'], re.IGNORECASE)
                    elif class_pattern and 'smtp_class' in current_capture:
                        class_match = re.match(class_pattern, current_capture['smtp_class'], re.IGNORECASE)

                    if attr_pattern and 'header_attr' in current_capture:
                        attr_match = re.match(attr_pattern, current_capture['header_attr'], re.IGNORECASE)
                    elif attr_pattern and 'payload_attr' in current_capture:
                        attr_match = re.match(attr_pattern, current_capture['payload_attr'], re.IGNORECASE)

                    if method_match and class_match and attr_match:
                        code_snippet = node.text.decode('utf8')

                        smtp_operations.append({
                            'type': 'smtp_operation',
                            'line': current_capture['line'],
                            'method': current_capture.get('send_method', '') or 
                                    current_capture.get('header_method', '') or 
                                    current_capture.get('mime_class', '') or
                                    current_capture.get('smtp_class', '') or 'assignment',
                            'header_name': current_capture.get('header_name', '') or 
                                         current_capture.get('header_attr', ''),
                            'header_value': current_capture.get('header_value', '') or 
                                          current_capture.get('from_addr', '') or
                                          current_capture.get('to_addrs', '') or
                                          current_capture.get('msg_content', '') or
                                          current_capture.get('payload_value', '') or
                                          current_capture.get('left_part', '') or
                                          current_capture.get('fstring_value', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'vulnerability_type': query_info.get('message', 'SMTP标头注入风险')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"SMTP标头注入查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(SMTP_USER_INPUT_SOURCES['query'])
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
                for pattern_info in SMTP_USER_INPUT_SOURCES['patterns']:
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

    # 第三步：收集标头构建操作
    try:
        query = LANGUAGES[language].query(EMAIL_HEADER_BUILDING_PATTERNS['query'])
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
                # 检查是否匹配标头构建模式
                for pattern_info in EMAIL_HEADER_BUILDING_PATTERNS['patterns']:
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
                        header_buildings.append({
                            'type': 'header_building',
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
        print(f"标头构建查询错误: {e}")

    # 第四步：分析SMTP标头注入漏洞
    for smtp_op in smtp_operations:
        vulnerability_details = analyze_smtp_operation(smtp_op, user_input_sources, header_buildings)
        if vulnerability_details:
            vulnerabilities.extend(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_smtp_operation(smtp_op, user_input_sources, header_buildings):
    """
    分析单个SMTP操作的安全问题
    """
    vulnerabilities = []
    code_snippet = smtp_op['code_snippet']
    line = smtp_op['line']
    method_name = smtp_op['method']
    header_value = smtp_op['header_value']

    # 检查直接用户输入
    if is_direct_user_input(smtp_op, user_input_sources):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SMTP标头注入',
            'severity': '高危',
            'message': f"{method_name} 操作直接使用用户输入作为邮件标头值"
        })

    # 检查字符串拼接
    elif is_string_concatenation(smtp_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SMTP标头注入',
            'severity': '高危',
            'message': f"{method_name} 操作使用字符串拼接构建邮件标头值"
        })

    # 检查format格式化
    elif is_format_operation(smtp_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SMTP标头注入',
            'severity': '高危',
            'message': f"{method_name} 操作使用format方法构建邮件标头值"
        })

    # 检查f-string格式化
    elif is_fstring_operation(smtp_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SMTP标头注入',
            'severity': '高危',
            'message': f"{method_name} 操作使用f-string构建邮件标头值"
        })

    # 检查标头注入模式
    elif contains_header_injection_patterns(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SMTP标头注入',
            'severity': '高危',
            'message': f"{method_name} 操作包含标头注入危险模式"
        })

    # 检查敏感标头操作
    elif is_sensitive_header_operation(smtp_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SMTP标头注入',
            'severity': '中危',
            'message': f"{method_name} 操作修改敏感邮件标头"
        })

    # 检查标头验证缺失
    elif not has_header_validation(code_snippet):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': 'SMTP标头注入',
            'severity': '中危',
            'message': f"{method_name} 操作缺少标头验证逻辑"
        })

    return vulnerabilities


def is_direct_user_input(smtp_op, user_input_sources):
    """
    检查标头值是否直接来自用户输入
    """
    header_value = smtp_op['header_value']
    
    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'request', 'args', 'form', 'get', 
                      'post', 'data', 'json', 'subject', 'from_addr', 'to_addr']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', header_value, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == smtp_op['node'] or is_child_node(smtp_op['node'], source['node']):
            return True

    return False


def is_string_concatenation(smtp_op):
    """
    检查是否使用字符串拼接构建标头值
    """
    code_snippet = smtp_op['code_snippet']
    return '+' in code_snippet and any(keyword in code_snippet for keyword in 
                                     ['add_header', 'Subject', 'From', 'To', 'sendmail'])


def is_format_operation(smtp_op):
    """
    检查是否使用format方法构建标头值
    """
    return 'format' in smtp_op.get('format_method', '')


def is_fstring_operation(smtp_op):
    """
    检查是否使用f-string构建标头值
    """
    return 'fstring_value' in smtp_op


def contains_header_injection_patterns(code_snippet):
    """
    检查是否包含标头注入危险模式
    """
    for pattern in DANGEROUS_HEADER_PATTERNS['header_injection_patterns']:
        if re.search(pattern, code_snippet, re.IGNORECASE):
            return True
    return False


def is_sensitive_header_operation(smtp_op):
    """
    检查是否操作敏感邮件标头
    """
    header_name = smtp_op['header_name']
    if not header_name:
        return False
        
    header_name_str = str(header_name).strip('"\'').title()
    
    for sensitive_header in DANGEROUS_HEADER_PATTERNS['sensitive_headers']:
        if sensitive_header in header_name_str:
            return True
            
    return False


def has_header_validation(code_snippet):
    """
    检查代码片段是否包含标头验证逻辑
    """
    validation_patterns = [
        r'replace\([\'"]\\r\\n[\'"]',
        r'replace\([\'"]\\n[\'"]',
        r'replace\([\'"]\\r[\'"]',
        r'strip\(\)',
        r'sanitize',
        r'validate',
        r'check',
        r'escape',
        r'encode',
        r'Header',
        r'formataddr',
        r'parsedate',
        r'utils'
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


def analyze_smtp_header_injection_main(code_string):
    """
    主函数：分析Python代码字符串中的SMTP标头注入漏洞
    """
    return analyze_smtp_header_injection(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
from flask import request
import os

# 不安全的SMTP标头注入示例
def insecure_smtp_examples():
    # 直接用户输入作为标头值 - 高危
    user_subject = request.args.get('subject')
    user_from = request.args.get('from')
    user_to = request.args.get('to')
    
    msg = MIMEText('Email body')
    msg['Subject'] = user_subject  # 高危: 标头注入
    msg['From'] = user_from        # 高危
    msg['To'] = user_to            # 高危
    
    # 字符串拼接标头值 - 高危
    base_subject = "Order Confirmation: "
    order_id = request.form.get('order_id')
    full_subject = base_subject + order_id  # 高危
    msg['Subject'] = full_subject
    
    # format格式化标头值 - 高危
    user_name = request.json.get('name')
    subject = "Welcome {}!".format(user_name)  # 高危
    msg['Subject'] = subject
    
    # f-string标头值 - 高危
    company = request.args.get('company')
    subject = f"Invoice from {company}"  # 高危
    msg['Subject'] = subject
    
    # 直接使用sendmail - 高危
    smtp = smtplib.SMTP('localhost')
    smtp.sendmail(user_from, user_to, msg.as_string())  # 高危
    
    # 包含CRLF的标头注入 - 严重
    malicious_subject = "Hello\\r\\nBcc: victim@example.com"
    msg['Subject'] = malicious_subject  # 严重: 添加隐藏收件人
    
    # 多部分邮件的标头注入
    multipart_msg = MIMEMultipart()
    multipart_msg['Subject'] = request.form.get('subject')  # 高危
    multipart_msg.add_header('Reply-To', request.args.get('reply_to'))  # 高危

# 相对安全的SMTP操作示例
def safe_smtp_examples():
    # 硬编码标头值 - 安全
    msg = MIMEText('Email body')
    msg['Subject'] = 'System Notification'  # 安全
    msg['From'] = 'noreply@example.com'     # 安全
    msg['To'] = 'admin@example.com'         # 安全
    
    # 经过验证的用户输入 - 安全
    user_subject = request.args.get('subject', '')
    if is_safe_header_value(user_subject):
        msg['Subject'] = user_subject  # 安全
    
    # 使用Header类编码 - 安全
    safe_subject = Header(request.form.get('subject', ''), 'utf-8')  # 安全
    msg['Subject'] = safe_subject
    
    # 使用formataddr - 安全
    safe_from = formataddr(('Sender', 'sender@example.com'))  # 安全
    msg['From'] = safe_from
    
    # 标头值清理 - 安全
    raw_subject = request.args.get('subject', '')
    clean_subject = raw_subject.replace('\\r', '').replace('\\n', '')  # 安全
    msg['Subject'] = clean_subject
    
    # 使用安全的send方法
    with smtplib.SMTP('localhost') as smtp:
        smtp.send_message(msg)  # 相对安全

# 邮件构建辅助函数
def is_safe_header_value(value):
    \"\"\"检查标头值是否安全\"\"\"
    if not value:
        return False
        
    # 检查CRLF注入模式
    dangerous_patterns = [r'\r\n', r'\n', r'\r', r'%0d%0a', r'%0a', r'%0d']
    for pattern in dangerous_patterns:
        if pattern in value:
            return False
            
    # 检查额外的邮件标头
    header_keywords = ['Bcc:', 'Cc:', 'To:', 'From:', 'Subject:', 'Content-Type:']
    for keyword in header_keywords:
        if keyword in value:
            return False
            
    return True

def build_safe_email(to_addr, subject, body):
    \"\"\"构建安全的邮件\"\"\"
    msg = MIMEText(body)
    
    # 使用固定的发件人
    msg['From'] = 'noreply@example.com'
    msg['To'] = to_addr
    
    # 清理主题
    clean_subject = subject.replace('\\r', '').replace('\\n', '').strip()
    msg['Subject'] = Header(clean_subject, 'utf-8')
    
    return msg

# 混合示例
def mixed_examples():
    # 部分验证
    user_subject = request.args.get('subject')
    if user_subject:  # 验证不充分
        msg = MIMEText('Body')
        msg['Subject'] = user_subject  # 高危
    
    # 使用安全函数
    safe_msg = build_safe_email(
        'user@example.com',
        request.form.get('subject', ''),
        'Email content'
    )  # 相对安全
    
    # 直接构造邮件内容 - 高危
    email_content = f\"\"\"From: {request.args.get('from')}
To: {request.args.get('to')}
Subject: {request.args.get('subject')}

{request.args.get('body')}
\"\"\"
    smtp = smtplib.SMTP('localhost')
    smtp.sendmail('from@example.com', ['to@example.com'], email_content)  # 高危

# Flask邮件发送示例
def flask_mail_example():
    from flask_mail import Mail, Message
    
    mail = Mail()
    
    # 不安全的Flask-Mail使用
    msg = Message(
        subject=request.form.get('subject'),  # 高危
        recipients=[request.form.get('to')],  # 高危
        body=request.form.get('body')         # 高危
    )
    mail.send(msg)
    
    # 相对安全的Flask-Mail使用
    safe_msg = Message(
        subject='System Alert',
        recipients=['admin@example.com'],
        body='Alert message'
    )
    mail.send(safe_msg)

if __name__ == "__main__":
    insecure_smtp_examples()
    safe_smtp_examples()
    mixed_examples()
    flask_mail_example()
"""

    print("=" * 60)
    print("Python SMTP标头注入漏洞检测")
    print("=" * 60)

    results = analyze_smtp_header_injection_main(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个SMTP标头注入漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SMTP标头注入漏洞")