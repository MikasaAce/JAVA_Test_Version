import os
import re
from tree_sitter import Language, Parser

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义日志伪造漏洞模式（简化版）
LOG_FORGERY_VULNERABILITIES = {
    'python': [
        # 主要检测模式 - 覆盖所有日志调用
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @logger_obj
                        attribute: (identifier) @log_level
                    )
                    arguments: (argument_list (_) @log_message)
                ) @call
            ''',
            'logger_pattern': r'^(logging|logger|log)$',
            'level_pattern': r'^(debug|info|warning|error|critical|exception)$',
            'message': '日志调用',
            'severity': '中危',
            'risk_type': 'log_call_main'
        },
        # 检测print语句
        {
            'query': '''
                (call
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @print_arg)
                ) @call
            ''',
            'func_pattern': r'^(print)$',
            'message': 'print语句',
            'severity': '低危',
            'risk_type': 'print_statement'
        },
        # 检测文件写入操作
        {
            'query': '''
                (call
                    function: (attribute
                        object: (call
                            function: (identifier) @open_func
                            arguments: (argument_list (_) @filename (_)? @mode)
                        ) @open_call
                        attribute: (identifier) @write_method
                    )
                    arguments: (argument_list (_) @write_content)
                ) @call
            ''',
            'open_pattern': r'^(open|file)$',
            'write_pattern': r'^(write|writelines)$',
            'message': '文件写入操作',
            'severity': '中危',
            'risk_type': 'file_write'
        },
        # 检测系统日志调用
        {
            'query': '''
                (call
                    function: (identifier) @syslog_func
                    arguments: (argument_list (_) @log_message)
                ) @call
            ''',
            'func_pattern': r'^(syslog)$',
            'message': '系统日志调用',
            'severity': '中危',
            'risk_type': 'syslog_call'
        }
    ]
}

# 日志伪造危险模式
LOG_FORGERY_PATTERNS = {
    'log_injection_indicators': [
        r'[\r\n]',  # 换行符注入
        r'.*%.*',  # 格式化字符串
        r'.*\{.*',  # 花括号（可能是格式化）
        r'.*\$.*',  # 美元符号（可能是模板）
    ],
    'sensitive_log_patterns': [
        r'password', r'passwd', r'pwd', r'secret', r'key',
        r'token', r'auth', r'credential', r'private',
        r'session', r'cookie', r'jwt', r'api[_-]?key',
        r'social[_-]?security', r'credit[_-]?card', r'ssn',
        r'bank[_-]?account', r'phone', r'email', r'address'
    ],
    'log_evasion_patterns': [
        r'.*\\x1b\[',  # ANSI转义序列
        r'.*\\u[0-9a-fA-F]{4}',  # Unicode转义
        r'.*\\[0-7]{1,3}',  # 八进制转义
    ]
}


def detect_log_forgery(code, language='python'):
    """
    检测Python代码中日志伪造漏洞（修复重复检测问题）
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
    log_operations = []  # 存储所有日志操作
    processed_locations = set()  # 用于去重

    # 第一步：收集所有日志操作（使用去重）
    for query_info in LOG_FORGERY_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['logger_obj', 'log_level', 'func_name', 'open_func', 'write_method', 'syslog_func']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['log_message', 'print_arg', 'write_content']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['call', 'open_call'] and current_capture:
                    # 检查是否匹配模式
                    if is_log_operation(current_capture, query_info):
                        # 使用位置信息进行去重
                        line = current_capture['line']
                        location_key = f"{line}:{current_capture.get('log_message', '')}"

                        if location_key not in processed_locations:
                            processed_locations.add(location_key)

                            code_snippet = node.text.decode('utf8')

                            operation = {
                                'type': 'log_operation',
                                'line': line,
                                'logger_obj': current_capture.get('logger_obj', ''),
                                'log_level': current_capture.get('log_level', ''),
                                'func_name': current_capture.get('func_name', ''),
                                'log_message': current_capture.get('log_message', ''),
                                'print_arg': current_capture.get('print_arg', ''),
                                'write_content': current_capture.get('write_content', ''),
                                'code_snippet': code_snippet,
                                'node': node,
                                'severity': query_info.get('severity', '中危'),
                                'risk_type': query_info.get('risk_type', 'unknown'),
                                'original_message': query_info.get('message', ''),
                                'query_info': query_info
                            }
                            log_operations.append(operation)

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：分析日志伪造漏洞
    for operation in log_operations:
        vulnerability_details = analyze_log_forgery_vulnerability(operation, code)
        if vulnerability_details:
            # 检查最终结果是否重复
            vuln_key = f"{vulnerability_details['line']}:{vulnerability_details.get('message', '')}"
            if not any(v['line'] == vulnerability_details['line'] and
                       v.get('message') == vulnerability_details.get('message')
                       for v in vulnerabilities):
                vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_log_operation(capture, query_info):
    """
    检查是否是日志操作
    """
    risk_type = query_info.get('risk_type', '')

    if risk_type == 'log_call_main':
        logger_obj = capture.get('logger_obj', '')
        log_level = capture.get('log_level', '')
        logger_pattern = query_info.get('logger_pattern', '')
        level_pattern = query_info.get('level_pattern', '')

        return (re.match(logger_pattern, logger_obj, re.IGNORECASE) and
                re.match(level_pattern, log_level, re.IGNORECASE))

    elif risk_type == 'print_statement':
        func_name = capture.get('func_name', '')
        func_pattern = query_info.get('func_pattern', '')
        return bool(re.match(func_pattern, func_name, re.IGNORECASE))

    elif risk_type == 'file_write':
        open_func = capture.get('open_func', '')
        write_method = capture.get('write_method', '')
        open_pattern = query_info.get('open_pattern', '')
        write_pattern = query_info.get('write_pattern', '')

        return (re.match(open_pattern, open_func, re.IGNORECASE) and
                re.match(write_pattern, write_method, re.IGNORECASE))

    elif risk_type == 'syslog_call':
        syslog_func = capture.get('syslog_func', '')
        func_pattern = query_info.get('func_pattern', '')
        return bool(re.match(func_pattern, syslog_func, re.IGNORECASE))

    return False


def analyze_log_forgery_vulnerability(operation, code):
    """
    分析日志伪造漏洞
    """
    risk_type = operation['risk_type']

    # 根据风险类型进行分析
    if risk_type in ['log_call_main', 'syslog_call']:
        return analyze_logging_vulnerability(operation, code)
    elif risk_type == 'print_statement':
        return analyze_print_vulnerability(operation, code)
    elif risk_type == 'file_write':
        return analyze_file_write_vulnerability(operation, code)

    return None


def analyze_logging_vulnerability(operation, code):
    """
    分析日志记录漏洞
    """
    log_message = operation.get('log_message', '')

    # 检查是否可能包含用户输入
    if may_contain_user_input(log_message):
        # 检查是否包含日志伪造模式
        if contains_log_forgery_patterns(log_message):
            vulnerability_details = {
                'line': operation['line'],
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': '日志伪造',
                'severity': '高危',
                'risk_type': operation['risk_type'],
                'message': "日志消息可能包含用户输入 - 容易遭受日志伪造攻击"
            }

            # 检查是否记录敏感信息
            if contains_sensitive_info(log_message):
                vulnerability_details['message'] += " (可能包含敏感信息)"
                vulnerability_details['severity'] = '严重'

            # 检查是否缺少验证
            if not has_log_sanitization(operation, code):
                vulnerability_details['message'] += " (缺少输入清理)"

            return vulnerability_details
        else:
            # 包含用户输入但未发现伪造模式，报告为警告
            vulnerability_details = {
                'line': operation['line'],
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': '日志伪造',
                'severity': '中危',
                'risk_type': operation['risk_type'],
                'message': "日志消息包含用户输入 - 需要输入验证和清理"
            }
            return vulnerability_details

    return None


def analyze_print_vulnerability(operation, code):
    """
    分析print语句漏洞
    """
    print_arg = operation.get('print_arg', '')

    # 检查是否可能包含用户输入
    if may_contain_user_input(print_arg):
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': '日志伪造',
            'severity': '低危',
            'risk_type': operation['risk_type'],
            'message': "print语句包含用户输入 - 可能遭受日志伪造攻击"
        }

        # 检查是否记录敏感信息
        if contains_sensitive_info(print_arg):
            vulnerability_details['message'] += " (可能包含敏感信息)"
            vulnerability_details['severity'] = '中危'

        return vulnerability_details

    return None


def analyze_file_write_vulnerability(operation, code):
    """
    分析文件写入漏洞
    """
    write_content = operation.get('write_content', '')

    # 检查是否可能包含用户输入
    if may_contain_user_input(write_content):
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': '日志伪造',
            'severity': '中危',
            'risk_type': operation['risk_type'],
            'message': "文件写入操作包含用户输入 - 可能遭受日志伪造攻击"
        }

        # 检查是否包含日志伪造模式
        if contains_log_forgery_patterns(write_content):
            vulnerability_details['severity'] = '高危'
            vulnerability_details['message'] += " (可能伪造日志条目)"

        return vulnerability_details

    return None


def may_contain_user_input(text):
    """
    检查文本是否可能包含用户输入
    """
    if not text:
        return False

    clean_text = text.strip('"\'')

    # 用户输入相关关键词
    user_input_keywords = [
        'request', 'args', 'form', 'input', 'user_input',
        'data', 'content', 'query', 'param', 'value',
        'get', 'post', 'cookies', 'headers', 'json'
    ]

    # 检查是否包含用户输入关键词
    for keyword in user_input_keywords:
        if re.search(rf'\b{keyword}\b', clean_text, re.IGNORECASE):
            return True

    # 检查是否包含变量（非字面量）
    if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*', clean_text) and not re.match(r'^[\'\"][^\'\"]*[\'\"]$', clean_text):
        return True

    return False


def contains_log_forgery_patterns(text):
    """
    检查文本是否包含日志伪造模式
    """
    if not text:
        return False

    clean_text = text.strip('"\'')

    # 检查日志注入指示器
    for pattern in LOG_FORGERY_PATTERNS['log_injection_indicators']:
        if re.search(pattern, clean_text, re.IGNORECASE):
            return True

    # 检查日志逃避模式
    for pattern in LOG_FORGERY_PATTERNS['log_evasion_patterns']:
        if re.search(pattern, clean_text, re.IGNORECASE):
            return True

    return False


def contains_sensitive_info(text):
    """
    检查文本是否包含敏感信息
    """
    if not text:
        return False

    clean_text = text.strip('"\'')

    # 检查敏感信息模式
    for pattern in LOG_FORGERY_PATTERNS['sensitive_log_patterns']:
        if re.search(pattern, clean_text, re.IGNORECASE):
            return True

    return False


def has_log_sanitization(operation, code):
    """
    检查是否有日志清理
    """
    line = operation['line']

    # 在附近代码中查找清理函数
    sanitization_functions = [
        're.escape', 'html.escape', 'cgi.escape', 'str.encode',
        'base64.encode', 'json.dumps', 'urllib.parse.quote',
        'sanitize', 'clean', 'validate', 'strip', 'replace'
    ]

    lines = code.split('\n')
    start_line = max(0, line - 5)
    end_line = min(len(lines), line + 5)

    for i in range(start_line, end_line):
        line_content = lines[i].lower()
        for func in sanitization_functions:
            if func in line_content:
                return True

    return False


def analyze_python_log_forgery(code_string):
    """
    分析Python代码字符串中的日志伪造漏洞
    """
    return detect_log_forgery(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = '''
import logging
import syslog
from flask import request, session
import json

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 易受日志伪造攻击的示例
@app.route('/vulnerable_logging')
def vulnerable_logging():
    # 1. 直接记录用户输入 - 高危
    username = request.args.get('username', 'anonymous')
    logger.info(f"User login: {username}")  # 可能伪造日志

    # 2. 格式化字符串日志 - 高危
    user_agent = request.headers.get('User-Agent', '')
    logger.info("User agent: %s", user_agent)  # 格式化注入

    # 3. 记录敏感信息 - 严重
    password = request.args.get('password', '')
    logger.debug(f"Password attempt: {password}")  # 记录密码！

    # 4. 换行符注入攻击
    search_term = request.args.get('search', '')
    logger.info(f"Search query: {search_term}")  # 可能注入换行符

    # 5. 系统日志调用
    syslog.syslog(f"API call from {request.remote_addr}")

    return "Logged"

# 具体的日志伪造攻击示例
@app.route('/log_forgery_attack')
def log_forgery_attack():
    # 攻击者可以伪造日志条目
    malicious_input = "admin\\n[INFO] User admin logged in successfully"
    logger.info(f"User action: {malicious_input}")
    # 日志输出:
    # [INFO] User action: admin
    # [INFO] User admin logged in successfully

    # 逃避检测的攻击
    escape_input = "malicious\\x1b[2A\\x1b[KNormal log entry"
    logger.error(f"Error: {escape_input}")  # 可能覆盖之前的日志

    # 敏感信息泄露
    token = request.cookies.get('session_token')
    logger.debug(f"Session token: {token}")  # 记录会话令牌！

    return "Attack demonstrated"

# 文件日志伪造示例
def write_to_log_file():
    # 直接写入日志文件
    user_input = request.args.get('log_entry', '')

    with open('app.log', 'a') as f:
        f.write(f"{user_input}\\n")  # 可能伪造整个日志文件

    # 使用print记录（可能重定向到文件）
    print(f"Debug: {request.json}")  # 可能包含敏感数据

# 相对安全的日志记录示例
@app.route('/secure_logging')
def secure_logging():
    # 1. 清理用户输入
    username = request.args.get('username', 'anonymous')
    safe_username = re.sub(r'[\\r\\n]', '', username)  # 移除换行符
    safe_username = safe_username[:50]  # 限制长度
    logger.info("User login: %s", safe_username)

    # 2. 使用结构化日志
    log_data = {
        'event': 'user_login',
        'username': safe_username,
        'ip': request.remote_addr,
        'timestamp': '2024-01-01T00:00:00Z'
    }
    logger.info("Security event: %s", json.dumps(log_data))

    # 3. 避免记录敏感信息
    # 不记录密码、令牌等敏感数据

    # 4. 使用审计专用日志
    audit_logger = logging.getLogger('audit')
    audit_logger.info("User %s accessed resource %s", 
                     safe_username, request.path)

    return "Secure logging"

# 安全的日志工具函数
def safe_log_user_action(username, action, ip_address):
    """安全记录用户操作"""
    # 验证输入
    if not username or not action:
        return

    # 清理输入
    safe_username = re.sub(r'[\\r\\n\\t]', '', username)
    safe_action = re.sub(r'[\\r\\n\\t]', '', action)
    safe_ip = re.sub(r'[^0-9.:]', '', ip_address)

    # 限制长度
    safe_username = safe_username[:100]
    safe_action = safe_action[:200]

    # 记录结构化日志
    audit_logger = logging.getLogger('audit')
    audit_logger.info(
        "User action - User: %s, Action: %s, IP: %s",
        safe_username, safe_action, safe_ip
    )

def sanitize_log_message(message):
    """清理日志消息"""
    if not message:
        return ""

    # 移除控制字符
    sanitized = re.sub(r'[\\x00-\\x1f\\x7f-\\x9f]', '', message)

    # 移除换行符和制表符
    sanitized = re.sub(r'[\\r\\n\\t]', ' ', sanitized)

    # 限制长度
    sanitized = sanitized[:1000]

    return sanitized

# 生产环境最佳实践
class SecureLogger:
    def __init__(self, name):
        self.logger = logging.getLogger(name)

    def log_user_action(self, username, action, **kwargs):
        """安全记录用户操作"""
        # 清理所有输入
        safe_username = self.sanitize_input(username)
        safe_action = self.sanitize_input(action)

        # 构建安全日志数据
        log_data = {
            'username': safe_username,
            'action': safe_action,
            'timestamp': kwargs.get('timestamp'),
            'ip': self.sanitize_input(kwargs.get('ip', '')),
            'user_agent': self.sanitize_input(kwargs.get('user_agent', ''))
        }

        # 移除空值
        log_data = {k: v for k, v in log_data.items() if v}

        self.logger.info("User action: %s", json.dumps(log_data))

    def sanitize_input(self, text):
        """清理输入文本"""
        if not text:
            return ""

        # 移除控制字符和换行符
        sanitized = re.sub(r'[\\x00-\\x1f\\x7f-\\x9f\\r\\n]', '', str(text))

        # 限制长度
        return sanitized[:500]

# 使用安全日志器
secure_logger = SecureLogger('security')

@app.route('/best_practice')
def best_practice():
    username = request.args.get('username', 'anonymous')
    secure_logger.log_user_action(
        username=username,
        action='page_access',
        ip=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    return "Best practice logging"

if __name__ == '__main__':
    app.run(debug=True)
'''

    print("=" * 70)
    print("Python 日志伪造漏洞检测（修复重复检测问题）")
    print("=" * 70)

    results = analyze_python_log_forgery(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个日志伪造漏洞:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   风险类型: {vuln['risk_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print("-" * 50)
    else:
        print("未检测到日志伪造漏洞")