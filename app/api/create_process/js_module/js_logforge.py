import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JavaScript的日志伪造漏洞模式
LOG_FORGERY_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (string) @log_message)
                ) @call
            ''',
            'pattern': r'^(console\.log|console\.info|console\.warn|console\.error|log|logger|winston|info|warn|error|debug|trace)$',
            'message': '直接字符串日志调用'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (string) @log_message)
                ) @call
            ''',
            'pattern': r'^(console|logger|log|winston|bunyan)$',
            'property_pattern': r'^(log|info|warn|error|debug|trace)$',
            'message': '成员函数字符串日志调用'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (template_string) @log_message)
                ) @call
            ''',
            'pattern': r'^(console\.log|console\.info|console\.warn|console\.error|log|logger|winston|info|warn|error|debug|trace)$',
            'message': '模板字符串日志调用'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (template_string) @log_message)
                ) @call
            ''',
            'pattern': r'^(console|logger|log|winston|bunyan)$',
            'property_pattern': r'^(log|info|warn|error|debug|trace)$',
            'message': '成员函数模板字符串日志调用'
        },
        {
            'query': '''
                (call_expression
                    function: (_) @func
                    arguments: (arguments (_) @first_arg (_)*)
                ) @call
            ''',
            'condition': 'contains_user_input',
            'message': '可能包含用户输入的日志调用'
        }
    ]
}

# 用户输入源模式
USER_INPUT_SOURCES = {
    'query': '''
        (call_expression
            function: (member_expression
                object: (identifier) @object
                property: (property_identifier) @property
            )
            arguments: (arguments) @args
        ) @call
        (#match? @object "^(req|request|query|params|body|headers|cookies|window|document|location|navigator)$")
        (#match? @property "^(query|param|params|body|headers|cookies|get|post|value|search|hash|href)$")
    ''',
    'message': '用户输入源'
}


def detect_js_log_forgery_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中日志伪造漏洞

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
    log_calls = []  # 存储所有日志调用
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集所有用户输入源
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'call':
                source_code = node.text.decode('utf8')
                user_input_sources.append({
                    'line': node.start_point[0] + 1,
                    'code_snippet': source_code,
                    'node': node
                })
    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第二步：收集所有日志调用
    for query_info in LOG_FORGERY_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, func_name, re.IGNORECASE):
                        current_capture['function'] = func_name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'object':
                    obj_name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if pattern and re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern', '')
                    if prop_pattern and re.match(prop_pattern, prop_name, re.IGNORECASE):
                        current_capture['property'] = prop_name

                elif tag in ['log_message', 'first_arg']:
                    log_content = node.text.decode('utf8')
                    current_capture['log_content'] = log_content
                    current_capture['content_node'] = node

                elif tag in ['call', 'func'] and current_capture:
                    # 完成一个完整的捕获
                    if ('function' in current_capture or
                            ('object' in current_capture and 'property' in current_capture)):

                        # 获取完整的代码片段
                        code_snippet = node.text.decode('utf8')

                        log_call = {
                            'type': 'log_call',
                            'line': current_capture['line'],
                            'code_snippet': code_snippet,
                            'node': node,
                            'log_content': current_capture.get('log_content', ''),
                            'content_node': current_capture.get('content_node')
                        }

                        # 检查是否包含用户输入
                        if query_info.get('condition') == 'contains_user_input':
                            if contains_user_input(node, user_input_sources, code):
                                log_call['contains_user_input'] = True

                        log_calls.append(log_call)
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第三步：分析日志伪造漏洞
    for log_call in log_calls:
        line = log_call['line']
        code_snippet = log_call['code_snippet']
        log_content = log_call['log_content']

        # 检查是否包含潜在的危险内容
        is_vulnerable = False
        vulnerability_reason = ""

        # 1. 检查是否直接包含用户输入
        if log_call.get('contains_user_input', False):
            is_vulnerable = True
            vulnerability_reason = "日志调用包含用户输入"

        # 2. 检查日志内容是否包含换行符
        elif log_content and contains_newline_chars(log_content):
            is_vulnerable = True
            vulnerability_reason = "日志内容包含换行符"

        # 3. 检查是否使用模板字符串且可能包含用户输入
        elif log_content.startswith('`') and log_content.endswith('`'):
            if contains_potential_user_input(log_content, user_input_sources):
                is_vulnerable = True
                vulnerability_reason = "模板字符串可能包含用户输入"

        # 4. 检查是否使用字符串拼接且可能包含用户输入
        elif '+' in code_snippet and not is_safe_string_concatenation(code_snippet):
            is_vulnerable = True
            vulnerability_reason = "不安全的字符串拼接"

        if is_vulnerable:
            vulnerabilities.append({
                'line': line,
                'message': f'日志伪造漏洞: {vulnerability_reason}',
                'code_snippet': code_snippet[:200] + ('...' if len(code_snippet) > 200 else ''),
                'vulnerability_type': '日志伪造',
                'severity': '中危',
                'recommendation': '应对用户输入进行清理，移除或转义换行符等特殊字符'
            })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_newline_chars(text):
    """检查文本是否包含换行符"""
    return '\n' in text or '\r' in text


def contains_user_input(log_node, user_input_sources, code):
    """检查日志调用是否包含用户输入"""
    log_start = log_node.start_byte
    log_end = log_node.end_byte

    for source in user_input_sources:
        source_start = source['node'].start_byte
        source_end = source['node'].end_byte

        # 检查用户输入源是否在日志调用范围内
        if source_start >= log_start and source_end <= log_end:
            return True

    return False


def contains_potential_user_input(template_string, user_input_sources):
    """检查模板字符串是否可能包含用户输入"""
    # 简单的启发式检查：包含${}插值表达式
    return re.search(r'\$\{[^}]+\}', template_string) is not None


def is_safe_string_concatenation(code_snippet):
    """检查字符串拼接是否安全"""
    # 如果只包含字面量字符串拼接，认为是安全的
    if re.search(r'[\'\"][+\s]*[\'\"]', code_snippet):
        return True

    # 如果包含变量但经过清理函数处理，认为是相对安全的
    safe_functions = ['encodeURIComponent', 'escape', 'replace', 'sanitize', 'escapeHtml']
    for func in safe_functions:
        if func in code_snippet:
            return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的日志伪造漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_log_forgery_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 存在日志伪造漏洞的代码示例
const userInput = req.query.input;
const userData = req.body.data;

// 1. 直接记录用户输入 - 高危
console.log("User input: " + userInput);
console.log(`User data: ${userData}`);

// 2. 包含换行符的用户输入 - 可伪造日志
const maliciousInput = "正常日志\\nERROR: 系统崩溃\\nWARN: 数据库连接失败";
console.log(maliciousInput);

// 3. 使用模板字符串记录用户输入
logger.info(`用户提交了数据: ${userData}`);

// 4. 复杂的字符串拼接
const logMessage = "操作记录: " + userInput + " 时间: " + new Date();
winston.info(logMessage);

// 5. 多层嵌套的用户输入
const processedData = processUserInput(req.body.content);
console.log("处理后的数据: " + processedData);

// 安全的日志记录示例
// 6. 对用户输入进行清理
const safeInput = userInput.replace(/[\\r\\n]/g, '');
console.log("安全输入: " + safeInput);

// 7. 只记录字面量字符串
console.log("用户操作完成");

// 8. 使用编码函数
console.log("用户输入: " + encodeURIComponent(userInput));

// 9. 限制日志长度
const limitedInput = userInput.substring(0, 100);
console.log(limitedInput);

// 10. 使用安全的模板字符串（无用户输入）
const timestamp = new Date().toISOString();
console.log(`操作完成于: ${timestamp}`);

// 11. 使用查询参数但不记录敏感内容
const page = req.query.page || 1;
console.log(`访问第 ${page} 页`); // 相对安全

// 12. 潜在危险的边缘情况
const config = { logLevel: 'debug' };
if (config.logLevel === 'debug') {
    console.log("调试信息: " + userInput); // 只在调试时危险
}

// 13. 使用第三方日志库但不处理输入
const log = require('some-logger');
log.info(userData);

// 14. 间接的用户输入
const userAgent = req.headers['user-agent'];
console.log("User agent: " + userAgent); // 可能包含恶意内容

// 15. 文件内容记录
const fileContent = readFileSync('userfile.txt');
console.log(fileContent); // 如果文件被篡改可能包含恶意内容
"""

    print("=" * 70)
    print("JavaScript 日志伪造漏洞检测")
    print("=" * 70)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   建议: {vuln['recommendation']}")
    else:
        print("未检测到日志伪造漏洞")