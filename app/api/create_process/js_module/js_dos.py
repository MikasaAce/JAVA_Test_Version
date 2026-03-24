import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JavaScript的DoS漏洞模式
DOS_VULNERABILITIES = {
    'javascript': [
        # 1. 无限循环检测
        {
            'query': '''
                (while_statement
                    condition: (true) @condition
                ) @while_loop
            ''',
            'message': '检测到无限while循环: while(true)',
            'severity': '高危'
        },
        {
            'query': '''
                (for_statement
                    condition: (_) @condition
                ) @for_loop
            ''',
            'condition_check': lambda node: is_infinite_for_loop(node),
            'message': '检测到可能无限for循环',
            'severity': '中危'
        },

        # 2. 递归调用无终止条件
        {
            'query': '''
                (function_declaration
                    name: (identifier) @func_name
                    body: (statement_block) @body
                ) @function
            ''',
            'recursion_check': True,
            'message': '检测到可能无限递归函数',
            'severity': '高危'
        },

        # 3. 同步阻塞操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                ) @sync_call
            ''',
            'pattern': r'^(sync|readFileSync|writeFileSync|execSync|spawnSync|readdirSync|existsSync)$',
            'message': '检测到同步阻塞操作，可能导致事件循环阻塞',
            'severity': '中危'
        },

        # 4. 大JSON解析
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments) @args
                ) @json_parse
            ''',
            'pattern': r'^(JSON\.parse|JSON\.stringify)$',
            'size_check': True,
            'message': '检测到JSON解析/序列化操作，可能处理大数据导致内存耗尽',
            'severity': '中危'
        },

        # 5. 正则表达式DoS (ReDoS)
        {
            'query': '''
                (regex_pattern) @regex_pattern
            ''',
            'redos_check': True,
            'message': '检测到可能易受ReDoS攻击的正则表达式',
            'severity': '高危'
        },

        # 6. 数组/字符串操作无限制
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (_) @obj
                        property: (property_identifier) @method
                    )
                    arguments: (arguments) @args
                ) @array_op
            ''',
            'pattern': r'^(join|concat|slice|splice|push|pop|shift|unshift)$',
            'unbounded_check': True,
            'message': '检测到可能无限制的数组操作',
            'severity': '中危'
        },

        # 7. 定时器滥用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments) @args
                ) @timer_call
            ''',
            'pattern': r'^(setInterval|setTimeout)$',
            'interval_check': True,
            'message': '检测到可能滥用定时器',
            'severity': '低危'
        }
    ]
}


def detect_js_dos_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中的拒绝服务漏洞

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
    for vuln_info in DOS_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(vuln_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['while_loop', 'for_loop', 'function', 'sync_call',
                           'json_parse', 'regex_pattern', 'array_op', 'timer_call']:
                    # 主捕获节点
                    current_capture = {
                        'node': node,
                        'line': node.start_point[0] + 1,
                        'code_snippet': node.text.decode('utf8'),
                        'tags': {}
                    }

                elif tag in ['condition', 'func_name', 'obj', 'method', 'args']:
                    current_capture['tags'][tag] = node.text.decode('utf8')

                # 执行特定检查
                if current_capture and all_conditions_met(current_capture, vuln_info):
                    vulnerabilities.append({
                        'line': current_capture['line'],
                        'message': vuln_info['message'],
                        'code_snippet': current_capture['code_snippet'],
                        'vulnerability_type': '拒绝服务漏洞',
                        'severity': vuln_info['severity']
                    })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {vuln_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def all_conditions_met(capture, vuln_info):
    """检查是否满足所有漏洞条件"""
    # 模式匹配检查
    if 'pattern' in vuln_info:
        pattern = vuln_info['pattern']
        if 'func_name' in capture['tags']:
            if not re.search(pattern, capture['tags']['func_name'], re.IGNORECASE):
                return False

    # 无限循环检查
    if vuln_info.get('condition_check'):
        if not vuln_info['condition_check'](capture['node']):
            return False

    # 递归检查
    if vuln_info.get('recursion_check'):
        if not has_recursion_without_base_case(capture['node']):
            return False

    # ReDoS检查
    if vuln_info.get('redos_check'):
        if not is_redos_vulnerable(capture['node']):
            return False

    # 大小检查
    if vuln_info.get('size_check'):
        if not has_large_data_risk(capture['node']):
            return False

    # 无限制检查
    if vuln_info.get('unbounded_check'):
        if not has_unbounded_operation(capture['node']):
            return False

    # 间隔检查
    if vuln_info.get('interval_check'):
        if not has_short_interval(capture['node']):
            return False

    return True


def is_infinite_for_loop(node):
    """检查for循环是否为无限循环"""
    # 简化检查：寻找没有条件或条件为true的for循环
    for child in node.children:
        if child.type == 'condition' and child.text.decode('utf8').strip() in ['', 'true', '1']:
            return True
    return False


def has_recursion_without_base_case(node):
    """检查函数是否可能无限递归"""
    # 简化实现：检查函数体内是否有自身调用但没有明显的终止条件
    func_body = None
    for child in node.children:
        if child.type == 'statement_block':
            func_body = child.text.decode('utf8')
            break

    if func_body:
        # 查找函数名
        func_name_node = None
        for child in node.children:
            if child.type == 'identifier':
                func_name_node = child
                break

        if func_name_node:
            func_name = func_name_node.text.decode('utf8')
            # 检查是否调用自身
            if re.search(rf'\b{func_name}\s*\(', func_body):
                # 简单检查是否有条件语句
                if not re.search(r'\b(if|else|return|throw)\b', func_body):
                    return True

    return False


def is_redos_vulnerable(node):
    """检查正则表达式是否易受ReDoS攻击"""
    regex_pattern = node.text.decode('utf8')

    # 检查常见的ReDoS模式
    redos_patterns = [
        r'\(.*\+.*\)',  # 重复分组
        r'\(.*\|.*\)*',  # 多选分支
        r'\^.*\$',  # 开头结尾锚点
        r'\.\*',  # 任意字符重复
    ]

    for pattern in redos_patterns:
        if re.search(pattern, regex_pattern):
            return True

    return False


def has_large_data_risk(node):
    """检查是否有处理大数据的风险"""
    # 检查JSON.parse/stringify的参数
    args_text = ''
    for child in node.children:
        if child.type == 'arguments':
            args_text = child.text.decode('utf8')
            break

    # 如果有变量参数，可能存在风险
    if re.search(r'[a-zA-Z_$][\w$]*', args_text):
        return True

    return False


def has_unbounded_operation(node):
    """检查是否有无限制的操作"""
    # 检查数组/字符串操作是否有大小限制
    args_text = ''
    for child in node.children:
        if child.type == 'arguments':
            args_text = child.text.decode('utf8')
            break

    # 如果没有明确的限制参数，可能存在风险
    if not re.search(r'\d+', args_text):  # 没有数字参数
        return True

    return False


def has_short_interval(node):
    """检查定时器间隔是否过短"""
    args_text = ''
    for child in node.children:
        if child.type == 'arguments':
            args_text = child.text.decode('utf8')
            break

    # 检查间隔参数
    interval_match = re.search(r'(\d+)', args_text)
    if interval_match:
        interval = int(interval_match.group(1))
        if interval < 10:  # 间隔小于10ms
            return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的DoS漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_dos_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// 无限循环示例
while(true) {
    console.log("Infinite loop");
}

// 可能无限for循环
for(;;) {
    processData();
}

// 无限递归函数
function recursiveFunc(n) {
    return recursiveFunc(n + 1); // 无终止条件
}

// 同步阻塞操作
const fs = require('fs');
const data = fs.readFileSync('/path/to/large/file.txt');

// 大JSON处理
const bigData = JSON.parse(largeJsonString);

// 可能ReDoS的正则表达式
const regex = /^(a+)+$/;

// 无限制数组操作
const largeArray = [];
for(let i = 0; i < 1000000; i++) {
    largeArray.push(i);
}
const result = largeArray.join('');

// 短间隔定时器
setInterval(() => {
    heavyOperation();
}, 1); // 1ms间隔

// 正常代码示例
function safeFunction(n) {
    if (n <= 0) return 1; // 有终止条件
    return safeFunction(n - 1);
}

const safeRegex = /^[a-z]+$/;
"""

    print("=" * 60)
    print("JavaScript 拒绝服务漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
    else:
        print("未检测到拒绝服务漏洞")