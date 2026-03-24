import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JavaScript命令注入漏洞模式
COMMAND_INJECTION_VULNERABILITIES = {
    'javascript': [
        # 检测child_process模块的危险函数调用
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @module
                        property: (property_identifier) @method
                    )
                    arguments: (arguments (string) @command)
                ) @call
            ''',
            'module_pattern': r'^(child_process|exec|spawn|execSync|spawnSync)$',
            'method_pattern': r'^(exec|spawn|execFile|execSync|spawnSync|execFileSync)$',
            'message': '子进程执行函数调用发现'
        },
        # 检测eval函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (_) @code)
                ) @call
            ''',
            'func_pattern': r'^(eval|setTimeout|setInterval|Function)$',
            'message': '动态代码执行函数调用发现'
        },
        # 检测用户输入直接传递给危险函数
        {
            'query': '''
                (call_expression
                    function: (_) @func
                    arguments: (arguments (_) @arg)
                ) @call
            ''',
            'func_pattern': r'^(exec|spawn|eval|setTimeout|setInterval|Function)$',
            'arg_check': True,  # 需要额外检查参数是否包含用户输入
            'message': '潜在的命令注入点'
        },
        # 检测模板字符串中的危险函数调用
        {
            'query': '''
                (call_expression
                    function: (_) @func
                    arguments: (arguments (template_string) @template)
                ) @call
            ''',
            'func_pattern': r'^(exec|spawn|eval|setTimeout|setInterval|Function)$',
            'message': '模板字符串中的命令执行'
        },
        # 检测通过require引入的危险模块
        {
            'query': '''
                (call_expression
                    function: (identifier) @require
                    arguments: (arguments (string) @module_name)
                ) @call
            ''',
            'require_pattern': r'^require$',
            'module_pattern': r'^(child_process|exec|spawn)$',
            'message': '危险模块引入'
        }
    ]
}

# 用户输入源模式
USER_INPUT_SOURCES = {
    'query': '''
        (call_expression
            function: (member_expression
                object: (_) @object
                property: (property_identifier) @property
            )
            arguments: (arguments) @args
        ) @call
        '''
    ,
    'patterns': [
        {
            'object_pattern': r'^(req|request|ctx|context|params|query|body|headers|cookies)$',
            'property_pattern': r'^(query|params|body|param|header|cookie|get)$',
            'message': 'HTTP请求参数'
        },
        {
            'object_pattern': r'^(document|window|location|navigator|history)$',
            'property_pattern': r'^(cookie|referrer|location|href|search|hash|URL|url)$',
            'message': '浏览器环境输入'
        },
        {
            'object_pattern': r'^(process|env)$',
            'property_pattern': r'^(env|argv|ARGV)$',
            'message': '进程环境变量'
        },
        {
            'object_pattern': r'^(fs|fileSystem)$',
            'property_pattern': r'^(readFile|readFileSync|readdir|readdirSync)$',
            'message': '文件系统读取'
        }
    ]
}


def detect_js_command_injection(code, language='javascript'):
    """
    检测JavaScript代码中命令注入漏洞

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
    dangerous_calls = []  # 存储所有危险函数调用
    user_input_sources = []  # 存储用户输入源

    # 第一步：收集所有危险函数调用
    for query_info in COMMAND_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['module', 'func_name', 'func']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('module_pattern') or query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'method':
                    method_name = node.text.decode('utf8')
                    method_pattern = query_info.get('method_pattern', '')
                    if (not method_pattern or
                            re.match(method_pattern, method_name, re.IGNORECASE)):
                        current_capture['method'] = method_name

                elif tag in ['command', 'code', 'arg', 'template', 'module_name']:
                    current_capture['arg'] = node.text.decode('utf8')
                    current_capture['arg_node'] = node

                elif tag in ['call'] and current_capture:
                    # 完成一个完整的捕获
                    if 'func' in current_capture:
                        # 获取完整的代码片段
                        code_snippet = node.text.decode('utf8')

                        dangerous_calls.append({
                            'type': 'dangerous_call',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'method': current_capture.get('method', ''),
                            'argument': current_capture.get('arg', ''),
                            'arg_node': current_capture.get('arg_node'),
                            'code_snippet': code_snippet,
                            'node': node,
                            'needs_input_check': query_info.get('arg_check', False)
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有用户输入源
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag == 'object':
                obj_name = node.text.decode('utf8')
                current_capture['object'] = obj_name
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'property':
                prop_name = node.text.decode('utf8')
                current_capture['property'] = prop_name

            elif tag == 'call' and current_capture:
                # 检查是否匹配任何用户输入模式
                for pattern_info in USER_INPUT_SOURCES['patterns']:
                    obj_pattern = pattern_info.get('object_pattern', '')
                    prop_pattern = pattern_info.get('property_pattern', '')

                    if (re.match(obj_pattern, current_capture.get('object', ''), re.IGNORECASE) and
                            re.match(prop_pattern, current_capture.get('property', ''), re.IGNORECASE)):
                        code_snippet = node.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': current_capture['line'],
                            'object': current_capture.get('object', ''),
                            'property': current_capture.get('property', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：分析漏洞
    for call in dangerous_calls:
        is_vulnerable = False
        vulnerability_details = {
            'line': call['line'],
            'code_snippet': call['code_snippet'],
            'vul_type': '命令注入',
            'severity': '高危'
        }

        # 情况1: 直接使用字符串字面量（可能是硬编码命令）
        if call['argument'] and is_direct_command(call['argument']):
            vulnerability_details['message'] = f"直接命令执行: {call['function']} 调用包含可能危险的命令"
            is_vulnerable = True

        # 情况2: 需要检查参数是否包含用户输入
        elif call['needs_input_check'] and call['arg_node']:
            # 检查参数是否来自用户输入
            if is_user_input_related(call['arg_node'], user_input_sources, root):
                vulnerability_details['message'] = f"用户输入直接传递给危险函数: {call['function']}"
                is_vulnerable = True

        # 情况3: 模板字符串可能包含用户输入
        elif call['argument'] and '${' in call['argument']:
            vulnerability_details['message'] = f"模板字符串中的命令执行: {call['function']} 可能包含动态内容"
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_direct_command(argument):
    """
    检查参数是否看起来像直接命令

    Args:
        argument: 参数字符串

    Returns:
        bool: 是否像直接命令
    """
    # 检查常见的命令模式
    command_patterns = [
        r'^\s*(rm\s+-|del\s+|ls\s*$|dir\s*$|cat\s+|echo\s+|ping\s+|curl\s+|wget\s+)',
        r'^\s*(\w+\.(exe|sh|bat|cmd|ps1)\b)',
        r'[;&|`]\s*\w',  # 命令分隔符后跟命令
        r'\$\{?\(.*\)',  # 命令替换语法
    ]

    for pattern in command_patterns:
        if re.search(pattern, argument, re.IGNORECASE):
            return True

    return False


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关

    Args:
        arg_node: 参数AST节点
        user_input_sources: 用户输入源列表
        root_node: 根AST节点

    Returns:
        bool: 是否与用户输入相关
    """
    # 获取参数节点的文本
    arg_text = arg_node.text.decode('utf8')

    # 简单检查：参数是否包含常见的用户输入变量名
    user_input_vars = ['req', 'request', 'query', 'param', 'body', 'input', 'data', 'form']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 复杂检查：通过数据流分析确定是否来自用户输入
    # 这里简化实现，实际应用中可能需要更复杂的数据流分析

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的命令注入漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_command_injection(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
const { exec, spawn } = require('child_process');
const http = require('http');

// 直接命令执行 - 高危
exec('ls -la', (error, stdout, stderr) => {
    if (error) {
        console.error(`执行错误: ${error}`);
        return;
    }
    console.log(`stdout: ${stdout}`);
    console.log(`stderr: ${stderr}`);
});

// 用户输入直接传递给命令 - 高危
http.createServer((req, res) => {
    const userInput = req.query.command;
    exec(userInput); // 命令注入漏洞

    // 另一种形式
    const fileName = req.body.filename;
    exec(`cat ${fileName}`); // 路径遍历/命令注入

    res.end('Done');
}).listen(3000);

// 模板字符串中的命令执行 - 中危
function runCommand(commandPrefix) {
    const fullCommand = `${commandPrefix} --all`;
    exec(fullCommand); // 潜在命令注入
}

// 动态代码执行 - 高危
const userCode = req.body.code;
eval(userCode); // 代码注入

// setTimeout/setInterval 潜在滥用
const userTime = req.query.time;
setTimeout(`console.log(${userTime})`, 1000);

// 通过spawn执行命令
const args = ['install', '--save', req.query.package];
spawn('npm', args); // 潜在命令注入

// 相对安全的做法 - 使用参数化
const safeArgs = ['install', '--save', 'some-package'];
spawn('npm', safeArgs); // 相对安全

// 使用execFile相对更安全
const { execFile } = require('child_process');
execFile('ls', ['-la'], (error, stdout, stderr) => {
    // 处理结果
});

// 危险模块引入
const cp = require('child_process');
cp.exec(req.body.cmd); // 命令注入
"""

    print("=" * 60)
    print("JavaScript命令注入漏洞检测")
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
        print("未检测到命令注入漏洞")