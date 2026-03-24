import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义表达式语言注入漏洞模式
EXPRESSION_INJECTION_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (string) @template_string)
                ) @call
            ''',
            'object_pattern': r'^(el|expression|spel|template|engine|context)$',
            'property_pattern': r'^(evaluate|parse|process|execute|render|compile|interpret)$',
            'message': '表达式语言执行调用发现'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (string) @template_string)
                ) @call
            ''',
            'pattern': r'^(evaluate|parseExpression|execute|render|compile|interpret|processTemplate)$',
            'message': '表达式语言相关函数调用'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (call_expression
                            function: (identifier) @constructor_name
                        )
                        property: (property_identifier) @method_name
                    )
                    arguments: (arguments (string) @template_string)
                ) @call
            ''',
            'constructor_pattern': r'^(SpelExpressionParser|TemplateEngine|ExpressionFactory|ScriptEngineManager)$',
            'method_pattern': r'^(parseExpression|createExpression|evaluate|process|render|getEngineByName)$',
            'message': '表达式语言解析器调用'
        },
        {
            'query': '''
                (new_expression
                    constructor: (identifier) @constructor_name
                    arguments: (arguments (string) @template_string)
                ) @new
            ''',
            'pattern': r'^(SpelExpressionParser|Template|Expression|ScriptEngine)$',
            'message': '表达式语言构造函数调用'
        },
        {
            'query': '''
                (assignment_expression
                    left: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    right: (string) @template_string
                ) @assignment
            ''',
            'object_pattern': r'^(el|expression|spel|template|value)$',
            'property_pattern': r'^(expression|value|template|content)$',
            'message': '表达式语言赋值操作'
        }
    ]
}


def detect_expression_injection_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中表达式语言注入漏洞

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

    # 检测所有可能的表达式语言注入点
    for query_info in EXPRESSION_INJECTION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['object', 'func_name', 'constructor_name', 'method_name']:
                    name = node.text.decode('utf8')
                    pattern = query_info.get('pattern') or query_info.get('object_pattern') or query_info.get(
                        'constructor_pattern')

                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture[tag] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern') or query_info.get('method_pattern')
                    if prop_pattern and re.match(prop_pattern, prop_name, re.IGNORECASE):
                        current_capture['property'] = prop_name

                elif tag == 'template_string':
                    template_content = node.text.decode('utf8')
                    current_capture['template'] = template_content

                elif tag in ['call', 'assignment', 'new'] and current_capture:
                    # 检查是否匹配所有条件
                    is_vulnerable = True

                    # 检查对象/函数名匹配
                    if 'object_pattern' in query_info and 'object' not in current_capture:
                        is_vulnerable = False
                    if 'property_pattern' in query_info and 'property' not in current_capture:
                        is_vulnerable = False
                    if 'constructor_pattern' in query_info and 'constructor_name' not in current_capture:
                        is_vulnerable = False
                    if 'method_pattern' in query_info and 'method_name' not in current_capture:
                        is_vulnerable = False

                    if is_vulnerable and 'template' in current_capture:
                        # 检查模板字符串是否包含潜在的表达式注入模式
                        template = current_capture['template']
                        if contains_expression_injection_pattern(template):
                            vulnerabilities.append({
                                'line': current_capture['line'],
                                'message': f'表达式语言注入漏洞: {query_info["message"]}',
                                'code_snippet': node.text.decode('utf8'),
                                'vulnerability_type': '表达式语言注入',
                                'severity': '高危',
                                'template_content': template
                            })

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def contains_expression_injection_pattern(template):
    """
    检查字符串是否包含表达式语言注入模式

    Args:
        template: 模板字符串

    Returns:
        bool: 是否包含潜在的危险模式
    """
    # Spring Expression Language (SpEL) 模式
    spel_patterns = [
        r'\#\{[^}]+\}',  # #{expression}
        r'\$\{[^}]+\}',  # ${expression}
        r'T\([^)]+\)',  # T(Class)
        r'@[a-zA-Z0-9_\.]+@',  # @bean@
        r'new\s+[a-zA-Z0-9_\.]+\(',  # new Class()
        r'\(\([^)]+\)\)',  # ((expression))
    ]

    # 检查是否包含任何表达式模式
    for pattern in spel_patterns:
        if re.search(pattern, template, re.IGNORECASE):
            return True

    # 检查是否包含常见的危险表达式
    dangerous_expressions = [
        'runtime.exec', 'processbuilder', 'system.exit',
        'class.forname', 'classloader', 'reflection',
        'scriptengine', 'eval', 'execution'
    ]

    for expr in dangerous_expressions:
        if expr in template.lower():
            return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的表达式语言注入漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_expression_injection_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
// Spring表达式语言注入漏洞示例
const spelParser = new SpelExpressionParser();
const expression = spelParser.parseExpression("#{T(java.lang.Runtime).getRuntime().exec('calc')}");

const templateEngine = new TemplateEngine();
templateEngine.process("${T(java.lang.Runtime).getRuntime().exec('calc')}", context);

// 使用eval或类似函数
eval("some dangerous code");
window.eval("more dangerous code");

// 模板字符串中的表达式
const userInput = req.query.input;
const result = templateEngine.render(`Welcome ${userInput}`, data);

// 安全的用法（应该不会被检测为漏洞）
const safeExpression = spelParser.parseExpression("1 + 1");
const safeTemplate = templateEngine.process("Hello #{name}", safeContext);

// 其他可能的表达式引擎
const scriptEngine = new ScriptEngineManager().getEngineByName("javascript");
scriptEngine.eval("dangerous script");

// 赋值操作中的表达式
elContext.expression = "#{systemProperties['user.dir']}";
template.value = "${user.name}";

// 函数调用
parseExpression("#{T(java.lang.System).exit(0)}");
evaluate("runtime.exec('malicious')");

// 潜在的误报情况（包含${}但不一定是表达式）
const normalString = "This is a ${variable} in normal text";
const configString = "server.port=${PORT:8080}";
"""

    print("=" * 60)
    print("JavaScript 表达式语言注入漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   模板内容: {vuln['template_content'][:50]}...")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到表达式语言注入漏洞")