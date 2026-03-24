import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义JavaScript的SSTI漏洞模式
SSTI_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @template_object
                        property: (property_identifier) @template_method
                    )
                    arguments: (arguments (string) @template_string)
                ) @template_call
            ''',
            'object_pattern': r'^(template|ejs|pug|handlebars|mustache|nunjucks|dot|underscore|_|lodash)$',
            'method_pattern': r'^(render|compile|renderFile|renderString|template)$',
            'message': '模板引擎渲染调用发现'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @template_func
                    arguments: (arguments (string) @template_string)
                ) @template_call
            ''',
            'func_pattern': r'^(render|compile|template|ejs\.render|pug\.compile|handlebars\.compile|mustache\.render|nunjucks\.render)$',
            'message': '模板渲染函数调用发现'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (call_expression
                            function: (identifier) @require_func
                            arguments: (arguments (string) @module_name)
                        )
                        property: (property_identifier) @template_method
                    )
                    arguments: (arguments (string) @template_string)
                ) @template_call
            ''',
            'require_pattern': r'^[\'"](ejs|pug|handlebars|mustache|nunjucks|underscore|lodash|dot)[\'"]$',
            'method_pattern': r'^(render|compile|renderFile|renderString|template)$',
            'message': '动态导入模板引擎的渲染调用'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @eval_object
                        property: (property_identifier) @eval_method
                    )
                    arguments: (arguments (string) @eval_string)
                ) @eval_call
            ''',
            'object_pattern': r'^(eval|Function|global|window|this)$',
            'method_pattern': r'^(call|apply|constructor)$',
            'message': '动态代码执行调用发现'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @eval_func
                    arguments: (arguments (string) @eval_string)
                ) @eval_call
            ''',
            'func_pattern': r'^(eval|setTimeout|setInterval|Function|exec|execSync)$',
            'message': '动态执行函数调用发现'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (_)
                        property: (property_identifier) @replace_method
                    )
                    arguments: (arguments (string) @pattern_string)
                ) @replace_call
            ''',
            'method_pattern': r'^(replace|replaceAll|split|match|search)$',
            'message': '字符串替换操作发现'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @fs_object
                        property: (property_identifier) @fs_method
                    )
                    arguments: (arguments (string) @fs_string)
                ) @fs_call
            ''',
            'object_pattern': r'^(fs|require\([\'"]fs[\'"]\))$',
            'method_pattern': r'^(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync)$',
            'message': '文件系统操作调用发现'
        }
    ]
}


def detect_js_ssti_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中服务器端模板注入漏洞

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
    user_input_sources = detect_user_input_sources(root, language, code)

    # 检测所有可能的SSTI模式
    for query_info in SSTI_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['template_object', 'eval_object', 'require_func', 'template_func', 'eval_func', 'fs_object']:
                    obj_name = node.text.decode('utf8')
                    pattern = query_info.get('object_pattern') or query_info.get('func_pattern') or query_info.get(
                        'require_pattern')
                    if pattern and re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['template_method', 'eval_method', 'replace_method', 'fs_method']:
                    method_name = node.text.decode('utf8')
                    method_pattern = query_info.get('method_pattern', '')
                    if method_pattern and re.match(method_pattern, method_name, re.IGNORECASE):
                        current_capture['method'] = method_name

                elif tag in ['template_string', 'eval_string', 'pattern_string', 'module_name', 'fs_string']:
                    string_value = node.text.decode('utf8')
                    current_capture['string'] = string_value
                    current_capture['string_node'] = node

                elif tag in ['template_call', 'eval_call', 'replace_call', 'fs_call'] and current_capture:
                    # 完成一个完整的捕获
                    if ('object' in current_capture or 'method' in current_capture) and 'string' in current_capture:
                        # 检查字符串是否包含用户输入
                        if is_potential_ssti_string(current_capture['string'], user_input_sources, code,
                                                    current_capture.get('object'), current_capture.get('method')):
                            code_snippet = node.text.decode('utf8')

                            vulnerabilities.append({
                                'line': current_capture['line'],
                                'message': f'潜在的服务器端模板注入: {query_info["message"]}',
                                'code_snippet': code_snippet,
                                'vulnerability_type': 'SSTI',
                                'severity': '高危',
                                'object': current_capture.get('object', ''),
                                'method': current_capture.get('method', ''),
                                'template_string': current_capture['string']
                            })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def detect_user_input_sources(root, language, code):
    """
    检测代码中的用户输入源

    Args:
        root: AST根节点
        language: 语言类型
        code: 完整代码字符串

    Returns:
        list: 用户输入源节点列表
    """
    user_input_patterns = [
        # req.query, req.params, req.body
        {
            'query': '''
                (member_expression
                    object: (member_expression
                        object: (identifier) @req_object
                        property: (property_identifier) @req_property
                    )
                    property: (property_identifier) @input_property
                ) @user_input
            ''',
            'object_pattern': r'^(req|request|ctx|context)$',
            'property_pattern': r'^(query|params|body|headers|cookies)$'
        },
        # req.query.param
        {
            'query': '''
                (member_expression
                    object: (member_expression
                        object: (member_expression
                            object: (identifier) @req_object
                            property: (property_identifier) @req_property
                        )
                        property: (property_identifier) @input_category
                    )
                    property: (property_identifier) @input_property
                ) @user_input
            ''',
            'object_pattern': r'^(req|request|ctx|context)$',
            'property_pattern': r'^(query|params|body|headers|cookies)$'
        },
        # document.getElementById().value, input.value
        {
            'query': '''
                (member_expression
                    object: (call_expression
                        function: (member_expression
                            object: (identifier) @dom_object
                            property: (property_identifier) @dom_method
                        )
                    )
                    property: (property_identifier) @value_property
                ) @user_input
            ''',
            'method_pattern': r'^(getElementById|getElementsByClassName|getElementsByTagName|querySelector|querySelectorAll)$',
            'property_pattern': r'^(value|textContent|innerHTML|innerText)$'
        },
        # URLSearchParams, location.search
        {
            'query': '''
                (member_expression
                    object: (identifier) @url_object
                    property: (property_identifier) @url_property
                ) @user_input
            ''',
            'object_pattern': r'^(location|URLSearchParams|window|document)$',
            'property_pattern': r'^(search|hash|href)$'
        },
        # process.env
        {
            'query': '''
                (member_expression
                    object: (member_expression
                        object: (identifier) @process_object
                        property: (property_identifier) @env_property
                    )
                    property: (property_identifier) @env_var
                ) @user_input
            ''',
            'object_pattern': r'^(process)$',
            'property_pattern': r'^(env)$'
        }
    ]

    user_input_sources = []

    for pattern in user_input_patterns:
        try:
            query = LANGUAGES[language].query(pattern['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['req_object', 'dom_object', 'url_object', 'process_object']:
                    obj_name = node.text.decode('utf8')
                    if re.match(pattern['object_pattern'], obj_name, re.IGNORECASE):
                        current_capture['object'] = obj_name
                        current_capture['node'] = node

                elif tag in ['req_property', 'dom_method', 'url_property', 'input_category', 'env_property']:
                    prop_name = node.text.decode('utf8')
                    prop_pattern = pattern.get('property_pattern') or pattern.get('method_pattern')
                    if prop_pattern and re.match(prop_pattern, prop_name, re.IGNORECASE):
                        current_capture['property'] = prop_name

                elif tag in ['input_property', 'env_var'] and current_capture:
                    input_prop = node.text.decode('utf8')
                    current_capture['input_property'] = input_prop

                    # 获取变量名（如果是标识符）
                    var_name = input_prop

                    user_input_sources.append({
                        'node': node,
                        'object': current_capture.get('object', ''),
                        'property': current_capture.get('property', ''),
                        'input_property': input_prop,
                        'var_name': var_name,
                        'line': node.start_point[0] + 1,
                        'code_snippet': node.parent.text.decode('utf8') if node.parent else ''
                    })
                    current_capture = {}

        except Exception as e:
            print(f"用户输入源检测错误: {e}")
            continue

    return user_input_sources


def is_potential_ssti_string(template_string, user_input_sources, code, object_name=None, method_name=None):
    """
    检查模板字符串是否可能包含用户输入

    Args:
        template_string: 模板字符串
        user_input_sources: 用户输入源列表
        code: 完整代码
        object_name: 调用对象名
        method_name: 调用方法名

    Returns:
        bool: 是否可能包含用户输入
    """
    # 清理字符串（去除引号）
    clean_string = template_string.strip('"\'').strip()

    # 对于eval和Function调用，任何用户输入都是危险的
    if object_name and object_name.lower() in ['eval', 'function']:
        if len(clean_string) > 0:
            return True

    # 对于文件系统操作，检查路径是否可能包含用户输入
    if object_name and 'fs' in object_name.lower():
        # 检查路径是否包含变量
        variable_pattern = r'[a-zA-Z_$][a-zA-Z0-9_$]*'
        variables = re.findall(variable_pattern, clean_string)
        return len(variables) > 0

    # 检查字符串是否包含常见的模板变量语法
    template_patterns = [
        r'\$\{[^}]+\}',  # ${variable}
        r'<%=.*?%>',  # <%= variable %>
        r'<%#.*?%>',  # <%# comment %>
        r'<%[^%]+%>',  # <% code %>
        r'\{\{.*?\}\}',  # {{ variable }}
        r'\{%.*?%\}',  # {% code %}
        r'\[\[.*?\]\]',  # [[ variable ]]
        r'%s|%d|%f',  # 格式化字符串
    ]

    # 如果字符串包含模板语法，可能是静态模板
    for pattern in template_patterns:
        if re.search(pattern, clean_string):
            return True

    # 检查字符串是否包含可能的变量名
    variable_pattern = r'[a-zA-Z_$][a-zA-Z0-9_$]*'
    variables = re.findall(variable_pattern, clean_string)

    # 检查这些变量是否可能是用户输入
    for var in variables:
        # 跳过常见的模板变量和关键字
        if var.lower() in ['html', 'template', 'view', 'layout', 'partial', 'include', 'extends', 'block', 'true',
                           'false', 'null', 'undefined']:
            continue

        # 检查变量是否在用户输入源中使用
        for input_source in user_input_sources:
            if (var == input_source.get('input_property', '') or
                    var == input_source.get('property', '') or
                    var == input_source.get('var_name', '')):
                return True

    # 检查字符串是否非常短或看起来像占位符
    if len(clean_string) < 5 and any(char in clean_string for char in ['$', '{', '}', '<', '%', '>']):
        return True

    # 检查是否包含常见的SSTI payload模式
    ssti_patterns = [
        r'process\.env',
        r'require\(|import\(|eval\(|Function\(',
        r'__dirname|__filename',
        r'child_process|exec|spawn',
        r'fs\.readFile|fs\.writeFile'
    ]

    for pattern in ssti_patterns:
        if re.search(pattern, clean_string, re.IGNORECASE):
            return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的SSTI漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_ssti_vulnerabilities(code_string, 'javascript')


# 测试函数
def test_ssti_detection():
    """测试SSTI检测功能"""

    # 测试安全的代码
    safe_code = """
const ejs = require('ejs');
const safeTemplate = "<h1>Hello, <%= username %></h1>";
ejs.render(safeTemplate, { username: 'admin' });

const handlebars = require('handlebars');
const fixedTemplate = "Welcome, {{user.name}}";
handlebars.compile(fixedTemplate)({ user: { name: 'guest' } });

const localVar = "John";
const dynamicTemplate = `User: ${localVar}`;
"""

    print("测试安全代码:")
    results = analyze_js_code(safe_code)
    if not results:
        print("✓ 未检测到SSTI漏洞 (正确)")
    else:
        print("✗ 误报检测到漏洞")
        for vuln in results:
            print(f"  误报: {vuln['message']}")

    print("\n" + "=" * 50 + "\n")

    # 测试危险的代码
    dangerous_code = """
const ejs = require('ejs');
const userTemplate = req.query.template;
ejs.render(userTemplate, data);

const pug = require('pug');
pug.compile(req.body.template);

eval(req.query.code);
Function(req.body.func)();

// 文件路径注入
const fs = require('fs');
const userFile = req.params.file;
fs.readFile(userFile, 'utf8', (err, data) => {});

// 字符串替换SSTI
const template = "Hello, ${name}!";
template.replace('${name}', req.query.name);
"""

    print("测试危险代码:")
    results = analyze_js_code(dangerous_code)
    if results:
        print("✓ 检测到SSTI漏洞 (正确):")
        for i, vuln in enumerate(results, 1):
            print(f"  {i}. {vuln['message']} (行 {vuln['line']})")
    else:
        print("✗ 未检测到漏洞 (漏报)")


# 示例使用
if __name__ == "__main__":
    print("=" * 60)
    print("JavaScript SSTI漏洞检测器")
    print("=" * 60)

    # 运行测试
    test_ssti_detection()

    # 也可以直接分析代码文件
    # with open('example.js', 'r', encoding='utf-8') as f:
    #     code_content = f.read()
    #     results = analyze_js_code(code_content)
    #     # 处理结果...