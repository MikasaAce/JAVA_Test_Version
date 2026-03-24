import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在config_path中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 简化的C++服务器端模板注入漏洞模式
SSTI_VULNERABILITIES = {
    'cpp': [
        # 检测模板引擎函数调用
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                )
            ''',
            'func_pattern': r'^(render|template|process|evaluate|execute|run|parse|compile|expand|substitute|format)$',
            'message': '模板引擎函数调用'
        },
        # 检测常见的C++模板库函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                )
            ''',
            'func_pattern': r'^(ctemplate|mustache|handlebars|inja|jinja|tinytemplate|string_template)',
            'message': '已知模板库函数调用'
        },
        # 检测字符串格式化函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                )
            ''',
            'func_pattern': r'^(sprintf|snprintf|swprintf|fmt::format|std::format|boost::format)$',
            'message': '格式化函数调用'
        },
        # 检测模板文件加载函数
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args
                )
            ''',
            'func_pattern': r'^(load_template|read_template|open_template|get_template|template_from_file)$',
            'message': '模板文件加载函数'
        }
    ]
}

# 简化的用户输入源模式
USER_INPUT_SOURCES = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list) @args
        )
    ''',
    'patterns': [
        r'^(cin|getline|gets|fgets|scanf|sscanf|fscanf|getc|getchar|read)$',
        r'^(recv|recvfrom|recvmsg|ReadFile)$',
        r'^(fread|fgetc|fgets|getline)$',
        r'^(getenv|_wgetenv)$',
        r'^(GetCommandLine|GetCommandLineW)$',
        r'^(getParameter|getQueryString|getHeader|getCookie)$'
    ]
}

# 模板注入特征模式
SSTI_INDICATORS = [
    r'\{\{.*\}\}',  # 双花括号模板语法
    r'\{%.*%\}',  # 花括号百分号模板语法
    r'\{#.*#\}',  # 花括号井号模板语法
    r'<\?.*\?>',  # PHP风格模板
    r'<%[^=].*%>',  # ASP风格模板（非表达式）
    r'\$\([^)]+\)',  # 变量替换语法
    r'@[A-Za-z_][A-Za-z0-9_]*',  # Razor风格模板
    r'\[\[.*\]\]',  # 双中括号模板
]


def detect_cpp_ssti_vulnerabilities(code, language='cpp'):
    """
    检测C++代码中服务器端模板注入漏洞
    """
    if language not in LANGUAGES:
        return []

    parser = Parser()
    parser.set_language(LANGUAGES[language])
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    vulnerabilities = []
    template_calls = []
    user_input_sources = []

    # 第一步：收集模板相关函数调用
    for query_info in SSTI_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            for node, tag in captures:
                if tag == 'func_name':
                    func_name = node.text.decode('utf8')
                    func_pattern = query_info.get('func_pattern', '')

                    if func_pattern and re.match(func_pattern, func_name, re.IGNORECASE):
                        call_node = node.parent
                        template_calls.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': call_node.text.decode('utf8'),
                            'node': call_node,
                            'message': query_info.get('message', '')
                        })

        except Exception as e:
            print(f"模板查询错误: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in USER_INPUT_SOURCES['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        call_node = node.parent
                        user_input_sources.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': call_node.text.decode('utf8'),
                            'node': call_node
                        })
                        break

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：分析SSTI漏洞
    for call in template_calls:
        # 检查调用参数是否包含用户输入
        args_text = call['code_snippet']

        # 检查是否直接包含用户输入函数
        for input_source in user_input_sources:
            if input_source['function'] in args_text:
                vulnerabilities.append({
                    'line': call['line'],
                    'code_snippet': call['code_snippet'],
                    'vulnerability_type': '服务器端模板注入',
                    'severity': '高危',
                    'message': f"用户输入({input_source['function']})传递给模板函数: {call['function']}"
                })
                break

        # 检查是否包含模板语法特征
        for pattern in SSTI_INDICATORS:
            if re.search(pattern, args_text):
                vulnerabilities.append({
                    'line': call['line'],
                    'code_snippet': call['code_snippet'],
                    'vulnerability_type': '服务器端模板注入',
                    'severity': '高危',
                    'message': f"模板内容包含动态语法特征: {call['function']}"
                })
                break

        # 检查常见的用户输入变量名
        user_input_vars = ['argv', 'argc', 'cin', 'getline', 'scanf', 'getenv', 'recv']
        for var in user_input_vars:
            if re.search(rf'\b{var}\b', args_text):
                vulnerabilities.append({
                    'line': call['line'],
                    'code_snippet': call['code_snippet'],
                    'vulnerability_type': '服务器端模板注入',
                    'severity': '高危',
                    'message': f"可能包含用户输入的变量({var})传递给模板函数: {call['function']}"
                })
                break

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_cpp_ssti(code_string):
    """分析C++代码字符串中的服务器端模板注入漏洞"""
    return detect_cpp_ssti_vulnerabilities(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>

using namespace std;

// 模拟模板函数
string render_template(const string& template_str) {
    return "Rendered: " + template_str;
}

string process_string(const string& input) {
    return "Processed: " + input;
}

void vulnerable_ssti(int argc, char* argv[]) {
    // 直接用户输入 - 高危
    string user_input;
    cout << "Enter template: ";
    getline(cin, user_input);
    render_template(user_input); // SSTI漏洞

    // 命令行参数 - 高危
    if (argc > 1) {
        render_template(argv[1]); // SSTI漏洞
    }

    // 环境变量 - 高危
    char* env_var = getenv("TEMPLATE");
    if (env_var) {
        render_template(env_var); // SSTI漏洞
    }

    // 字符串拼接 - 高危
    string base = "Hello ";
    string name;
    cout << "Enter name: ";
    cin >> name;
    string full_template = base + name + " {{ malicious_code }}";
    render_template(full_template); // SSTI漏洞

    // 格式化字符串 - 高危
    char buffer[100];
    sprintf(buffer, "Welcome %s", name.c_str());
    process_string(buffer); // SSTI漏洞

    // 网络输入模拟
    string network_data;
    // recv(socket, buffer, size, 0); // 模拟网络接收
    process_string(network_data); // 潜在SSTI
}

void safe_usage() {
    // 安全的使用方式
    render_template("static_template.html");
    process_string("hardcoded_string");

    const string safe_var = "safe_content";
    render_template(safe_var);
}

int main(int argc, char* argv[]) {
    vulnerable_ssti(argc, argv);
    safe_usage();
    return 0;
}
"""

    print("=" * 60)
    print("C++服务器端模板注入漏洞检测")
    print("=" * 60)

    results = analyze_cpp_ssti(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在SSTI漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到服务器端模板注入漏洞")