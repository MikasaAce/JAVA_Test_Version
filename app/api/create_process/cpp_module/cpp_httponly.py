import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义Cookie HTTPOnly设置检测模式
COOKIE_HTTPONLY_VULNERABILITIES = {
    'cpp': [
        # 检测Set-Cookie头设置，缺少HttpOnly标志
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (_) @arg1
                        (_)? @arg2
                        (_)? @arg3
                    )
                ) @call
                (#match? @func_name "^(SetCookie|setcookie|Set-Cookie|set_cookie)$")
            ''',
            'message': 'Cookie设置函数调用，缺少HttpOnly标志'
        },
        # 检测HTTP响应头设置中的Set-Cookie
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (string_literal) @header_name
                        (_) @header_value
                    )
                ) @call
                (#match? @func_name "^(AddHeader|addHeader|SetHeader|setHeader|append_header)$")
            ''',
            'message': 'HTTP响应头设置，可能包含Cookie'
        },
        # 检测字符串操作构建Set-Cookie头
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list 
                        (binary_expression
                            left: (_) @left
                            operator: "+"
                            right: (_) @right
                        ) @concat_arg
                    )
                ) @call
                (#match? @func_name "^(printf|sprintf|snprintf|strcat|strncat)$")
            ''',
            'message': '字符串操作可能用于构建Cookie头'
        },
        # 检测直接写入HTTP响应的Cookie设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
                (#match? @func_name "^(write|fwrite|send|printf|fprintf)$")
            ''',
            'message': '直接输出操作可能包含Cookie设置'
        }
    ]
}

# HttpOnly标志检测模式
HTTPONLY_PATTERNS = [
    r'HttpOnly',
    r'http-only',
    r'httponly',
    r';\\s*HttpOnly',
    r';\\s*http-only',
    r';\\s*httponly'
]


class VulnerabilityDetector:
    """通用的漏洞检测器，包含去重机制"""

    def __init__(self, language='cpp'):
        self.language = language
        self.parser = Parser()
        self.parser.set_language(LANGUAGES[language])
        self.seen_nodes = set()  # 全局去重集合

    def get_call_expression_node(self, node):
        """获取调用表达式节点"""
        current = node
        while current and current.type != 'call_expression':
            current = current.parent
        return current

    def get_node_unique_id(self, node):
        """获取节点的唯一标识符"""
        if node:
            return f"{node.start_byte}:{node.end_byte}:{node.type}"
        return None

    def detect_cookie_httponly_vulnerability(self, code):
        """检测Cookie HttpOnly未设置漏洞"""
        tree = self.parser.parse(bytes(code, 'utf8'))
        root = tree.root_node

        vulnerabilities = []
        cookie_operations = []

        # 重置去重集合
        self.seen_nodes.clear()

        # 收集所有Cookie相关操作
        for query_info in COOKIE_HTTPONLY_VULNERABILITIES[self.language]:
            try:
                query = LANGUAGES[self.language].query(query_info['query'])
                captures = query.captures(root)

                current_capture = {}
                for node, tag in captures:
                    call_node = self.get_call_expression_node(node)
                    node_id = self.get_node_unique_id(call_node)

                    # 跳过已经处理过的节点
                    if node_id and node_id in self.seen_nodes:
                        continue

                    if tag == 'func_name':
                        name = node.text.decode('utf8')
                        current_capture['func'] = name
                        current_capture['line'] = node.start_point[0] + 1
                        current_capture['call_node'] = call_node

                    elif tag in ['arg1', 'arg2', 'arg3', 'concat_arg', 'header_name', 'header_value']:
                        current_capture[tag] = node.text.decode('utf8')

                    elif tag == 'call' and current_capture and 'call_node' in current_capture:
                        call_node = current_capture['call_node']
                        node_id = self.get_node_unique_id(call_node)

                        # 标记为已处理
                        if node_id:
                            self.seen_nodes.add(node_id)

                        code_snippet = call_node.text.decode('utf8')

                        operation_info = {
                            'type': 'cookie_operation',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'code_snippet': code_snippet,
                            'call_node': call_node,
                            'node_id': node_id
                        }

                        # 添加参数信息
                        for arg_tag in ['arg1', 'arg2', 'arg3', 'concat_arg', 'header_name', 'header_value']:
                            if arg_tag in current_capture:
                                operation_info[arg_tag] = current_capture[arg_tag]

                        cookie_operations.append(operation_info)
                        current_capture = {}

            except Exception as e:
                print(f"查询错误 {query_info.get('message')}: {e}")
                continue

        # 分析漏洞
        seen_vuln_nodes = set()
        for operation in cookie_operations:
            if operation['node_id'] in seen_vuln_nodes:
                continue

            is_vulnerable = False
            vulnerability_details = {
                'line': operation['line'],
                'code_snippet': operation['code_snippet'],
                'vulnerability_type': 'Cookie安全: HttpOnly未设置',
                'severity': '中危',
                'node_id': operation['node_id']
            }

            # 检查是否缺少HttpOnly标志
            if self.is_missing_httponly(operation):
                vulnerability_details[
                    'message'] = f"Cookie设置缺少HttpOnly标志: {operation.get('function', '未知函数')}"
                is_vulnerable = True

            # 检查是否明确设置了HttpOnly但值为false
            elif self.has_httponly_false(operation):
                vulnerability_details[
                    'message'] = f"Cookie设置HttpOnly标志为false: {operation.get('function', '未知函数')}"
                vulnerability_details['severity'] = '高危'
                is_vulnerable = True

            if is_vulnerable:
                seen_vuln_nodes.add(operation['node_id'])
                vulnerabilities.append(vulnerability_details)

        return sorted(vulnerabilities, key=lambda x: x['line'])

    def is_missing_httponly(self, operation):
        """检查Cookie操作是否缺少HttpOnly标志"""
        code_text = operation['code_snippet'].lower()

        # 检查是否是明确的Cookie设置操作
        if not self.is_cookie_operation(code_text):
            return False

        # 检查是否已经包含HttpOnly标志
        for pattern in HTTPONLY_PATTERNS:
            if re.search(pattern, code_text, re.IGNORECASE):
                return False

        # 对于特定的Cookie设置函数，检查参数
        func_name = operation['function'].lower()
        if 'setcookie' in func_name or 'set-cookie' in func_name:
            return True

        # 对于HTTP头设置，检查是否包含Set-Cookie但没有HttpOnly
        if any(header_func in func_name for header_func in ['addheader', 'setheader', 'append_header']):
            if 'header_name' in operation and 'set-cookie' in operation['header_name'].lower():
                if 'header_value' in operation:
                    header_value = operation['header_value'].lower()
                    return not any(pattern in header_value for pattern in ['httponly', 'http-only'])

        return True

    def has_httponly_false(self, operation):
        """检查是否明确将HttpOnly设置为false"""
        code_text = operation['code_snippet'].lower()

        false_patterns = [
            r'httponly\s*=\s*false',
            r'http-only\s*=\s*false',
            r'httponly\s*=\s*0',
            r'http-only\s*=\s*0'
        ]

        for pattern in false_patterns:
            if re.search(pattern, code_text, re.IGNORECASE):
                return True

        return False

    def is_cookie_operation(self, code_text):
        """检查代码文本是否是Cookie相关操作"""
        cookie_patterns = [
            r'set-cookie',
            r'setcookie',
            r'cookie',
            r'COOKIE'
        ]

        for pattern in cookie_patterns:
            if re.search(pattern, code_text, re.IGNORECASE):
                return True

        return False


# 兼容旧接口的函数
def detect_cpp_cookie_httponly_vulnerability(code, language='cpp'):
    """检测C++代码中Cookie HttpOnly未设置漏洞"""
    detector = VulnerabilityDetector(language)
    return detector.detect_cookie_httponly_vulnerability(code)


def analyze_cpp_code(code_string):
    """分析C++代码字符串中的Cookie HttpOnly未设置漏洞"""
    return detect_cpp_cookie_httponly_vulnerability(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstring>
#include <string>

using namespace std;

void vulnerable_cookie_function() {
    // 缺少HttpOnly标志 - 漏洞
    setcookie("sessionid", "abc123", 3600, "/", "example.com", false, false);

    // 直接设置Cookie头，缺少HttpOnly - 漏洞
    cout << "Set-Cookie: sessionid=abc123; Path=/; Domain=example.com; Secure\\r\\n";

    // 使用字符串拼接设置Cookie - 漏洞
    string cookie = "Set-Cookie: user=john; Path=/;";
    string fullCookie = cookie + " Domain=example.com; Secure";
    printf("%s", fullCookie.c_str());

    // 重复的setcookie调用 - 应该只报告一次
    setcookie("sessionid", "abc123", 3600, "/", "example.com", false, false);
}

void safe_cookie_function() {
    // 正确设置HttpOnly - 安全
    setcookie("sessionid", "abc123", 3600, "/", "example.com", true, true);

    // 正确设置Cookie头 - 安全
    cout << "Set-Cookie: sessionid=abc123; Path=/; Domain=example.com; Secure; HttpOnly\\r\\n";
}

int main() {
    vulnerable_cookie_function();
    safe_cookie_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++ Cookie HttpOnly未设置漏洞检测")
    print("=" * 60)

    results = analyze_cpp_code(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Cookie HttpOnly未设置漏洞")