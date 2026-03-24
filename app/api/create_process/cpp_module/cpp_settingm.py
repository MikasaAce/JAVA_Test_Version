import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义C++设置操纵漏洞模式
SETTING_MANIPULATION_VULNERABILITIES = {
    'cpp': [
        # 检测环境变量操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_) @arg1 (_)? @arg2)
                ) @call
            ''',
            'func_pattern': r'^(putenv|setenv|_putenv|_wputenv|SetEnvironmentVariable)$',
            'message': '环境变量设置函数调用'
        },
        # 检测注册表操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(RegSetValue|RegSetValueEx|RegCreateKey|RegCreateKeyEx|RegDeleteValue|RegDeleteKey)$',
            'message': 'Windows注册表操作函数'
        },
        # 检测配置文件操作
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(WritePrivateProfileString|WriteProfileString|WritePrivateProfileSection|WriteProfileSection)$',
            'message': 'INI配置文件写入函数'
        },
        # 检测系统设置修改
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(SystemParametersInfo|SetSystemTime|SetLocalTime|SetTimeZoneInformation)$',
            'message': '系统参数设置函数'
        },
        # 检测文件权限修改
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(chmod|_chmod|fchmod|SetFileSecurity|SetNamedSecurityInfo|SetSecurityInfo)$',
            'message': '文件权限设置函数'
        },
        # 检测服务配置修改
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(ChangeServiceConfig|CreateService|DeleteService|StartService)$',
            'message': 'Windows服务配置函数'
        },
        # 检测进程/线程优先级设置
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)* @args)
                ) @call
            ''',
            'func_pattern': r'^(SetPriorityClass|SetThreadPriority|SetProcessPriorityBoost|SetThreadPriorityBoost)$',
            'message': '进程/线程优先级设置函数'
        }
    ]
}

# C++用户输入源模式（复用之前的定义）
USER_INPUT_SOURCES = {
    'query': '''
        [
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list) @args
            )
            (call_expression
                function: (field_expression
                    object: (_) @obj
                    field: (_) @field
                )
                arguments: (argument_list) @args
            )
        ] @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(cin|getline|gets|fgets|scanf|sscanf|fscanf|getc|getchar|read)$',
            'message': '标准输入函数'
        },
        {
            'func_pattern': r'^(recv|recvfrom|recvmsg|ReadFile)$',
            'message': '网络输入函数'
        },
        {
            'func_pattern': r'^(fread|fgetc|fgets|getline)$',
            'message': '文件输入函数'
        },
        {
            'obj_pattern': r'^(std::cin|cin)$',
            'field_pattern': r'^(operator>>|get|getline|read)$',
            'message': 'C++标准输入'
        },
        {
            'func_pattern': r'^(getenv|_wgetenv)$',
            'message': '环境变量获取'
        },
        {
            'func_pattern': r'^(GetCommandLine|GetCommandLineW)$',
            'message': '命令行参数获取'
        }
    ]
}

# 危险字符串函数模式（复用之前的定义）
DANGEROUS_STRING_FUNCTIONS = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list (_)* @args)
        ) @call
    ''',
    'patterns': [
        r'^strcat$',
        r'^strcpy$',
        r'^wcscat$',
        r'^wcscpy$',
        r'^sprintf$',
        r'^swprintf$',
        r'^vsprintf$',
        r'^vswprintf$'
    ]
}


def detect_cpp_setting_manipulation(code, language='cpp'):
    """
    检测C++代码中设置操纵漏洞

    Args:
        code: C++源代码字符串
        language: 语言类型，默认为'cpp'

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
    setting_operations = []  # 存储所有设置操作函数调用
    user_input_sources = []  # 存储用户输入源
    dangerous_string_ops = []  # 存储危险字符串操作

    # 第一步：收集所有设置操作函数调用
    for query_info in SETTING_MANIPULATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag == 'func_name':
                    name = node.text.decode('utf8')
                    pattern = query_info.get('func_pattern', '')
                    if pattern and re.match(pattern, name, re.IGNORECASE):
                        current_capture['func'] = name
                        current_capture['node'] = node.parent
                        current_capture['line'] = node.start_point[0] + 1

                elif tag in ['arg1', 'arg2']:
                    current_capture[f'arg{tag[-1]}'] = node.text.decode('utf8')
                    current_capture[f'arg{tag[-1]}_node'] = node

                elif tag == 'call' and current_capture:
                    # 完成一个完整的捕获
                    if 'func' in current_capture:
                        code_snippet = node.text.decode('utf8')

                        setting_operations.append({
                            'type': 'setting_operation',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'arguments': {
                                'arg1': current_capture.get('arg1', ''),
                                'arg2': current_capture.get('arg2', '')
                            },
                            'arg_nodes': {
                                'arg1': current_capture.get('arg1_node'),
                                'arg2': current_capture.get('arg2_node')
                            },
                            'code_snippet': code_snippet,
                            'node': node
                        })
                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集所有用户输入源（复用之前的代码）
    try:
        query = LANGUAGES[language].query(USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                current_capture['func'] = func_name
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['obj', 'field']:
                name = node.text.decode('utf8')
                if tag == 'obj':
                    current_capture['object'] = name
                else:
                    current_capture['field'] = name

            elif tag == 'call' and current_capture:
                # 检查是否匹配任何用户输入模式
                for pattern_info in USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    obj_pattern = pattern_info.get('obj_pattern', '')
                    field_pattern = pattern_info.get('field_pattern', '')

                    match = False
                    if func_pattern and 'func' in current_capture:
                        if re.match(func_pattern, current_capture['func'], re.IGNORECASE):
                            match = True
                    elif obj_pattern and field_pattern and 'object' in current_capture and 'field' in current_capture:
                        if (re.match(obj_pattern, current_capture['object'], re.IGNORECASE) and
                                re.match(field_pattern, current_capture['field'], re.IGNORECASE)):
                            match = True

                    if match:
                        code_snippet = node.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': current_capture['line'],
                            'function': current_capture.get('func', ''),
                            'object': current_capture.get('object', ''),
                            'field': current_capture.get('field', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：收集危险字符串操作（复用之前的代码）
    try:
        query = LANGUAGES[language].query(DANGEROUS_STRING_FUNCTIONS['query'])
        captures = query.captures(root)

        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                for pattern in DANGEROUS_STRING_FUNCTIONS['patterns']:
                    if re.match(pattern, func_name, re.IGNORECASE):
                        dangerous_string_ops.append({
                            'line': node.start_point[0] + 1,
                            'function': func_name,
                            'code_snippet': node.parent.text.decode('utf8'),
                            'node': node.parent
                        })
                        break

    except Exception as e:
        print(f"危险字符串函数查询错误: {e}")

    # 第四步：分析设置操纵漏洞
    for operation in setting_operations:
        is_vulnerable = False
        vulnerability_details = {
            'line': operation['line'],
            'code_snippet': operation['code_snippet'],
            'vulnerability_type': '设置操纵',
            'severity': '中危'
        }

        # 检查参数是否来自用户输入
        for arg_key, arg_node in operation['arg_nodes'].items():
            if arg_node and is_user_input_related(arg_node, user_input_sources, root):
                vulnerability_details['message'] = f"用户输入直接用于系统设置: {operation['function']}"
                is_vulnerable = True
                break

        # 检查参数是否经过危险字符串操作
        if not is_vulnerable:
            for arg_key, arg_node in operation['arg_nodes'].items():
                if arg_node and is_dangerous_string_operation(arg_node, dangerous_string_ops, root):
                    vulnerability_details['message'] = f"经过危险字符串操作后用于系统设置: {operation['function']}"
                    is_vulnerable = True
                    break

        # 对于特定高危函数，即使没有明显用户输入也标记
        if not is_vulnerable and is_high_risk_operation(operation):
            vulnerability_details['message'] = f"高危系统设置操作: {operation['function']}"
            vulnerability_details['severity'] = '高危'
            is_vulnerable = True

        if is_vulnerable:
            vulnerabilities.append(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_user_input_related(arg_node, user_input_sources, root_node):
    """
    检查参数节点是否与用户输入相关
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查常见的用户输入变量名
    user_input_vars = ['argv', 'env', 'input', 'buffer', 'param', 'data', 'user', 'cmd']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', arg_text, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == arg_node or is_child_node(arg_node, source['node']):
            return True

    return False


def is_dangerous_string_operation(arg_node, dangerous_string_ops, root_node):
    """
    检查参数是否经过危险字符串操作
    """
    arg_text = arg_node.text.decode('utf8')

    # 检查是否直接使用了危险字符串函数的缓冲区
    for op in dangerous_string_ops:
        # 简单的文本匹配（实际应用中需要更精确的数据流分析）
        if op['function'] in arg_text:
            return True

    return False


def is_high_risk_operation(operation):
    """
    检查是否为高危设置操作
    """
    high_risk_functions = [
        'SetEnvironmentVariable', 'putenv', 'setenv',
        'RegSetValue', 'RegSetValueEx', 'RegCreateKey', 'RegCreateKeyEx',
        'SystemParametersInfo', 'SetFileSecurity', 'SetNamedSecurityInfo',
        'ChangeServiceConfig', 'CreateService'
    ]

    return operation['function'] in high_risk_functions


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


def analyze_cpp_code(code_string):
    """
    分析C++代码字符串中的设置操纵漏洞
    """
    return detect_cpp_setting_manipulation(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstdlib>
#include <windows.h>
#include <winreg.h>

using namespace std;

void vulnerable_function(int argc, char* argv[]) {
    // 环境变量操作 - 高危
    putenv("PATH=/usr/local/bin:/usr/bin:/bin");

    // 用户输入直接设置环境变量 - 高危
    if (argc > 1) {
        char env_var[100];
        sprintf(env_var, "PATH=%s", argv[1]);
        putenv(env_var); // 设置操纵漏洞
    }

    // 注册表操作 - 高危
    HKEY hKey;
    RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\\\MyApp", 0, KEY_WRITE, &hKey);
    RegSetValueEx(hKey, "Setting", 0, REG_SZ, (BYTE*)"value", 6);

    // 用户输入用于注册表操作 - 高危
    if (argc > 2) {
        RegSetValueEx(hKey, "UserSetting", 0, REG_SZ, (BYTE*)argv[2], strlen(argv[2]));
    }
    RegCloseKey(hKey);

    // 系统参数设置 - 高危
    SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, "wallpaper.bmp", SPIF_UPDATEINIFILE);

    // 文件权限设置 - 中危
    _chmod("config.ini", _S_IREAD | _S_IWRITE);

    // 相对安全的做法 - 使用固定值
    const char* safe_path = "C:\\\\Program Files\\\\MyApp";
    SetEnvironmentVariable("APP_PATH", safe_path);
}

void safe_function() {
    // 安全的硬编码设置
    putenv("LANG=en_US.UTF-8");

    // 安全的注册表操作（固定值）
    HKEY hKey;
    RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\\\MyApp", 0, KEY_WRITE, &hKey);
    RegSetValueEx(hKey, "Version", 0, REG_SZ, (BYTE*)"1.0.0", 6);
    RegCloseKey(hKey);
}

int main(int argc, char* argv[]) {
    vulnerable_function(argc, argv);
    safe_function();
    return 0;
}
"""

    print("=" * 60)
    print("C++设置操纵漏洞检测")
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
        print("未检测到设置操纵漏洞")