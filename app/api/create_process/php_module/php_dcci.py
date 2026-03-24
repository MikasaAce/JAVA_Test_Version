import re

def detect_php_code_injection(php_code):
    """
    PHP动态代码注入漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测危险函数调用
    detect_dangerous_functions(lines, vulnerabilities)
    
    # 检测动态函数调用
    detect_dynamic_function_calls(lines, vulnerabilities)
    
    # 检测可变变量
    detect_variable_variables(lines, vulnerabilities)
    
    # 检测文件包含
    detect_file_inclusion(lines, vulnerabilities)
    
    # 检测动态方法调用
    detect_dynamic_method_calls(lines, vulnerabilities)
    
    return vulnerabilities


def detect_dangerous_functions(lines, vulnerabilities):
    """
    检测危险的代码执行函数
    """
    dangerous_functions = {
        "eval": "代码注入",
        "assert": "代码注入",
        "preg_replace": "代码注入",
        "create_function": "动态函数创建",
        "call_user_func": "动态函数调用",
        "call_user_func_array": "动态函数调用",
        "forward_static_call": "动态函数调用",
        "forward_static_call_array": "动态函数调用",
    }
    
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检查每个危险函数
        for func_name, vuln_type in dangerous_functions.items():
            # 构建匹配函数调用的正则表达式
            patterns = [
                # 模式1：标准函数调用 $var = func_name(...);
                r'\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*' + re.escape(func_name) + r'\s*\(',
                # 模式2：直接函数调用 func_name(...);
                r'\b' + re.escape(func_name) + r'\s*\(\s*[^;]*\)\s*;',
                # 模式3：在复杂表达式中的函数调用
                r'\b' + re.escape(func_name) + r'\s*\('
            ]
            
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = '高危'
                    detailed_type = vuln_type
                    
                    # 特殊处理preg_replace的/e修饰符
                    if func_name == 'preg_replace':
                        if re.search(r'/[^/]*/e', line) or re.search(r'[\'"]e[\'"]', line):
                            severity = '严重'
                            detailed_type = "preg_replace代码注入 - 使用/e修饰符"
                        else:
                            continue  # 如果没有/e修饰符，跳过preg_replace检测
                    
                    # 检查是否包含用户输入
                    for indicator in user_input_indicators:
                        if indicator in line:
                            severity = '严重'
                            detailed_type = f"{vuln_type} - 用户输入直接执行"
                            break
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到危险函数 '{func_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': detailed_type,
                        'severity': severity
                    })
                    break  # 找到一个匹配就跳出内层循环


def detect_dynamic_function_calls(lines, vulnerabilities):
    """
    检测动态函数调用
    """
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测变量函数调用：$var();
        dynamic_func_pattern = r'\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*[^)]*\s*\)\s*;'
        if re.search(dynamic_func_pattern, line):
            severity = '中危'
            
            # 检查函数名是否来自用户输入
            for indicator in user_input_indicators:
                if indicator in line:
                    severity = '严重'
                    break
            
            vulnerabilities.append({
                'line': line_num,
                'message': "检测到动态函数调用",
                'code_snippet': line_clean,
                'vulnerability_type': "动态函数注入",
                'severity': severity
            })


def detect_variable_variables(lines, vulnerabilities):
    """
    检测可变变量
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测可变变量 ${$var} 或 $$var
        variable_variable_patterns = [
            r'\$\{\s*\$[^}]+\s*\}',  # ${$var}
            r'\$\$[a-zA-Z_\x7f-\xff]',  # $$var
        ]
        
        for pattern in variable_variable_patterns:
            if re.search(pattern, line):
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到可变变量使用",
                    'code_snippet': line_clean,
                    'vulnerability_type': "动态变量注入",
                    'severity': '中危'
                })
                break


def detect_file_inclusion(lines, vulnerabilities):
    """
    检测文件包含函数
    """
    include_functions = {
        "include": "include文件包含",
        "require": "require文件包含",
        "include_once": "include_once文件包含",
        "require_once": "require_once文件包含"
    }
    
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        for func_name, include_type in include_functions.items():
            # 匹配包含函数
            patterns = [
                r'\b' + re.escape(func_name) + r'\s*\(\s*[^;]*\)\s*;',
                r'\b' + re.escape(func_name) + r'\s*\('
            ]
            
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = '高危'
                    
                    # 检查包含路径是否来自用户输入
                    for indicator in user_input_indicators:
                        if indicator in line:
                            severity = '严重'
                            break
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到{include_type}",
                        'code_snippet': line_clean,
                        'vulnerability_type': include_type,
                        'severity': severity
                    })
                    break


def detect_dynamic_method_calls(lines, vulnerabilities):
    """
    检测动态方法调用
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测动态对象方法调用：$object->{$method}()
        dynamic_method_pattern = r'->\s*\{\s*\$[^}]+\s*\}\s*\('
        if re.search(dynamic_method_pattern, line):
            vulnerabilities.append({
                'line': line_num,
                'message': "检测到动态方法调用",
                'code_snippet': line_clean,
                'vulnerability_type': "动态方法注入",
                'severity': '中危'
            })
        
        # 检测动态静态方法调用：Class::{$method}()
        dynamic_static_pattern = r'::\s*\{\s*\$[^}]+\s*\}\s*\('
        if re.search(dynamic_static_pattern, line):
            vulnerabilities.append({
                'line': line_num,
                'message': "检测到动态静态方法调用",
                'code_snippet': line_clean,
                'vulnerability_type': "动态静态方法注入",
                'severity': '中危'
            })


# 增强版检测函数
def detect_php_code_injection_enhanced(php_code):
    """
    PHP动态代码注入漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_dangerous_functions_enhanced(lines, vulnerabilities)
    detect_dynamic_calls_enhanced(lines, vulnerabilities)
    detect_variable_usage_enhanced(lines, vulnerabilities)
    detect_inclusion_enhanced(lines, vulnerabilities)
    
    return vulnerabilities


def detect_dangerous_functions_enhanced(lines, vulnerabilities):
    """
    增强版的危险函数检测
    """
    dangerous_functions = {
        "eval": "代码注入",
        "assert": "代码注入",
        "preg_replace": "代码注入",
        "create_function": "动态函数创建",
        "call_user_func": "动态函数调用",
        "call_user_func_array": "动态函数调用",
        "forward_static_call": "动态函数调用",
        "forward_static_call_array": "动态函数调用",
    }
    
    user_input_sources = [
        r'\$_GET\[[^\]]+\]',
        r'\$_POST\[[^\]]+\]',
        r'\$_REQUEST\[[^\]]+\]',
        r'\$_COOKIE\[[^\]]+\]',
        r'\$_FILES\[[^\]]+\]',
        r'file_get_contents\s*\(\s*[^)]*php://input[^)]*\)'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
            
        for func_name, vuln_type in dangerous_functions.items():
            # 更精确的函数调用匹配，捕获参数内容
            func_pattern = r'(?:\$[a-zA-Z_\x7f-\xff][\w\x7f-\xff]*\s*=\s*)?\b' + re.escape(func_name) + r'\s*\(\s*([^;){]*)\s*\)'
            
            match = re.search(func_pattern, line, re.IGNORECASE)
            if match:
                severity = '高危'
                detailed_type = vuln_type
                
                # 特殊处理preg_replace
                if func_name == 'preg_replace':
                    if re.search(r'/[^/]*/e', line) or re.search(r'[\'"]e[\'"]', line):
                        severity = '严重'
                        detailed_type = "preg_replace代码注入 - 使用/e修饰符"
                    else:
                        continue
                
                # 检查参数是否包含用户输入
                if match.groups():
                    param_content = match.group(1)
                    for user_input_pattern in user_input_sources:
                        if re.search(user_input_pattern, param_content, re.IGNORECASE):
                            severity = '严重'
                            detailed_type = f"{vuln_type} - 用户输入直接执行"
                            break
                
                # 避免重复报告
                if not any(v['line'] == line_num and v['code_snippet'] == line_clean for v in vulnerabilities):
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到危险函数 '{func_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': detailed_type,
                        'severity': severity
                    })


def detect_dynamic_calls_enhanced(lines, vulnerabilities):
    """
    增强版的动态调用检测
    """
    user_input_sources = [
        r'\$_GET\[[^\]]+\]',
        r'\$_POST\[[^\]]+\]',
        r'\$_REQUEST\[[^\]]+\]',
        r'\$_COOKIE\[[^\]]+\]'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
            
        # 检测各种动态调用模式
        dynamic_patterns = [
            (r'\$([a-zA-Z_\x7f-\xff][\w\x7f-\xff]*)\s*\(\s*[^)]*\s*\)\s*;', "动态函数调用"),
            (r'->\s*\{\s*\$([^}]+)\s*\}\s*\(\s*[^)]*\s*\)', "动态方法调用"),
            (r'::\s*\{\s*\$([^}]+)\s*\}\s*\(\s*[^)]*\s*\)', "动态静态方法调用")
        ]
        
        for pattern, call_type in dynamic_patterns:
            match = re.search(pattern, line)
            if match:
                severity = '中危'
                
                # 检查是否使用用户输入
                for user_input_pattern in user_input_sources:
                    if re.search(user_input_pattern, line):
                        severity = '严重'
                        break
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{call_type}",
                    'code_snippet': line_clean,
                    'vulnerability_type': call_type,
                    'severity': severity
                })
                break


def detect_variable_usage_enhanced(lines, vulnerabilities):
    """
    增强版的变量使用检测
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
            
        # 检测可变变量和潜在危险用法
        variable_patterns = [
            (r'\$\{\s*(\$[^}]+)\s*\}', "可变变量"),
            (r'\$\$[a-zA-Z_\x7f-\xff]', "可变变量"),
            (r'extract\s*\([^)]*\)', "extract函数使用")
        ]
        
        for pattern, var_type in variable_patterns:
            if re.search(pattern, line):
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{var_type}使用",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"{var_type}注入",
                    'severity': '中危'
                })
                break


def detect_inclusion_enhanced(lines, vulnerabilities):
    """
    增强版的文件包含检测
    """
    include_functions = ["include", "require", "include_once", "require_once"]
    
    user_input_sources = [
        r'\$_GET\[[^\]]+\]',
        r'\$_POST\[[^\]]+\]',
        r'\$_REQUEST\[[^\]]+\]',
        r'\$_COOKIE\[[^\]]+\]'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
            
        for func_name in include_functions:
            func_pattern = r'\b' + re.escape(func_name) + r'\s*\(\s*([^;)]+)\s*\)'
            match = re.search(func_pattern, line, re.IGNORECASE)
            if match:
                severity = '高危'
                include_type = f"{func_name}文件包含"
                
                # 检查参数是否包含用户输入
                if match.groups():
                    param_content = match.group(1)
                    for user_input_pattern in user_input_sources:
                        if re.search(user_input_pattern, param_content, re.IGNORECASE):
                            severity = '严重'
                            break
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{include_type}",
                    'code_snippet': line_clean,
                    'vulnerability_type': include_type,
                    'severity': severity
                })
                break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 PHP 代码中的动态代码注入漏洞

// 直接代码执行
eval('echo "test";');
eval($_GET['code']);
assert($_POST['assertion']);

// preg_replace with /e modifier (已废弃但可能存在于老代码)
preg_replace('/.*/e', $_GET['code'], $data);
preg_replace("/^(.*)=(.+)$/e", "'\\1'", $input);

// 动态函数创建和调用
$func_name = $_GET['function'];
$func_name();
call_user_func($_POST['callback'], $param);
call_user_func_array($callback, $args);

// 可变变量
${$variable} = 'value';
${$_GET['var_name']} = 'dangerous';

// 动态函数调用
$function = 'system';
$function('ls -la');

// 动态方法调用
$object->{$method_name}();
$class::{$static_method}();

// 文件包含漏洞
include $_GET['page'];
require $_POST['template'];
include_once $user_input;
require_once $_COOKIE['config'];

// create_function 动态函数创建
$func = create_function('$a', 'return ' . $_GET['code'] . ';');

// 相对安全的用法
eval('return 1+1;');
include 'fixed_file.php';
require_once 'constant_path.php';

// 安全示例
echo "正常代码";
$safe_var = 'static_value';
?>
"""

    print("=" * 60)
    print("PHP动态代码注入漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_php_code_injection_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到动态代码注入漏洞")