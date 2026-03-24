import re

def detect_php_command_injection(php_code):
    """
    PHP命令注入漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 定义危险函数及其对应的漏洞类型
    dangerous_functions = {
        "system": "命令注入",
        "exec": "命令注入", 
        "shell_exec": "命令注入",
        "passthru": "命令注入",
        "proc_open": "命令注入",
        "popen": "命令注入",
        "eval": "代码注入",
        "assert": "代码注入"
    }
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 构建正则表达式模式，匹配危险函数调用
    # 模式解释：匹配函数名后跟括号，括号内可以有各种字符
    function_patterns = {}
    for func_name in dangerous_functions.keys():
        # 匹配函数调用，包括各种可能的空格和参数
        function_patterns[func_name] = re.compile(
            r'\b' + re.escape(func_name) + r'\s*\(\s*[^;]*\)\s*;',
            re.IGNORECASE
        )
    
    # 遍历每一行代码
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#'):
            continue
            
        # 检查每一行是否包含危险函数
        for func_name, pattern in function_patterns.items():
            if pattern.search(line):
                vuln_type = dangerous_functions[func_name]
                severity = '高危'
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到危险函数 '{func_name}'",
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })
                break  # 避免同一行重复检测多个函数
    
    return vulnerabilities


# 增强版检测函数，提供更精确的匹配
def detect_php_command_injection_enhanced(php_code):
    """
    PHP命令注入漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    dangerous_functions = {
        "system": "命令注入",
        "exec": "命令注入", 
        "shell_exec": "命令注入",
        "passthru": "命令注入",
        "proc_open": "命令注入",
        "popen": "命令注入",
        "eval": "代码注入",
        "assert": "代码注入"
    }
    
    lines = php_code.split('\n')
    
    # 更精确的模式：匹配赋值语句或直接调用中的危险函数
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和注释
        if not line_clean or line_clean.startswith(('//', '#')) or line_clean.startswith('/*'):
            continue
        
        # 检查每个危险函数
        for func_name, vuln_type in dangerous_functions.items():
            # 多种匹配模式以提高检测率
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
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到危险函数 '{func_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': vuln_type,
                        'severity': severity
                    })
                    break  # 找到一个匹配就跳出内层循环
    
    return vulnerabilities


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 PHP 代码中的命令注入漏洞

// 危险函数调用示例
$output1 = shell_exec('ls -la');
$result = system('dir ' . $_GET['path']);
$data = exec($_POST['command']);
$test = passthru('cat ' . $_REQUEST['file']);

// 代码执行示例
eval('echo "test";');
assert('some_condition');

// 安全示例
echo "Hello World";
$safe = escapeshellarg($_GET['input']);

// 更多测试用例
popen($cmd, 'r');
proc_open($command, $descriptorspec, $pipes);
?>
"""

    print("=" * 60)
    print("PHP命令注入漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用基础版本检测
    results = detect_php_command_injection(test_php_code)
    
    # 如果没有检测到，尝试增强版本
    if not results:
        results = detect_php_command_injection_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到命令注入漏洞")