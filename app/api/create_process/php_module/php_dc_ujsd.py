import re

def detect_php_unserialize_vulnerability(php_code):
    """
    PHP不安全的反序列化漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测危险的反序列化函数
    detect_dangerous_functions(lines, vulnerabilities)
    
    # 检测包含魔术方法的类
    detect_magic_methods(lines, vulnerabilities)
    
    return vulnerabilities


def detect_dangerous_functions(lines, vulnerabilities):
    """
    检测危险的反序列化函数调用
    """
    dangerous_functions = {
        "unserialize": "不安全的反序列化",
        "json_decode": "JSON反序列化",
    }
    
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER', 'php://input']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#'):
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
                    # 分析严重程度
                    severity = '中危'
                    detailed_type = vuln_type
                    
                    # 检查是否包含用户输入
                    for indicator in user_input_indicators:
                        if indicator in line:
                            severity = '高危'
                            detailed_type = f"{vuln_type} - 用户输入直接反序列化"
                            break
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到潜在危险函数 '{func_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': detailed_type,
                        'severity': severity
                    })
                    break  # 找到一个匹配就跳出内层循环


def detect_magic_methods(lines, vulnerabilities):
    """
    检测包含魔术方法的类定义
    """
    magic_methods = {
        '__wakeup': '反序列化时自动调用',
        '__destruct': '对象销毁时自动调用',
        '__toString': '对象被当作字符串时调用',
        '__construct': '构造函数',
        '__call': '调用不可访问方法时调用'
    }
    
    in_class = False
    current_class = ""
    class_start_line = 0
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#'):
            continue
        
        # 检测类定义开始
        class_match = re.search(r'class\s+([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)', line)
        if class_match and not in_class:
            in_class = True
            current_class = class_match.group(1)
            class_start_line = line_num
            continue
        
        # 检测类定义结束（简单通过大括号匹配）
        if in_class and '}' in line_clean and '{' not in line_clean:
            # 简单的结束检测，实际应该使用更复杂的括号匹配
            in_class = False
            current_class = ""
            continue
        
        # 在类内部检测魔术方法
        if in_class:
            for method_name, description in magic_methods.items():
                # 匹配方法定义
                method_pattern = r'(?:public|private|protected)?\s*function\s+' + re.escape(method_name) + r'\s*\([^)]*\)'
                if re.search(method_pattern, line):
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"类 '{current_class}' 中包含魔术方法 '{method_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"反序列化魔术方法 - {description}",
                        'severity': '中危'
                    })


# 增强版检测函数
def detect_php_unserialize_vulnerability_enhanced(php_code):
    """
    PHP不安全反序列化漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_dangerous_functions_enhanced(lines, vulnerabilities)
    detect_magic_methods_enhanced(lines, vulnerabilities)
    
    return vulnerabilities


def detect_dangerous_functions_enhanced(lines, vulnerabilities):
    """
    增强版的危险函数检测
    """
    dangerous_functions = {
        "unserialize": "不安全的反序列化",
        "json_decode": "JSON反序列化",
    }
    
    user_input_sources = [
        r'\$_GET\[[^\]]+\]',
        r'\$_POST\[[^\]]+\]', 
        r'\$_REQUEST\[[^\]]+\]',
        r'\$_COOKIE\[[^\]]+\]',
        r'\$_FILES\[[^\]]+\]',
        r'\$_SERVER\[[^\]]+\]',
        r'php://input',
        r'file_get_contents\s*\(\s*[^)]*php://input[^)]*\)',
        r'fopen\s*\(\s*[^)]*php://input[^)]*\)'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
            
        for func_name, vuln_type in dangerous_functions.items():
            # 更精确的函数调用匹配
            func_pattern = r'(?:\$[a-zA-Z_\x7f-\xff][\w\x7f-\xff]*\s*=\s*)?\b' + re.escape(func_name) + r'\s*\(\s*([^;]*)\s*\)'
            
            match = re.search(func_pattern, line, re.IGNORECASE)
            if match:
                severity = '中危'
                detailed_type = vuln_type
                
                # 检查参数是否包含用户输入
                param_content = match.group(1) if match.groups() else ""
                
                for user_input_pattern in user_input_sources:
                    if re.search(user_input_pattern, param_content, re.IGNORECASE):
                        severity = '高危'
                        detailed_type = f"{vuln_type} - 用户输入直接反序列化"
                        break
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到潜在危险函数 '{func_name}'",
                    'code_snippet': line_clean,
                    'vulnerability_type': detailed_type,
                    'severity': severity
                })


def detect_magic_methods_enhanced(lines, vulnerabilities):
    """
    增强版的魔术方法检测
    """
    magic_methods = {
        '__wakeup': '反序列化时自动调用',
        '__destruct': '对象销毁时自动调用',
        '__toString': '对象被当作字符串时调用',
        '__call': '调用不可访问方法时调用',
        '__callStatic': '静态调用不可访问方法时调用',
        '__get': '访问不可访问属性时调用',
        '__set': '设置不可访问属性时调用'
    }
    
    # 检测类定义和魔术方法
    class_pattern = r'class\s+([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)'
    method_pattern = r'(?:public|private|protected)?\s*function\s+(__\w+)\s*\([^)]*\)'
    
    current_class = None
    brace_count = 0
    in_class = False
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        # 检测类开始
        class_match = re.search(class_pattern, line)
        if class_match and not in_class:
            current_class = class_match.group(1)
            in_class = True
            brace_count = 0
            # 计算起始行的大括号
            brace_count += line.count('{')
            brace_count -= line.count('}')
            continue
        
        if in_class:
            brace_count += line.count('{')
            brace_count -= line.count('}')
            
            # 检测魔术方法
            method_match = re.search(method_pattern, line)
            if method_match and current_class:
                method_name = method_match.group(1)
                if method_name in magic_methods:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"类 '{current_class}' 中包含魔术方法 '{method_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"反序列化魔术方法 - {magic_methods[method_name]}",
                        'severity': '中危'
                    })
            
            # 类结束
            if brace_count <= 0 and in_class:
                in_class = False
                current_class = None


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 PHP 代码中的不安全反序列化漏洞

// 不安全的unserialize使用
$data1 = unserialize($_GET['data']);
$data2 = unserialize(file_get_contents('php://input'));
$data3 = unserialize($user_input);

// 相对安全的unserialize使用（但仍有风险）
$safe_data = unserialize(base64_decode($encoded_data));

// JSON反序列化
$json1 = json_decode($_POST['json_data']);  // 返回对象
$json2 = json_decode($_POST['json_data'], true);  // 返回数组

// 包含魔术方法的类（可能被反序列化利用）
class VulnerableClass {
    private $command;

    public function __wakeup() {
        // 反序列化时自动执行
        system($this->command);
    }

    public function __destruct() {
        // 对象销毁时执行
        echo "Object destroyed";
    }
}

class SafeClass {
    public function __construct() {
        // 构造函数
    }
}

// 安全示例
$safe_json = json_decode('{"key": "value"}', true);
echo "正常代码";
?>
"""

    print("=" * 60)
    print("PHP不安全反序列化漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_php_unserialize_vulnerability_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到反序列化漏洞")