import re

def detect_php_unserialize_vulnerability(php_code):
    """
    PHP不安全反序列化漏洞检测主函数 - 使用正则表达式版本
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
        "unserialize": "不安全反序列化",
        "json_decode": "JSON反序列化",
    }
    
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER']
    
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
                    # 设置基础严重程度
                    severity = '高危' if func_name == 'unserialize' else '中危'
                    detailed_type = vuln_type
                    
                    # 检查是否包含用户输入
                    for indicator in user_input_indicators:
                        if indicator in line:
                            severity = '严重'
                            detailed_type = f"{vuln_type} - 用户输入直接反序列化"
                            break
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到危险函数 '{func_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': detailed_type,
                        'severity': severity
                    })
                    break  # 找到一个匹配就跳出内层循环


def detect_magic_methods(lines, vulnerabilities):
    """
    检测包含魔术方法的类定义
    """
    dangerous_magic_methods = {
        '__wakeup': '反序列化时自动调用',
        '__destruct': '对象销毁时自动调用',
        '__toString': '对象被当作字符串时调用',
        '__call': '调用不可访问方法时调用',
        '__callStatic': '静态调用不可访问方法时调用'
    }
    
    # 状态跟踪
    in_class = False
    current_class = ""
    class_brace_count = 0
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or (line_clean.startswith('/*') and not in_class):
            # 如果在类内部，仍然需要处理多行注释
            if not in_class:
                continue
        
        # 检测类定义开始
        class_match = re.search(r'class\s+([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)', line)
        if class_match and not in_class:
            in_class = True
            current_class = class_match.group(1)
            class_brace_count = line.count('{') - line.count('}')
            continue
        
        # 如果在类内部，更新大括号计数
        if in_class:
            class_brace_count += line.count('{')
            class_brace_count -= line.count('}')
            
            # 检测魔术方法
            for method_name, description in dangerous_magic_methods.items():
                # 匹配方法定义：可选的可见性修饰符 + function + 方法名 + 参数
                method_pattern = r'(?:public|private|protected)?\s*function\s+' + re.escape(method_name) + r'\s*\([^)]*\)'
                if re.search(method_pattern, line):
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"类 '{current_class}' 中包含危险魔术方法 '{method_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"反序列化魔术方法 - {description}",
                        'severity': '中危'
                    })
            
            # 检查类是否结束
            if class_brace_count <= 0 and in_class:
                in_class = False
                current_class = ""


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
        "unserialize": "不安全反序列化",
        "json_decode": "JSON反序列化",
    }
    
    user_input_patterns = [
        r'\$_GET\s*\[[^\]]+\]',
        r'\$_POST\s*\[[^\]]+\]',
        r'\$_REQUEST\s*\[[^\]]+\]',
        r'\$_COOKIE\s*\[[^\]]+\]',
        r'\$_FILES\s*\[[^\]]+\]',
        r'\$_SERVER\s*\[[^\]]+\]',
        r'file_get_contents\s*\(\s*[\'"]php://input[\'"]\s*\)',
        r'php://input'
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
                severity = '高危' if func_name == 'unserialize' else '中危'
                detailed_type = vuln_type
                
                # 检查参数是否包含用户输入
                if match.groups():
                    param_content = match.group(1)
                    for user_input_pattern in user_input_patterns:
                        if re.search(user_input_pattern, param_content, re.IGNORECASE):
                            severity = '严重'
                            detailed_type = f"{vuln_type} - 用户输入直接反序列化"
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


def detect_magic_methods_enhanced(lines, vulnerabilities):
    """
    增强版的魔术方法检测
    """
    dangerous_magic_methods = {
        '__wakeup': '反序列化时自动调用',
        '__destruct': '对象销毁时自动调用',
        '__toString': '对象被当作字符串时调用',
        '__call': '调用不可访问方法时调用',
        '__callStatic': '静态调用不可访问方法时调用',
        '__get': '访问不可访问属性时调用',
        '__set': '设置不可访问属性时调用',
        '__isset': '对不可访问属性调用isset()或empty()时调用',
        '__unset': '对不可访问属性调用unset()时调用',
        '__sleep': '序列化时调用',
        '__invoke': '当对象被当作函数调用时调用'
    }
    
    # 状态跟踪
    in_class = False
    current_class = ""
    brace_stack = []
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和注释（但在类内部时需要继续处理）
        if not line_clean:
            continue
            
        # 检测多行注释开始/结束
        if '/*' in line and '*/' not in line:
            continue
        if '*/' in line and '/*' not in line:
            continue
            
        # 跳过单行注释（除非在类内部）
        if line_clean.startswith('//') or line_clean.startswith('#') or (line_clean.startswith('/*') and '*/' in line_clean):
            if not in_class:
                continue
        
        # 检测类定义开始
        class_match = re.search(r'class\s+([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*(\{|extends|implements)', line)
        if class_match and not in_class:
            in_class = True
            current_class = class_match.group(1)
            # 初始化大括号计数
            brace_count = line.count('{') - line.count('}')
            brace_stack = [brace_count] if brace_count > 0 else [0]
            continue
        
        # 如果在类内部
        if in_class and current_class:
            # 更新大括号计数
            if '{' in line:
                brace_stack.append(brace_stack[-1] + line.count('{'))
            if '}' in line:
                if brace_stack:
                    brace_stack[-1] -= line.count('}')
                    if brace_stack[-1] <= 0:
                        brace_stack.pop()
            
            # 检测魔术方法
            for method_name, description in dangerous_magic_methods.items():
                # 更精确的方法匹配
                method_pattern = r'(?:(?:public|private|protected|static|\s)*)\bfunction\s+' + re.escape(method_name) + r'\s*\([^)]*\)\s*\{?'
                if re.search(method_pattern, line):
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"类 '{current_class}' 中包含危险魔术方法 '{method_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"反序列化魔术方法 - {description}",
                        'severity': '中危'
                    })
            
            # 检查类是否结束
            if not brace_stack and in_class:
                in_class = False
                current_class = ""


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 PHP 代码中的不安全反序列化漏洞

// 危险函数调用示例
$data1 = unserialize($_GET['data']);
$data2 = unserialize($_POST['user_data']);
$data3 = unserialize($input);
$data4 = json_decode($_REQUEST['json']);

// 文件操作中的反序列化
$file_data = file_get_contents('data.txt');
$object = unserialize($file_data);

// 相对安全的用法（但仍有风险）
$encoded = base64_decode($_GET['data']);
$decoded = unserialize($encoded);

// 包含危险魔术方法的类
class ExploitableClass {
    private $command;

    public function __wakeup() {
        // 反序列化时自动执行 - 可能被利用
        if (isset($this->command)) {
            system($this->command);
        }
    }

    public function __destruct() {
        // 对象销毁时执行 - 可能被利用
        echo "执行清理操作";
    }

    public function __toString() {
        return $this->command;
    }
}

class AnotherVulnerableClass {
    public $data;

    public function __call($name, $arguments) {
        // 调用不存在方法时执行
        call_user_func_array($name, $arguments);
    }
}

// 安全示例
$safe_data = json_decode('{"key": "value"}', true);
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
        print("未检测到不安全反序列化漏洞")