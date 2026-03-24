import re

def detect_json_injection(php_code):
    """
    PHP JSON注入漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测json_encode函数调用
    detect_json_encode_vulnerabilities(lines, vulnerabilities)
    
    # 检测手动JSON构建
    detect_manual_json_building(lines, vulnerabilities)
    
    # 检测json_decode函数调用
    detect_json_decode_vulnerabilities(lines, vulnerabilities)
    
    # 检测JSON输出问题
    detect_json_output_vulnerabilities(lines, vulnerabilities)
    
    # 检测JavaScript中的JSON使用
    detect_javascript_json_vulnerabilities(lines, vulnerabilities)
    
    # 检测JSONP回调函数
    detect_jsonp_vulnerabilities(lines, vulnerabilities)
    
    return vulnerabilities


def detect_json_encode_vulnerabilities(lines, vulnerabilities):
    """
    检测json_encode函数中的注入漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    sanitization_functions = ['json_encode', 'addslashes', 'htmlspecialchars', 'htmlentities', 'filter_var', 'intval', 'floatval']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测json_encode函数调用
        if 'json_encode' in line:
            user_input_detected = False
            unsanitized_input = False
            is_in_script_tag = False
            
            # 检查是否在script标签中
            if 'script' in line.lower() or 'var ' in line:
                is_in_script_tag = True
            
            # 检查是否包含用户输入
            for indicator in user_input_indicators:
                if re.search(indicator, line):
                    user_input_detected = True
                    
                    # 检查是否经过适当的过滤
                    has_sanitization = any(func in line for func in sanitization_functions)
                    if not has_sanitization:
                        unsanitized_input = True
                    break
            
            if user_input_detected:
                severity = '高危' if (unsanitized_input or is_in_script_tag) else '中危'
                message = "检测到json_encode使用用户输入"
                vuln_type = "JSON注入"
                
                if unsanitized_input:
                    message += " - 未经过适当过滤"
                if is_in_script_tag:
                    message += " - 在JavaScript中直接使用"
                    vuln_type = "JSON注入 - XSS风险"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })


def detect_manual_json_building(lines, vulnerabilities):
    """
    检测手动JSON构建（字符串拼接）中的漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    json_patterns = [r'\{\"', r'\"\:', r',\"', r'\"\}', r"\'\{", r"\'\"", r"\'\]", r"\{\'"]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测JSON字符串拼接模式
        is_json_building = any(re.search(pattern, line) for pattern in json_patterns)
        
        if is_json_building:
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到手动JSON字符串拼接使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "JSON注入 - 手动构建",
                    'severity': '高危'
                })


def detect_json_decode_vulnerabilities(lines, vulnerabilities):
    """
    检测json_decode函数中的漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测json_decode函数调用
        if 'json_decode' in line:
            user_input_detected = False
            object_injection_risk = False
            
            # 检查是否包含用户输入
            for indicator in user_input_indicators:
                if re.search(indicator, line):
                    user_input_detected = True
                    
                    # 检查是否返回对象（第二个参数为false或缺失）
                    if not re.search(r'true|1', line, re.IGNORECASE):
                        object_injection_risk = True
                    break
            
            if user_input_detected:
                severity = '中危'
                message = "检测到json_decode使用用户输入"
                vuln_type = "JSON反序列化"
                
                if object_injection_risk:
                    severity = '高危'
                    message += " - 返回对象可能存在对象注入风险"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })


def detect_json_output_vulnerabilities(lines, vulnerabilities):
    """
    检测JSON输出相关问题
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测echo/print输出JSON
        if ('echo' in line or 'print' in line) and 'json_encode' in line:
            # 检查是否设置正确的Content-Type
            has_content_type = 'header' in line and ('Content-Type' in line or 'content-type' in line.lower())
            
            # 检查是否在script标签中
            is_in_script = 'script' in line.lower()
            
            # 只有在纯PHP输出（不在script标签中）且没有Content-Type时才报告
            if not has_content_type and not is_in_script:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到JSON输出未设置Content-Type头",
                    'code_snippet': line_clean,
                    'vulnerability_type': "JSON注入 - 内容嗅探",
                    'severity': '低危'
                })


def detect_javascript_json_vulnerabilities(lines, vulnerabilities):
    """
    检测JavaScript中的JSON使用漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检查内联JavaScript中的JSON使用
        if 'script' in line.lower():
            # 检测JSON.parse使用PHP变量
            if 'JSON.parse' in line and ('<?=' in line or '<?php' in line):
                # 检查是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到JavaScript中直接使用PHP用户输入进行JSON解析",
                        'code_snippet': line_clean,
                        'vulnerability_type': "JSON注入 - 客户端解析",
                        'severity': '高危'
                    })
            
            # 检测直接PHP变量输出到JavaScript
            elif ('<?=' in line or '<?php' in line) and any(indicator in line for indicator in user_input_indicators):
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到JavaScript中直接输出PHP用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "JSON注入 - 客户端XSS",
                    'severity': '高危'
                })


def detect_jsonp_vulnerabilities(lines, vulnerabilities):
    """
    检测JSONP回调函数漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    jsonp_patterns = ['callback=', 'jsonp=', 'cb=']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测JSONP模式
        is_jsonp = any(pattern in line for pattern in jsonp_patterns)
        
        if is_jsonp:
            # 检查回调函数名是否来自用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到JSONP回调函数使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "JSONP注入",
                    'severity': '中危'
                })


# 增强版检测函数
def detect_json_injection_enhanced(php_code):
    """
    PHP JSON注入漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_json_vulnerabilities(lines, vulnerabilities)
    detect_advanced_injection_patterns(lines, vulnerabilities)
    detect_context_specific_vulnerabilities(lines, vulnerabilities)
    
    return vulnerabilities


def detect_comprehensive_json_vulnerabilities(lines, vulnerabilities):
    """
    增强版的JSON漏洞检测
    """
    user_input_sources = [
        r'\$_GET\[[^\]]+\]',
        r'\$_POST\[[^\]]+\]',
        r'\$_REQUEST\[[^\]]+\]',
        r'\$_COOKIE\[[^\]]+\]'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
        
        # 检测json_encode使用用户输入
        if 'json_encode' in line:
            user_input_found = False
            for user_input_pattern in user_input_sources:
                if re.search(user_input_pattern, line):
                    user_input_found = True
                    break
            
            if user_input_found:
                # 检查过滤情况
                safe_patterns = [
                    r'htmlspecialchars\s*\([^)]*\)',
                    r'htmlentities\s*\([^)]*\)',
                    r'filter_var\s*\([^)]*\)',
                    r'intval\s*\([^)]*\)',
                    r'floatval\s*\([^)]*\)'
                ]
                
                has_sanitization = any(re.search(pattern, line) for pattern in safe_patterns)
                
                severity = '高危' if not has_sanitization else '中危'
                message = "检测到json_encode使用用户输入"
                
                if not has_sanitization:
                    message += " - 未经过适当过滤"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': "JSON注入",
                    'severity': severity
                })
        
        # 检测json_decode使用用户输入
        elif 'json_decode' in line:
            user_input_found = False
            for user_input_pattern in user_input_sources:
                if re.search(user_input_pattern, line):
                    user_input_found = True
                    break
            
            if user_input_found:
                # 检查是否使用数组返回（更安全）
                uses_array = re.search(r'true|1', line, re.IGNORECASE)
                
                severity = '高危' if not uses_array else '中危'
                message = "检测到json_decode使用用户输入"
                
                if not uses_array:
                    message += " - 返回对象可能存在对象注入风险"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': "JSON反序列化",
                    'severity': severity
                })


def detect_advanced_injection_patterns(lines, vulnerabilities):
    """
    检测高级注入模式
    """
    injection_patterns = [
        # 复杂的字符串拼接
        (r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'\"][^{]*\{[^}]*\}[^}]*[\'\"]\s*\.\s*\$_', "复杂JSON拼接"),
        # 多层嵌套的用户输入
        (r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'\"][^{]*\{[^{]*\{[^}]*\}[^}]*\}[^}]*[\'\"]\s*\.\s*\$_', "嵌套JSON拼接"),
        # 动态属性名
        (r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*\[\s*\$_[^\]]+\]\s*=\s*[^;]', "动态JSON键名"),
        # 不安全的JSON序列化
        (r'json_encode\s*\(\s*[^)]*\$\{[^}]+\}[^)]*\)', "变量插值JSON")
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        for pattern, pattern_type in injection_patterns:
            if re.search(pattern, line):
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{pattern_type}模式",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"JSON注入 - {pattern_type}",
                    'severity': '高危'
                })
                break


def detect_context_specific_vulnerabilities(lines, vulnerabilities):
    """
    检测上下文特定的JSON漏洞
    """
    contexts = [
        # JavaScript上下文
        (r'<script[^>]*>.*\$_GET.*</script>', "JavaScript上下文用户输入"),
        (r'<script[^>]*>.*\$_POST.*</script>', "JavaScript上下文用户输入"),
        (r'var\s+\w+\s*=\s*<?=.*\$_', "PHP内联JavaScript"),
        # AJAX响应上下文
        (r'echo\s+json_encode.*\$_GET', "AJAX响应用户输入"),
        (r'echo\s+json_encode.*\$_POST', "AJAX响应用户输入"),
        # 配置文件上下文
        (r'\$config\s*=\s*json_decode.*\$_', "配置JSON反序列化")
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        for pattern, context_type in contexts:
            if re.search(pattern, line, re.IGNORECASE | re.DOTALL):
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{context_type}",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"JSON注入 - {context_type}",
                    'severity': '高危'
                })
                break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 JSON注入漏洞

// 不安全的json_encode使用
$data1 = json_encode($_GET);
$data2 = json_encode(array('user' => $_POST['username']));
$data3 = json_encode($_REQUEST['data']);

// 手动JSON构建 - 高危
$json1 = '{"name": "' . $_GET['name'] . '", "age": ' . $_POST['age'] . '}';
$json2 = "{\\"email\\": \\"" . $_REQUEST['email'] . "\\"}";

// 不安全的json_decode使用
$obj1 = json_decode($_GET['json_data']);
$obj2 = json_decode($_POST['data']); // 返回对象
$arr1 = json_decode($_REQUEST['json'], true); // 返回数组，相对安全

// JSON输出未设置Content-Type
echo json_encode($data);
print json_encode($_POST);

// JavaScript中的JSON注入风险
?>
<script>
var data = JSON.parse('<?= json_encode($_GET) ?>');
var userData = <?= $_POST['json_data'] ?>;
var config = <?php echo json_encode($_REQUEST); ?>;
</script>

// JSONP回调注入
$callback = $_GET['callback'];
echo $callback . '(' . json_encode($data) . ')';

// 相对安全的JSON使用
// 经过过滤的输入
$filtered_data = array(
    'name' => htmlspecialchars($_POST['name']),
    'email' => filter_var($_POST['email'], FILTER_SANITIZE_EMAIL)
);
$safe_json = json_encode($filtered_data);

// 设置正确的Content-Type
header('Content-Type: application/json; charset=utf-8');
echo json_encode($data);

// 安全的json_decode使用
$json_input = file_get_contents('php://input');
$decoded = json_decode($json_input, true); // 返回数组

// 白名单验证回调函数
$allowed_callbacks = ['myCallback', 'parseData'];
$callback = in_array($_GET['callback'], $allowed_callbacks) ? $_GET['callback'] : 'defaultCallback';
echo $callback . '(' . json_encode($data) . ')';

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP JSON注入漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_json_injection_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到JSON注入漏洞")