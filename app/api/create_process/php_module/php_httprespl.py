import re

def detect_http_response_splitting(php_code):
    """
    PHP HTTP响应拆分漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测header函数调用
    detect_header_vulnerabilities(lines, vulnerabilities)
    
    # 检测setcookie函数调用
    detect_setcookie_vulnerabilities(lines, vulnerabilities)
    
    # 检测setrawcookie函数调用
    detect_setrawcookie_vulnerabilities(lines, vulnerabilities)
    
    # 检测header_remove函数调用
    detect_header_remove_vulnerabilities(lines, vulnerabilities)
    
    # 检测重定向漏洞
    detect_redirect_vulnerabilities(lines, vulnerabilities)
    
    return vulnerabilities


def detect_header_vulnerabilities(lines, vulnerabilities):
    """
    检测header函数中的HTTP响应拆分漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE', r'\$_SERVER']
    crlf_patterns = [r'\\r', r'\\n', r'%0d', r'%0a', r'0x0d', r'0x0a']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测header函数调用
        if 'header' in line:
            # 检查是否包含用户输入
            user_input_detected = False
            crlf_injection_risk = False
            
            for indicator in user_input_indicators:
                if re.search(indicator, line):
                    user_input_detected = True
                    break
            
            # 检查CRLF注入风险
            for pattern in crlf_patterns:
                if re.search(pattern, line):
                    crlf_injection_risk = True
                    break
            
            if user_input_detected:
                severity = '高危' if crlf_injection_risk else '中危'
                message = "检测到header函数使用用户输入"
                vuln_type = "HTTP响应拆分"
                
                if crlf_injection_risk:
                    message += " - 可能包含CRLF注入字符"
                    vuln_type = "HTTP响应拆分 - CRLF注入风险"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })


def detect_setcookie_vulnerabilities(lines, vulnerabilities):
    """
    检测setcookie函数中的HTTP响应拆分漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    crlf_patterns = [r'\\r', r'\\n', r'%0d', r'%0a']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测setcookie函数调用
        if 'setcookie' in line:
            user_input_detected = False
            crlf_injection_risk = False
            
            for indicator in user_input_indicators:
                if re.search(indicator, line):
                    user_input_detected = True
                    break
            
            for pattern in crlf_patterns:
                if re.search(pattern, line):
                    crlf_injection_risk = True
                    break
            
            if user_input_detected:
                severity = '高危' if crlf_injection_risk else '中危'
                message = "检测到setcookie函数使用用户输入"
                vuln_type = "Cookie注入 - HTTP响应拆分"
                
                if crlf_injection_risk:
                    message += " - 可能包含CRLF注入字符"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })


def detect_setrawcookie_vulnerabilities(lines, vulnerabilities):
    """
    检测setrawcookie函数中的HTTP响应拆分漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测setrawcookie函数调用
        if 'setrawcookie' in line:
            user_input_detected = False
            
            for indicator in user_input_indicators:
                if re.search(indicator, line):
                    user_input_detected = True
                    break
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到setrawcookie函数使用用户输入 - 原始Cookie值可能包含CRLF",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Cookie注入 - HTTP响应拆分",
                    'severity': '高危'
                })


def detect_header_remove_vulnerabilities(lines, vulnerabilities):
    """
    检测header_remove函数调用
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测header_remove函数调用
        if 'header_remove' in line:
            vulnerabilities.append({
                'line': line_num,
                'message': "检测到header_remove函数 - 可能用于绕过安全头",
                'code_snippet': line_clean,
                'vulnerability_type': "HTTP头操作 - 安全绕过",
                'severity': '低危'
            })


def detect_redirect_vulnerabilities(lines, vulnerabilities):
    """
    检测重定向相关的HTTP响应拆分漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    crlf_patterns = [r'\\r', r'\\n', r'%0d', r'%0a']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测Location重定向
        if 'header' in line and ('Location:' in line or 'location:' in line.lower()):
            user_input_detected = False
            crlf_injection_risk = False
            
            for indicator in user_input_indicators:
                if re.search(indicator, line):
                    user_input_detected = True
                    break
            
            for pattern in crlf_patterns:
                if re.search(pattern, line):
                    crlf_injection_risk = True
                    break
            
            if user_input_detected:
                severity = '高危' if crlf_injection_risk else '中危'
                message = "检测到Location重定向使用用户输入"
                vuln_type = "HTTP响应拆分 - 重定向注入"
                
                if crlf_injection_risk:
                    message += " - 可能包含CRLF注入字符"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })


# 增强版检测函数
def detect_http_response_splitting_enhanced(php_code):
    """
    PHP HTTP响应拆分漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_header_vulnerabilities(lines, vulnerabilities)
    detect_content_type_vulnerabilities(lines, vulnerabilities)
    detect_custom_header_vulnerabilities(lines, vulnerabilities)
    detect_complex_injection_patterns(lines, vulnerabilities)
    
    return vulnerabilities


def detect_comprehensive_header_vulnerabilities(lines, vulnerabilities):
    """
    增强版的header函数漏洞检测
    """
    header_functions = ['header', 'setcookie', 'setrawcookie']
    user_input_sources = [
        r'\$_GET\[[^\]]+\]',
        r'\$_POST\[[^\]]+\]',
        r'\$_REQUEST\[[^\]]+\]',
        r'\$_COOKIE\[[^\]]+\]',
        r'\$_SERVER\[[^\]]+\]'
    ]
    crlf_patterns = [r'\\r\\n', r'\\n\\r', r'%0d%0a', r'%0a%0d']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
        
        for func_name in header_functions:
            if func_name in line:
                # 检查是否包含用户输入
                user_input_found = False
                for user_input_pattern in user_input_sources:
                    if re.search(user_input_pattern, line):
                        user_input_found = True
                        break
                
                # 检查CRLF注入风险
                crlf_found = False
                for crlf_pattern in crlf_patterns:
                    if re.search(crlf_pattern, line):
                        crlf_found = True
                        break
                
                if user_input_found:
                    severity = '高危' if crlf_found else '中危'
                    
                    if func_name == 'header':
                        vuln_type = "HTTP响应拆分"
                        message = "检测到header函数使用用户输入"
                    elif func_name == 'setcookie':
                        vuln_type = "Cookie注入 - HTTP响应拆分"
                        message = "检测到setcookie函数使用用户输入"
                    else:  # setrawcookie
                        vuln_type = "Cookie注入 - HTTP响应拆分"
                        message = "检测到setrawcookie函数使用用户输入 - 原始Cookie值风险"
                        severity = '高危'
                    
                    if crlf_found:
                        message += " - 检测到CRLF注入字符"
                        vuln_type += " - CRLF注入风险"
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': vuln_type,
                        'severity': severity
                    })


def detect_content_type_vulnerabilities(lines, vulnerabilities):
    """
    检测Content-Type相关的HTTP响应拆分漏洞
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
        
        # 检测Content-Type设置
        if 'header' in line and ('Content-Type:' in line or 'content-type:' in line.lower()):
            user_input_found = False
            for user_input_pattern in user_input_sources:
                if re.search(user_input_pattern, line):
                    user_input_found = True
                    break
            
            if user_input_found:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到Content-Type设置使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "HTTP响应拆分 - Content-Type注入",
                    'severity': '中危'
                })


def detect_custom_header_vulnerabilities(lines, vulnerabilities):
    """
    检测自定义HTTP头相关的漏洞
    """
    user_input_sources = [
        r'\$_GET\[[^\]]+\]',
        r'\$_POST\[[^\]]+\]',
        r'\$_REQUEST\[[^\]]+\]',
        r'\$_COOKIE\[[^\]]+\]',
        r'\$_SERVER\[[^\]]+\]'
    ]
    
    # 标准HTTP头列表（排除这些以避免误报）
    standard_headers = [
        'Location:', 'Content-Type:', 'Set-Cookie:', 'Cache-Control:',
        'Expires:', 'Last-Modified:', 'ETag:', 'Accept-Ranges:',
        'Content-Length:', 'Content-Disposition:', 'Content-Encoding:',
        'Content-Language:', 'Vary:', 'Pragma:', 'Referrer-Policy:',
        'X-Content-Type-Options:', 'X-Frame-Options:', 'X-XSS-Protection:'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        # 检测header函数调用
        if 'header' in line:
            # 检查是否是自定义头（非标准头）
            is_standard_header = any(header in line for header in standard_headers)
            
            if not is_standard_header and ':' in line:
                # 检查是否包含用户输入
                user_input_found = False
                for user_input_pattern in user_input_sources:
                    if re.search(user_input_pattern, line):
                        user_input_found = True
                        break
                
                # 检查CRLF风险
                crlf_risk = bool(re.search(r'\\r|\\n|%0d|%0a', line))
                
                if user_input_found:
                    severity = '高危' if crlf_risk else '中危'
                    message = "检测到自定义HTTP头使用用户输入"
                    vuln_type = "HTTP响应拆分 - 自定义头注入"
                    
                    if crlf_risk:
                        message += " - 可能包含CRLF注入字符"
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': vuln_type,
                        'severity': severity
                    })


def detect_complex_injection_patterns(lines, vulnerabilities):
    """
    检测复杂的注入模式
    """
    injection_patterns = [
        # 字符串拼接模式
        (r'header\s*\(\s*[^)]*\.[^)]*\$_', "字符串拼接注入"),
        # 变量插值模式
        (r'header\s*\(\s*[^)]*\"[^\"]*\$\{[^}]+\}[^\"]*\"', "变量插值注入"),
        # 多重CRLF模式
        (r'(\\r\\n|\\n\\r|%0d%0a|%0a%0d).*(\\r\\n|\\n\\r|%0d%0a|%0a%0d)', "多重CRLF注入"),
        # header_remove模式
        (r'header_remove\s*\(\s*[\'"]X-', "安全头移除"),
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        for pattern, pattern_type in injection_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                if pattern_type == "安全头移除":
                    severity = '低危'
                    vuln_type = "HTTP头操作 - 安全绕过"
                    message = "检测到header_remove函数移除安全头"
                else:
                    severity = '高危'
                    vuln_type = f"HTTP响应拆分 - {pattern_type}"
                    message = f"检测到{pattern_type}模式"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })
                break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 HTTP响应拆分漏洞

// 不安全的header调用 - 使用用户输入
header("X-Custom-Header: " . $_GET['header_value']);
header("Location: " . $_POST['redirect_url']);
header("Content-Type: " . $_REQUEST['content_type']);

// 不安全的header调用 - 可能包含CRLF
header("Custom: value\\r\\nInjected-Header: malicious");
header("Set-Cookie: session=" . $_GET['session'] . "\\r\\nInjected-Header: test");

// 不安全的setcookie调用
setcookie("user", $_GET['username']);
setcookie("preferences", $_POST['prefs'], time() + 3600);
setrawcookie("raw_data", $_REQUEST['data']);

// 重定向漏洞 - HTTP响应拆分
header("Location: " . $_GET['url']);
header('Location: ' . $_POST['return_to']);

// Content-Type注入
header("Content-Type: " . $_COOKIE['mime_type']);

// 自定义头注入
header("X-Forwarded-For: " . $_SERVER['HTTP_X_FORWARDED_FOR']);
header("User-Agent: " . $_GET['agent']);

// 相对安全的header调用
header("Content-Type: text/html; charset=utf-8");
header("Location: /login.php");
header("Cache-Control: no-cache");

// 经过过滤的安全调用
$filtered_header = str_replace(array("\\r", "\\n"), '', $_GET['header']);
header("X-Filtered: " . $filtered_header);

$safe_url = filter_var($_GET['url'], FILTER_SANITIZE_URL);
header("Location: " . $safe_url);

// 使用header_remove
header_remove("X-Powered-By");
header_remove();

// 安全的setcookie调用
setcookie("safe_cookie", "fixed_value", time() + 3600);
setcookie("user_cookie", htmlspecialchars($user_data), time() + 3600);

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP HTTP响应拆分漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_http_response_splitting_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到HTTP响应拆分漏洞")