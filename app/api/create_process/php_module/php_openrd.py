import re

def detect_open_redirect_vulnerability(php_code):
    """
    PHP开放重定向漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测header函数重定向
    detect_header_redirects(lines, vulnerabilities)
    
    # 检测HTML meta refresh重定向
    detect_meta_refresh_redirects(lines, vulnerabilities)
    
    # 检测JavaScript重定向
    detect_javascript_redirects(lines, vulnerabilities)
    
    # 检测die/exit后的重定向
    detect_die_exit_redirects(lines, vulnerabilities)
    
    # 检测自定义重定向函数
    detect_custom_redirect_functions(lines, vulnerabilities)
    
    # 检测框架重定向函数
    detect_framework_redirects(lines, vulnerabilities)
    
    # 检测URL拼接重定向
    detect_url_concatenation_redirects(lines, vulnerabilities)
    
    return vulnerabilities


def detect_header_redirects(lines, vulnerabilities):
    """
    检测header函数中的重定向漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    external_url_patterns = [r'http://', r'https://', r'//', r'www\.']
    validation_patterns = ['in_array', 'strpos', 'preg_match', 'filter_var', 'whitelist', 'allowed', 'validate']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测header Location重定向
        if 'header' in line and ('Location:' in line or 'location:' in line.lower()):
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            # 检查是否重定向到外部域名
            external_url_detected = any(re.search(pattern, line) for pattern in external_url_patterns)
            
            # 检查是否有白名单验证
            no_validation = not any(pattern in line for pattern in validation_patterns)
            
            if user_input_detected and external_url_detected and no_validation:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到开放重定向漏洞 - Location重定向使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "开放重定向",
                    'severity': '中危'
                })
        
        # 检测header Refresh重定向
        elif 'header' in line and ('Refresh:' in line or 'refresh:' in line.lower()):
            # 检查URL是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到Refresh重定向使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "开放重定向 - Refresh重定向",
                    'severity': '中危'
                })


def detect_meta_refresh_redirects(lines, vulnerabilities):
    """
    检测HTML meta refresh重定向
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测meta refresh标签
        if ('meta http-equiv="refresh"' in line.lower() or 
            'http-equiv="refresh"' in line.lower() or
            'content="0;url=' in line.lower()):
            
            # 检查URL是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到HTML meta refresh重定向使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "开放重定向 - HTML meta重定向",
                    'severity': '中危'
                })


def detect_javascript_redirects(lines, vulnerabilities):
    """
    检测JavaScript重定向
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    js_redirect_patterns = [
        'window.location', 'location.href', 'location.replace',
        'document.location', 'window.navigate'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检查JavaScript重定向
        for pattern in js_redirect_patterns:
            if pattern in line:
                # 检查URL是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到JavaScript重定向 '{pattern}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "开放重定向 - JavaScript重定向",
                        'severity': '中危'
                    })
                break


def detect_die_exit_redirects(lines, vulnerabilities):
    """
    检测die/exit后的header重定向
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测die/exit调用
        if 'die(' in line or 'exit(' in line:
            # 检查前面几行是否有header重定向
            start_line = max(1, line_num - 3)
            end_line = line_num
            context_lines = lines[start_line - 1:end_line]
            context_code = '\n'.join(context_lines)
            
            # 检查是否有header重定向和用户输入
            if 'header(' in context_code and 'Location:' in context_code:
                user_input_detected = any(
                    any(re.search(indicator, context_line) for indicator in user_input_indicators)
                    for context_line in context_lines
                )
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到header重定向后使用die/exit - 可能包含用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "开放重定向",
                        'severity': '中危'
                    })


def detect_custom_redirect_functions(lines, vulnerabilities):
    """
    检测自定义重定向函数
    """
    redirect_keywords = ['redirect', 'goto', 'forward', 'location']
    
    # 首先收集所有函数定义
    function_definitions = {}
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测函数定义
        func_match = re.search(r'function\s+([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)', line)
        if func_match and '{' in line:
            func_name = func_match.group(1)
            # 检查函数名是否包含重定向关键词
            if any(keyword in func_name.lower() for keyword in redirect_keywords):
                function_definitions[func_name] = line_num
    
    # 检查自定义重定向函数的使用
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for func_name, def_line in function_definitions.items():
        # 查找该函数的调用
        for line_num, line in enumerate(lines, 1):
            line_clean = line.strip()
            
            if not line_clean or line_clean.startswith(('//', '#', '/*')):
                continue
                
            # 检测函数调用
            if func_name + '(' in line and line_num > def_line:
                # 检查是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到自定义重定向函数 '{func_name}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "开放重定向 - 自定义重定向函数",
                        'severity': '中危'
                    })


def detect_framework_redirects(lines, vulnerabilities):
    """
    检测框架重定向函数
    """
    framework_redirect_functions = [
        'redirect', 'Redirect::to', 'redirect_to', 'go', 'forward'
    ]
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测框架重定向函数
        for func_name in framework_redirect_functions:
            if func_name in line:
                # 检查是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到框架重定向函数 '{func_name}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "开放重定向 - 框架重定向",
                        'severity': '中危'
                    })


def detect_url_concatenation_redirects(lines, vulnerabilities):
    """
    检测URL拼接重定向
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    redirect_patterns = ['Location:', 'redirect', 'goto', 'returnUrl', 'url=']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测重定向相关的URL拼接
        is_redirect_context = any(pattern in line for pattern in redirect_patterns)
        
        if is_redirect_context:
            # 检查是否包含用户输入和URL拼接
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            has_concatenation = '.' in line or '+' in line
            
            if user_input_detected and has_concatenation:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到URL拼接重定向使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "开放重定向 - URL拼接",
                    'severity': '中危'
                })


# 增强版检测函数
def detect_open_redirect_vulnerability_enhanced(php_code):
    """
    PHP开放重定向漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_redirects(lines, vulnerabilities)
    detect_advanced_redirect_patterns(lines, vulnerabilities)
    detect_context_aware_redirects(lines, vulnerabilities)
    
    return vulnerabilities


def detect_comprehensive_redirects(lines, vulnerabilities):
    """
    增强版的重定向漏洞检测
    """
    redirect_patterns = [
        # header重定向
        (r'header\s*\(\s*[\'"]Location:\s*[^\'"]*\$\{[^}]+\}[^\'"]*[\'"]\s*\)', "变量插值重定向"),
        (r'header\s*\(\s*[\'"]Location:\s*[^\'"]*\.[^\'"]*\$_[^\'"]*[\'"]\s*\)', "字符串拼接重定向"),
        # meta refresh
        (r'echo\s+[\'"]<meta[^>]*http-equiv=[\'\"]refresh[\'\"][^>]*>[\'"]', "meta refresh重定向"),
        # JavaScript重定向
        (r'echo\s+[\'"]<script[^>]*>.*location\..*=.*\$_.*</script>[\'"]', "JavaScript location重定向"),
        # 框架重定向
        (r'redirect\s*\(\s*[^)]*\$_[^)]*\)', "框架redirect函数"),
        (r'Redirect::to\s*\(\s*[^)]*\$_[^)]*\)', "Laravel重定向")
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
        
        for pattern, redirect_type in redirect_patterns:
            if re.search(pattern, line, re.IGNORECASE | re.DOTALL):
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{redirect_type}使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"开放重定向 - {redirect_type}",
                    'severity': '中危'
                })
                break


def detect_advanced_redirect_patterns(lines, vulnerabilities):
    """
    检测高级重定向模式
    """
    advanced_patterns = [
        # 动态重定向目标
        (r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^;]*\$_[^;]*;.*header\s*\(\s*Location:\s*\$[a-zA-Z_][a-zA-Z0-9_]*', "变量传递重定向"),
        # 条件重定向
        (r'if\s*\([^)]*\)\s*\{[^}]*header\s*\(\s*Location:\s*[^}]*\$_[^}]*', "条件重定向"),
        # 循环中的重定向
        (r'foreach\s*\([^)]*\)\s*\{[^}]*header\s*\(\s*Location:\s*[^}]*\$_[^}]*', "循环重定向"),
        # 函数返回重定向
        (r'function\s+\w+\s*\([^)]*\)\s*\{[^}]*return\s*[\'"]Location:\s*[^}]*\$_[^}]*', "返回重定向头")
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        # 检查多行模式
        start_line = max(1, line_num - 2)
        end_line = min(len(lines), line_num + 2)
        context = '\n'.join(lines[start_line - 1:end_line])
        
        for pattern, pattern_type in advanced_patterns:
            if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{pattern_type}",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"开放重定向 - {pattern_type}",
                    'severity': '中危'
                })
                break


def detect_context_aware_redirects(lines, vulnerabilities):
    """
    检测上下文感知的重定向漏洞
    """
    contexts = [
        # 登录后重定向
        (r'login.*redirect.*\$_', "登录后重定向"),
        # 注销重定向
        (r'logout.*redirect.*\$_', "注销重定向"),
        # 错误页面重定向
        (r'error.*redirect.*\$_', "错误重定向"),
        # 成功操作重定向
        (r'success.*redirect.*\$_', "成功重定向"),
        # 支付回调重定向
        (r'payment.*redirect.*\$_', "支付重定向"),
        # OAuth回调
        (r'oauth.*redirect.*\$_', "OAuth重定向"),
        # 社交登录回调
        (r'social.*redirect.*\$_', "社交登录重定向")
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        for pattern, context_type in contexts:
            if re.search(pattern, line, re.IGNORECASE):
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{context_type}使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"开放重定向 - {context_type}",
                    'severity': '中危'
                })
                break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试开放重定向漏洞

// 不安全的Location重定向
header("Location: " . $_GET['redirect_url']);
header('Location: ' . $_POST['return_to']);
header("Location: " . $_REQUEST['url']);

// 不安全的Refresh重定向
header("Refresh: 0; url=" . $_GET['redirect']);
header("refresh: 5; URL=" . $_POST['target']);

// HTML meta refresh重定向
echo '<meta http-equiv="refresh" content="0;url=' . $_GET['url'] . '">';
echo "<meta http-equiv=\\"refresh\\" content=\\"5;URL=" . $_POST['redirect'] . "\\">";

// JavaScript重定向
echo '<script>window.location = "' . $_GET['url'] . '";</script>';
echo "<script>location.href = \\"" . $_POST['redirect'] . "\\";</script>";
echo '<script>window.location.href = "' . $_REQUEST['goto'] . '";</script>';

// die/exit后的重定向
header("Location: " . $_GET['url']);
exit();

header('Location: ' . $_POST['redirect']);
die();

// 自定义重定向函数
function redirect($url) {
    header("Location: " . $url);
    exit;
}
redirect($_GET['url']);

function safeRedirect($url) {
    // 相对安全的实现
    $allowed_domains = ['example.com', 'localhost'];
    $parsed = parse_url($url);
    if (in_array($parsed['host'], $allowed_domains)) {
        header("Location: " . $url);
        exit;
    }
}

// 框架重定向函数（模拟）
redirect($_POST['return_url']);
Redirect::to($_GET['target']);

// URL拼接重定向
$redirect_url = "https://example.com?return=" . $_GET['url'];
header("Location: " . $redirect_url);

$base_url = "https://trusted.com/redirect?url=";
header("Location: " . $base_url . $_POST['external_url']);

// 相对安全的实现
// 白名单验证
$allowed_urls = ['/home', '/login', '/dashboard'];
if (in_array($_GET['redirect'], $allowed_urls)) {
    header("Location: " . $_GET['redirect']);
    exit;
}

// 域名白名单
$allowed_domains = ['example.com', 'trusted-site.com'];
$url = $_POST['url'];
$parsed = parse_url($url);
if (in_array($parsed['host'], $allowed_domains)) {
    header("Location: " . $url);
    exit;
}

// 相对路径重定向（安全）
header("Location: /login.php");
header('Location: ../dashboard/');

// 固定URL重定向（安全）
header("Location: https://example.com/success");
redirect("https://trusted.com/home");

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP开放重定向漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_open_redirect_vulnerability_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到开放重定向漏洞")