import re

def detect_cookie_httponly_vulnerability(php_code):
    """
    PHP Cookie安全 - HttpOnly未设置漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测setcookie函数调用
    detect_setcookie_vulnerabilities(lines, vulnerabilities)
    
    # 检测setrawcookie函数调用
    detect_setrawcookie_vulnerabilities(lines, vulnerabilities)
    
    # 检测session_set_cookie_params函数
    detect_session_cookie_params(lines, vulnerabilities)
    
    # 检测header函数设置Cookie
    detect_header_cookie_vulnerabilities(lines, vulnerabilities)
    
    # 检测ini_set配置
    detect_ini_set_vulnerabilities(lines, vulnerabilities)
    
    return vulnerabilities


def detect_setcookie_vulnerabilities(lines, vulnerabilities):
    """
    检测setcookie函数中的HttpOnly缺失
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测setcookie函数调用
        if 'setcookie' in line:
            # 检查是否设置了HttpOnly标志
            httponly_set = False
            
            # 检查显式的httponly参数
            if re.search(r'httponly\s*=>\s*true', line, re.IGNORECASE) or \
               re.search(r'httponly\s*:\s*true', line, re.IGNORECASE) or \
               re.search(r'[\'"]httponly[\'"]\s*=>\s*true', line, re.IGNORECASE):
                httponly_set = True
            
            # 检查位置参数（第7个参数是httponly）
            if not httponly_set:
                # 匹配setcookie函数调用并分析参数
                setcookie_pattern = r'setcookie\s*\(\s*[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^)]+)\)'
                match = re.search(setcookie_pattern, line)
                if match:
                    seventh_param = match.group(1).strip()
                    if re.search(r'true|1', seventh_param, re.IGNORECASE):
                        httponly_set = True
            
            # 检查数组参数格式
            if not httponly_set:
                array_pattern = r'setcookie\s*\(\s*[^,]+,\s*([^)]+)\)'
                match = re.search(array_pattern, line)
                if match:
                    array_content = match.group(1)
                    if 'httponly' in array_content.lower() and 'true' in array_content.lower():
                        httponly_set = True
            
            if not httponly_set:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到setcookie函数 - 未设置HttpOnly标志",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Cookie安全 - 缺少HttpOnly标志",
                    'severity': '中危'
                })


def detect_setrawcookie_vulnerabilities(lines, vulnerabilities):
    """
    检测setrawcookie函数中的HttpOnly缺失
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测setrawcookie函数调用
        if 'setrawcookie' in line:
            httponly_set = False
            
            # 检查显式的httponly参数
            if re.search(r'httponly\s*=>\s*true', line, re.IGNORECASE) or \
               re.search(r'[\'"]httponly[\'"]\s*=>\s*true', line, re.IGNORECASE):
                httponly_set = True
            
            # 检查位置参数
            if not httponly_set:
                setrawcookie_pattern = r'setrawcookie\s*\(\s*[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^)]+)\)'
                match = re.search(setrawcookie_pattern, line)
                if match:
                    seventh_param = match.group(1).strip()
                    if re.search(r'true|1', seventh_param, re.IGNORECASE):
                        httponly_set = True
            
            # 检查数组参数格式
            if not httponly_set:
                array_pattern = r'setrawcookie\s*\(\s*[^,]+,\s*([^)]+)\)'
                match = re.search(array_pattern, line)
                if match:
                    array_content = match.group(1)
                    if 'httponly' in array_content.lower() and 'true' in array_content.lower():
                        httponly_set = True
            
            if not httponly_set:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到setrawcookie函数 - 未设置HttpOnly标志",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Cookie安全 - 缺少HttpOnly标志",
                    'severity': '中危'
                })


def detect_session_cookie_params(lines, vulnerabilities):
    """
    检测session_set_cookie_params函数中的HttpOnly缺失
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测session_set_cookie_params函数调用
        if 'session_set_cookie_params' in line:
            httponly_set = False
            
            # 检查显式的httponly参数
            if re.search(r'httponly\s*=>\s*true', line, re.IGNORECASE) or \
               re.search(r'[\'"]httponly[\'"]\s*=>\s*true', line, re.IGNORECASE):
                httponly_set = True
            
            # 检查位置参数（第5个参数是httponly）
            if not httponly_set:
                params_pattern = r'session_set_cookie_params\s*\(\s*[^,]+,[^,]+,[^,]+,[^,]+,([^)]+)\)'
                match = re.search(params_pattern, line)
                if match:
                    fifth_param = match.group(1).strip()
                    if re.search(r'true|1', fifth_param, re.IGNORECASE):
                        httponly_set = True
            
            # 检查数组参数格式
            if not httponly_set:
                array_pattern = r'session_set_cookie_params\s*\(\s*([^)]+)\)'
                match = re.search(array_pattern, line)
                if match:
                    array_content = match.group(1)
                    if 'httponly' in array_content.lower() and 'true' in array_content.lower():
                        httponly_set = True
            
            if not httponly_set:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到session_set_cookie_params函数 - 未设置HttpOnly标志",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Session Cookie安全 - 缺少HttpOnly标志",
                    'severity': '中危'
                })


def detect_header_cookie_vulnerabilities(lines, vulnerabilities):
    """
    检测header函数设置Cookie中的HttpOnly缺失
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测header函数设置Cookie
        if 'header' in line and ('Set-Cookie:' in line or 'set-cookie:' in line.lower()):
            # 检查是否包含HttpOnly标志
            if not re.search(r'httponly', line, re.IGNORECASE):
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到header函数设置Cookie - 未设置HttpOnly标志",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Cookie安全 - 缺少HttpOnly标志",
                    'severity': '中危'
                })


def detect_ini_set_vulnerabilities(lines, vulnerabilities):
    """
    检测ini_set配置中的HttpOnly问题
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测ini_set设置session.cookie_httponly
        if 'ini_set' in line and 'session.cookie_httponly' in line.lower():
            # 检查是否显式禁用HttpOnly
            if re.search(r'session\.cookie_httponly\s*,\s*[\'"]?\s*0\s*[\'"]?', line) or \
               re.search(r'session\.cookie_httponly\s*,\s*[\'"]?\s*false\s*[\'"]?', line, re.IGNORECASE) or \
               re.search(r'session\.cookie_httponly\s*,\s*[\'"]?\s*off\s*[\'"]?', line, re.IGNORECASE):
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到ini_set禁用session.cookie_httponly",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Session Cookie安全 - 显式禁用HttpOnly",
                    'severity': '高危'
                })


# 增强版检测函数
def detect_cookie_httponly_vulnerability_enhanced(php_code):
    """
    PHP Cookie安全 - HttpOnly未设置漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_cookie_vulnerabilities(lines, vulnerabilities)
    detect_advanced_parameter_analysis(lines, vulnerabilities)
    
    return vulnerabilities


def detect_comprehensive_cookie_vulnerabilities(lines, vulnerabilities):
    """
    增强版的Cookie安全检测
    """
    cookie_functions = [
        ('setcookie', 'setcookie函数'),
        ('setrawcookie', 'setrawcookie函数'),
        ('session_set_cookie_params', 'session_set_cookie_params函数')
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
        
        # 检测各种Cookie设置函数
        for func_name, func_desc in cookie_functions:
            if func_name in line:
                # 检查是否设置了HttpOnly
                if not is_httponly_set(line, func_name):
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到{func_desc} - 未设置HttpOnly标志",
                        'code_snippet': line_clean,
                        'vulnerability_type': "Cookie安全 - 缺少HttpOnly标志",
                        'severity': '中危'
                    })
        
        # 检测header设置Cookie
        if 'header' in line and re.search(r'Set-Cookie:\s*[^;]*;', line, re.IGNORECASE):
            if not re.search(r';\s*httponly\s*(;|$)', line, re.IGNORECASE):
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到header函数设置Cookie - 未设置HttpOnly标志",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Cookie安全 - 缺少HttpOnly标志",
                    'severity': '中危'
                })
        
        # 检测ini_set配置
        if 'ini_set' in line and re.search(r'session\.cookie_httponly', line, re.IGNORECASE):
            if re.search(r'session\.cookie_httponly\s*,\s*[\'"]?\s*(0|false|off)\s*[\'"]?', line, re.IGNORECASE):
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到ini_set禁用session.cookie_httponly",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Session Cookie安全 - 显式禁用HttpOnly",
                    'severity': '高危'
                })


def detect_advanced_parameter_analysis(lines, vulnerabilities):
    """
    高级参数分析检测
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        # 检测复杂的Cookie设置模式
        complex_patterns = [
            # 变量赋值后设置Cookie
            (r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'"]Set-Cookie:[^;]*;[\'"]', "变量Cookie设置"),
            # 动态构建Cookie头
            (r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*\.=\s*[\'"];[^;]*[\'"]', "动态Cookie构建")
        ]
        
        for pattern, desc in complex_patterns:
            if re.search(pattern, line):
                if 'httponly' not in line.lower():
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到{desc} - 可能缺少HttpOnly标志",
                        'code_snippet': line_clean,
                        'vulnerability_type': "Cookie安全 - 潜在HttpOnly缺失",
                        'severity': '中危'
                    })


def is_httponly_set(line, func_name):
    """
    检查行中是否设置了HttpOnly标志
    """
    # 检查显式的httponly参数（数组格式）
    if re.search(r'httponly\s*=>\s*true', line, re.IGNORECASE) or \
       re.search(r'[\'"]httponly[\'"]\s*=>\s*true', line, re.IGNORECASE):
        return True
    
    # 检查位置参数
    if func_name == 'setcookie' or func_name == 'setrawcookie':
        # 第7个参数是httponly
        pattern = func_name + r'\s*\(\s*[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^)]+)\)'
        match = re.search(pattern, line)
        if match:
            seventh_param = match.group(1).strip()
            if re.search(r'true|1', seventh_param, re.IGNORECASE):
                return True
    
    elif func_name == 'session_set_cookie_params':
        # 第5个参数是httponly
        pattern = func_name + r'\s*\(\s*[^,]+,[^,]+,[^,]+,[^,]+,([^)]+)\)'
        match = re.search(pattern, line)
        if match:
            fifth_param = match.group(1).strip()
            if re.search(r'true|1', fifth_param, re.IGNORECASE):
                return True
    
    # 检查数组参数中的httponly
    array_pattern = func_name + r'\s*\(\s*[^,]+,\s*([^)]+)\)'
    match = re.search(array_pattern, line)
    if match:
        array_content = match.group(1)
        if 'httponly' in array_content.lower() and 'true' in array_content.lower():
            return True
    
    return False


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 Cookie HttpOnly 安全漏洞

// 不安全的setcookie调用 - 缺少HttpOnly
setcookie("session_id", $session_id);
setcookie("user", $username, time() + 3600);
setcookie("auth", $token, time() + 3600, "/", "example.com");
setcookie("cookie1", $value, time() + 3600, "/", "", false); // 第6个参数是secure，第7个是httponly缺失

// 安全的setcookie调用
setcookie("safe_cookie", $value, time() + 3600, "/", "example.com", false, true);
setcookie("another_cookie", $data, [
    'expires' => time() + 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => false,
    'httponly' => true
]);

// setrawcookie函数 - 不安全
setrawcookie("raw_cookie", $value);
setrawcookie("raw_cookie2", $value, time() + 3600, "/", "example.com");

// setrawcookie函数 - 安全
setrawcookie("safe_raw_cookie", $value, time() + 3600, "/", "example.com", false, true);

// header函数设置Cookie - 不安全
header("Set-Cookie: user_id=12345");
header('Set-Cookie: session=' . $session . '; path=/');
header("Set-Cookie: admin=yes; path=/; secure"); // 只有secure，没有httponly

// header函数设置Cookie - 安全
header("Set-Cookie: safe_session=abc123; path=/; httponly");
header("Set-Cookie: admin=yes; path=/; secure; httponly");

// session_set_cookie_params - 不安全
session_set_cookie_params(3600);
session_set_cookie_params(3600, '/', 'example.com');
session_set_cookie_params(3600, '/', 'example.com', true); // 第4个参数是secure，第5个是httponly缺失

// session_set_cookie_params - 安全
session_set_cookie_params(3600, '/', 'example.com', false, true);
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => false,
    'httponly' => true
]);

// ini_set配置 - 不安全（显式禁用HttpOnly）
ini_set('session.cookie_httponly', 0);
ini_set('session.cookie_httponly', 'false');

// ini_set配置 - 安全
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_httponly', 'true');

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP Cookie安全 - HttpOnly未设置漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_cookie_httponly_vulnerability_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Cookie HttpOnly安全漏洞")