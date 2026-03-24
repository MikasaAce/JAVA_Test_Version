import re

def detect_cookie_ssl_vulnerability(php_code):
    """
    PHP Cookie安全 - 未通过SSL发送Cookie漏洞检测主函数 - 使用正则表达式版本
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
    
    # 检测session_start调用
    detect_session_start_vulnerabilities(lines, vulnerabilities)
    
    return vulnerabilities


def detect_setcookie_vulnerabilities(lines, vulnerabilities):
    """
    检测setcookie函数中的Secure标志缺失
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测setcookie函数调用
        if 'setcookie' in line:
            # 检查是否设置了Secure标志
            secure_set = False
            
            # 检查显式的secure参数
            if re.search(r'secure\s*=>\s*true', line, re.IGNORECASE) or \
               re.search(r'[\'"]secure[\'"]\s*=>\s*true', line, re.IGNORECASE):
                secure_set = True
            
            # 检查位置参数（第6个参数是secure）
            if not secure_set:
                setcookie_pattern = r'setcookie\s*\(\s*[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^)]+)\)'
                match = re.search(setcookie_pattern, line)
                if match:
                    sixth_param = match.group(1).strip()
                    if re.search(r'true|1', sixth_param, re.IGNORECASE):
                        secure_set = True
            
            # 检查数组参数格式
            if not secure_set:
                array_pattern = r'setcookie\s*\(\s*[^,]+,\s*([^)]+)\)'
                match = re.search(array_pattern, line)
                if match:
                    array_content = match.group(1)
                    if 'secure' in array_content.lower() and 'true' in array_content.lower():
                        secure_set = True
            
            # 检查显式禁用secure
            explicitly_disabled = False
            if re.search(r'secure\s*=>\s*false', line, re.IGNORECASE) or \
               re.search(r'[\'"]secure[\'"]\s*=>\s*false', line, re.IGNORECASE):
                explicitly_disabled = True
            
            if not secure_set:
                message = "检测到setcookie函数 - 未设置Secure标志"
                vuln_type = "Cookie安全 - 未通过SSL发送"
                severity = '高危'
                
                if explicitly_disabled:
                    message = "检测到setcookie函数 - 显式禁用Secure标志"
                    vuln_type = "Cookie安全 - 显式禁用SSL"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })


def detect_setrawcookie_vulnerabilities(lines, vulnerabilities):
    """
    检测setrawcookie函数中的Secure标志缺失
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测setrawcookie函数调用
        if 'setrawcookie' in line:
            secure_set = False
            
            # 检查显式的secure参数
            if re.search(r'secure\s*=>\s*true', line, re.IGNORECASE) or \
               re.search(r'[\'"]secure[\'"]\s*=>\s*true', line, re.IGNORECASE):
                secure_set = True
            
            # 检查位置参数
            if not secure_set:
                setrawcookie_pattern = r'setrawcookie\s*\(\s*[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^)]+)\)'
                match = re.search(setrawcookie_pattern, line)
                if match:
                    sixth_param = match.group(1).strip()
                    if re.search(r'true|1', sixth_param, re.IGNORECASE):
                        secure_set = True
            
            # 检查数组参数格式
            if not secure_set:
                array_pattern = r'setrawcookie\s*\(\s*[^,]+,\s*([^)]+)\)'
                match = re.search(array_pattern, line)
                if match:
                    array_content = match.group(1)
                    if 'secure' in array_content.lower() and 'true' in array_content.lower():
                        secure_set = True
            
            # 检查显式禁用secure
            explicitly_disabled = False
            if re.search(r'secure\s*=>\s*false', line, re.IGNORECASE) or \
               re.search(r'[\'"]secure[\'"]\s*=>\s*false', line, re.IGNORECASE):
                explicitly_disabled = True
            
            if not secure_set:
                message = "检测到setrawcookie函数 - 未设置Secure标志"
                vuln_type = "Cookie安全 - 未通过SSL发送"
                severity = '高危'
                
                if explicitly_disabled:
                    message = "检测到setrawcookie函数 - 显式禁用Secure标志"
                    vuln_type = "Cookie安全 - 显式禁用SSL"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })


def detect_session_cookie_params(lines, vulnerabilities):
    """
    检测session_set_cookie_params函数中的Secure标志缺失
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测session_set_cookie_params函数调用
        if 'session_set_cookie_params' in line:
            secure_set = False
            
            # 检查显式的secure参数
            if re.search(r'secure\s*=>\s*true', line, re.IGNORECASE) or \
               re.search(r'[\'"]secure[\'"]\s*=>\s*true', line, re.IGNORECASE):
                secure_set = True
            
            # 检查位置参数（第4个参数是secure）
            if not secure_set:
                params_pattern = r'session_set_cookie_params\s*\(\s*[^,]+,[^,]+,[^,]+,([^)]+)\)'
                match = re.search(params_pattern, line)
                if match:
                    fourth_param = match.group(1).strip()
                    if re.search(r'true|1', fourth_param, re.IGNORECASE):
                        secure_set = True
            
            # 检查数组参数格式
            if not secure_set:
                array_pattern = r'session_set_cookie_params\s*\(\s*([^)]+)\)'
                match = re.search(array_pattern, line)
                if match:
                    array_content = match.group(1)
                    if 'secure' in array_content.lower() and 'true' in array_content.lower():
                        secure_set = True
            
            if not secure_set:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到session_set_cookie_params函数 - 未设置Secure标志",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Session Cookie安全 - 未通过SSL发送",
                    'severity': '高危'
                })


def detect_header_cookie_vulnerabilities(lines, vulnerabilities):
    """
    检测header函数设置Cookie中的Secure标志缺失
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测header函数设置Cookie
        if 'header' in line and ('Set-Cookie:' in line or 'set-cookie:' in line.lower()):
            # 检查是否包含Secure标志
            if not re.search(r'secure', line, re.IGNORECASE):
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到header函数设置Cookie - 未设置Secure标志",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Cookie安全 - 未通过SSL发送",
                    'severity': '高危'
                })


def detect_ini_set_vulnerabilities(lines, vulnerabilities):
    """
    检测ini_set配置中的Secure问题
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测ini_set设置session.cookie_secure
        if 'ini_set' in line and 'session.cookie_secure' in line.lower():
            # 检查是否显式禁用Secure
            if re.search(r'session\.cookie_secure\s*,\s*[\'"]?\s*0\s*[\'"]?', line) or \
               re.search(r'session\.cookie_secure\s*,\s*[\'"]?\s*false\s*[\'"]?', line, re.IGNORECASE) or \
               re.search(r'session\.cookie_secure\s*,\s*[\'"]?\s*off\s*[\'"]?', line, re.IGNORECASE):
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到ini_set禁用session.cookie_secure",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Session Cookie安全 - 显式禁用SSL",
                    'severity': '高危'
                })


def detect_session_start_vulnerabilities(lines, vulnerabilities):
    """
    检测session_start调用前的安全配置
    """
    session_start_lines = []
    
    # 首先收集所有session_start的位置
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        if 'session_start' in line and '(' in line and ')' in line:
            session_start_lines.append(line_num)
    
    # 检查每个session_start调用前的配置
    for start_line in session_start_lines:
        # 检查前10行内是否有安全配置
        start_check = max(1, start_line - 10)
        end_check = start_line - 1
        
        has_secure_config = False
        for check_line in range(start_check, end_check + 1):
            if check_line <= len(lines):
                line_content = lines[check_line - 1].strip()
                if ('session_set_cookie_params' in line_content and 'secure' in line_content.lower() and 'true' in line_content.lower()) or \
                   ('ini_set' in line_content and 'session.cookie_secure' in line_content.lower() and ('1' in line_content or 'true' in line_content.lower())):
                    has_secure_config = True
                    break
        
        if not has_secure_config:
            code_snippet = lines[start_line - 1].strip() if start_line <= len(lines) else ""
            vulnerabilities.append({
                'line': start_line,
                'message': "检测到session_start调用 - 未显式设置Secure参数",
                'code_snippet': code_snippet,
                'vulnerability_type': "Session Cookie安全 - 默认配置可能不安全",
                'severity': '中危'
            })


# 增强版检测函数
def detect_cookie_ssl_vulnerability_enhanced(php_code):
    """
    PHP Cookie安全 - SSL漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_cookie_vulnerabilities(lines, vulnerabilities)
    detect_modern_cookie_patterns(lines, vulnerabilities)
    
    return vulnerabilities


def detect_comprehensive_cookie_vulnerabilities(lines, vulnerabilities):
    """
    增强版的Cookie SSL安全检测
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
                # 检查是否设置了Secure
                if not is_secure_set(line, func_name):
                    # 检查是否显式禁用
                    if is_secure_explicitly_disabled(line):
                        message = f"检测到{func_desc} - 显式禁用Secure标志"
                        vuln_type = "Cookie安全 - 显式禁用SSL"
                    else:
                        message = f"检测到{func_desc} - 未设置Secure标志"
                        vuln_type = "Cookie安全 - 未通过SSL发送"
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': vuln_type,
                        'severity': '高危'
                    })
        
        # 检测header设置Cookie
        if 'header' in line and re.search(r'Set-Cookie:\s*[^;]*;', line, re.IGNORECASE):
            if not re.search(r';\s*secure\s*(;|$)', line, re.IGNORECASE):
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到header函数设置Cookie - 未设置Secure标志",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Cookie安全 - 未通过SSL发送",
                    'severity': '高危'
                })
        
        # 检测ini_set配置
        if 'ini_set' in line and re.search(r'session\.cookie_secure', line, re.IGNORECASE):
            if re.search(r'session\.cookie_secure\s*,\s*[\'"]?\s*(0|false|off)\s*[\'"]?', line, re.IGNORECASE):
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到ini_set禁用session.cookie_secure",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Session Cookie安全 - 显式禁用SSL",
                    'severity': '高危'
                })


def detect_modern_cookie_patterns(lines, vulnerabilities):
    """
    检测现代Cookie设置模式
    """
    modern_patterns = [
        # 数组参数中secure缺失
        (r'setcookie\s*\(\s*[^,]+,\s*[^)]+\'secure\'\s*=>\s*false[^)]+\)', "显式禁用Secure"),
        (r'setcookie\s*\(\s*[^,]+,\s*[^)]+\"secure\"\s*=>\s*false[^)]+\)', "显式禁用Secure"),
        # 数组参数中缺少secure
        (r'setcookie\s*\(\s*[^,]+,\s*\[[^]]*\]\s*\)', "数组参数Secure检查"),
        (r'setrawcookie\s*\(\s*[^,]+,\s*\[[^]]*\]\s*\)', "数组参数Secure检查")
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        for pattern, pattern_type in modern_patterns:
            match = re.search(pattern, line)
            if match:
                if pattern_type == "显式禁用Secure":
                    message = "检测到显式禁用Secure标志"
                    vuln_type = "Cookie安全 - 显式禁用SSL"
                else:
                    # 检查数组参数是否包含secure
                    if 'secure' not in line.lower():
                        message = "检测到数组参数格式Cookie设置 - 未设置secure选项"
                        vuln_type = "Cookie安全 - 未通过SSL发送"
                    else:
                        continue  # 如果包含secure，跳过
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': '高危'
                })
                break


def is_secure_set(line, func_name):
    """
    检查行中是否设置了Secure标志
    """
    # 检查显式的secure参数（数组格式）
    if re.search(r'secure\s*=>\s*true', line, re.IGNORECASE) or \
       re.search(r'[\'"]secure[\'"]\s*=>\s*true', line, re.IGNORECASE):
        return True
    
    # 检查位置参数
    if func_name == 'setcookie' or func_name == 'setrawcookie':
        # 第6个参数是secure
        pattern = func_name + r'\s*\(\s*[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^)]+)\)'
        match = re.search(pattern, line)
        if match:
            sixth_param = match.group(1).strip()
            if re.search(r'true|1', sixth_param, re.IGNORECASE):
                return True
    
    elif func_name == 'session_set_cookie_params':
        # 第4个参数是secure
        pattern = func_name + r'\s*\(\s*[^,]+,[^,]+,[^,]+,([^)]+)\)'
        match = re.search(pattern, line)
        if match:
            fourth_param = match.group(1).strip()
            if re.search(r'true|1', fourth_param, re.IGNORECASE):
                return True
    
    # 检查数组参数中的secure
    array_pattern = func_name + r'\s*\(\s*[^,]+,\s*([^)]+)\)'
    match = re.search(array_pattern, line)
    if match:
        array_content = match.group(1)
        if 'secure' in array_content.lower() and 'true' in array_content.lower():
            return True
    
    return False


def is_secure_explicitly_disabled(line):
    """
    检查是否显式禁用Secure标志
    """
    return bool(re.search(r'secure\s*=>\s*false', line, re.IGNORECASE) or \
               re.search(r'[\'"]secure[\'"]\s*=>\s*false', line, re.IGNORECASE))


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 Cookie SSL安全漏洞

// 不安全的setcookie调用 - 缺少Secure标志
setcookie("session_id", $session_id);
setcookie("user", $username, time() + 3600);
setcookie("auth", $token, time() + 3600, "/", "example.com");
setcookie("cookie1", $value, time() + 3600, "/", "", false); // 第6个参数是secure缺失

// 显式禁用Secure标志
setcookie("insecure_cookie", $value, time() + 3600, "/", "", false);

// 安全的setcookie调用
setcookie("secure_cookie", $value, time() + 3600, "/", "example.com", true);
setcookie("another_cookie", $data, [
    'expires' => time() + 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => true,
    'httponly' => true
]);

// setrawcookie函数 - 不安全
setrawcookie("raw_cookie", $value);
setrawcookie("raw_cookie2", $value, time() + 3600, "/", "example.com");

// setrawcookie函数 - 安全
setrawcookie("secure_raw_cookie", $value, time() + 3600, "/", "example.com", true);

// header函数设置Cookie - 不安全
header("Set-Cookie: user_id=12345");
header('Set-Cookie: session=' . $session . '; path=/');
header("Set-Cookie: admin=yes; path=/; httponly"); // 只有httponly，没有secure

// header函数设置Cookie - 安全
header("Set-Cookie: secure_session=abc123; path=/; secure; httponly");
header("Set-Cookie: admin=yes; path=/; secure; httponly");

// session_set_cookie_params - 不安全
session_set_cookie_params(3600);
session_set_cookie_params(3600, '/', 'example.com');
session_set_cookie_params(3600, '/', 'example.com', false); // 第4个参数是secure缺失

// session_set_cookie_params - 安全
session_set_cookie_params(3600, '/', 'example.com', true);
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => true,
    'httponly' => true
]);

// ini_set配置 - 不安全（显式禁用Secure）
ini_set('session.cookie_secure', 0);
ini_set('session.cookie_secure', 'false');

// ini_set配置 - 安全
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_secure', 'true');

// session_start - 没有显式配置
session_start();

// session_start - 有安全配置
session_set_cookie_params(3600, '/', 'example.com', true);
session_start();

// 数组参数格式 - 不安全
setcookie('modern_cookie', $value, [
    'expires' => time() + 3600,
    'path' => '/',
    'domain' => 'example.com',
    'httponly' => true
    // secure 缺失
]);

setcookie('explicit_insecure', $value, [
    'expires' => time() + 3600,
    'path' => '/',
    'secure' => false  // 显式禁用
]);

// 数组参数格式 - 安全
setcookie('secure_modern', $value, [
    'expires' => time() + 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => true,
    'httponly' => true
]);

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP Cookie安全 - 未通过SSL发送Cookie漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_cookie_ssl_vulnerability_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Cookie SSL安全漏洞")