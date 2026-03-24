import re

def detect_log_forgery_vulnerability(php_code):
    """
    PHP日志伪造漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测日志记录函数中的用户输入
    detect_logging_functions(lines, vulnerabilities)
    
    # 检测文件写入操作中的日志伪造
    detect_file_logging_vulnerabilities(lines, vulnerabilities)
    
    # 检测系统日志函数
    detect_system_logging_vulnerabilities(lines, vulnerabilities)
    
    # 检测错误日志记录
    detect_error_logging_vulnerabilities(lines, vulnerabilities)
    
    # 检测日志格式拼接漏洞
    detect_log_format_vulnerabilities(lines, vulnerabilities)
    
    return vulnerabilities


def detect_logging_functions(lines, vulnerabilities):
    """
    检测日志记录函数中的伪造漏洞
    """
    logging_functions = [
        'error_log', 'syslog', 'openlog', 'closelog'
    ]
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE', r'\$_SERVER']
    crlf_patterns = [r'\\r', r'\\n', r'%0d', r'%0a']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测日志记录函数
        for log_func in logging_functions:
            if log_func in line:
                user_input_detected = False
                crlf_injection_risk = False
                
                # 检查是否包含用户输入
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
                    message = f"检测到{log_func}函数使用用户输入"
                    vuln_type = "日志伪造"
                    
                    if crlf_injection_risk:
                        message += " - 可能包含CRLF注入字符"
                        vuln_type = "日志伪造 - CRLF注入"
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': vuln_type,
                        'severity': severity
                    })


def detect_file_logging_vulnerabilities(lines, vulnerabilities):
    """
    检测文件写入操作中的日志伪造漏洞
    """
    file_functions = [
        'file_put_contents', 'fwrite', 'fputs', 'file'
    ]
    
    log_file_patterns = [
        r'\.log', r'log/', r'_log', r'error\.', r'access\.', r'debug\.'
    ]
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测文件写入函数
        for file_func in file_functions:
            if file_func in line:
                # 检查是否是日志文件
                is_log_file = any(re.search(pattern, line, re.IGNORECASE) for pattern in log_file_patterns)
                
                if is_log_file:
                    # 检查是否包含用户输入
                    user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                    
                    if user_input_detected:
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到日志文件写入使用用户输入 - {file_func}",
                            'code_snippet': line_clean,
                            'vulnerability_type': "日志伪造 - 文件写入",
                            'severity': '中危'
                        })


def detect_system_logging_vulnerabilities(lines, vulnerabilities):
    """
    检测系统日志函数中的伪造漏洞
    """
    system_log_patterns = [
        (r'syslog\s*\([^)]*LOG_[^,]*,\s*[^)]*\$_[^)]*\)', 'syslog函数'),
        (r'openlog\s*\([^)]*\$_[^)]*\)', 'openlog函数')
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        for pattern, func_name in system_log_patterns:
            if re.search(pattern, line):
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{func_name}使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "日志伪造 - 系统日志",
                    'severity': '中危'
                })
                break


def detect_error_logging_vulnerabilities(lines, vulnerabilities):
    """
    检测错误日志记录中的伪造漏洞
    """
    error_log_patterns = [
        (r'error_log\s*\(\s*[^,]*\$_[^,]*,[^)]*\)', 'error_log消息参数'),
        (r'error_log\s*\(\s*[^,]*,[^,]*\$_[^)]*\)', 'error_log目标参数'),
        (r'ini_set\s*\(\s*[\'"]error_log[\'"][^)]*\$_[^)]*\)', 'error_log路径设置')
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        for pattern, desc in error_log_patterns:
            if re.search(pattern, line):
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到错误日志{desc}使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "日志伪造 - 错误日志",
                    'severity': '中危'
                })
                break


def detect_log_format_vulnerabilities(lines, vulnerabilities):
    """
    检测日志格式拼接漏洞
    """
    format_patterns = [
        # 时间戳拼接
        (r'\[\s*[^\]]*\s*\]\s*\.\s*\$_[^\s]', "日志时间戳拼接"),
        # IP地址拼接
        (r'IP:\s*[^\s]*\s*\.\s*\$_[^\s]', "日志IP地址拼接"),
        # 用户代理拼接
        (r'User-Agent:\s*[^\s]*\s*\.\s*\$_[^\s]', "日志User-Agent拼接"),
        # 自定义日志格式
        (r'[\'\"][^\"\']*\\[tnr][^\"\']*[\'\"]\s*\.\s*\$_[^\s]', "日志转义字符拼接")
    ]
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE', r'\$_SERVER']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检查是否包含用户输入
        has_user_input = any(re.search(indicator, line) for indicator in user_input_indicators)
        
        if has_user_input:
            for pattern, desc in format_patterns:
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到{desc}使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "日志伪造 - 格式注入",
                        'severity': '中危'
                    })
                    break


# 增强版检测函数
def detect_log_forgery_vulnerability_enhanced(php_code):
    """
    PHP日志伪造漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_log_vulnerabilities(lines, vulnerabilities)
    detect_context_aware_logging(lines, vulnerabilities)
    detect_log_injection_patterns(lines, vulnerabilities)
    
    return vulnerabilities


def detect_comprehensive_log_vulnerabilities(lines, vulnerabilities):
    """
    增强版的日志伪造漏洞检测
    """
    log_operations = [
        # 标准日志函数
        (r'error_log\s*\(\s*([^)]*)\s*\)', 'error_log'),
        (r'syslog\s*\(\s*[^,]+,\s*([^)]+)\s*\)', 'syslog'),
        # 文件日志操作
        (r'file_put_contents\s*\(\s*[^,]+\.log[^,]*,\s*([^)]+)\s*\)', '文件日志'),
        (r'fwrite\s*\(\s*[^,]+,\s*([^)]+)\s*\)', '文件写入'),
        # 自定义日志函数
        (r'log_message\s*\(\s*([^)]+)\s*\)', '自定义日志'),
        (r'write_log\s*\(\s*([^)]+)\s*\)', '写日志'),
        (r'logger\s*->\s*\w+\s*\(\s*([^)]+)\s*\)', '日志器方法')
    ]
    
    user_input_sources = [
        r'\$_GET\[[^\]]+\]',
        r'\$_POST\[[^\]]+\]',
        r'\$_REQUEST\[[^\]]+\]',
        r'\$_COOKIE\[[^\]]+\]',
        r'\$_SERVER\[[^\]]+\]'
    ]
    
    dangerous_patterns = [
        r'\\r\\n', r'\\n\\r', r'%0d%0a', r'%0a%0d',
        r'\\t', r'\\n', r'\\r'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
        
        for pattern, log_type in log_operations:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                # 检查是否包含用户输入
                user_input_found = False
                for user_input_pattern in user_input_sources:
                    if re.search(user_input_pattern, line):
                        user_input_found = True
                        break
                
                # 检查危险字符
                dangerous_chars_found = False
                for dangerous_pattern in dangerous_patterns:
                    if re.search(dangerous_pattern, line):
                        dangerous_chars_found = True
                        break
                
                if user_input_found:
                    severity = '高危' if dangerous_chars_found else '中危'
                    message = f"检测到{log_type}使用用户输入"
                    
                    if dangerous_chars_found:
                        message += " - 包含危险控制字符"
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': "日志伪造",
                        'severity': severity
                    })


def detect_context_aware_logging(lines, vulnerabilities):
    """
    检测上下文感知的日志伪造漏洞
    """
    contexts = [
        # Web访问日志
        (r'[\'\"][^\'"]*IP[^\'"]*[\'\"]\s*\.\s*\$_SERVER\s*\[\s*[\'"]REMOTE_ADDR[\'"]\s*\]', 'IP地址日志'),
        (r'[\'\"][^\'"]*User-Agent[^\'"]*[\'\"]\s*\.\s*\$_SERVER\s*\[\s*[\'"]HTTP_USER_AGENT[\'"]\s*\]', 'User-Agent日志'),
        (r'[\'\"][^\'"]*Referer[^\'"]*[\'\"]\s*\.\s*\$_SERVER\s*\[\s*[\'"]HTTP_REFERER[\'"]\s*\]', 'Referer日志'),
        # 认证日志
        (r'[\'\"][^\'"]*user[^\'"]*[\'\"]\s*\.\s*\$_POST\s*\[\s*[\'"]username[\'"]\s*\]', '用户名日志'),
        (r'[\'\"][^\'"]*login[^\'"]*[\'\"]\s*\.\s*\$_POST\s*\[\s*[\'"]email[\'"]\s*\]', '登录日志'),
        # 操作日志
        (r'[\'\"][^\'"]*action[^\'"]*[\'\"]\s*\.\s*\$_GET\s*\[\s*[\'"]action[\'"]\s*\]', '操作日志'),
        (r'[\'\"][^\'"]*id[^\'"]*[\'\"]\s*\.\s*\$_REQUEST\s*\[\s*[\'"]id[\'"]\s*\]', 'ID日志')
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
                    'vulnerability_type': f"日志伪造 - {context_type}",
                    'severity': '中危'
                })
                break


def detect_log_injection_patterns(lines, vulnerabilities):
    """
    检测日志注入模式
    """
    injection_patterns = [
        # 多行日志注入
        (r'\\r\\n\w+', "多行日志注入"),
        # 日志分隔符注入
        (r'[\'\"][^\"\']*[|,;][^\"\']*[\'\"]\s*\.\s*\$_[^\s]', "日志分隔符注入"),
        # 日志级别伪造
        (r'[\'\"][^\"\']*(ERROR|WARN|INFO|DEBUG)[^\"\']*[\'\"]\s*\.\s*\$_[^\s]', "日志级别伪造"),
        # 时间戳伪造
        (r'[\'\"][^\"\']*\d{4}-\d{2}-\d{2}[^\"\']*[\'\"]\s*\.\s*\$_[^\s]', "时间戳伪造"),
        # JSON日志注入
        (r'[\'\"][^\"\']*\{[^}]*\}[^\"\']*[\'\"]\s*\.\s*\$_[^\s]', "JSON日志注入")
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        for pattern, injection_type in injection_patterns:
            if re.search(pattern, line):
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{injection_type}模式",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"日志伪造 - {injection_type}",
                    'severity': '中危'
                })
                break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试日志伪造漏洞

// 不安全的error_log使用
error_log("User action: " . $_GET['action']);
error_log("Error from IP: " . $_SERVER['REMOTE_ADDR']);
error_log($_POST['message']);

// 不安全的syslog使用
syslog(LOG_INFO, "User login: " . $_POST['username']);
openlog("App_" . $_GET['module'], LOG_PID, LOG_USER);

// 文件日志写入漏洞
file_put_contents('/var/log/app.log', "Action: " . $_REQUEST['action'] . "\\n", FILE_APPEND);
fwrite($log_file, "User: " . $_COOKIE['user_id'] . "\\n");

// 自定义日志函数中的漏洞
function log_message($message) {
    file_put_contents('debug.log', date('Y-m-d H:i:s') . " - " . $message . "\\n", FILE_APPEND);
}
log_message("Request: " . $_SERVER['HTTP_USER_AGENT']);

// 日志格式拼接漏洞
$log_entry = "[" . date('Y-m-d H:i:s') . "] IP: " . $_SERVER['REMOTE_ADDR'] . " - " . $_GET['message'];
$log_entry = "ERROR: " . $_POST['error'] . " | User: " . $_COOKIE['username'];

// 多行日志注入风险
error_log("Data: " . $_GET['data'] . "\\r\\n[INJECTED] Fake log entry");

// JSON日志伪造
$json_log = '{"timestamp": "' . date('c') . '", "user": "' . $_POST['user'] . '", "action": "' . $_GET['action'] . '"}';

// 相对安全的日志记录
// 经过过滤的输入
$filtered_message = htmlspecialchars($_POST['message']);
error_log("Safe: " . $filtered_message);

// 使用白名单验证
$allowed_actions = ['login', 'logout', 'view'];
$action = in_array($_GET['action'], $allowed_actions) ? $_GET['action'] : 'unknown';
error_log("Action: " . $action);

// 限制日志内容长度
$log_message = substr($_POST['message'], 0, 100);
error_log("Truncated: " . $log_message);

// 使用预定义格式
$log_entry = sprintf("[%s] IP: %s Action: %s", 
    date('Y-m-d H:i:s'), 
    $_SERVER['REMOTE_ADDR'],
    $action
);
error_log($log_entry);

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP日志伪造漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_log_forgery_vulnerability_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到日志伪造漏洞")