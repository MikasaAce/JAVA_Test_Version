import re

def detect_configuration_manipulation(php_code):
    """
    PHP设置操纵漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测ini_set函数调用
    detect_ini_set_vulnerabilities(lines, vulnerabilities)
    
    # 检测ini_get函数调用
    detect_ini_get_vulnerabilities(lines, vulnerabilities)
    
    # 检测putenv函数调用
    detect_putenv_vulnerabilities(lines, vulnerabilities)
    
    # 检测set_time_limit函数调用
    detect_set_time_limit_vulnerabilities(lines, vulnerabilities)
    
    # 检测会话相关函数
    detect_session_functions(lines, vulnerabilities)
    
    # 检测error_reporting函数调用
    detect_error_reporting_vulnerabilities(lines, vulnerabilities)
    
    # 检测时区设置函数
    detect_timezone_functions(lines, vulnerabilities)
    
    # 检测安全头设置
    detect_security_headers(lines, vulnerabilities)
    
    # 检测配置数组操作
    detect_config_array_operations(lines, vulnerabilities)
    
    # 检测常量定义
    detect_constant_definitions(lines, vulnerabilities)
    
    return vulnerabilities


def detect_ini_set_vulnerabilities(lines, vulnerabilities):
    """
    检测ini_set函数中的设置操纵漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    dangerous_settings = [
        'disable_functions', 'safe_mode', 'open_basedir',
        'allow_url_fopen', 'allow_url_include', 'memory_limit',
        'max_execution_time', 'max_input_time', 'post_max_size',
        'upload_max_filesize', 'display_errors', 'error_reporting',
        'log_errors', 'error_log', 'session.save_path'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测ini_set函数调用
        if 'ini_set' in line:
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            # 检查危险的PHP设置
            dangerous_setting = any(setting in line.lower() for setting in dangerous_settings)
            
            if user_input_detected:
                severity = '高危' if dangerous_setting else '中危'
                message = "检测到ini_set函数使用用户输入"
                vuln_type = "设置操纵 - PHP配置"
                
                if dangerous_setting:
                    message += " - 可能操纵危险PHP设置"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })


def detect_ini_get_vulnerabilities(lines, vulnerabilities):
    """
    检测ini_get函数中的配置信息泄露
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测ini_get函数调用
        if 'ini_get' in line:
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到ini_get函数使用用户输入 - 可能泄露配置信息",
                    'code_snippet': line_clean,
                    'vulnerability_type': "设置操纵 - 配置信息泄露",
                    'severity': '低危'
                })


def detect_putenv_vulnerabilities(lines, vulnerabilities):
    """
    检测putenv函数中的环境变量操纵漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测putenv函数调用
        if 'putenv' in line:
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到putenv函数使用用户输入 - 环境变量操纵",
                    'code_snippet': line_clean,
                    'vulnerability_type': "设置操纵 - 环境变量",
                    'severity': '高危'
                })


def detect_set_time_limit_vulnerabilities(lines, vulnerabilities):
    """
    检测set_time_limit函数中的执行时间限制操纵漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测set_time_limit函数调用
        if 'set_time_limit' in line:
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到set_time_limit函数使用用户输入 - 执行时间限制操纵",
                    'code_snippet': line_clean,
                    'vulnerability_type': "设置操纵 - 执行时间限制",
                    'severity': '中危'
                })


def detect_session_functions(lines, vulnerabilities):
    """
    检测会话相关函数中的设置操纵漏洞
    """
    session_functions = {
        "session_save_path": "会话保存路径",
        "session_name": "会话名称",
        "session_set_cookie_params": "会话Cookie参数",
        "session_id": "会话ID",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测会话函数
        for func_name, func_desc in session_functions.items():
            if func_name in line:
                # 检查是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到会话函数 '{func_name}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"设置操纵 - {func_desc}",
                        'severity': '中危'
                    })


def detect_error_reporting_vulnerabilities(lines, vulnerabilities):
    """
    检测error_reporting函数中的错误报告级别操纵漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测error_reporting函数调用
        if 'error_reporting' in line:
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到error_reporting函数使用用户输入 - 错误报告级别操纵",
                    'code_snippet': line_clean,
                    'vulnerability_type': "设置操纵 - 错误报告",
                    'severity': '中危'
                })


def detect_timezone_functions(lines, vulnerabilities):
    """
    检测时区设置函数中的设置操纵漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测date_default_timezone_set函数调用
        if 'date_default_timezone_set' in line:
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到date_default_timezone_set函数使用用户输入 - 时区设置操纵",
                    'code_snippet': line_clean,
                    'vulnerability_type': "设置操纵 - 时区设置",
                    'severity': '低危'
                })


def detect_security_headers(lines, vulnerabilities):
    """
    检测安全头设置中的操纵漏洞
    """
    security_headers = [
        'X-Frame-Options', 'X-Content-Type-Options',
        'X-XSS-Protection', 'Content-Security-Policy',
        'Strict-Transport-Security', 'Referrer-Policy'
    ]
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测header函数调用
        if 'header' in line:
            # 检查安全头设置
            for header in security_headers:
                if header in line:
                    # 检查是否包含用户输入
                    user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                    
                    if user_input_detected:
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到安全头 '{header}' 设置使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "设置操纵 - 安全头设置",
                            'severity': '中危'
                        })
                    break


def detect_config_array_operations(lines, vulnerabilities):
    """
    检测配置数组操作中的设置操纵漏洞
    """
    config_vars = [r'\$config', r'\$GLOBALS', r'\$_ENV', r'\$_SERVER']
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测配置数组操作
        for config_var in config_vars:
            if re.search(config_var + r'\[', line):
                # 检查是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    var_name = config_var.replace('\\', '')
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到配置数组 '{var_name}' 操作使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "设置操纵 - 配置数组",
                        'severity': '中危'
                    })
                    break


def detect_constant_definitions(lines, vulnerabilities):
    """
    检测常量定义中的设置操纵漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测常量定义
        if 'define(' in line or 'const ' in line:
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到常量定义使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "设置操纵 - 常量定义",
                    'severity': '中危'
                })


# 增强版检测函数
def detect_configuration_manipulation_enhanced(php_code):
    """
    PHP设置操纵漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_config_manipulation(lines, vulnerabilities)
    detect_advanced_config_patterns(lines, vulnerabilities)
    detect_context_aware_config_manipulation(lines, vulnerabilities)
    
    return vulnerabilities


def detect_comprehensive_config_manipulation(lines, vulnerabilities):
    """
    增强版的设置操纵检测
    """
    config_operations = [
        # PHP配置操作
        (r'ini_set\s*\(\s*[^,]*\$_[^,]*,[^)]*\)', 'ini_set'),
        (r'ini_get\s*\(\s*[^)]*\$_[^)]*\)', 'ini_get'),
        # 环境变量操作
        (r'putenv\s*\(\s*[^)]*\$_[^)]*\)', 'putenv'),
        (r'getenv\s*\(\s*[^)]*\$_[^)]*\)', 'getenv'),
        # 执行时间操作
        (r'set_time_limit\s*\(\s*[^)]*\$_[^)]*\)', 'set_time_limit'),
        # 会话操作
        (r'session_save_path\s*\(\s*[^)]*\$_[^)]*\)', 'session_save_path'),
        (r'session_name\s*\(\s*[^)]*\$_[^)]*\)', 'session_name'),
        # 错误报告
        (r'error_reporting\s*\(\s*[^)]*\$_[^)]*\)', 'error_reporting'),
        # 时区设置
        (r'date_default_timezone_set\s*\(\s*[^)]*\$_[^)]*\)', 'date_default_timezone_set')
    ]
    
    dangerous_settings = [
        'disable_functions', 'safe_mode', 'open_basedir',
        'allow_url_fopen', 'allow_url_include'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
        
        for pattern, operation in config_operations:
            if re.search(pattern, line, re.IGNORECASE):
                # 根据操作类型确定严重程度
                if operation == 'ini_set':
                    # 检查是否涉及危险设置
                    is_dangerous = any(setting in line.lower() for setting in dangerous_settings)
                    severity = '高危' if is_dangerous else '中危'
                elif operation in ['putenv', 'session_save_path']:
                    severity = '高危'
                elif operation in ['ini_get', 'getenv']:
                    severity = '低危'
                else:
                    severity = '中危'
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{operation}使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"设置操纵 - {operation}",
                    'severity': severity
                })
                break


def detect_advanced_config_patterns(lines, vulnerabilities):
    """
    检测高级设置操纵模式
    """
    advanced_patterns = [
        # 动态配置加载
        (r'include\s*\(\s*[^)]*config.*\$_[^)]*\)', "动态配置加载"),
        (r'require\s*\(\s*[^)]*settings.*\$_[^)]*\)', "动态设置加载"),
        # 序列化配置
        (r'unserialize\s*\(\s*[^)]*\$_[^)]*\)', "配置反序列化"),
        # JSON配置解析
        (r'json_decode\s*\(\s*[^)]*\$_[^)]*\)', "JSON配置解析"),
        # 动态常量定义
        (r'define\s*\(\s*[^,]*\$_[^,]*,[^)]*\)', "动态常量定义"),
        # 全局变量操作
        (r'\$GLOBALS\s*\[\s*[^\]]*\$_[^\]]*\s*\]', "全局变量动态操作"),
        # 配置合并
        (r'array_merge\s*\(\s*[^)]*\$_[^)]*\)', "配置数组合并")
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        for pattern, pattern_type in advanced_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                severity = '高危' if pattern_type in ["动态配置加载", "配置反序列化"] else '中危'
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{pattern_type}使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"设置操纵 - {pattern_type}",
                    'severity': severity
                })
                break


def detect_context_aware_config_manipulation(lines, vulnerabilities):
    """
    检测上下文感知的设置操纵漏洞
    """
    contexts = [
        # 调试模式设置
        (r'debug.*\.\s*\$_', "调试模式设置"),
        # 错误显示设置
        (r'error.*display.*\.\s*\$_', "错误显示设置"),
        # 日志配置
        (r'log.*\.\s*\$_', "日志配置"),
        # 会话配置
        (r'session.*\.\s*\$_', "会话配置"),
        # 安全设置
        (r'security.*\.\s*\$_', "安全设置"),
        # 性能设置
        (r'performance.*\.\s*\$_', "性能设置"),
        # 数据库配置
        (r'database.*\.\s*\$_', "数据库配置")
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
                    'vulnerability_type': f"设置操纵 - {context_type}",
                    'severity': '中危'
                })
                break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试设置操纵漏洞

// PHP配置操纵 - 高危
ini_set('display_errors', $_GET['display_errors']);
ini_set('memory_limit', $_POST['memory_limit']);
ini_set('max_execution_time', $_REQUEST['max_time']);

// 危险PHP设置操纵
ini_set('disable_functions', $_GET['disabled_funcs']);
ini_set('allow_url_fopen', $_POST['allow_urls']);
ini_set('allow_url_include', $_REQUEST['allow_include']);

// 环境变量操纵 - 高危
putenv('PATH=' . $_GET['new_path']);
putenv('LD_LIBRARY_PATH=' . $_POST['lib_path']);

// 执行时间限制操纵 - 中危
set_time_limit($_GET['time_limit']);

// 会话设置操纵 - 中危
session_save_path($_POST['session_path']);
session_name($_REQUEST['session_name']);
session_set_cookie_params(3600, '/', $_GET['domain']);

// 错误报告设置操纵 - 中危
error_reporting($_GET['error_level']);

// 时区设置操纵 - 低危
date_default_timezone_set($_POST['timezone']);

// 安全头设置操纵 - 中危
header('X-Frame-Options: ' . $_GET['frame_options']);
header('Content-Security-Policy: ' . $_POST['csp']);
header('Strict-Transport-Security: ' . $_REQUEST['hsts']);

// 配置数组操纵 - 中危
$config['debug'] = $_GET['debug_mode'];
$GLOBALS['settings'] = $_POST['app_settings'];
$_ENV['APP_ENV'] = $_REQUEST['environment'];

// 常量定义操纵 - 中危
define('DEBUG_MODE', $_GET['debug']);
define('APP_VERSION', $_POST['version']);

// 配置信息泄露 - 低危
$setting_value = ini_get($_GET['setting_name']);
$env_value = getenv($_POST['env_var']);

// 相对安全的实现
// 固定配置设置
ini_set('display_errors', '0');
ini_set('memory_limit', '128M');
set_time_limit(30);

// 白名单验证
$allowed_timezones = ['UTC', 'America/New_York', 'Europe/London'];
if (in_array($_POST['timezone'], $allowed_timezones)) {
    date_default_timezone_set($_POST['timezone']);
}

// 数值范围验证
$time_limit = intval($_GET['time_limit']);
if ($time_limit > 0 && $time_limit <= 60) {
    set_time_limit($time_limit);
}

// 固定安全头设置
header('X-Frame-Options: DENY');
header('Content-Security-Policy: default-src \\'self\\'');
header('Strict-Transport-Security: max-age=31536000');

// 配置数组安全设置
$config['debug'] = false;
$GLOBALS['settings'] = ['theme' => 'default'];
$_ENV['APP_ENV'] = 'production';

// 常量安全定义
define('DEBUG_MODE', false);
define('APP_VERSION', '1.0.0');

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP设置操纵漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_configuration_manipulation_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到设置操纵漏洞")