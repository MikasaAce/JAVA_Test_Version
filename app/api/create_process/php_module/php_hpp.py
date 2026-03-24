import re

def detect_http_parameter_pollution(php_code):
    """
    PHP HTTP参数污染漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    processed_lines = set()  # 用于跟踪已处理的行号
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测超全局变量直接使用
    detect_super_globals(lines, vulnerabilities, processed_lines)
    
    # 检测敏感函数中的参数污染
    detect_sensitive_functions(lines, vulnerabilities, processed_lines)
    
    # 检测SQL查询中的参数污染
    detect_sql_injection_patterns(lines, vulnerabilities, processed_lines)
    
    # 检测HTTP头操作中的参数污染
    detect_header_manipulation(lines, vulnerabilities, processed_lines)
    
    # 检测文件操作中的参数污染
    detect_file_operations(lines, vulnerabilities, processed_lines)
    
    # 检测重定向中的参数污染
    detect_redirect_vulnerabilities(lines, vulnerabilities, processed_lines)
    
    return vulnerabilities


def detect_super_globals(lines, vulnerabilities, processed_lines):
    """
    检测超全局变量的直接使用
    """
    super_globals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES']
    
    for line_num, line in enumerate(lines, 1):
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测直接使用超全局变量
        for global_var in super_globals:
            if global_var in line:
                # 检查是否是数组访问形式（避免匹配注释中的文本）
                if re.search(r'\b' + re.escape(global_var) + r'\b', line):
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到直接使用超全局变量 '{global_var}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': "HTTP参数访问",
                        'severity': '中危'
                    })
                    break


def detect_sensitive_functions(lines, vulnerabilities, processed_lines):
    """
    检测敏感函数中的参数污染
    """
    sensitive_functions = {
        "include": "文件包含",
        "require": "文件包含", 
        "include_once": "文件包含",
        "require_once": "文件包含",
        "eval": "代码执行",
        "system": "命令执行",
        "exec": "命令执行",
        "shell_exec": "命令执行",
        "passthru": "命令执行",
        "unlink": "文件删除",
        "file_get_contents": "文件读取",
        "fopen": "文件操作",
    }
    
    super_globals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        for func_name, vuln_type in sensitive_functions.items():
            # 构建函数调用模式
            patterns = [
                r'\b' + re.escape(func_name) + r'\s*\(\s*[^)]*\)',
                r'->\s*' + re.escape(func_name) + r'\s*\('
            ]
            
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # 检查是否包含用户输入
                    for global_var in super_globals:
                        if global_var in line:
                            processed_lines.add(line_num)
                            
                            severity = '高危' if func_name in ['include', 'require', 'eval'] else '中危'
                            
                            vulnerabilities.append({
                                'line': line_num,
                                'message': f"检测到敏感函数 '{func_name}' 使用用户输入",
                                'code_snippet': line_clean,
                                'vulnerability_type': f"参数污染 - {vuln_type}",
                                'severity': severity
                            })
                            break
                    break


def detect_sql_injection_patterns(lines, vulnerabilities, processed_lines):
    """
    检测SQL查询中的参数污染
    """
    sql_functions = [
        'mysql_query', 'mysqli_query', 'pg_query', 'sqlsrv_query',
        'oci_parse', 'mysqli_prepare', 'pg_prepare'
    ]
    
    super_globals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测SQL函数调用
        for sql_func in sql_functions:
            if sql_func in line:
                # 检查是否包含用户输入拼接
                for global_var in super_globals:
                    if global_var in line and ('.' in line or '+' in line):
                        processed_lines.add(line_num)
                        
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到SQL函数 '{sql_func}' 使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SQL注入 - 参数污染",
                            'severity': '严重'
                        })
                        break
                break
        
        # 检测PDO查询
        pdo_patterns = [
            r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*query\s*\(\s*[^)]+\)',
            r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*->\s*exec\s*\(\s*[^)]+\)'
        ]
        
        for pattern in pdo_patterns:
            if re.search(pattern, line):
                for global_var in super_globals:
                    if global_var in line and ('.' in line or '+' in line):
                        processed_lines.add(line_num)
                        
                        vulnerabilities.append({
                            'line': line_num,
                            'message': "检测到PDO查询使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SQL注入 - 参数污染",
                            'severity': '严重'
                        })
                        break
                break


def detect_header_manipulation(lines, vulnerabilities, processed_lines):
    """
    检测HTTP头操作中的参数污染
    """
    header_functions = ['header', 'setcookie']
    super_globals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        for header_func in header_functions:
            if header_func in line:
                # 检查是否包含用户输入
                for global_var in super_globals:
                    if global_var in line:
                        processed_lines.add(line_num)
                        
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到'{header_func}'函数使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "HTTP头注入 - 参数污染",
                            'severity': '中危'
                        })
                        break
                break


def detect_file_operations(lines, vulnerabilities, processed_lines):
    """
    检测文件操作中的参数污染
    """
    file_functions = [
        'unlink', 'file_get_contents', 'fopen', 'file',
        'readfile', 'file_put_contents', 'move_uploaded_file'
    ]
    
    super_globals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        for file_func in file_functions:
            if file_func in line:
                # 检查是否包含用户输入
                for global_var in super_globals:
                    if global_var in line:
                        processed_lines.add(line_num)
                        
                        severity = '高危' if file_func in ['unlink', 'file_put_contents'] else '中危'
                        
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到文件操作 '{file_func}' 使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "文件操作 - 参数污染",
                            'severity': severity
                        })
                        break
                break


def detect_redirect_vulnerabilities(lines, vulnerabilities, processed_lines):
    """
    检测重定向中的参数污染
    """
    super_globals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测header重定向
        if 'header' in line and 'Location:' in line:
            for global_var in super_globals:
                if global_var in line:
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到重定向使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "开放重定向 - 参数污染",
                        'severity': '中危'
                    })
                    break


# 增强版检测函数
def detect_http_parameter_pollution_enhanced(php_code):
    """
    PHP HTTP参数污染漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    processed_lines = set()
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_parameter_usage(lines, vulnerabilities, processed_lines)
    detect_concatenation_patterns(lines, vulnerabilities, processed_lines)
    detect_configuration_risks(lines, vulnerabilities, processed_lines)
    
    return vulnerabilities


def detect_comprehensive_parameter_usage(lines, vulnerabilities, processed_lines):
    """
    增强版的参数使用检测
    """
    super_global_patterns = [
        (r'\$_(GET|POST|REQUEST|COOKIE|FILES)\b', '超全局变量'),
        (r'\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[[^\]]+\]', '数组参数访问')
    ]
    
    sensitive_operations = [
        (r'\b(include|require)(_once)?\s*\(\s*[^)]*\$_[^)]*\)', '文件包含', '高危'),
        (r'\beval\s*\(\s*[^)]*\$_[^)]*\)', '代码执行', '严重'),
        (r'\b(system|exec|shell_exec|passthru)\s*\(\s*[^)]*\$_[^)]*\)', '命令执行', '严重'),
        (r'\b(unlink|file_put_contents)\s*\(\s*[^)]*\$_[^)]*\)', '文件操作', '高危'),
        (r'\b(file_get_contents|fopen|file|readfile)\s*\(\s*[^)]*\$_[^)]*\)', '文件读取', '中危')
    ]
    
    for line_num, line in enumerate(lines, 1):
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
        
        # 检测超全局变量使用
        for pattern, desc in super_global_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                processed_lines.add(line_num)
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{desc}使用",
                    'code_snippet': line_clean,
                    'vulnerability_type': "HTTP参数访问",
                    'severity': '中危'
                })
                break
        
        # 检测敏感操作
        for pattern, op_type, severity in sensitive_operations:
            if re.search(pattern, line, re.IGNORECASE):
                if line_num not in processed_lines:
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到{op_type}使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"参数污染 - {op_type}",
                        'severity': severity
                    })
                break


def detect_concatenation_patterns(lines, vulnerabilities, processed_lines):
    """
    检测字符串拼接中的参数污染
    """
    super_globals = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        # 检测字符串拼接操作
        for global_pattern in super_globals:
            # 查找用户输入与字符串拼接的模式
            if re.search(global_pattern, line) and ('.' in line or '+' in line):
                # 排除安全的过滤函数
                safe_filters = [
                    'filter_var', 'intval', 'floatval', 'htmlspecialchars',
                    'htmlentities', 'addslashes', 'mysql_real_escape_string',
                    'mysqli_real_escape_string', 'preg_replace', 'strip_tags'
                ]
                
                has_safe_filter = any(filter_func in line for filter_func in safe_filters)
                
                if not has_safe_filter and line_num not in processed_lines:
                    processed_lines.add(line_num)
                    
                    # 判断上下文风险
                    risk_context = "字符串拼接"
                    severity = '中危'
                    
                    if any(func in line for func in ['include', 'require', 'eval']):
                        risk_context = "动态代码执行"
                        severity = '严重'
                    elif any(func in line for func in ['mysql_query', 'mysqli_query', 'PDO']):
                        risk_context = "SQL查询"
                        severity = '严重'
                    elif any(func in line for func in ['system', 'exec', 'shell_exec']):
                        risk_context = "命令执行"
                        severity = '严重'
                    elif any(func in line for func in ['header', 'setcookie']):
                        risk_context = "HTTP头操作"
                        severity = '中危'
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到用户输入在{risk_context}中使用",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"参数污染 - {risk_context}",
                        'severity': severity
                    })
                    break


def detect_configuration_risks(lines, vulnerabilities, processed_lines):
    """
    检测配置相关的参数污染风险
    """
    config_patterns = [
        (r'config\s*/\s*[^.]*\$_[^.]*\.php', '配置文件包含'),
        (r'\.\s*php\s*[\'"]\s*\.\s*\$_', '动态文件扩展名'),
        (r'/\w+/\s*\$_', '动态路径构造')
    ]
    
    for line_num, line in enumerate(lines, 1):
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        for pattern, risk_type in config_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                processed_lines.add(line_num)
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{risk_type}风险",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"配置污染 - {risk_type}",
                    'severity': '高危'
                })
                break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 HTTP 参数污染漏洞

// 直接使用超全局变量
$username = $_GET['user'];
$password = $_POST['pass'];
$action = $_REQUEST['action'];

// 文件包含漏洞 - 参数污染
include($_GET['page'] . '.php');
require_once($_POST['template']);

// SQL注入 - 参数污染
mysql_query("SELECT * FROM users WHERE id = " . $_GET['id']);
mysqli_query($conn, "UPDATE products SET name = '" . $_POST['name'] . "'");
$pdo->query("DELETE FROM logs WHERE date = '" . $_REQUEST['date'] . "'");

// 命令执行 - 参数污染
system("ls " . $_GET['dir']);
exec($_POST['command']);

// 代码执行 - 参数污染
eval('echo ' . $_GET['code'] . ';');

// HTTP头注入 - 参数污染
header("Content-Type: " . $_POST['content_type']);
setcookie("session", $_GET['session_id']);

// 开放重定向 - 参数污染
header("Location: " . $_GET['redirect_url']);
header('Location: ' . $_POST['return_url']);

// 文件操作 - 参数污染
unlink($_GET['file_path']);
$content = file_get_contents($_POST['filename']);
fopen($_REQUEST['config_file'], 'r');

// 敏感配置 - 参数污染
$config_file = "config/" . $_GET['env'] . ".php";
$log_file = "/var/log/" . $_POST['app'] . ".log";

// 数组参数污染
$filters = $_GET['filters']; // 可能传递数组参数
$options = $_POST['options'];

// Cookie污染
$theme = $_COOKIE['theme'];
$language = $_COOKIE['lang'];

// 相对安全的用法（经过过滤）
$filtered_user = filter_var($_GET['user'], FILTER_SANITIZE_STRING);
$safe_id = intval($_POST['id']);
$validated_page = in_array($_GET['page'], ['home', 'about']) ? $_GET['page'] : 'home';

// 使用预处理语句（安全）
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$_POST['username']]);

// 安全示例
$fixed_page = 'home.php';
include('templates/header.php');
echo "正常业务逻辑";
?>
"""

    print("=" * 60)
    print("PHP HTTP参数污染漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_http_parameter_pollution_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到HTTP参数污染漏洞")