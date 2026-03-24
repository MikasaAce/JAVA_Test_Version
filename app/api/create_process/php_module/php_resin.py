import re

def detect_resource_injection(php_code):
    """
    PHP资源注入漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测URL操作函数
    detect_url_operations(lines, vulnerabilities)
    
    # 检测数据库连接函数
    detect_database_connections(lines, vulnerabilities)
    
    # 检测文件系统操作函数
    detect_filesystem_operations(lines, vulnerabilities)
    
    # 检测命令执行函数
    detect_command_execution(lines, vulnerabilities)
    
    # 检测LDAP操作函数
    detect_ldap_operations(lines, vulnerabilities)
    
    # 检测邮件操作函数
    detect_mail_operations(lines, vulnerabilities)
    
    # 检测XML操作函数
    detect_xml_operations(lines, vulnerabilities)
    
    # 检测资源URL拼接
    detect_resource_concatenation(lines, vulnerabilities)
    
    return vulnerabilities


def detect_url_operations(lines, vulnerabilities):
    """
    检测URL操作函数中的资源注入漏洞
    """
    url_functions = {
        "file_get_contents": "URL内容读取",
        "fopen": "URL流打开",
        "curl_init": "cURL初始化",
        "curl_setopt": "cURL设置",
        "fsockopen": "网络套接字",
        "stream_socket_client": "流套接字客户端",
        "get_headers": "获取HTTP头",
        "get_meta_tags": "获取meta标签",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    url_patterns = [r'http://', r'https://', r'ftp://', r'file://', r'php://']
    validation_patterns = ['filter_var', 'parse_url', 'preg_match', 'strpos', 'whitelist', 'allowed', 'validate']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测URL操作函数
        for func_name, func_desc in url_functions.items():
            if func_name in line:
                # 检查是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                # 检查是否访问外部资源
                external_resource_detected = any(re.search(pattern, line) for pattern in url_patterns)
                
                # 检查是否有URL验证
                no_validation = not any(pattern in line for pattern in validation_patterns)
                
                if user_input_detected and external_resource_detected:
                    severity = '高危' if no_validation else '中危'
                    message = f"检测到URL操作函数 '{func_name}' 使用用户输入"
                    vuln_type = f"资源注入 - {func_desc}"
                    
                    if no_validation:
                        message += " - 未进行URL验证"
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': vuln_type,
                        'severity': severity
                    })


def detect_database_connections(lines, vulnerabilities):
    """
    检测数据库连接函数中的资源注入漏洞
    """
    db_functions = {
        "mysql_connect": "MySQL连接",
        "mysqli_connect": "MySQLi连接",
        "pg_connect": "PostgreSQL连接",
        "sqlsrv_connect": "SQL Server连接",
        "oci_connect": "Oracle连接",
        "PDO": "PDO连接",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测数据库连接函数
        for func_name, func_desc in db_functions.items():
            if func_name in line:
                # 检查连接参数是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到数据库连接函数 '{func_name}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"资源注入 - 数据库连接",
                        'severity': '高危'
                    })


def detect_filesystem_operations(lines, vulnerabilities):
    """
    检测文件系统操作函数中的资源注入漏洞
    """
    filesystem_functions = {
        "file_get_contents": "文件读取",
        "file_put_contents": "文件写入",
        "fopen": "文件打开",
        "unlink": "文件删除",
        "copy": "文件复制",
        "rename": "文件重命名",
        "mkdir": "目录创建",
        "rmdir": "目录删除",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    special_protocols = [r'php://', r'data://', r'expect://', r'phar://']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测文件系统函数
        for func_name, func_desc in filesystem_functions.items():
            if func_name in line:
                # 检查文件路径是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                # 检查是否访问特殊协议
                protocol_detected = any(re.search(protocol, line) for protocol in special_protocols)
                
                if user_input_detected:
                    severity = '高危' if protocol_detected else '中危'
                    message = f"检测到文件系统函数 '{func_name}' 使用用户输入"
                    vuln_type = f"资源注入 - 文件系统操作"
                    
                    if protocol_detected:
                        message += " - 可能使用特殊协议"
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': vuln_type,
                        'severity': severity
                    })


def detect_command_execution(lines, vulnerabilities):
    """
    检测命令执行函数中的资源注入漏洞
    """
    command_functions = {
        "system": "系统命令执行",
        "exec": "命令执行",
        "shell_exec": "Shell命令执行",
        "passthru": "透传命令执行",
        "popen": "进程打开",
        "proc_open": "进程打开",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测命令执行函数
        for func_name, func_desc in command_functions.items():
            if func_name in line:
                # 检查命令参数是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到命令执行函数 '{func_name}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"资源注入 - 命令执行",
                        'severity': '严重'
                    })
        
        # 检测反引号命令执行
        if '`' in line and '$' in line:
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            if user_input_detected:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到反引号命令执行使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "资源注入 - 反引号命令执行",
                    'severity': '严重'
                })


def detect_ldap_operations(lines, vulnerabilities):
    """
    检测LDAP操作函数中的资源注入漏洞
    """
    ldap_functions = {
        "ldap_connect": "LDAP连接",
        "ldap_bind": "LDAP绑定",
        "ldap_search": "LDAP搜索",
        "ldap_modify": "LDAP修改",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测LDAP函数
        for func_name, func_desc in ldap_functions.items():
            if func_name in line:
                # 检查LDAP参数是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到LDAP函数 '{func_name}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"资源注入 - LDAP操作",
                        'severity': '高危'
                    })


def detect_mail_operations(lines, vulnerabilities):
    """
    检测邮件操作函数中的资源注入漏洞
    """
    mail_functions = {
        "mail": "邮件发送",
        "imap_open": "IMAP连接",
        "imap_mail": "IMAP邮件",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测邮件函数
        for func_name, func_desc in mail_functions.items():
            if func_name in line:
                # 检查邮件参数是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到邮件函数 '{func_name}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"资源注入 - 邮件操作",
                        'severity': '中危'
                    })


def detect_xml_operations(lines, vulnerabilities):
    """
    检测XML操作函数中的资源注入漏洞
    """
    xml_functions = {
        "simplexml_load_file": "SimpleXML文件加载",
        "simplexml_load_string": "SimpleXML字符串加载",
        "DOMDocument::load": "DOM文档加载",
        "DOMDocument::loadXML": "DOM XML加载",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测XML函数
        for func_name, func_desc in xml_functions.items():
            if func_name in line:
                # 检查XML源是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到XML函数 '{func_name}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"资源注入 - XML操作",
                        'severity': '高危'
                    })


def detect_resource_concatenation(lines, vulnerabilities):
    """
    检测资源URL拼接中的资源注入漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    resource_patterns = [r'http://', r'https://', r'ftp://', r'file://', r'ldap://', r'mysql://']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测资源相关的字符串拼接
        is_resource_context = any(re.search(pattern, line) for pattern in resource_patterns)
        
        if is_resource_context:
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            # 检查是否有字符串拼接操作
            has_concatenation = '.' in line or '+' in line
            
            if user_input_detected and has_concatenation:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到资源URL拼接使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "资源注入 - URL拼接",
                    'severity': '中危'
                })


# 增强版检测函数
def detect_resource_injection_enhanced(php_code):
    """
    PHP资源注入漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_resource_injection(lines, vulnerabilities)
    detect_advanced_injection_patterns(lines, vulnerabilities)
    detect_context_aware_injection(lines, vulnerabilities)
    
    return vulnerabilities


def detect_comprehensive_resource_injection(lines, vulnerabilities):
    """
    增强版的资源注入检测
    """
    resource_operations = [
        # URL操作
        (r'file_get_contents\s*\(\s*[^)]*\$_[^)]*\)', 'file_get_contents'),
        (r'fopen\s*\(\s*[^)]*\$_[^)]*\)', 'fopen'),
        (r'curl_init\s*\(\s*[^)]*\$_[^)]*\)', 'curl_init'),
        (r'fsockopen\s*\(\s*[^)]*\$_[^)]*\)', 'fsockopen'),
        # 数据库操作
        (r'mysql_connect\s*\(\s*[^)]*\$_[^)]*\)', 'mysql_connect'),
        (r'PDO\s*\(\s*[^)]*\$_[^)]*\)', 'PDO'),
        # 命令执行
        (r'system\s*\(\s*[^)]*\$_[^)]*\)', 'system'),
        (r'exec\s*\(\s*[^)]*\$_[^)]*\)', 'exec'),
        (r'shell_exec\s*\(\s*[^)]*\$_[^)]*\)', 'shell_exec'),
        # 特殊协议
        (r'php://[^)]*\$_[^)]*', 'php://协议'),
        (r'data://[^)]*\$_[^)]*', 'data://协议'),
        (r'phar://[^)]*\$_[^)]*', 'phar://协议')
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
        
        for pattern, operation in resource_operations:
            if re.search(pattern, line, re.IGNORECASE):
                # 根据操作类型确定严重程度
                if operation in ['system', 'exec', 'shell_exec']:
                    severity = '严重'
                elif operation in ['mysql_connect', 'PDO', 'php://协议', 'data://协议']:
                    severity = '高危'
                else:
                    severity = '中危'
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{operation}使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"资源注入 - {operation}",
                    'severity': severity
                })
                break


def detect_advanced_injection_patterns(lines, vulnerabilities):
    """
    检测高级资源注入模式
    """
    advanced_patterns = [
        # 动态函数调用
        (r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*[^)]*\$_[^)]*\)', "动态函数调用"),
        # 回调函数
        (r'call_user_func\s*\(\s*[^)]*\$_[^)]*\)', "回调函数"),
        (r'call_user_func_array\s*\(\s*[^)]*\$_[^)]*\)', "回调函数数组"),
        # 变量变量
        (r'\$\$[a-zA-Z_][a-zA-Z0-9_]*', "变量变量"),
        # 动态包含
        (r'include\s*\(\s*\$_[^)]*\)', "动态包含"),
        (r'require\s*\(\s*\$_[^)]*\)', "动态require"),
        # 序列化操作
        (r'unserialize\s*\(\s*[^)]*\$_[^)]*\)', "反序列化")
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
        
        for pattern, pattern_type in advanced_patterns:
            if re.search(pattern, line):
                severity = '高危'
                if pattern_type == "反序列化":
                    severity = '严重'
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{pattern_type}使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': f"资源注入 - {pattern_type}",
                    'severity': severity
                })
                break


def detect_context_aware_injection(lines, vulnerabilities):
    """
    检测上下文感知的资源注入漏洞
    """
    contexts = [
        # API端点
        (r'api.*\.\s*\$_', "API端点注入"),
        # 文件上传
        (r'upload.*\.\s*\$_', "文件上传注入"),
        # 数据库查询
        (r'query.*\.\s*\$_', "数据库查询注入"),
        # 外部服务调用
        (r'service.*\.\s*\$_', "外部服务注入"),
        # 配置加载
        (r'config.*\.\s*\$_', "配置加载注入"),
        # 模板渲染
        (r'template.*\.\s*\$_', "模板渲染注入"),
        # 缓存操作
        (r'cache.*\.\s*\$_', "缓存操作注入")
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
                    'vulnerability_type': f"资源注入 - {context_type}",
                    'severity': '中危'
                })
                break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试资源注入漏洞

// URL资源注入 - 高危
$content = file_get_contents($_GET['url']);
$data = file_get_contents('http://' . $_POST['domain'] . '/api');
$fp = fopen($_REQUEST['remote_file'], 'r');

// cURL资源注入 - 高危
$ch = curl_init($_GET['api_url']);
curl_setopt($ch, CURLOPT_URL, $_POST['endpoint']);

// 数据库连接注入 - 高危
mysql_connect($_GET['db_host'], $_POST['db_user'], $_REQUEST['db_pass']);
new PDO('mysql:host=' . $_GET['host'] . ';dbname=test', 'user', 'pass');

// 文件系统资源注入 - 中危
file_put_contents($_GET['log_file'], $data);
copy($_POST['source'], $_REQUEST['destination']);

// 特殊协议注入 - 高危
include($_GET['data_url']);  // data://text/plain,<?php system('id'); ?>
file_get_contents('php://filter/read=convert.base64-encode/resource=' . $_POST['file']);

// 命令执行资源注入 - 严重
system('ping ' . $_GET['host']);
exec('nslookup ' . $_POST['domain']);
$output = `dig ` . $_REQUEST['dns_query'];

// LDAP资源注入 - 高危
ldap_connect($_GET['ldap_server']);
ldap_bind($conn, $_POST['ldap_user'], $_REQUEST['ldap_pass']);

// 邮件资源注入 - 中危
mail($_GET['to'], $_POST['subject'], $_REQUEST['message']);
imap_open('{' . $_GET['mail_server'] . ':993/imap/ssl}INBOX', $user, $pass);

// XML资源注入 - 高危
simplexml_load_file($_GET['xml_url']);
$dom = new DOMDocument();
$dom->load($_POST['xml_file']);

// 网络套接字注入 - 高危
fsockopen($_GET['host'], $_POST['port']);
stream_socket_client('tcp://' . $_REQUEST['server'] . ':80');

// 资源URL拼接 - 中危
$api_url = 'https://api.example.com/v1/' . $_GET['endpoint'];
$image_url = 'http://' . $_POST['cdn'] . '/images/' . $_REQUEST['filename'];

// 相对安全的实现
// URL白名单验证
$allowed_urls = [
    'https://api.trusted.com/data',
    'https://cdn.safe.com/images'
];
if (in_array($_GET['url'], $allowed_urls)) {
    $content = file_get_contents($_GET['url']);
}

// 使用filter_var验证URL
if (filter_var($_POST['url'], FILTER_VALIDATE_URL)) {
    $parsed = parse_url($_POST['url']);
    if ($parsed['host'] === 'trusted.com') {
        $content = file_get_contents($_POST['url']);
    }
}

// 参数化数据库连接（安全）
$db_host = 'localhost';
$db_user = 'app_user';
$db_pass = 'secure_password';
mysql_connect($db_host, $db_user, $db_pass);

// 命令执行白名单
$allowed_commands = ['ls', 'pwd', 'whoami'];
if (in_array($_GET['command'], $allowed_commands)) {
    system($_GET['command']);
}

// 固定资源（安全）
file_get_contents('https://api.trusted.com/data');
$ch = curl_init('https://cdn.safe.com/image.jpg');
system('ls /var/log/');

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP资源注入漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_resource_injection_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到资源注入漏洞")