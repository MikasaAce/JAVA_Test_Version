import re


def detect_ssrf_vulnerability(php_code):
    """
    PHP SSRF漏洞检测主函数 - 使用正则匹配
    """
    vulnerabilities = []
    processed_lines = set()  # 用于跟踪已处理的行号
    
    lines = php_code.split('\n')
    
    # 文件读取函数
    file_functions = {
        "file_get_contents": "文件/URL内容读取",
        "fopen": "文件/URL打开", 
        "file": "文件/URL读取",
        "readfile": "文件/URL读取输出",
        "curl_init": "cURL初始化",
        "curl_exec": "cURL执行",
        "fsockopen": "网络套接字",
        "stream_socket_client": "流套接字客户端",
    }
    
    # cURL选项函数
    curl_functions = ['curl_setopt', 'curl_setopt_array']
    
    # HTTP库函数
    http_libraries = ['get_headers', 'get_meta_tags', 'http_get', 'http_post']
    
    # 重定向函数
    redirect_functions = ['header']
    
    # XML函数
    xml_functions = [
        'simplexml_load_file', 'simplexml_load_string',
        'DOMDocument::load', 'DOMDocument::loadXML'
    ]
    
    # 用户输入标识符
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    # URL模式
    url_patterns = ['http://', 'https://', 'ftp://', 'file://', 'gopher://', 'dict://', 'tcp://']
    
    # 内部资源模式
    internal_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.', '10.', '172.16.', '192.168.']
    
    # 验证函数
    validation_patterns = [
        'filter_var', 'parse_url', 'preg_match', 'strpos',
        'whitelist', 'allowed', 'validate', 'check'
    ]
    
    # 危险cURL选项
    dangerous_options = [
        'CURLOPT_FOLLOWLOCATION', 'CURLOPT_RETURNTRANSFER',
        'CURLOPT_PROTOCOLS', 'CURLOPT_REDIR_PROTOCOLS'
    ]
    
    # URL协议
    url_protocols = ['http://', 'https://', 'ftp://', 'php://', 'data://', 'gopher://', 'dict://']

    for i, line in enumerate(lines):
        line_num = i + 1
        
        # 跳过已处理的行
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        # 1. 检测文件读取函数
        for func_name in file_functions.keys():
            func_pattern = r'\b' + re.escape(func_name) + r'\s*\('
            if re.search(func_pattern, line_clean):
                # 获取完整的函数调用
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    # 检查是否访问URL
                    url_detected = any(pattern in full_call for pattern in url_patterns)
                    
                    # 检查是否访问内部资源
                    internal_resource_detected = any(pattern in full_call for pattern in internal_patterns)
                    
                    # 检查是否有URL验证
                    no_validation = not any(pattern in full_call for pattern in validation_patterns)
                    
                    if user_input_detected and url_detected:
                        severity = '高危' if (internal_resource_detected or no_validation) else '中危'
                        message = f"检测到函数 '{func_name}' 使用用户输入访问URL"
                        vuln_type = f"SSRF - {file_functions[func_name]}"

                        if internal_resource_detected:
                            message += " - 可能访问内部资源"
                        if no_validation:
                            message += " - 未进行URL验证"

                        # 标记为已处理
                        processed_lines.add(line_num)

                        vulnerabilities.append({
                            'line': line_num,
                            'message': message,
                            'code_snippet': line_clean,
                            'vulnerability_type': vuln_type,
                            'severity': severity
                        })
                break
        
        # 2. 检测cURL选项设置
        for curl_func in curl_functions:
            curl_pattern = r'\b' + re.escape(curl_func) + r'\s*\('
            if re.search(curl_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查是否设置危险选项
                    dangerous_detected = any(option in full_call for option in dangerous_options)
                    
                    # 检查是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    if user_input_detected and dangerous_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)

                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到cURL选项设置 '{curl_func}' 使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SSRF - cURL选项",
                            'severity': '中危'
                        })
        
        # 3. 检测SoapClient使用
        if 'new SoapClient' in line_clean and line_num not in processed_lines:
            full_call = extract_full_function_call(lines, i)
            
            if full_call:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)

                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到SoapClient使用用户输入 - XXE/SSRF风险",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SSRF - SoapClient",
                        'severity': '高危'
                    })
        
        # 4. 检测URL字符串拼接
        if any(pattern in line_clean for pattern in url_patterns) and line_num not in processed_lines:
            # 检查是否包含用户输入
            user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
            
            # 检查是否访问内部资源
            internal_detected = any(pattern in line_clean for pattern in internal_patterns)
            
            # 检查字符串拼接
            string_concatenation = '+' in line_clean or '.' in line_clean
            
            if user_input_detected and string_concatenation:
                severity = '高危' if internal_detected else '中危'
                message = "检测到URL字符串拼接使用用户输入"

                if internal_detected:
                    message += " - 可能访问内部资源"

                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': "SSRF - URL拼接",
                    'severity': severity
                })
        
        # 5. 检测HTTP请求库
        for http_func in http_libraries:
            http_pattern = r'\b' + re.escape(http_func) + r'\s*\('
            if re.search(http_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查参数是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    if user_input_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)

                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到HTTP库函数 '{http_func}' 使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SSRF - HTTP库",
                            'severity': '中危'
                        })
        
        # 6. 检测重定向相关函数
        for redirect_func in redirect_functions:
            redirect_pattern = r'\b' + re.escape(redirect_func) + r'\s*\('
            if re.search(redirect_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查Location重定向
                    if 'Location:' in full_call:
                        # 检查是否包含用户输入
                        user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                        
                        # 检查是否重定向到外部URL
                        external_detected = any(pattern in full_call for pattern in ['http://', 'https://'])
                        
                        if user_input_detected and external_detected:
                            # 标记为已处理
                            processed_lines.add(line_num)

                            vulnerabilities.append({
                                'line': line_num,
                                'message': "检测到重定向使用用户输入 - 开放重定向风险",
                                'code_snippet': line_clean,
                                'vulnerability_type': "SSRF - 开放重定向",
                                'severity': '中危'
                            })
        
        # 7. 检测文件包含函数
        include_patterns = [r'\binclude\s*\(', r'\brequire\s*\(', r'\binclude_once\s*\(', r'\brequire_once\s*\(']
        for pattern in include_patterns:
            if re.search(pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查是否使用URL协议
                    protocol_detected = any(protocol in full_call for protocol in url_protocols)
                    
                    # 检查是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    if user_input_detected and protocol_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)

                        vulnerabilities.append({
                            'line': line_num,
                            'message': "检测到文件包含使用URL协议和用户输入 - RFI/SSRF风险",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SSRF - 远程文件包含",
                            'severity': '高危'
                        })
        
        # 8. 检测XML相关函数
        for xml_func in xml_functions:
            xml_pattern = r'\b' + re.escape(xml_func) + r'\s*\('
            if re.search(xml_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查参数是否包含用户输入和URL
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    url_detected = any(protocol in full_call for protocol in ['http://', 'https://'])
                    
                    if user_input_detected and url_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)

                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到XML函数 '{xml_func}' 使用用户输入访问URL - XXE/SSRF风险",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SSRF - XML外部实体",
                            'severity': '高危'
                        })
        
        # 9. 检测new DOMDocument使用
        if 'new DOMDocument' in line_clean and line_num not in processed_lines:
            full_call = extract_full_function_call(lines, i)
            
            if full_call:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)

                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到DOMDocument使用用户输入 - XXE/SSRF风险",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SSRF - DOMDocument",
                        'severity': '高危'
                    })
        
        # 10. 检测危险协议使用
        dangerous_protocols = ['file://', 'gopher://', 'dict://', 'tcp://']
        for protocol in dangerous_protocols:
            if protocol in line_clean and line_num not in processed_lines:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)

                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到使用危险协议 '{protocol}' 和用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SSRF - 危险协议",
                        'severity': '高危'
                    })
        
        # 11. 检测内部资源访问
        if any(pattern in line_clean for pattern in internal_patterns) and line_num not in processed_lines:
            # 检查是否包含用户输入
            user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
            
            # 检查是否在URL上下文中
            url_context = any(pattern in line_clean for pattern in url_patterns)
            
            if user_input_detected and url_context:
                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到用户输入可能访问内部资源",
                    'code_snippet': line_clean,
                    'vulnerability_type': "SSRF - 内部资源访问",
                    'severity': '高危'
                })

    return vulnerabilities


def extract_full_function_call(lines, start_line):
    """
    提取完整的函数调用（处理跨行情况）
    """
    line_num = start_line
    call_content = ""
    open_parentheses = 0
    close_parentheses = 0
    
    while line_num < len(lines):
        line = lines[line_num].strip()
        call_content += line
        
        # 统计括号
        open_parentheses += line.count('(')
        close_parentheses += line.count(')')
        
        # 如果括号匹配，则结束
        if open_parentheses > 0 and open_parentheses == close_parentheses:
            return call_content
        
        line_num += 1
        
        # 防止无限循环，最多检查10行
        if line_num - start_line > 10:
            break
    
    return call_content if open_parentheses == close_parentheses else None


# 测试代码（保持不变）
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 SSRF漏洞

// 不安全的文件读取函数 - 高危
$content = file_get_contents($_GET['url']);
$data = fopen($_POST['file_url'], 'r');
$lines = file($_REQUEST['remote_file']);

// cURL SSRF - 高危
$ch = curl_init($_GET['api_endpoint']);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_exec($ch);

// 网络套接字 - 高危
$fp = fsockopen($_POST['host'], $_REQUEST['port']);
stream_socket_client('tcp://' . $_GET['server'] . ':80');

// SoapClient SSRF - 高危
$client = new SoapClient($_GET['wsdl_url']);

// URL字符串拼接 - 中危
$api_url = 'https://api.example.com/v1/' . $_GET['endpoint'];
$image_url = 'http://' . $_POST['cdn'] . '/images/' . $_REQUEST['filename'];

// HTTP库函数 - 中危
$headers = get_headers($_GET['check_url']);
$meta_tags = get_meta_tags($_POST['site_url']);

// 重定向SSRF - 中危
header('Location: ' . $_GET['redirect_url']);

// 文件包含SSRF - 高危
include($_GET['remote_script']);
require($_POST['external_file']);

// XML外部实体 - 高危
$xml = simplexml_load_file($_GET['xml_url']);
$dom = new DOMDocument();
$dom->load($_POST['xml_file']);

// 内部资源访问 - 高危
file_get_contents('http://localhost:8080/api');
curl_exec(curl_init('http://127.0.0.1/admin'));
fopen('http://192.168.1.1/config', 'r');

// 危险协议 - 高危
file_get_contents('file:///etc/passwd');
fopen('gopher://internal-server:25', 'r');
curl_exec(curl_init('dict://localhost:11211/info'));

// 相对安全的实现
// URL白名单验证
$allowed_domains = ['api.trusted.com', 'cdn.safe.com'];
$url = $_POST['url'];
$parsed = parse_url($url);
if (in_array($parsed['host'], $allowed_domains)) {
    $content = file_get_contents($url);
}

// 使用filter_var验证URL
if (filter_var($_GET['url'], FILTER_VALIDATE_URL)) {
    $parsed = parse_url($_GET['url']);
    // 禁止内部网络访问
    $internal_networks = ['127.0.0.1', 'localhost', '10.', '192.168.'];
    $is_internal = false;
    foreach ($internal_networks as $network) {
        if (strpos($parsed['host'], $network) === 0) {
            $is_internal = true;
            break;
        }
    }
    if (!$is_internal) {
        $content = file_get_contents($_GET['url']);
    }
}

// 限制cURL协议
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $url,
    CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    CURLOPT_FOLLOWLOCATION => false
]);

// 固定URL（安全）
file_get_contents('https://api.trusted.com/data');
$ch = curl_init('https://cdn.safe.com/image.jpg');

// 禁用危险函数（安全）
// 在php.ini中设置 allow_url_fopen = Off
// 在php.ini中设置 allow_url_include = Off

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP SSRF漏洞检测（正则版本）")
    print("=" * 60)

    results = detect_ssrf_vulnerability(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SSRF漏洞")