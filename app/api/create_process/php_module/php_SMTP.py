import re

def detect_smtp_header_injection(php_code):
    """
    PHP SMTP标头伪造漏洞检测主函数 - 使用正则匹配
    """
    vulnerabilities = []
    processed_lines = set()  # 用于跟踪已处理的行号
    
    lines = php_code.split('\n')
    
    # 邮件相关函数列表
    mail_functions = ['mail', 'imap_mail', 'mb_send_mail']
    
    # 用户输入标识符
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES']
    
    # CRLF注入模式
    crlf_patterns = [r'\\r', r'\\n', r'%0d', r'%0a', r'\r', r'\n']
    
    # 邮件头模式
    header_patterns = [
        'To:', 'From:', 'Subject:', 'Cc:', 'Bcc:',
        'Reply-To:', 'Content-Type:', 'MIME-Version:',
        'X-Mailer:', 'X-Priority:', 'Return-Path:'
    ]
    
    # 1. 检测mail函数调用
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # 跳过已处理的行
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        # 检测mail函数
        mail_match = re.search(r'\bmail\s*\(', line_clean)
        if mail_match:
            # 获取完整的函数调用（可能跨多行）
            full_call = extract_full_function_call(lines, i)
            
            if full_call:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 检查CRLF注入风险
                    crlf_injection_detected = any(re.search(pattern, full_call) for pattern in crlf_patterns)
                    
                    # 检查邮件头注入风险
                    header_injection_risk = any(pattern in full_call for pattern in header_patterns)
                    
                    # 分析参数
                    params = extract_function_parameters(full_call)
                    
                    severity = '中危'
                    message = "检测到mail函数使用用户输入"
                    
                    if crlf_injection_detected:
                        message += " - 可能包含CRLF注入"
                        severity = '高危'
                    
                    if header_injection_risk:
                        message += " - 可能伪造邮件头"
                        severity = '高危'
                    
                    # 检查第4个参数（额外头信息）
                    if len(params) >= 4 and any(indicator in params[3] for indicator in user_input_indicators):
                        message += " - 额外头参数使用用户输入（高风险）"
                        severity = '高危'
                    
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': "SMTP标头注入",
                        'severity': severity,
                        'full_call': full_call[:200]  # 截断长调用
                    })
        
        # 检测imap_mail函数
        imap_match = re.search(r'\bimap_mail\s*\(', line_clean)
        if imap_match and line_num not in processed_lines:
            full_call = extract_full_function_call(lines, i)
            if full_call and any(indicator in full_call for indicator in user_input_indicators):
                processed_lines.add(line_num)
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到imap_mail函数使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "SMTP标头伪造 - IMAP邮件",
                    'severity': '中危'
                })
        
        # 检测mb_send_mail函数
        mb_match = re.search(r'\bmb_send_mail\s*\(', line_clean)
        if mb_match and line_num not in processed_lines:
            full_call = extract_full_function_call(lines, i)
            if full_call and any(indicator in full_call for indicator in user_input_indicators):
                processed_lines.add(line_num)
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到mb_send_mail函数使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "SMTP标头伪造 - 多字节邮件",
                    'severity': '中危'
                })
    
    # 2. 检测邮件头字符串拼接
    for i, line in enumerate(lines):
        line_num = i + 1
        
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        # 检查邮件头相关的字符串拼接
        header_concatenation = False
        for header in header_patterns:
            if header in line_clean and any(op in line_clean for op in ['.', '.=']):
                header_concatenation = True
                break
        
        if header_concatenation:
            user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
            crlf_detected = any(re.search(pattern, line_clean) for pattern in crlf_patterns)
            
            if user_input_detected:
                severity = '高危' if crlf_detected else '中危'
                message = "检测到邮件头字符串拼接使用用户输入"
                
                if crlf_detected:
                    message += " - 可能包含CRLF注入"
                
                processed_lines.add(line_num)
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': "SMTP标头伪造 - 头拼接",
                    'severity': severity
                })
    
    # 3. 检测自定义邮件发送函数
    function_pattern = r'function\s+(\w+)\s*\([^)]*\)'
    for i, line in enumerate(lines):
        line_num = i + 1
        
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        func_match = re.search(function_pattern, line_clean)
        if func_match:
            func_name = func_match.group(1)
            mail_keywords = ['mail', 'send', 'email', 'smtp']
            
            if any(keyword in func_name.lower() for keyword in mail_keywords):
                # 检查函数体内是否有mail调用
                func_body = extract_function_body(lines, i)
                if func_body and 'mail(' in func_body:
                    # 检查函数体内是否使用用户输入
                    user_input_in_func = any(indicator in func_body for indicator in user_input_indicators)
                    
                    if user_input_in_func:
                        processed_lines.add(line_num)
                        
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到自定义邮件发送函数 '{func_name}' 使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SMTP标头伪造 - 自定义邮件函数",
                            'severity': '低危'
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


def extract_function_parameters(function_call):
    """
    从函数调用中提取参数
    """
    # 找到第一个括号和最后一个括号
    start = function_call.find('(')
    end = function_call.rfind(')')
    
    if start == -1 or end == -1:
        return []
    
    # 提取参数部分
    params_str = function_call[start+1:end].strip()
    
    if not params_str:
        return []
    
    # 简单的参数分割（基于逗号，但忽略字符串内的逗号）
    params = []
    current_param = ""
    in_string = False
    string_char = None
    bracket_count = 0
    
    for char in params_str:
        if char in ['"', "'"] and not in_string:
            in_string = True
            string_char = char
        elif char == string_char and in_string:
            in_string = False
            string_char = None
        elif char == '(' and not in_string:
            bracket_count += 1
        elif char == ')' and not in_string:
            bracket_count -= 1
        
        if char == ',' and not in_string and bracket_count == 0:
            params.append(current_param.strip())
            current_param = ""
        else:
            current_param += char
    
    if current_param.strip():
        params.append(current_param.strip())
    
    return params


def extract_function_body(lines, start_line):
    """
    提取函数体内容（简化版本）
    """
    line_num = start_line
    body = ""
    brace_count = 0
    found_brace = False
    
    # 查找函数开始的左大括号
    while line_num < len(lines):
        line = lines[line_num]
        body += line + "\n"
        
        if '{' in line:
            brace_count += line.count('{')
            found_brace = True
            break
        
        line_num += 1
        if line_num - start_line > 5:  # 最多查找5行
            return None
    
    if not found_brace:
        return None
    
    # 继续直到大括号匹配完成
    line_num += 1
    while line_num < len(lines) and brace_count > 0:
        line = lines[line_num]
        body += line + "\n"
        
        brace_count += line.count('{')
        brace_count -= line.count('}')
        
        line_num += 1
        
        # 最多检查50行函数体
        if line_num - start_line > 50:
            break
    
    return body


# 测试代码（保持不变）
if __name__ == "__main__":
    test_php_code = """<?php
// 测试SMTP标头伪造漏洞

// 不安全的mail函数使用 - 高危
mail($_GET['to'], $_POST['subject'], $_REQUEST['message']);
mail($email, $subject, $body, $_GET['headers']);

// CRLF注入风险 - 高危
mail($_POST['to'], "Subject", "Body", "From: " . $_GET['from'] . "\\r\\nBcc: attacker@evil.com");
mail($to, $subject, $message, "Reply-To: " . $_REQUEST['reply_to'] . "\\r\\nX-Mailer: Evil");

// 邮件头伪造 - 中危
$headers = "From: " . $_GET['sender'] . "\\r\\n";
$headers .= "Cc: " . $_POST['cc'] . "\\r\\n";
$headers .= "Bcc: " . $_REQUEST['bcc'] . "\\r\\n";
mail($to, $subject, $message, $headers);

// 自定义邮件函数 - 低危
function sendEmail($to, $subject, $message) {
    $headers = "From: webmaster@example.com\\r\\n";
    $headers .= "Reply-To: " . $_GET['reply_to'] . "\\r\\n";  // 不安全
    mail($to, $subject, $message, $headers);
}

// imap_mail函数 - 中危
imap_mail($_GET['to'], $_POST['subject'], $_REQUEST['message']);

// mb_send_mail函数 - 中危
mb_send_mail($_GET['to'], $_POST['subject'], $_REQUEST['message']);

// 相对安全的实现
// 输入过滤和验证
$to = filter_var($_POST['to'], FILTER_VALIDATE_EMAIL);
$subject = htmlspecialchars($_POST['subject']);
$from = "noreply@example.com";

if ($to) {
    $headers = "From: $from\\r\\n";
    $headers .= "Reply-To: $from\\r\\n";
    mail($to, $subject, $message, $headers);
}

// 固定头信息（安全）
mail('user@example.com', 'Welcome', 'Welcome message', 'From: noreply@example.com');

// 白名单验证
$allowed_domains = array('example.com', 'company.com');
$to_domain = explode('@', $_POST['to'])[1];
if (in_array($to_domain, $allowed_domains)) {
    mail($_POST['to'], $subject, $message, $headers);
}

// CRLF过滤
$safe_from = str_replace(array("\\r", "\\n"), '', $_POST['from']);
$headers = "From: $safe_from\\r\\n";

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP SMTP标头伪造漏洞检测（正则版本）")
    print("=" * 60)

    results = detect_smtp_header_injection(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SMTP标头伪造漏洞")