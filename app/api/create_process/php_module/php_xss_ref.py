import re


def detect_reflected_xss_vulnerability(php_code):
    """
    PHP反射型XSS漏洞检测主函数 - 使用正则匹配
    """
    vulnerabilities = []
    processed_lines = set()
    
    lines = php_code.split('\n')
    
    # 用户输入标识符
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    # 输出函数
    output_functions = ['echo', 'print', 'printf', 'sprintf', 'vprintf', 'vsprintf']
    
    # 编码函数
    encoding_functions = [
        'htmlspecialchars', 'htmlentities', 'urlencode', 'rawurlencode',
        'json_encode', 'addslashes', 'filter_var'
    ]
    
    # HTTP头函数
    header_functions = ['header']
    
    # 文件包含函数
    include_functions = ['include', 'require', 'include_once', 'require_once']

    for i, line in enumerate(lines):
        line_num = i + 1
        
        # 跳过已处理的行
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        # 1. 检测直接输出用户输入
        for output_func in output_functions:
            output_pattern = r'\b' + re.escape(output_func) + r'\s+[^;]+'
            if re.search(output_pattern, line_clean):
                # 检查是否包含用户输入
                user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 检查是否使用编码
                    encoding_used = any(func in line_clean for func in encoding_functions)
                    
                    if not encoding_used:
                        # 确定上下文类型
                        context_type = determine_output_context(line_clean)
                        
                        severity = '高危' if 'HTML' in context_type or 'JavaScript' in context_type else '中危'
                        
                        # 标记为已处理
                        processed_lines.add(line_num)
                        
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到{output_func}直接输出用户输入{context_type}，缺少输出编码",
                            'code_snippet': line_clean,
                            'vulnerability_type': f"反射型XSS - {context_type}",
                            'severity': severity
                        })
                break
        
        # 2. 检测HTTP头注入
        for header_func in header_functions:
            header_pattern = r'\b' + re.escape(header_func) + r'\s*\([^;]+\)'
            if re.search(header_pattern, line_clean) and line_num not in processed_lines:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到header函数使用用户输入 - HTTP响应头注入风险",
                        'code_snippet': line_clean,
                        'vulnerability_type': "HTTP响应头注入",
                        'severity': '中危'
                    })
        
        # 3. 检测内联HTML输出
        if ('<?=' in line_clean or '<?php echo' in line_clean) and line_num not in processed_lines:
            # 检查是否包含用户输入
            user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
            
            if user_input_detected:
                # 检查是否使用编码
                encoding_used = any(func in line_clean for func in encoding_functions)
                
                if not encoding_used:
                    # 标记为已处理
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到HTML内直接输出用户输入，缺少HTML编码",
                        'code_snippet': line_clean,
                        'vulnerability_type': "反射型XSS - HTML内联输出",
                        'severity': '高危'
                    })
        
        # 4. 检测变量赋值和后续使用
        assignment_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[^;]+'
        assignment_match = re.search(assignment_pattern, line_clean)
        if assignment_match and line_num not in processed_lines:
            var_name = assignment_match.group(1)
            
            # 检查赋值是否来自用户输入
            user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
            
            if user_input_detected:
                # 查找后续行中该变量的不安全使用
                find_unsafe_variable_usage(var_name, i, lines, vulnerabilities, processed_lines, line_clean)
        
        # 5. 检测文件包含中的用户输入
        for include_func in include_functions:
            include_pattern = r'\b' + re.escape(include_func) + r'\s*\([^;]+\)'
            if re.search(include_pattern, line_clean) and line_num not in processed_lines:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到{include_func}使用用户输入 - 文件包含漏洞风险",
                        'code_snippet': line_clean,
                        'vulnerability_type': "文件包含漏洞",
                        'severity': '高危'
                    })
        
        # 6. 检测字符串拼接中的XSS风险
        if any(indicator in line_clean for indicator in user_input_indicators):
            # 检查字符串拼接
            if '+' in line_clean or '.' in line_clean:
                # 检查是否在输出上下文中
                in_output_context = any(func in line_clean for func in output_functions) or '<?=' in line_clean
                
                if in_output_context:
                    # 检查是否使用编码
                    encoding_used = any(func in line_clean for func in encoding_functions)
                    
                    if not encoding_used and line_num not in processed_lines:
                        # 标记为已处理
                        processed_lines.add(line_num)
                        
                        context_type = determine_output_context(line_clean)
                        
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到字符串拼接输出用户输入{context_type}，缺少编码",
                            'code_snippet': line_clean,
                            'vulnerability_type': f"反射型XSS - {context_type}",
                            'severity': '高危'
                        })
        
        # 7. 检测HTML属性中的用户输入
        html_attribute_patterns = [
            r'href\s*=\s*["\'][^"\']*' + re.escape(indicator) for indicator in user_input_indicators
        ]
        
        for pattern in html_attribute_patterns:
            if re.search(pattern, line_clean, re.IGNORECASE) and line_num not in processed_lines:
                # 检查是否使用编码
                encoding_used = any(func in line_clean for func in ['urlencode', 'rawurlencode', 'htmlspecialchars'])
                
                if not encoding_used:
                    # 标记为已处理
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到HTML属性中使用用户输入，缺少URL编码",
                        'code_snippet': line_clean,
                        'vulnerability_type': "反射型XSS - URL属性上下文",
                        'severity': '中危'
                    })
        
        # 8. 检测JavaScript上下文中的用户输入
        js_context_patterns = [
            r'<script[^>]*>[^<]*' + re.escape(indicator) for indicator in user_input_indicators
        ]
        
        for pattern in js_context_patterns:
            if re.search(pattern, line_clean, re.IGNORECASE) and line_num not in processed_lines:
                # 检查是否使用编码
                encoding_used = any(func in line_clean for func in ['json_encode', 'addslashes'])
                
                if not encoding_used:
                    # 标记为已处理
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到JavaScript中使用用户输入，缺少JavaScript编码",
                        'code_snippet': line_clean,
                        'vulnerability_type': "反射型XSS - JavaScript上下文",
                        'severity': '高危'
                    })
        
        # 9. 检测表单值中的用户输入回显
        form_value_patterns = [
            r'value\s*=\s*["\'][^"\']*' + re.escape(indicator) for indicator in user_input_indicators
        ]
        
        for pattern in form_value_patterns:
            if re.search(pattern, line_clean, re.IGNORECASE) and line_num not in processed_lines:
                # 检查是否使用编码
                encoding_used = any(func in line_clean for func in encoding_functions)
                
                if not encoding_used:
                    # 标记为已处理
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到表单值中使用用户输入，缺少HTML属性编码",
                        'code_snippet': line_clean,
                        'vulnerability_type': "反射型XSS - 表单值上下文",
                        'severity': '中危'
                    })

    return vulnerabilities


def determine_output_context(code_snippet):
    """确定输出上下文类型"""
    code_lower = code_snippet.lower()
    
    if 'script' in code_lower:
        return "JavaScript上下文"
    elif 'href=' in code_lower or 'src=' in code_lower:
        return "URL上下文"
    elif '<' in code_lower and '>' in code_lower:
        return "HTML上下文"
    else:
        return "直接输出"


def find_unsafe_variable_usage(var_name, start_index, lines, vulnerabilities, processed_lines, original_snippet):
    """查找变量的不安全使用"""
    encoding_functions = ['htmlspecialchars', 'htmlentities', 'json_encode']
    output_functions = ['echo', 'print', 'printf']
    
    # 在后续行中查找变量的使用
    for i in range(start_index + 1, min(start_index + 20, len(lines))):
        line_num = i + 1
        line = lines[i].strip()
        
        # 跳过已处理的行
        if line_num in processed_lines:
            continue
        
        # 检查变量是否在输出中使用
        if var_name in line and any(func in line for func in output_functions):
            # 检查是否使用编码
            encoding_used = any(func in line for func in encoding_functions)
            
            if not encoding_used:
                # 标记为已处理
                processed_lines.add(line_num)
                
                vulnerabilities.append({
                    'line': start_index + 1,  # 原始赋值行号
                    'message': f"检测到用户输入赋值给变量${var_name}并在后续直接输出，缺少编码",
                    'code_snippet': f"{original_snippet} -> {line}",
                    'vulnerability_type': "反射型XSS - 变量传递",
                    'severity': '高危'
                })
            break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试反射型XSS漏洞

// 高危：直接输出用户输入，无编码
echo $_GET['username'];
print $_POST['comment'];

// 高危：HTML上下文中直接输出
echo "<div>" . $_GET['content'] . "</div>";
echo '<input value="' . $_REQUEST['input_value'] . '">';

// 高危：JavaScript上下文中直接输出
echo "<script>var user = '" . $_COOKIE['user'] . "';</script>";

// 中危：URL上下文中直接输出
echo '<a href="' . $_GET['url'] . '">Link</a>';

// 高危：格式化输出
printf("Welcome %s", $_POST['name']);

// 高危：变量赋值后输出
$user_data = $_GET['data'];
echo $user_data;

// 中危：HTTP头注入
header("Location: " . $_REQUEST['redirect']);

// 安全示例：使用编码
echo htmlspecialchars($_GET['safe_input']);
echo "<div>" . htmlentities($_POST['safe_content']) . "</div>";

// 安全示例：JSON编码
echo "<script>var data = " . json_encode($_GET['data']) . ";</script>";

// 正常输出
echo "Hello World";

// 表单值回显
echo '<input type="text" name="username" value="' . $_POST['username'] . '">';

// 内联HTML
?>
<div class="content">
    <?= $_GET['unsafe_content'] ?>
</div>
<div class="safe-content">
    <?= htmlspecialchars($_GET['safe_content']) ?>
</div>
<?php
// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP反射型XSS漏洞检测（正则版本）")
    print("=" * 60)

    results = detect_reflected_xss_vulnerability(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到反射型XSS漏洞")