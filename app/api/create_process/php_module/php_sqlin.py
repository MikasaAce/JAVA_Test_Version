import re


def detect_sql_injection(php_code):
    """
    PHP SQL注入漏洞检测主函数 - 使用正则匹配
    """
    vulnerabilities = []
    processed_lines = set()  # 用于跟踪已处理的行号
    
    lines = php_code.split('\n')
    
    # SQL相关函数列表
    sql_functions = {
        "mysql_query": "MySQL查询",
        "mysqli_query": "MySQLi查询", 
        "pg_query": "PostgreSQL查询",
        "sqlsrv_query": "SQL Server查询",
        "oci_parse": "Oracle解析",
        "oci_execute": "Oracle执行",
        "PDO::query": "PDO查询",
        "PDO::exec": "PDO执行",
        "mysqli_prepare": "MySQLi预处理",
        "pg_prepare": "PostgreSQL预处理",
    }
    
    # PDO方法
    pdo_methods = ['prepare', 'execute', 'bindValue', 'bindParam', 'query', 'exec']
    
    # MySQLi预处理函数
    mysqli_prepare_functions = ['mysqli_prepare', 'mysqli_stmt_bind_param', 'mysqli_stmt_execute']
    
    # 数据库连接函数
    db_connection_functions = [
        'mysql_connect', 'mysqli_connect', 'pg_connect',
        'sqlsrv_connect', 'oci_connect', 'PDO'
    ]
    
    # 用户输入标识符
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER']
    
    # SQL关键字
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WHERE', 'FROM', 'SET', 'VALUES']
    
    # SQL注释
    sql_comments = ['--', '/*', '*/', '#']
    
    # 1. 检测SQL查询函数
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # 跳过已处理的行
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        # 检测SQL函数调用
        for func_name in sql_functions.keys():
            func_pattern = r'\b' + re.escape(func_name) + r'\s*\('
            if re.search(func_pattern, line_clean):
                # 获取完整的函数调用
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    # 检查字符串拼接
                    string_concatenation_detected = '+' in full_call or '.' in full_call
                    
                    # 检查是否使用预处理语句
                    no_prepared_statement = not any(pattern in full_call for pattern in ['prepare', 'bind_param', '?', ':'])
                    
                    if user_input_detected and string_concatenation_detected and no_prepared_statement:
                        severity = '高危'
                        message = f"检测到SQL函数 '{func_name}' 使用字符串拼接和用户输入"
                        vuln_type = f"SQL注入 - {sql_functions[func_name]}"
                        
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
        
        # 2. 检测PDO方法调用
        pdo_pattern = r'(\$[a-zA-Z_][a-zA-Z0-9_]*)->(' + '|'.join(pdo_methods) + r')\s*\('
        pdo_match = re.search(pdo_pattern, line_clean)
        if pdo_match and line_num not in processed_lines:
            method_name = pdo_match.group(2)
            full_call = extract_full_function_call(lines, i)
            
            if full_call:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                
                # 检查是否直接拼接用户输入到SQL中
                if user_input_detected and ('+' in full_call or '.' in full_call):
                    # 标记为已处理
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到PDO方法 '{method_name}' 使用字符串拼接和用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SQL注入 - PDO不安全使用",
                        'severity': '高危'
                    })
        
        # 3. 检测MySQLi预处理函数
        for mysqli_func in mysqli_prepare_functions:
            mysqli_pattern = r'\b' + re.escape(mysqli_func) + r'\s*\('
            if re.search(mysqli_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    # 检查字符串拼接
                    if user_input_detected and ('+' in full_call or '.' in full_call):
                        # 标记为已处理
                        processed_lines.add(line_num)
                        
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到MySQLi预处理函数 '{mysqli_func}' 使用字符串拼接",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SQL注入 - MySQLi不安全预处理",
                            'severity': '高危'
                        })
        
        # 4. 检测字符串拼接中的SQL注入
        if any(keyword in line_clean.upper() for keyword in sql_keywords):
            # 检查是否包含用户输入
            user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
            
            # 检查字符串拼接
            string_concatenation = '+' in line_clean or '.' in line_clean
            
            if user_input_detected and string_concatenation and line_num not in processed_lines:
                # 标记为已处理
                processed_lines.add(line_num)
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到SQL查询字符串拼接使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "SQL注入 - 字符串拼接",
                    'severity': '高危'
                })
        
        # 5. 检测echo/print输出SQL查询（调试信息泄露）
        if re.search(r'\b(echo|print|print_r|var_dump)\s*', line_clean) and line_num not in processed_lines:
            # 检查是否输出SQL查询
            is_sql_output = any(keyword in line_clean.upper() for keyword in sql_keywords)
            
            if is_sql_output:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到SQL查询输出 - 可能泄露敏感信息",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SQL注入 - 信息泄露",
                        'severity': '中危'
                    })
        
        # 6. 检测变量赋值中的SQL查询
        assignment_pattern = r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^;]+'
        assignment_match = re.search(assignment_pattern, line_clean)
        if assignment_match and line_num not in processed_lines:
            assignment_line = assignment_match.group()
            
            # 检查SQL查询赋值
            is_sql_assignment = any(keyword in assignment_line.upper() for keyword in sql_keywords)
            
            if is_sql_assignment:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in assignment_line for indicator in user_input_indicators)
                
                # 检查字符串拼接
                string_concatenation = '+' in assignment_line or '.' in assignment_line
                
                if user_input_detected and string_concatenation:
                    # 标记为已处理
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到SQL查询变量赋值使用字符串拼接和用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SQL注入 - 变量赋值",
                        'severity': '高危'
                    })
        
        # 7. 检测数据库连接函数中的用户输入
        for conn_func in db_connection_functions:
            conn_pattern = r'\b' + re.escape(conn_func) + r'\s*\('
            if re.search(conn_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查连接参数是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    if user_input_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)
                        
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到数据库连接函数 '{conn_func}' 使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SQL注入 - 数据库连接",
                            'severity': '高危'
                        })
        
        # 8. 检测SQL注释绕过
        for sql_func in ['mysql_query', 'mysqli_query', 'pg_query']:
            func_pattern = r'\b' + re.escape(sql_func) + r'\s*\('
            if re.search(func_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查是否包含SQL注释
                    comment_detected = any(comment in full_call for comment in sql_comments)
                    
                    # 检查是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    if user_input_detected and comment_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)
                        
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到SQL查询可能包含注释绕过",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SQL注入 - 注释绕过",
                            'severity': '中危'
                        })
        
        # 9. 检测new PDO实例化
        if 'new PDO' in line_clean and line_num not in processed_lines:
            full_call = extract_full_function_call(lines, i)
            
            if full_call:
                # 检查连接参数是否包含用户输入
                user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到PDO实例化使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SQL注入 - PDO连接",
                        'severity': '高危'
                    })
        
        # 10. 检测SQL注入过滤函数的使用（安全模式）
        if any(pattern in line_clean for pattern in ['mysql_real_escape_string', 'mysqli_real_escape_string', 
                                                    'pg_escape_string', 'addslashes', 'htmlspecialchars']):
            # 检查是否与用户输入一起使用
            user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
            
            if user_input_detected and line_num not in processed_lines:
                # 标记为已处理（安全使用，但可能仍有风险）
                processed_lines.add(line_num)
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到使用转义函数处理用户输入 - 相对安全但仍建议使用预处理语句",
                    'code_snippet': line_clean,
                    'vulnerability_type': "SQL注入 - 转义函数使用",
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


# 测试代码（保持不变）
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 SQL注入漏洞

// 不安全的SQL查询 - 高危
mysql_query("SELECT * FROM users WHERE username = '" . $_GET['username'] . "'");
mysqli_query($conn, "UPDATE products SET price = " . $_POST['price'] . " WHERE id = " . $_REQUEST['id']);
pg_query("DELETE FROM logs WHERE date = '" . $_COOKIE['date'] . "'");

// PDO不安全使用 - 高危
$pdo->query("SELECT * FROM users WHERE email = '" . $_GET['email'] . "'");
$pdo->exec("INSERT INTO orders VALUES (NULL, '" . $_POST['product'] . "', " . $_REQUEST['quantity'] . ")");

// MySQLi预处理不安全使用 - 高危
$stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE name = '" . $_GET['name'] . "'");
mysqli_stmt_execute($stmt);

// 字符串拼接SQL - 高危
$sql = "SELECT * FROM products WHERE category = '" . $_GET['category'] . "'";
$query = "INSERT INTO users (username, password) VALUES ('" . $_POST['user'] . "', '" . $_POST['pass'] . "')";

// 数据库连接使用用户输入 - 高危
mysql_connect($_GET['host'], $_POST['user'], $_REQUEST['pass']);
new PDO('mysql:host=' . $_GET['db_host'] . ';dbname=app', 'user', 'pass');

// SQL注释绕过 - 中危
mysql_query("SELECT * FROM users WHERE id = " . $_GET['id'] . "--");
mysqli_query($conn, "SELECT * FROM products /*" . $_POST['comment'] . "*/ WHERE price > 0");

// 输出SQL查询（信息泄露） - 中危
echo "执行的SQL: SELECT * FROM users WHERE id = " . $_GET['id'];
print_r("查询: " . $sql);

// 相对安全的实现
// 使用预处理语句 - 安全
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$_POST['username']]);

$stmt = mysqli_prepare($conn, "SELECT * FROM products WHERE id = ?");
mysqli_stmt_bind_param($stmt, "i", $_GET['id']);
mysqli_stmt_execute($stmt);

// 使用参数化查询 - 安全
$stmt = $pdo->prepare("INSERT INTO orders (product, quantity) VALUES (:product, :quantity)");
$stmt->bindParam(':product', $_POST['product']);
$stmt->bindParam(':quantity', $_POST['quantity'], PDO::PARAM_INT);
$stmt->execute();

// 输入验证和过滤 - 安全
$user_id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
if ($user_id !== false) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
}

// 使用转义函数 - 相对安全（但仍不推荐）
$safe_username = mysqli_real_escape_string($conn, $_POST['username']);
mysql_query("SELECT * FROM users WHERE username = '" . $safe_username . "'");

// 白名单验证 - 安全
$allowed_categories = ['electronics', 'books', 'clothing'];
if (in_array($_GET['category'], $allowed_categories)) {
    $stmt = $pdo->prepare("SELECT * FROM products WHERE category = ?");
    $stmt->execute([$_GET['category']]);
}

// 固定查询（安全）
$pdo->query("SELECT * FROM config WHERE setting = 'version'");
mysql_query("UPDATE counters SET visits = visits + 1");

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP SQL注入漏洞检测（正则版本）")
    print("=" * 60)

    results = detect_sql_injection(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到SQL注入漏洞")