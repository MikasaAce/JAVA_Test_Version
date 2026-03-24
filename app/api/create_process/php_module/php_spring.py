import re


def detect_spring_expression_injection(php_code):
    """
    Spring表达式注入漏洞检测主函数 - 使用正则匹配
    """
    vulnerabilities = []
    processed_lines = set()  # 用于跟踪已处理的行号

    lines = php_code.split('\n')

    # Spring表达式模式
    spel_patterns = [
        r'#\{[^}]+\}',  # #{expression}
        r'\$\{[^}]+\}',  # ${expression}
        r'T\([^)]+\)',  # T(type)
        r'@[a-zA-Z_][a-zA-Z0-9_]*',  # @bean
        r'new\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)',  # new Object()
    ]

    # Spring相关注解
    spring_annotations = [
        r'@Value\s*\(\s*[^)]+\s*\)',
        r'@PreAuthorize\s*\(\s*[^)]+\s*\)',
        r'@PostAuthorize\s*\(\s*[^)]+\s*\)',
        r'@PreFilter\s*\(\s*[^)]+\s*\)',
        r'@PostFilter\s*\(\s*[^)]+\s*\)',
    ]

    # Thymeleaf表达式
    thymeleaf_patterns = [
        r'th:text\s*=\s*"[^"]*"',
        r'th:value\s*=\s*"[^"]*"',
        r'th:utext\s*=\s*"[^"]*"',
        r'\$\{[^}]+\}',
        r'\*\{[^}]+\}',
    ]

    # 用户输入标识符
    user_input_indicators = ['request', 'param', 'getParameter', 'PathVariable', 'RequestParam', '$_GET', '$_POST', '$_REQUEST']

    # 危险操作模式
    dangerous_patterns = [
        'T(java.lang.Runtime)', 'T(java.lang.ProcessBuilder)',
        'T(java.lang.System)', 'T(java.lang.Class)',
        'new java.net.URL', 'new java.io.File',
        'getRuntime()', 'exec(', 'exit(', 'getProperty('
    ]

    # 安全表达式模式
    safe_patterns = ["#{\'", '#{"', '#{systemProperties', '#{environment', '#{1', '#{true', '#{false']

    for i, line in enumerate(lines):
        line_num = i + 1
        line_clean = line.strip()

        # 跳过已处理的行
        if line_num in processed_lines:
            continue

        # 跳过空行和注释
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('/*'):
            continue

        # 检测1: Spring SpEL表达式
        for pattern in spel_patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                expression = match.group()
                
                # 检查是否包含用户输入
                user_input_detected = any(indicator in line for indicator in user_input_indicators)

                # 检查是否包含危险操作
                dangerous_detected = any(dangerous in expression for dangerous in dangerous_patterns)

                # 检查是否是固定值（安全）
                is_safe_expression = any(safe in expression for safe in safe_patterns)

                if (user_input_detected or dangerous_detected) and not is_safe_expression:
                    severity = '高危' if dangerous_detected else '中危'
                    message = "检测到Spring表达式可能使用用户输入"
                    vuln_type = "Spring表达式注入 - SpEL"

                    if dangerous_detected:
                        message += " - 可能包含危险操作"
                    elif user_input_detected:
                        message += " - 使用用户输入"

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

        # 检测2: Spring安全注解
        for annotation_pattern in spring_annotations:
            if re.search(annotation_pattern, line) and line_num not in processed_lines:
                # 检查是否包含用户输入
                user_input_detected = any(
                    indicator in line for indicator in ['#', 'param', 'authentication', 'principal'])

                # 检查是否是简单的安全表达式
                simple_security = any(
                    pattern in line for pattern in ['hasRole', 'hasAuthority', 'permitAll', 'denyAll'])

                if user_input_detected and not simple_security:
                    # 标记为已处理
                    processed_lines.add(line_num)

                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到Spring安全注解使用复杂表达式",
                        'code_snippet': line_clean,
                        'vulnerability_type': "Spring表达式注入 - 安全注解",
                        'severity': '高危'
                    })
                break

        # 检测3: Thymeleaf表达式
        for pattern in thymeleaf_patterns:
            if re.search(pattern, line) and line_num not in processed_lines:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in line for indicator in ['${', '*{', '#', 'param'])

                # 检查是否使用非转义内容
                unsafe_detected = 'th:utext' in line

                if user_input_detected:
                    severity = '高危' if unsafe_detected else '中危'
                    message = "检测到Thymeleaf表达式使用用户输入"

                    if unsafe_detected:
                        message += " - 使用非转义内容"

                    # 标记为已处理
                    processed_lines.add(line_num)

                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': "Spring表达式注入 - Thymeleaf",
                        'severity': severity
                    })
                break

        # 检测4: @Value注解中的表达式
        if '@Value' in line and ('#{' in line or '${' in line) and line_num not in processed_lines:
            # 检查是否包含系统命令或危险操作
            dangerous_detected = any(pattern in line for pattern in dangerous_patterns)

            # 检查是否是固定值
            is_safe_expression = any(pattern in line for pattern in safe_patterns)

            if dangerous_detected or not is_safe_expression:
                severity = '高危' if dangerous_detected else '中危'
                message = "检测到@Value注解使用Spring表达式"

                if dangerous_detected:
                    message += " - 可能包含危险操作"

                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': "Spring表达式注入 - @Value注解",
                    'severity': severity
                })

        # 检测5: Spring Security表达式
        if any(annotation in line for annotation in
               ['@PreAuthorize', '@PostAuthorize', '@PreFilter', '@PostFilter']) and line_num not in processed_lines:
            # 检查是否包含用户控制的表达式
            complex_expression_detected = any(
                pattern in line for pattern in ['#', 'authentication', 'principal', 'returnObject'])

            # 检查是否是简单的角色检查
            simple_role_check = all(pattern in line for pattern in ['hasRole', '\''])

            if complex_expression_detected and not simple_role_check:
                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到Spring Security注解使用复杂表达式",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Spring表达式注入 - Security注解",
                    'severity': '高危'
                })

        # 检测6: Spring MVC参数绑定
        if any(annotation in line for annotation in
               ['@RequestParam', '@PathVariable', '@ModelAttribute']) and line_num not in processed_lines:
            # 检查是否在表达式中使用
            if '#{' in line or '${' in line:
                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到Spring MVC参数在表达式中使用",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Spring表达式注入 - MVC参数",
                    'severity': '中危'
                })

        # 检测7: JSP EL表达式
        if any(pattern in line for pattern in ['${', '#{']) and line_num not in processed_lines:
            # 在JSP/JSF上下文中的检测
            if any(context in line for context in ['pageContext', 'requestScope', 'sessionScope', 'param']):
                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到JSP EL表达式使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "表达式注入 - JSP EL",
                    'severity': '中危'
                })

        # 检测8: 表达式解析器使用
        if any(keyword in line for keyword in
               ['SpelExpressionParser', 'StandardEvaluationContext', 'Expression']) and line_num not in processed_lines:
            # 检查是否使用用户输入
            user_input_detected = any(
                indicator in line for indicator in ['parseExpression', 'setValue', 'getValue'])

            if user_input_detected:
                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到Spring表达式解析器使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Spring表达式注入 - 表达式解析器",
                    'severity': '高危'
                })

        # 检测9: XML配置中的SpEL
        if any(pattern in line for pattern in ['#{', '${']) and line_num not in processed_lines:
            # 在XML配置上下文中的检测
            if any(context in line for context in ['<bean', '<property', '<value']):
                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到XML配置中使用Spring表达式",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Spring表达式注入 - XML配置",
                    'severity': '中危'
                })

        # 检测10: 数据库查询中的SpEL
        if any(keyword in line for keyword in ['@Query', 'Query']) and line_num not in processed_lines:
            if '#{' in line or '${' in line:
                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到数据库查询中使用Spring表达式",
                    'code_snippet': line_clean,
                    'vulnerability_type': "Spring表达式注入 - 数据库查询",
                    'severity': '高危'
                })

        # 检测11: 跨行表达式检测
        if any(pattern in line for pattern in ['#{', '${', 'T(']) and line_num not in processed_lines:
            # 检查是否是跨行表达式的一部分
            full_expression = extract_multiline_expression(lines, i)
            if full_expression and len(full_expression) > len(line_clean):
                # 检查完整表达式中的危险模式
                dangerous_in_full = any(dangerous in full_expression for dangerous in dangerous_patterns)
                user_input_in_full = any(indicator in full_expression for indicator in user_input_indicators)
                
                if dangerous_in_full or user_input_in_full:
                    severity = '高危' if dangerous_in_full else '中危'
                    message = "检测到跨行Spring表达式使用用户输入"
                    
                    if dangerous_in_full:
                        message += " - 可能包含危险操作"
                    
                    processed_lines.add(line_num)
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean + " ...",
                        'vulnerability_type': "Spring表达式注入 - 跨行表达式",
                        'severity': severity
                    })

    return vulnerabilities


def extract_multiline_expression(lines, start_line):
    """
    提取跨多行的完整表达式
    """
    line_num = start_line
    expression_content = ""
    brace_count = 0
    parenthesis_count = 0
    in_expression = False
    
    while line_num < len(lines):
        line = lines[line_num].strip()
        expression_content += line
        
        # 统计大括号和圆括号
        if '#{' in line or '${' in line:
            in_expression = True
        
        if in_expression:
            brace_count += line.count('{')
            brace_count -= line.count('}')
            parenthesis_count += line.count('(')
            parenthesis_count -= line.count(')')
            
            # 如果所有括号都匹配，则表达式结束
            if brace_count <= 0 and parenthesis_count <= 0 and (line.endswith('}') or line.endswith(')')):
                break
        
        line_num += 1
        
        # 最多检查5行
        if line_num - start_line > 5:
            break
    
    return expression_content


# 测试代码（保持不变）
if __name__ == "__main__":
    test_php_code = '''<?php
// 测试Spring表达式注入漏洞
// 注意：这里使用PHP代码模拟Java Spring代码的内容

/*
模拟Spring Java代码内容
*/

// Spring SpEL表达式注入 - 高危
$code1 = '
@Value("#{systemProperties[\'user.dir\"]}")
private String userDir;

@Value("#{T(java.lang.Runtime).getRuntime().exec(\'calc\')}")
private Process process;

@Value("#{${server.port} + 1000}")
private int customPort;
';

// Spring Security表达式 - 高危
$code2 = '
@PreAuthorize("hasRole(\'ADMIN\') or #user.username == authentication.name")
public void updateUser(User user);

@PostAuthorize("returnObject.owner == authentication.name")
public Document getDocument(Long id);
';

// Thymeleaf表达式注入 - 中危
$html1 = '
<div th:text="${user.name}"></div>
<input th:value="*{user.email}" />
<p th:utext="${unsafeContent}"></p>
';

// Spring MVC参数绑定 - 中危
$code3 = '
@RequestMapping("/user/{id}")
public String getUser(@PathVariable("id") String id, Model model) {
    model.addAttribute("userId", "#{T(java.lang.Long).parseLong(" + id + ")}");
    return "user";
}
';

// 表达式解析器使用 - 高危
$code4 = '
SpelExpressionParser parser = new SpelExpressionParser();
Expression expression = parser.parseExpression(request.getParameter("expr"));
Object value = expression.getValue();
';

// XML配置中的SpEL - 中危
$xml1 = '
<bean id="dataSource" class="com.example.DataSource">
    <property name="url" value="#{systemProperties[\'db.url\']}" />
    <property name="username" value="${db.username}" />
</bean>
';

// 数据库查询中的SpEL - 高危
$code5 = '
@Query("SELECT u FROM User u WHERE u.name = :#{#user.name}")
List<User> findUsers(@Param("user") User user);

@Query("SELECT u FROM User u WHERE u.email = \'#{T(java.lang.System).getProperty(\"user.email\")}\'")
List<User> findSystemUsers();
';

// JSP EL表达式 - 中危
$jsp1 = '
<c:out value="${param.userInput}" />
${pageContext.request.getParameter("input")}
#{userBean.name}
';

// 相对安全的实现
// 使用SimpleEvaluationContext - 安全
$safe_code1 = '
SpelExpressionParser parser = new SpelExpressionParser();
StandardEvaluationContext context = new StandardEvaluationContext();
context.setBeanResolver(beanFactory);
// 使用SimpleEvaluationContext限制功能
';

// 固定表达式 - 安全
$safe_code2 = '
@Value("#{\'fixedValue\'}")
private String fixedValue;

@PreAuthorize("hasRole(\'USER\')")
public void userAction();
';

// 白名单验证 - 安全
$safe_code3 = '
private static final Set<String> ALLOWED_EXPRESSIONS = Set.of("user.name", "user.email");

public boolean isValidExpression(String expr) {
    return ALLOWED_EXPRESSIONS.contains(expr);
}
';

// 输入过滤 - 安全
$safe_code4 = '
public String sanitizeExpression(String input) {
    // 移除危险字符和关键字
    return input.replaceAll("[T\\(\\)\\$\\#\\@]", "");
}
';

// 正常业务逻辑
echo "应用程序代码";
?>
'''

    print("=" * 60)
    print("Spring表达式注入漏洞检测（正则版本）")
    print("=" * 60)

    results = detect_spring_expression_injection(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到Spring表达式注入漏洞")