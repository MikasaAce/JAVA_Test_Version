import re


def detect_ssti_vulnerability(php_code):
    """
    PHP服务器端模板注入漏洞检测主函数 - 使用正则匹配
    """
    vulnerabilities = []
    processed_lines = set()  # 用于跟踪已处理的行号
    
    lines = php_code.split('\n')
    
    # 模板引擎列表
    template_engines = [
        'Twig_Environment', 'Twig\\Environment',
        'Smarty', 'SmartyBC',
        'Mustache_Engine', 'Mustache\\Engine',
        'Latte\\Engine', 'BladeOne', 'Plates',
        'PhpRenderer', 'Template'
    ]
    
    # 模板渲染方法
    render_methods = [
        'render', 'display', 'fetch', 'make', 'process',
        'parse', 'compile', 'evaluate', 'execute'
    ]
    
    # 模板变量赋值方法
    assign_methods = [
        'assign', 'set', 'with', 'addData', 'setData',
        'withParam', 'withVar', 'setVar'
    ]
    
    # 模板配置方法
    config_methods = [
        'setCache', 'enableAutoescape', 'addExtension',
        'setLoader', 'setCharset', 'setBaseTemplateClass'
    ]
    
    # 用户输入标识符
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    # 模板语法模式
    template_patterns = [
        '{{', '}}',  # Twig, Jinja2
        '{%', '%}',  # Twig blocks
        '{#', '#}',  # Twig comments
        '{$', '}',  # Smarty
        '{{=', '=}}',  # Mustache
        '{{{', '}}}',  # Mustache unescaped
        '[[', ']]',  # Plates
        '<!--{', '}-->'  # Some template engines
    ]
    
    # 危险配置
    dangerous_configs = [
        'autoescape', 'false', '0', 'null',
        'PHP', 'php', 'exec', 'system'
    ]
    
    # 代码执行函数
    code_execution_functions = ['eval', 'create_function']

    for i, line in enumerate(lines):
        line_num = i + 1
        
        # 跳过已处理的行
        if line_num in processed_lines:
            continue
            
        line_clean = line.strip()
        
        # 1. 检测模板引擎实例化
        for engine in template_engines:
            new_pattern = r'new\s+' + re.escape(engine) + r'\s*\('
            if re.search(new_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    if user_input_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)

                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到模板引擎 '{engine}' 实例化使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SSTI - 模板引擎实例化",
                            'severity': '中危'
                        })
        
        # 2. 检测模板渲染方法
        for method in render_methods:
            method_pattern = r'->\s*' + re.escape(method) + r'\s*\('
            if re.search(method_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查参数是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    if user_input_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)

                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到模板渲染方法 '{method}' 使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SSTI - 模板渲染",
                            'severity': '高危'
                        })
        
        # 3. 检测模板变量赋值方法
        for method in assign_methods:
            method_pattern = r'->\s*' + re.escape(method) + r'\s*\('
            if re.search(method_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查参数是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    if user_input_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)

                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到模板变量赋值方法 '{method}' 使用用户输入",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SSTI - 变量赋值",
                            'severity': '中危'
                        })
        
        # 4. 检测eval函数使用
        eval_pattern = r'\beval\s*\('
        if re.search(eval_pattern, line_clean) and line_num not in processed_lines:
            full_call = extract_full_function_call(lines, i)
            
            if full_call:
                # 检查eval参数是否包含用户输入
                user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)

                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到eval函数使用用户输入 - 代码注入风险",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SSTI - eval注入",
                        'severity': '严重'
                    })
        
        # 5. 检测create_function使用
        create_func_pattern = r'\bcreate_function\s*\('
        if re.search(create_func_pattern, line_clean) and line_num not in processed_lines:
            full_call = extract_full_function_call(lines, i)
            
            if full_call:
                # 检查create_function参数是否包含用户输入
                user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)

                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到create_function使用用户输入 - 代码注入风险",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SSTI - create_function注入",
                        'severity': '严重'
                    })
        
        # 6. 检测字符串拼接中的模板语法
        if any(pattern in line_clean for pattern in template_patterns) and line_num not in processed_lines:
            # 检查是否包含用户输入
            user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
            
            # 检查字符串拼接
            string_concatenation = '+' in line_clean or '.' in line_clean
            
            if user_input_detected and string_concatenation:
                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到模板语法字符串拼接使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "SSTI - 模板语法拼接",
                    'severity': '高危'
                })
        
        # 7. 检测include/require中的用户输入
        include_patterns = [
            r'\binclude\s*\(', r'\brequire\s*\(', 
            r'\binclude_once\s*\(', r'\brequire_once\s*\('
        ]
        for pattern in include_patterns:
            if re.search(pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查包含路径是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    if user_input_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)

                        vulnerabilities.append({
                            'line': line_num,
                            'message': "检测到文件包含使用用户输入 - 模板文件包含风险",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SSTI - 文件包含",
                            'severity': '高危'
                        })
        
        # 8. 检测动态函数调用
        dynamic_func_pattern = r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*\('
        if re.search(dynamic_func_pattern, line_clean) and line_num not in processed_lines:
            # 检查函数名是否来自用户输入
            user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
            
            if user_input_detected:
                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到动态函数调用使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "SSTI - 动态函数调用",
                    'severity': '高危'
                })
        
        # 9. 检测可变变量使用
        variable_variable_patterns = [
            r'\$\$[a-zA-Z_][a-zA-Z0-9_]*',
            r'\$\{\$[a-zA-Z_][a-zA-Z0-9_]*\}',
            r'\$\{\$[^\}]+\}'
        ]
        for pattern in variable_variable_patterns:
            if re.search(pattern, line_clean) and line_num not in processed_lines:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)

                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到可变变量使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SSTI - 可变变量",
                        'severity': '中危'
                    })
        
        # 10. 检测模板配置设置
        for method in config_methods:
            method_pattern = r'->\s*' + re.escape(method) + r'\s*\('
            if re.search(method_pattern, line_clean) and line_num not in processed_lines:
                full_call = extract_full_function_call(lines, i)
                
                if full_call:
                    # 检查危险配置
                    dangerous_detected = any(config in full_call.lower() for config in dangerous_configs)
                    
                    # 检查是否包含用户输入
                    user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                    
                    if dangerous_detected or user_input_detected:
                        # 标记为已处理
                        processed_lines.add(line_num)

                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到模板配置方法 '{method}' 可能包含危险设置",
                            'code_snippet': line_clean,
                            'vulnerability_type': "SSTI - 模板配置",
                            'severity': '中危'
                        })
        
        # 11. 检测assert函数使用
        assert_pattern = r'\bassert\s*\('
        if re.search(assert_pattern, line_clean) and line_num not in processed_lines:
            full_call = extract_full_function_call(lines, i)
            
            if full_call:
                # 检查参数是否包含用户输入
                user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)

                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到assert函数使用用户输入 - 代码注入风险",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SSTI - assert注入",
                        'severity': '高危'
                    })
        
        # 12. 检测preg_replace的/e修饰符
        if 'preg_replace' in line_clean and '/e' in line_clean and line_num not in processed_lines:
            full_call = extract_full_function_call(lines, i)
            
            if full_call:
                # 检查是否包含用户输入
                user_input_detected = any(indicator in full_call for indicator in user_input_indicators)
                
                if user_input_detected:
                    # 标记为已处理
                    processed_lines.add(line_num)

                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到preg_replace使用/e修饰符和用户输入 - 代码注入风险",
                        'code_snippet': line_clean,
                        'vulnerability_type': "SSTI - preg_replace注入",
                        'severity': '高危'
                    })
        
        # 13. 检测动态类实例化
        dynamic_class_pattern = r'new\s*\$[a-zA-Z_][a-zA-Z0-9_]*'
        if re.search(dynamic_class_pattern, line_clean) and line_num not in processed_lines:
            # 检查是否包含用户输入
            user_input_detected = any(indicator in line_clean for indicator in user_input_indicators)
            
            if user_input_detected:
                # 标记为已处理
                processed_lines.add(line_num)

                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到动态类实例化使用用户输入",
                    'code_snippet': line_clean,
                    'vulnerability_type': "SSTI - 动态类实例化",
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
// 测试服务器端模板注入漏洞

// Twig模板引擎 - 高危
$loader = new Twig_Loader_Array([
    'index' => $_GET['template']
]);
$twig = new Twig_Environment($loader);
echo $twig->render('index', ['name' => $_POST['user']]);

// Smarty模板引擎 - 高危
$smarty = new Smarty();
$smarty->assign('content', $_REQUEST['user_content']);
$smarty->display('template.tpl');

// Mustache模板引擎 - 中危
$mustache = new Mustache_Engine();
echo $mustache->render($_POST['template'], $data);

// eval直接代码执行 - 严重
eval('echo ' . $_GET['code'] . ';');
eval($_POST['php_code']);

// create_function代码注入 - 严重
$func = create_function('$a', 'return ' . $_REQUEST['expression'] . ';');

// 字符串拼接模板语法 - 高危
$template = 'Hello, {{ ' . $_GET['name'] . ' }}!';
$smarty_template = 'Welcome {$' . $_POST['var'] . '}';

// 文件包含模板 - 高危
include($_GET['template_file'] . '.php');
require($_POST['view']);

// 动态函数调用 - 高危
$function_name = $_GET['func'];
$function_name($data);

// 可变变量 - 中危
${$_POST['var_name']} = 'value';

// 模板配置风险 - 中危
$twig = new Twig_Environment($loader, [
    'autoescape' => $_GET['autoescape']  // 可能被设置为false
]);
$twig->addExtension(new $_POST['extension']());

// 相对安全的实现
// 固定模板内容 - 安全
$twig = new Twig_Environment($loader);
echo $twig->render('fixed_template.html', [
    'name' => htmlspecialchars($user_input)
]);

// 白名单验证 - 安全
$allowed_templates = ['home', 'about', 'contact'];
if (in_array($_GET['template'], $allowed_templates)) {
    echo $twig->render($_GET['template'] . '.html', $data);
}

// 输入过滤 - 安全
$safe_template = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['template']);
echo $twig->render($safe_template . '.html', $data);

// 启用自动转义 - 安全
$twig = new Twig_Environment($loader, ['autoescape' => true]);
$smarty->escape_html = true;

// 禁用PHP标签 - 安全
$twig = new Twig_Environment($loader, [
    'autoescape' => true,
    'optimizations' => -1  // 禁用优化，提高安全性
]);

// 使用安全的模板引擎配置
class SafeTwigExtension extends Twig_Extension {
    // 自定义安全扩展
}

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP服务器端模板注入漏洞检测（正则版本）")
    print("=" * 60)

    results = detect_ssti_vulnerability(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到服务器端模板注入漏洞")