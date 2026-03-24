import re

def detect_php_dos_vulnerability(php_code):
    """
    PHP拒绝服务漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测危险函数调用
    detect_dangerous_functions(lines, vulnerabilities)
    
    # 检测循环结构
    detect_loop_structures(lines, vulnerabilities)
    
    # 检测递归函数
    detect_recursive_functions(lines, vulnerabilities)
    
    # 检测大数组操作
    detect_large_arrays(lines, vulnerabilities)
    
    # 检测正则表达式ReDoS
    detect_redos_patterns(lines, vulnerabilities)
    
    # 检测内存密集型操作
    detect_memory_intensive_operations(lines, vulnerabilities)
    
    return vulnerabilities


def detect_dangerous_functions(lines, vulnerabilities):
    """
    检测可能导致资源耗尽的危险函数
    """
    dangerous_functions = {
        "unlink": "文件删除",
        "file_get_contents": "大文件读取",
        "file": "大文件读取",
        "fopen": "文件操作",
        "fread": "文件读取",
        "fwrite": "文件写入",
        "readfile": "文件读取输出",
        "gzuncompress": "压缩解压",
        "gzinflate": "压缩解压",
        "base64_decode": "大字符串解码",
        "simplexml_load_string": "XML解析",
        "simplexml_load_file": "XML解析",
        "DOMDocument::load": "XML解析",
        "DOMDocument::loadXML": "XML解析",
        "json_decode": "大JSON解析",
        "unserialize": "反序列化",
    }
    
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检查每个危险函数
        for func_name, vuln_type in dangerous_functions.items():
            # 构建匹配函数调用的正则表达式
            patterns = [
                # 模式1：标准函数调用 $var = func_name(...);
                r'\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*' + re.escape(func_name) + r'\s*\(',
                # 模式2：直接函数调用 func_name(...);
                r'\b' + re.escape(func_name) + r'\s*\(\s*[^;]*\)\s*;',
                # 模式3：在复杂表达式中的函数调用
                r'\b' + re.escape(func_name) + r'\s*\(',
                # 模式4：对象方法调用
                r'->\s*' + re.escape(func_name.split('::')[-1]) + r'\s*\('
            ]
            
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = '中危'
                    detailed_type = vuln_type
                    
                    # 根据函数类型调整风险等级
                    if func_name in ['unlink', 'file_get_contents', 'file']:
                        severity = '高危'
                    elif func_name in ['simplexml_load_string', 'DOMDocument::load', 'gzuncompress']:
                        severity = '高危'
                    
                    # 检查是否包含用户输入
                    for indicator in user_input_indicators:
                        if indicator in line:
                            severity = '严重'
                            detailed_type = f"{vuln_type} - 用户输入可能导致资源耗尽"
                            break
                    
                    # 特殊检测：大文件操作
                    if func_name in ['file_get_contents', 'file', 'readfile']:
                        if 'php://input' in line:
                            severity = '严重'
                            detailed_type = f"{vuln_type} - 直接读取输入流可能导致内存耗尽"
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到潜在DoS函数 '{func_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': detailed_type,
                        'severity': severity
                    })
                    break  # 找到一个匹配就跳出内层循环


def detect_loop_structures(lines, vulnerabilities):
    """
    检测循环结构
    """
    user_input_indicators = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测while循环
        if re.search(r'\bwhile\s*\([^)]+\)\s*\{', line):
            severity = '中危'
            
            # 检查循环条件是否包含用户输入
            for indicator in user_input_indicators:
                if indicator in line:
                    severity = '高危'
                    break
            
            vulnerabilities.append({
                'line': line_num,
                'message': "检测到while循环结构",
                'code_snippet': line_clean,
                'vulnerability_type': "潜在无限循环",
                'severity': severity
            })
        
        # 检测for循环
        elif re.search(r'\bfor\s*\([^)]+\)\s*\{', line):
            severity = '低危'
            
            # 检查循环条件是否包含用户输入
            for indicator in user_input_indicators:
                if indicator in line:
                    severity = '中危'
                    break
            
            vulnerabilities.append({
                'line': line_num,
                'message': "检测到for循环结构",
                'code_snippet': line_clean,
                'vulnerability_type': "循环结构",
                'severity': severity
            })
        
        # 检测foreach循环
        elif re.search(r'\bforeach\s*\([^)]+\)\s*\{', line):
            severity = '低危'
            
            # 检查是否遍历用户输入
            for indicator in user_input_indicators:
                if indicator in line:
                    severity = '中危'
                    break
            
            vulnerabilities.append({
                'line': line_num,
                'message': "检测到foreach循环结构",
                'code_snippet': line_clean,
                'vulnerability_type': "数组遍历",
                'severity': severity
            })


def detect_recursive_functions(lines, vulnerabilities):
    """
    检测递归函数
    """
    function_definitions = {}
    
    # 第一遍：收集所有函数定义
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测函数定义
        func_match = re.search(r'function\s+([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*\([^)]*\)\s*\{', line)
        if func_match:
            func_name = func_match.group(1)
            function_definitions[func_name] = line_num
    
    # 第二遍：检测递归调用
    for func_name, def_line in function_definitions.items():
        # 获取函数体（简单实现：取定义行后面的若干行）
        func_body_start = def_line
        func_body_end = min(def_line + 20, len(lines))  # 简单假设函数体在20行内
        
        func_body = '\n'.join(lines[func_body_start:func_body_end])
        
        # 统计函数名在函数体中出现的次数（排除定义行）
        call_count = func_body.count(func_name) - 1  # 减去定义本身
        
        if call_count > 0:
            code_snippet = lines[def_line - 1].strip() if def_line <= len(lines) else ""
            
            vulnerabilities.append({
                'line': def_line,
                'message': f"检测到潜在递归函数 '{func_name}'",
                'code_snippet': code_snippet,
                'vulnerability_type': "递归调用可能导致栈溢出",
                'severity': '中危'
            })


def detect_large_arrays(lines, vulnerabilities):
    """
    检测大数组操作
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测数组定义
        if re.search(r'\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*\[', line) or \
           re.search(r'\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*array\s*\(', line):
            
            # 简单检测：逗号数量超过阈值认为是大数组
            comma_count = line.count(',')
            if comma_count > 20:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到大数组定义",
                    'code_snippet': line_clean,
                    'vulnerability_type': "大内存分配",
                    'severity': '低危'
                })
        
        # 检测range函数创建大数组
        range_match = re.search(r'range\s*\(\s*\d+\s*,\s*(\d+)\s*\)', line)
        if range_match:
            end_value = int(range_match.group(1))
            if end_value > 10000:
                vulnerabilities.append({
                    'line': line_num,
                    'message': "检测到大范围数组创建",
                    'code_snippet': line_clean,
                    'vulnerability_type': "大内存分配",
                    'severity': '中危'
                })


def detect_redos_patterns(lines, vulnerabilities):
    """
    检测正则表达式ReDoS模式
    """
    preg_functions = ['preg_match', 'preg_match_all', 'preg_replace', 'preg_split', 'preg_grep']
    
    redos_patterns = [
        r'\(\s*a\s*\)\s*\+',  # (a)+
        r'\(\s*a\s*\)\s*\*',  # (a)*
        r'\(\s*a\s*\+\s*\)',  # (a+)
        r'\(\s*a\s*\*\s*\)',  # (a*)
        r'\.\s*\*',           # .*
        r'\.\s*\+',           # .+
        r'\w\s*\{\s*\d+\s*,\s*\}',  # a{10,}
        r'\|\s*\w\s*\|',      # |a|b|
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测preg函数
        for preg_func in preg_functions:
            if preg_func in line:
                # 检查是否包含复杂的正则模式
                for redos_pattern in redos_patterns:
                    if re.search(redos_pattern, line):
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到复杂正则表达式 '{preg_func}'",
                            'code_snippet': line_clean,
                            'vulnerability_type': "潜在正则表达式拒绝服务(ReDoS)",
                            'severity': '中危'
                        })
                        break


def detect_memory_intensive_operations(lines, vulnerabilities):
    """
    检测内存密集型操作
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测大字符串创建
        if 'str_repeat' in line:
            # 检查重复次数是否很大
            repeat_match = re.search(r'str_repeat\s*\(\s*[^,]+\s*,\s*(\d+)', line)
            if repeat_match:
                repeat_count = int(repeat_match.group(1))
                if repeat_count > 100000:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': "检测到大字符串创建",
                        'code_snippet': line_clean,
                        'vulnerability_type': "大内存分配",
                        'severity': '中危'
                    })
        
        # 检测大文件读取到内存
        if 'file_get_contents' in line and ('php://input' in line or '$_' in line):
            vulnerabilities.append({
                'line': line_num,
                'message': "检测到潜在大文件内存读取",
                'code_snippet': line_clean,
                'vulnerability_type': "内存耗尽风险",
                'severity': '高危'
            })


# 增强版检测函数
def detect_php_dos_vulnerability_enhanced(php_code):
    """
    PHP拒绝服务漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_dangerous_functions_enhanced(lines, vulnerabilities)
    detect_loop_structures_enhanced(lines, vulnerabilities)
    detect_recursive_patterns_enhanced(lines, vulnerabilities)
    detect_resource_intensive_operations(lines, vulnerabilities)
    
    return vulnerabilities


def detect_dangerous_functions_enhanced(lines, vulnerabilities):
    """
    增强版的危险函数检测
    """
    high_risk_functions = {
        "unlink": "文件删除",
        "file_get_contents": "大文件读取", 
        "file": "大文件读取",
        "readfile": "文件读取输出",
        "gzuncompress": "压缩解压",
        "simplexml_load_string": "XML解析",
        "DOMDocument::load": "XML解析",
    }
    
    user_input_sources = [
        r'\$_GET\[[^\]]+\]',
        r'\$_POST\[[^\]]+\]',
        r'\$_REQUEST\[[^\]]+\]',
        r'\$_COOKIE\[[^\]]+\]',
        r'\$_FILES\[[^\]]+\]',
        r'php://input'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
            
        for func_name, vuln_type in high_risk_functions.items():
            func_pattern = r'(?:\$[a-zA-Z_\x7f-\xff][\w\x7f-\xff]*\s*=\s*)?\b' + re.escape(func_name) + r'\s*\(\s*([^;){]*)\s*\)'
            
            match = re.search(func_pattern, line, re.IGNORECASE)
            if match:
                severity = '高危'
                detailed_type = vuln_type
                
                # 检查参数是否包含用户输入
                if match.groups():
                    param_content = match.group(1)
                    for user_input_pattern in user_input_sources:
                        if re.search(user_input_pattern, param_content, re.IGNORECASE):
                            severity = '严重'
                            detailed_type = f"{vuln_type} - 用户输入可能导致资源耗尽"
                            break
                
                # 避免重复报告
                if not any(v['line'] == line_num and v['code_snippet'] == line_clean for v in vulnerabilities):
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到潜在DoS函数 '{func_name}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': detailed_type,
                        'severity': severity
                    })


def detect_loop_structures_enhanced(lines, vulnerabilities):
    """
    增强版的循环结构检测
    """
    user_input_sources = [
        r'\$_GET\[[^\]]+\]',
        r'\$_POST\[[^\]]+\]', 
        r'\$_REQUEST\[[^\]]+\]',
        r'\$_COOKIE\[[^\]]+\]'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
            
        # 检测各种循环结构
        loop_patterns = [
            (r'\bwhile\s*\(\s*([^)]+)\s*\)\s*\{', "while循环", "潜在无限循环"),
            (r'\bfor\s*\(\s*([^)]+)\s*\)\s*\{', "for循环", "循环结构"),
            (r'\bforeach\s*\(\s*([^)]+)\s*\)\s*\{', "foreach循环", "数组遍历")
        ]
        
        for pattern, loop_type, vuln_type in loop_patterns:
            match = re.search(pattern, line)
            if match:
                severity = '低危'
                
                if loop_type == "while循环":
                    severity = '中危'
                
                # 检查是否使用用户输入
                condition = match.group(1) if match.groups() else ""
                for user_input_pattern in user_input_sources:
                    if re.search(user_input_pattern, condition, re.IGNORECASE):
                        severity = '高危' if loop_type == "while循环" else '中危'
                        break
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{loop_type}",
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })
                break


def detect_recursive_patterns_enhanced(lines, vulnerabilities):
    """
    增强版的递归模式检测
    """
    # 收集函数定义和调用
    functions = {}
    calls = []
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
            
        # 检测函数定义
        func_match = re.search(r'function\s+([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)', line)
        if func_match and '{' in line:
            func_name = func_match.group(1)
            functions[func_name] = line_num
        
        # 检测函数调用
        call_match = re.search(r'\b([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*\([^)]*\)', line)
        if call_match:
            called_func = call_match.group(1)
            if called_func in functions and not re.search(r'function\s+' + called_func, line):
                calls.append((called_func, line_num))
    
    # 分析递归调用
    for func_name, def_line in functions.items():
        # 查找该函数的调用
        func_calls = [call for call in calls if call[0] == func_name and call[1] > def_line]
        
        if func_calls:
            # 简单认为在函数定义后出现的同名调用可能是递归
            code_snippet = lines[def_line - 1].strip() if def_line <= len(lines) else ""
            
            vulnerabilities.append({
                'line': def_line,
                'message': f"检测到潜在递归函数 '{func_name}'",
                'code_snippet': code_snippet,
                'vulnerability_type': "递归调用可能导致栈溢出",
                'severity': '中危'
            })


def detect_resource_intensive_operations(lines, vulnerabilities):
    """
    检测资源密集型操作
    """
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
            
        # 检测大内存操作
        memory_patterns = [
            (r'str_repeat\s*\(\s*[^,]+\s*,\s*(\d{6,})', "大字符串创建"),
            (r'range\s*\(\s*\d+\s*,\s*(\d{5,})\s*\)', "大范围数组"),
            (r'array_fill\s*\(\s*\d+\s*,\s*(\d{5,})', "大数组填充"),
            (r'file_get_contents\s*\(\s*php://input', "输入流完整读取")
        ]
        
        for pattern, operation_type in memory_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                vulnerabilities.append({
                    'line': line_num,
                    'message': f"检测到{operation_type}",
                    'code_snippet': line_clean,
                    'vulnerability_type': "内存耗尽风险",
                    'severity': '中危'
                })
                break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 PHP 代码中的拒绝服务漏洞

// 文件操作相关DoS
unlink($_GET['file']);  // 删除文件
$content = file_get_contents($_POST['url']);  // 读取大文件
$data = file('/etc/passwd');  // 读取系统文件
readfile($user_file);  // 直接输出文件内容

// 压缩解压操作
$data = gzuncompress($compressed_data);  // 解压大文件
$inflated = gzinflate($_GET['data']);  // 解压用户输入

// XML解析DoS（XXE和实体扩展）
$xml = simplexml_load_string($_POST['xml_data']);
$dom = new DOMDocument();
$dom->load($_GET['xml_file']);
$dom->loadXML($user_xml);

// 大JSON解析
$big_json = json_decode(file_get_contents('php://input'));
$array = json_decode($_POST['large_json']);

// 反序列化DoS
$object = unserialize($user_input);

// 正则表达式ReDoS
preg_match('/(a+)+$/', $input);  // 指数级复杂度
preg_replace('/.*?<script>.*?<\/script>.*?/s', '', $html);

// 循环结构
while ($condition) {  // 可能无限循环
    // 处理逻辑
}

for ($i = 0; $i < $_GET['limit']; $i++) {  // 用户控制循环次数
    // 大量迭代
}

foreach ($_POST['big_array'] as $item) {  // 遍历大数组
    // 处理每个元素
}

// 递归函数
function recursive($n) {
    if ($n <= 0) return;
    recursive($n - 1);  // 递归调用
}

// 大数组定义
$big_array = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25];

// 内存密集型操作
$huge_string = str_repeat('A', 1000000);  // 创建大字符串
$big_array = range(1, 100000);  // 创建大范围数组

// 相对安全的操作
$safe_content = file_get_contents('small_file.txt');
$safe_json = json_decode('{"key": "value"}');
for ($i = 0; $i < 10; $i++) {
    // 有限循环
}

// 安全示例
echo "正常代码";
?>
"""

    print("=" * 60)
    print("PHP拒绝服务漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_php_dos_vulnerability_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到拒绝服务漏洞")