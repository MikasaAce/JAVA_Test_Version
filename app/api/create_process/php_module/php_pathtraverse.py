import re

def detect_path_traversal(php_code):
    """
    PHP路径遍历漏洞检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测文件操作函数
    detect_file_operations(lines, vulnerabilities)
    
    # 检测目录操作函数
    detect_directory_operations(lines, vulnerabilities)
    
    # 检测文件信息函数
    detect_file_info_functions(lines, vulnerabilities)
    
    # 检测路径拼接漏洞
    detect_path_concatenation(lines, vulnerabilities)
    
    # 检测文件上传相关函数
    detect_upload_functions(lines, vulnerabilities)
    
    # 检测文件包含漏洞
    detect_include_vulnerabilities(lines, vulnerabilities)
    
    return vulnerabilities


def detect_file_operations(lines, vulnerabilities):
    """
    检测文件操作函数中的路径遍历漏洞
    """
    file_functions = {
        "file_get_contents": "文件读取",
        "fopen": "文件打开",
        "file": "文件读取",
        "readfile": "文件读取输出",
        "file_put_contents": "文件写入",
        "fwrite": "文件写入",
        "fread": "文件读取",
        "include": "文件包含",
        "require": "文件包含",
        "include_once": "文件包含",
        "require_once": "文件包含",
        "copy": "文件复制",
        "rename": "文件重命名",
        "unlink": "文件删除",
        "move_uploaded_file": "文件移动",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    traversal_patterns = [r'\.\./', r'\.\.\\\\', r'%2e%2e%2f', r'\.\.\.\.//', r'\.\.\.\.\\\\']
    validation_patterns = ['basename', 'realpath', 'dirname', 'pathinfo', 'str_replace', 'preg_replace', 'filter_var']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测文件操作函数
        for func_name, func_desc in file_functions.items():
            if func_name in line:
                # 检查是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                # 检查路径遍历模式
                traversal_detected = any(re.search(pattern, line) for pattern in traversal_patterns)
                
                # 检查是否有路径验证
                no_validation = not any(pattern in line for pattern in validation_patterns)
                
                if user_input_detected:
                    severity = '高危' if traversal_detected else '中危'
                    message = f"检测到文件操作函数 '{func_name}' 使用用户输入"
                    vuln_type = f"路径遍历 - {func_desc}"
                    
                    if traversal_detected:
                        message += " - 可能包含路径遍历序列"
                    if no_validation:
                        message += " - 未进行路径验证"
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': vuln_type,
                        'severity': severity
                    })


def detect_directory_operations(lines, vulnerabilities):
    """
    检测目录操作函数中的路径遍历漏洞
    """
    directory_functions = {
        "opendir": "目录打开",
        "readdir": "目录读取",
        "scandir": "目录扫描",
        "glob": "文件匹配",
        "is_dir": "目录检查",
        "chdir": "目录切换",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测目录操作函数
        for func_name, func_desc in directory_functions.items():
            if func_name in line:
                # 检查是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到目录操作函数 '{func_name}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"路径遍历 - {func_desc}",
                        'severity': '中危'
                    })


def detect_file_info_functions(lines, vulnerabilities):
    """
    检测文件信息函数中的路径遍历漏洞
    """
    fileinfo_functions = {
        "file_exists": "文件存在检查",
        "is_file": "文件检查",
        "filesize": "文件大小",
        "filemtime": "文件修改时间",
        "filectime": "文件创建时间",
        "fileatime": "文件访问时间",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测文件信息函数
        for func_name, func_desc in fileinfo_functions.items():
            if func_name in line:
                # 检查是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到文件信息函数 '{func_name}' 使用用户输入",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"路径遍历 - {func_desc}",
                        'severity': '中危'
                    })


def detect_path_concatenation(lines, vulnerabilities):
    """
    检测路径拼接中的路径遍历漏洞
    """
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    path_patterns = [r'/', r'\\\\', r'\.\./', r'\.\.\\\\', r'uploads/', r'files/']
    traversal_patterns = [r'\.\./', r'\.\.\\\\', r'%2e%2e%2f']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测路径相关的字符串拼接
        is_path_context = any(re.search(pattern, line) for pattern in path_patterns)
        
        if is_path_context:
            # 检查是否包含用户输入
            user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
            
            # 检查路径遍历模式
            traversal_detected = any(re.search(pattern, line) for pattern in traversal_patterns)
            
            # 检查是否有字符串拼接操作
            has_concatenation = '.' in line or '+' in line
            
            if user_input_detected and has_concatenation:
                severity = '高危' if traversal_detected else '中危'
                message = "检测到路径拼接使用用户输入"
                vuln_type = "路径遍历 - 路径拼接"
                
                if traversal_detected:
                    message += " - 可能包含路径遍历序列"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': vuln_type,
                    'severity': severity
                })


def detect_upload_functions(lines, vulnerabilities):
    """
    检测文件上传相关函数中的路径遍历漏洞
    """
    upload_functions = {
        "move_uploaded_file": "上传文件移动",
        "is_uploaded_file": "上传文件检查",
    }
    
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测上传函数
        for func_name, func_desc in upload_functions.items():
            if func_name in line:
                # 检查目标路径是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                if user_input_detected:
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到上传函数 '{func_name}' 使用用户输入作为目标路径",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"路径遍历 - {func_desc}",
                        'severity': '高危'
                    })


def detect_include_vulnerabilities(lines, vulnerabilities):
    """
    检测文件包含漏洞
    """
    include_functions = ['include', 'require', 'include_once', 'require_once']
    user_input_indicators = [r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE']
    traversal_patterns = [r'\.\./', r'\.\.\\\\', r'%2e%2e%2f']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测文件包含函数
        for func_name in include_functions:
            if func_name in line:
                # 检查是否包含用户输入
                user_input_detected = any(re.search(indicator, line) for indicator in user_input_indicators)
                
                # 检查路径遍历模式
                traversal_detected = any(re.search(pattern, line) for pattern in traversal_patterns)
                
                if user_input_detected:
                    severity = '高危' if traversal_detected else '中危'
                    message = "检测到文件包含使用用户输入"
                    vuln_type = "路径遍历 - 文件包含"
                    
                    if traversal_detected:
                        message += " - 可能包含路径遍历序列"
                    
                    vulnerabilities.append({
                        'line': line_num,
                        'message': message,
                        'code_snippet': line_clean,
                        'vulnerability_type': vuln_type,
                        'severity': severity
                    })


# 增强版检测函数
def detect_path_traversal_enhanced(php_code):
    """
    PHP路径遍历漏洞检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_path_traversal(lines, vulnerabilities)
    detect_advanced_traversal_patterns(lines, vulnerabilities)
    detect_context_aware_traversal(lines, vulnerabilities)
    
    return vulnerabilities


def detect_comprehensive_path_traversal(lines, vulnerabilities):
    """
    增强版的路径遍历检测
    """
    sensitive_operations = [
        # 文件读取操作
        (r'file_get_contents\s*\(\s*[^)]*\$_[^)]*\)', 'file_get_contents'),
        (r'fopen\s*\(\s*[^)]*\$_[^)]*\)', 'fopen'),
        (r'file\s*\(\s*[^)]*\$_[^)]*\)', 'file'),
        (r'readfile\s*\(\s*[^)]*\$_[^)]*\)', 'readfile'),
        # 文件写入操作
        (r'file_put_contents\s*\(\s*[^)]*\$_[^)]*\)', 'file_put_contents'),
        (r'fwrite\s*\(\s*[^)]*\$_[^)]*\)', 'fwrite'),
        # 文件包含操作
        (r'include\s*\(\s*[^)]*\$_[^)]*\)', 'include'),
        (r'require\s*\(\s*[^)]*\$_[^)]*\)', 'require'),
        (r'include_once\s*\(\s*[^)]*\$_[^)]*\)', 'include_once'),
        (r'require_once\s*\(\s*[^)]*\$_[^)]*\)', 'require_once'),
        # 文件操作
        (r'unlink\s*\(\s*[^)]*\$_[^)]*\)', 'unlink'),
        (r'copy\s*\(\s*[^)]*\$_[^)]*\)', 'copy'),
        (r'rename\s*\(\s*[^)]*\$_[^)]*\)', 'rename'),
        # 目录操作
        (r'scandir\s*\(\s*[^)]*\$_[^)]*\)', 'scandir'),
        (r'opendir\s*\(\s*[^)]*\$_[^)]*\)', 'opendir'),
        (r'glob\s*\(\s*[^)]*\$_[^)]*\)', 'glob')
    ]
    
    traversal_patterns = [
        r'\.\./', r'\.\.\\\\', r'%2e%2e%2f', r'%2e%2e%2f',
        r'\.\.%2f', r'%2e%2e/', r'\.%2e%2f'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
        
        for pattern, operation in sensitive_operations:
            if re.search(pattern, line, re.IGNORECASE):
                # 检查是否包含路径遍历序列
                traversal_found = False
                for traversal_pattern in traversal_patterns:
                    if re.search(traversal_pattern, line, re.IGNORECASE):
                        traversal_found = True
                        break
                
                severity = '高危' if traversal_found else '中危'
                message = f"检测到{operation}使用用户输入"
                
                if traversal_found:
                    message += " - 包含路径遍历序列"
                
                vulnerabilities.append({
                    'line': line_num,
                    'message': message,
                    'code_snippet': line_clean,
                    'vulnerability_type': f"路径遍历 - {operation}",
                    'severity': severity
                })
                break


def detect_advanced_traversal_patterns(lines, vulnerabilities):
    """
    检测高级路径遍历模式
    """
    advanced_patterns = [
        # 空字节注入（PHP < 5.3.4）
        (r'\$_[^\s]+\s*\.\s*[\'"]\.[^\.]*php[\'"]', "空字节注入风险"),
        # 双重编码
        (r'%252e%252e%252f', "双重编码路径遍历"),
        (r'%255c%255c', "双重编码反斜杠"),
        # Unicode编码
        (r'%u2215', "Unicode斜杠"),
        (r'%c0%af', "UTF-8过长的斜杠"),
        # 绝对路径遍历
        (r'/etc/passwd', "绝对路径遍历"),
        (r'C:\\\\Windows\\\\', "Windows绝对路径"),
        # 相对路径遍历
        (r'\.\./\.\./\.\./', "多层路径遍历"),
        (r'\.\.\\\\\.\.\\\\\.\.\\\\', "多层反斜杠遍历")
    ]
    
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
        
        # 检查是否包含用户输入
        user_input_found = False
        for user_input_pattern in user_input_sources:
            if re.search(user_input_pattern, line):
                user_input_found = True
                break
        
        if user_input_found:
            for pattern, pattern_type in advanced_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到{pattern_type}",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"路径遍历 - {pattern_type}",
                        'severity': '高危'
                    })
                    break


def detect_context_aware_traversal(lines, vulnerabilities):
    """
    检测上下文感知的路径遍历漏洞
    """
    contexts = [
        # 配置文件读取
        (r'config.*\.\s*\$_', "配置文件读取"),
        # 日志文件操作
        (r'log.*\.\s*\$_', "日志文件操作"),
        # 模板包含
        (r'template.*\.\s*\$_', "模板包含"),
        # 上传文件处理
        (r'upload.*\.\s*\$_', "上传文件处理"),
        # 备份文件访问
        (r'backup.*\.\s*\$_', "备份文件访问"),
        # 静态资源访问
        (r'static.*\.\s*\$_', "静态资源访问"),
        # 用户文件访问
        (r'user.*file.*\.\s*\$_', "用户文件访问")
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
                    'vulnerability_type': f"路径遍历 - {context_type}",
                    'severity': '中危'
                })
                break


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试路径遍历漏洞

// 文件读取操作 - 高危
$content = file_get_contents($_GET['file']);
$data = file($_POST['filename']);
readfile($_REQUEST['document']);

// 文件写入操作 - 高危
file_put_contents($_GET['log_file'], $data);
fopen($_POST['config_path'], 'w');

// 文件包含漏洞 - 高危
include($_GET['page']);
require($_POST['template']);
include_once($_REQUEST['module']);
require_once($user_input . '.php');

// 文件删除操作 - 高危
unlink($_GET['file_to_delete']);

// 文件复制/移动操作 - 高危
copy($_POST['source'], $_POST['destination']);
rename($_GET['old_name'], $_GET['new_name']);

// 目录遍历操作 - 中危
$files = scandir($_GET['directory']);
$handle = opendir($_POST['folder']);
$matches = glob($_REQUEST['pattern']);

// 文件信息检查 - 中危
if (file_exists($_GET['file_path'])) {
    $size = filesize($_GET['file_path']);
}

// 路径拼接漏洞 - 高危
$upload_path = 'uploads/' . $_GET['filename'];
$config_file = '/etc/' . $_POST['config'];
$log_path = '../logs/' . $_REQUEST['logfile'];

// 文件上传路径遍历 - 高危
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_POST['filename']);

// 相对路径遍历
$file = '../../../../etc/passwd';
$content = file_get_contents($file);

// URL编码的路径遍历
$file = '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd';
include($file);

// 空字节注入（PHP < 5.3.4）
$file = $_GET['file'] . '.php';
include($file);  // 如果file=../../../etc/passwd%00，则.php被截断

// 相对安全的实现
// 白名单验证
$allowed_files = ['page1.php', 'page2.php', 'page3.php'];
if (in_array($_GET['page'], $allowed_files)) {
    include($_GET['page']);
}

// 使用basename防止目录遍历
$safe_file = basename($_GET['file']);
include('pages/' . $safe_file);

// 使用realpath验证
$requested_file = realpath('./files/' . $_POST['filename']);
$base_dir = realpath('./files');
if (strpos($requested_file, $base_dir) === 0) {
    include($requested_file);
}

// 路径过滤
$filtered_path = str_replace(['../', '..\\\\'], '', $_GET['path']);
$safe_path = 'uploads/' . $filtered_path;

// 固定路径（安全）
include('templates/header.php');
file_get_contents('/var/log/app.log');
$files = scandir('uploads/');

// 正常业务逻辑
echo "应用程序代码";
?>
"""

    print("=" * 60)
    print("PHP路径遍历漏洞检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_path_traversal_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到路径遍历漏洞")