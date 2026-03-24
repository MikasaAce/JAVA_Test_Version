import re

def detect_hardcoded_passwords(php_code):
    """
    PHP硬编码密码检测主函数 - 使用正则表达式版本
    """
    vulnerabilities = []
    
    # 按行分割代码
    lines = php_code.split('\n')
    
    # 检测变量赋值中的硬编码密码
    detect_variable_assignments(lines, vulnerabilities)
    
    # 检测数组中的硬编码密码
    detect_array_passwords(lines, vulnerabilities)
    
    # 检测数据库连接中的硬编码密码
    detect_database_connections(lines, vulnerabilities)
    
    # 检测常量定义中的硬编码密码
    detect_constant_passwords(lines, vulnerabilities)
    
    # 检测类属性中的硬编码密码
    detect_class_properties(lines, vulnerabilities)
    
    # 检测常见弱密码模式
    detect_weak_password_patterns(lines, vulnerabilities)
    
    return vulnerabilities


def detect_variable_assignments(lines, vulnerabilities):
    """
    检测变量赋值中的硬编码密码
    """
    password_keywords = [
        'password', 'pass', 'pwd', 'secret', 'key', 'token',
        'auth', 'credential', 'apikey', 'apisecret', 'privatekey',
        'encryption', 'salt', 'hash'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        # 跳过空行和纯注释行
        if not line_clean or line_clean.startswith('//') or line_clean.startswith('#') or line_clean.startswith('/*'):
            continue
            
        # 检测变量赋值模式：$var = "value";
        assignment_pattern = r'\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*=\s*([\'"])([^\'"]*)([\'"])'
        
        match = re.search(assignment_pattern, line)
        if match:
            var_name = match.group(1).lower()
            value = match.group(3)
            
            # 检查变量名是否包含密码关键词
            for keyword in password_keywords:
                if keyword in var_name:
                    # 检查值是否看起来像密码（非空且不是明显的占位符）
                    if value and not is_placeholder_value(value):
                        severity = '高危'
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到硬编码密码变量 '${match.group(1)}'",
                            'code_snippet': line_clean,
                            'vulnerability_type': "硬编码密码",
                            'severity': severity
                        })
                    break


def detect_array_passwords(lines, vulnerabilities):
    """
    检测数组中的硬编码密码
    """
    password_keywords = ['password', 'pass', 'pwd', 'secret', 'key', 'token']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测数组键值对模式：'key' => 'value'
        array_pattern = r'[\'"](\w+)[\'"]\s*=>\s*[\'"]([^\'"]*)[\'"]'
        
        matches = re.findall(array_pattern, line)
        for key, value in matches:
            key_lower = key.lower()
            
            # 检查键名是否包含密码关键词
            for keyword in password_keywords:
                if keyword in key_lower:
                    # 检查值是否看起来像密码
                    if value and not is_placeholder_value(value):
                        severity = '高危'
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到数组中的密码键 '{key}'",
                            'code_snippet': line_clean,
                            'vulnerability_type': "硬编码密码",
                            'severity': severity
                        })
                    break


def detect_database_connections(lines, vulnerabilities):
    """
    检测数据库连接中的硬编码密码
    """
    db_connection_functions = [
        'mysql_connect', 'mysqli_connect', 'pg_connect',
        'sqlsrv_connect', 'oci_connect', 'PDO'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检查每个数据库连接函数
        for func_name in db_connection_functions:
            if func_name in line:
                # 检测函数调用中的字符串参数（密码通常在第三个参数）
                if 'PDO' in func_name:
                    # PDO构造函数模式
                    pdo_pattern = r'new\s+PDO\s*\([^)]+[\'"]([^\'"]*)[\'"][^)]*\)'
                    pdo_match = re.search(pdo_pattern, line)
                    if pdo_match:
                        # 简单检测：如果包含明显的密码特征
                        if has_password_like_content(line):
                            vulnerabilities.append({
                                'line': line_num,
                                'message': f"检测到数据库连接函数 '{func_name}' 中的硬编码密码",
                                'code_snippet': line_clean,
                                'vulnerability_type': "硬编码数据库密码",
                                'severity': '严重'
                            })
                else:
                    # 传统数据库函数模式
                    func_pattern = re.escape(func_name) + r'\s*\([^)]+[\'"]([^\'"]*)[\'"][^)]*\)'
                    if re.search(func_pattern, line):
                        if has_password_like_content(line):
                            vulnerabilities.append({
                                'line': line_num,
                                'message': f"检测到数据库连接函数 '{func_name}' 中的硬编码密码",
                                'code_snippet': line_clean,
                                'vulnerability_type': "硬编码数据库密码",
                                'severity': '严重'
                            })


def detect_constant_passwords(lines, vulnerabilities):
    """
    检测常量定义中的硬编码密码
    """
    password_keywords = ['password', 'pass', 'pwd', 'secret', 'key', 'token']
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 检测define常量
        define_pattern = r'define\s*\(\s*[\'"](\w+)[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\s*\)'
        define_match = re.search(define_pattern, line, re.IGNORECASE)
        if define_match:
            const_name = define_match.group(1).lower()
            value = define_match.group(2)
            
            for keyword in password_keywords:
                if keyword in const_name:
                    if value and not is_placeholder_value(value):
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到define常量中的密码 '{define_match.group(1)}'",
                            'code_snippet': line_clean,
                            'vulnerability_type': "硬编码密码常量",
                            'severity': '高危'
                        })
                    break
        
        # 检测const常量
        const_pattern = r'const\s+(\w+)\s*=\s*[\'"]([^\'"]*)[\'"]'
        const_match = re.search(const_pattern, line, re.IGNORECASE)
        if const_match:
            const_name = const_match.group(1).lower()
            value = const_match.group(2)
            
            for keyword in password_keywords:
                if keyword in const_name:
                    if value and not is_placeholder_value(value):
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到const常量中的密码 '{const_match.group(1)}'",
                            'code_snippet': line_clean,
                            'vulnerability_type': "硬编码密码常量",
                            'severity': '高危'
                        })
                    break


def detect_class_properties(lines, vulnerabilities):
    """
    检测类属性中的硬编码密码
    """
    password_keywords = ['password', 'pass', 'pwd', 'secret', 'key', 'token']
    
    in_class = False
    current_class = ""
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean:
            continue
            
        # 检测类定义开始
        class_match = re.search(r'class\s+([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)', line)
        if class_match:
            in_class = True
            current_class = class_match.group(1)
            continue
            
        # 检测类定义结束（简单通过大括号匹配）
        if in_class and '}' in line_clean and '{' not in line_clean:
            in_class = False
            current_class = ""
            continue
            
        # 在类内部检测属性赋值
        if in_class:
            # 检测类属性：private $var = "value";
            property_pattern = r'(?:public|private|protected|var)\s+\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*=\s*[\'"]([^\'"]*)[\'"]'
            property_match = re.search(property_pattern, line)
            if property_match:
                prop_name = property_match.group(1).lower()
                value = property_match.group(2)
                
                for keyword in password_keywords:
                    if keyword in prop_name:
                        if value and not is_placeholder_value(value):
                            vulnerabilities.append({
                                'line': line_num,
                                'message': f"检测到类 '{current_class}' 中的密码属性 '${prop_name}'",
                                'code_snippet': line_clean,
                                'vulnerability_type': "硬编码密码属性",
                                'severity': '高危'
                            })
                        break
            
            # 检测类常量
            class_const_pattern = r'const\s+(\w+)\s*=\s*[\'"]([^\'"]*)[\'"]'
            const_match = re.search(class_const_pattern, line)
            if const_match:
                const_name = const_match.group(1).lower()
                value = const_match.group(2)
                
                for keyword in password_keywords:
                    if keyword in const_name:
                        if value and not is_placeholder_value(value):
                            vulnerabilities.append({
                                'line': line_num,
                                'message': f"检测到类 '{current_class}' 中的密码常量 '{const_match.group(1)}'",
                                'code_snippet': line_clean,
                                'vulnerability_type': "硬编码密码常量",
                                'severity': '高危'
                            })
                        break


def detect_weak_password_patterns(lines, vulnerabilities):
    """
    检测常见弱密码模式
    """
    weak_passwords = [
        'password123', '123456', 'admin', 'root', 'passw0rd',
        'qwerty', 'letmein', 'welcome', '12345678', '123456789',
        '12345', '1234', '123', 'abc123', 'password1', 'test123',
        'guest', 'default', 'secret', 'changeme'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#', '/*')):
            continue
            
        # 查找字符串中的弱密码
        string_pattern = r'[\'"]([^\'"]*)[\'"]'
        string_matches = re.findall(string_pattern, line)
        
        for string_value in string_matches:
            for weak_pass in weak_passwords:
                if weak_pass.lower() in string_value.lower():
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到常见弱密码模式 '{weak_pass}'",
                        'code_snippet': line_clean,
                        'vulnerability_type': "硬编码弱密码",
                        'severity': '高危'
                    })
                    break


def is_placeholder_value(value):
    """
    检查值是否是明显的占位符
    """
    placeholders = [
        '', 'password', 'pass', 'pwd', 'secret', 'key', 'token',
        'your_password', 'your_secret', 'changeme', '********',
        'xxx', 'yyy', 'test', 'demo'
    ]
    return value.lower() in placeholders or len(value) < 3


def has_password_like_content(line):
    """
    检查行中是否包含类似密码的内容
    """
    # 排除明显的占位符
    if 'your_password' in line.lower() or 'changeme' in line.lower():
        return False
    
    # 检查是否包含实际的字符串值
    string_pattern = r'[\'"]([^\'"]{4,})[\'"]'
    matches = re.findall(string_pattern, line)
    
    for match in matches:
        if not is_placeholder_value(match) and len(match) >= 4:
            return True
    
    return False


# 增强版检测函数
def detect_hardcoded_passwords_enhanced(php_code):
    """
    PHP硬编码密码检测 - 增强正则表达式版本
    """
    vulnerabilities = []
    
    lines = php_code.split('\n')
    
    # 使用增强检测
    detect_comprehensive_assignments(lines, vulnerabilities)
    detect_configuration_patterns(lines, vulnerabilities)
    detect_connection_strings(lines, vulnerabilities)
    
    return vulnerabilities


def detect_comprehensive_assignments(lines, vulnerabilities):
    """
    增强版的赋值检测
    """
    password_indicators = [
        ('password', '密码'),
        ('pass', '密码'),
        ('pwd', '密码'),
        ('secret', '密钥'),
        ('key', '密钥'),
        ('token', '令牌'),
        ('apikey', 'API密钥'),
        ('apisecret', 'API密钥'),
        ('privatekey', '私钥'),
        ('encryption', '加密密钥'),
        ('salt', '盐值'),
        ('hash', '哈希值'),
        ('credential', '凭据'),
        ('auth', '认证')
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')) or (line_clean.startswith('/*') and '*/' not in line_clean):
            continue
            
        # 检测各种赋值模式
        assignment_patterns = [
            r'\$(\w+)\s*=\s*([\'"])([^\'"]*)([\'"])',  # 变量赋值
            r'[\'"](\w+)[\'"]\s*=>\s*([\'"])([^\'"]*)([\'"])',  # 数组赋值
            r'(?:public|private|protected|var)\s+\$(\w+)\s*=\s*([\'"])([^\'"]*)([\'"])',  # 类属性
            r'define\s*\(\s*[\'"](\w+)[\'"]\s*,\s*([\'"])([^\'"]*)([\'"])\s*\)',  # define常量
            r'const\s+(\w+)\s*=\s*([\'"])([^\'"]*)([\'"])'  # const常量
        ]
        
        for pattern in assignment_patterns:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                name = match.group(1).lower()
                value = match.group(3)
                
                # 检查名称是否包含密码指示器
                for indicator, desc in password_indicators:
                    if indicator in name:
                        # 验证值是否是真实的密码
                        if is_likely_real_password(value):
                            vuln_type = f"硬编码{desc}"
                            severity = '高危' if desc == '密码' else '中危'
                            
                            vulnerabilities.append({
                                'line': line_num,
                                'message': f"检测到硬编码{desc} '{match.group(1)}'",
                                'code_snippet': line_clean,
                                'vulnerability_type': vuln_type,
                                'severity': severity
                            })
                        break


def detect_configuration_patterns(lines, vulnerabilities):
    """
    检测配置文件模式中的密码
    """
    config_patterns = [
        (r'\$config\s*\[[\'"]\w*password\w*[\'"]\]\s*=\s*[\'"][^\'"]+[\'"]', '配置密码'),
        (r'\$db\w*\s*\[[\'"]\w*pass\w*[\'"]\]\s*=\s*[\'"][^\'"]+[\'"]', '数据库密码'),
        (r'\$settings\s*\[[\'"]\w*secret\w*[\'"]\]\s*=\s*[\'"][^\'"]+[\'"]', '设置密钥'),
        (r'\$options\s*\[[\'"]\w*key\w*[\'"]\]\s*=\s*[\'"][^\'"]+[\'"]', '选项密钥')
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
            
        for pattern, desc in config_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                if has_password_like_content(line):
                    vulnerabilities.append({
                        'line': line_num,
                        'message': f"检测到{desc}",
                        'code_snippet': line_clean,
                        'vulnerability_type': f"硬编码{desc}",
                        'severity': '高危'
                    })
                break


def detect_connection_strings(lines, vulnerabilities):
    """
    检测连接字符串中的密码
    """
    connection_indicators = [
        'mysql_connect', 'mysqli_connect', 'pg_connect', 'sqlsrv_connect',
        'oci_connect', 'PDO', 'mysql_pconnect', 'mysqli_real_connect'
    ]
    
    for line_num, line in enumerate(lines, 1):
        line_clean = line.strip()
        
        if not line_clean or line_clean.startswith(('//', '#')):
            continue
            
        for connector in connection_indicators:
            if connector in line:
                # 检查是否包含字符串密码参数
                string_count = line.count("'") + line.count('"')
                if string_count >= 4:  # 至少有两个字符串参数（可能包含密码）
                    if has_password_like_content(line):
                        vulnerabilities.append({
                            'line': line_num,
                            'message': f"检测到连接函数 '{connector}' 中的硬编码密码",
                            'code_snippet': line_clean,
                            'vulnerability_type': "硬编码连接密码",
                            'severity': '严重'
                        })
                break


def is_likely_real_password(value):
    """
    判断值是否可能是真实密码（而非占位符）
    """
    if not value or len(value) < 4:
        return False
        
    placeholders = [
        'password', 'pass', 'pwd', 'secret', 'key', 'token',
        'your_password', 'your_secret', 'changeme', '********',
        'xxx', 'yyy', 'test', 'demo', 'example', 'placeholder'
    ]
    
    if value.lower() in placeholders:
        return False
        
    # 检查是否包含数字和字母的组合（更像真实密码）
    has_letter = bool(re.search(r'[a-zA-Z]', value))
    has_digit = bool(re.search(r'\d', value))
    
    # 如果同时包含字母和数字，更可能是真实密码
    if has_letter and has_digit:
        return True
        
    # 或者长度足够长
    if len(value) >= 8:
        return True
        
    return False


# 测试代码
if __name__ == "__main__":
    test_php_code = """<?php
// 测试 PHP 代码中的硬编码密码

// 变量赋值中的硬编码密码
$password = "secret123";
$db_pass = "mydbpassword";
$api_key = "sk-1234567890abcdef";
$admin_pwd = "admin123";

// 数组配置中的硬编码密码
$config = array(
    'username' => 'admin',
    'password' => 'P@ssw0rd123',
    'host' => 'localhost'
);

$db_config = [
    'user' => 'root',
    'pass' => 'root123456',
    'database' => 'myapp'
];

// 数据库连接中的硬编码密码
mysql_connect('localhost', 'root', 'rootpassword');
mysqli_connect('127.0.0.1', 'admin', 'adminpass', 'database');
new PDO('mysql:host=localhost;dbname=test', 'user', 'userpass');

// 常量定义中的硬编码密码
define('DB_PASSWORD', 'MySecretPassword123');
define('API_SECRET_KEY', 'sk-abcdef123456');
const ENCRYPTION_KEY = 'myencryptionkey';

// 类属性中的硬编码密码
class DatabaseConfig {
    private $host = 'localhost';
    private $username = 'admin';
    private $password = 'ClassPassword123';
    public $api_key = 'pk-123456789';
}

class AppSettings {
    const SECRET_TOKEN = 'token123456';
    public static $encryption_key = 'encryptkey789';
}

// 函数参数中的硬编码密码
function connectDB($host, $user, $pass) {
    // 连接数据库
}
connectDB('localhost', 'root', 'rootpass');

// 常见的弱密码
$weak_password = "123456";
$default_pass = "password";
$test_pwd = "test123";

// 安全示例（从环境变量或配置文件中读取）
$safe_password = getenv('DB_PASSWORD');
$config_password = $config['db_password']; // 从外部配置读取
$api_secret = $_ENV['API_SECRET'];

// 正常代码
echo "正常业务逻辑";
?>
"""

    print("=" * 60)
    print("PHP硬编码密码检测 - 正则表达式版本")
    print("=" * 60)

    # 使用增强版本检测
    results = detect_hardcoded_passwords_enhanced(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到硬编码密码")