import os
import re
import base64
from tree_sitter import Language, Parser

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义硬编码密码漏洞模式
HARDCODED_PASSWORD_VULNERABILITIES = {
    'python': [
        # 检测变量赋值中的密码
        {
            'query': '''
                (assignment
                    left: (identifier) @var_name
                    right: (string) @password_value
                ) @assignment
            ''',
            'message': '变量赋值中的硬编码密码',
            'severity': '高危',
            'risk_type': 'variable_assignment'
        },
        # 检测字典中的密码
        {
            'query': '''
                (pair
                    key: (string) @key_name
                    value: (string) @password_value
                ) @dict_pair
            ''',
            'message': '字典中的硬编码密码',
            'severity': '高危',
            'risk_type': 'dict_password'
        },
        # 检测函数调用参数中的密码
        {
            'query': '''
                (call
                    function: (_) @func_name
                    arguments: (argument_list 
                        (_)* @args
                        (keyword_argument
                            name: (identifier) @kw_name
                            value: (string) @password_value
                        ) @kw_arg
                    )
                ) @call
            ''',
            'message': '函数参数中的硬编码密码',
            'severity': '高危',
            'risk_type': 'function_argument'
        },
        # 检测类属性中的密码
        {
            'query': '''
                (class_definition
                    body: (block
                        (expression_statement
                            (assignment
                                left: (attribute) @attr_name
                                right: (string) @password_value
                            ) @attr_assignment
                        )
                    )
                ) @class_def
            ''',
            'message': '类属性中的硬编码密码',
            'severity': '高危',
            'risk_type': 'class_attribute'
        },
        # 检测Base64编码的密码
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @module
                        attribute: (identifier) @func_name
                    )
                    arguments: (argument_list (string) @encoded_value)
                ) @call
            ''',
            'module_pattern': r'^(base64)$',
            'func_pattern': r'^(b64decode|b32decode|b16decode)$',
            'message': 'Base64编码的密码',
            'severity': '中危',
            'risk_type': 'base64_encoded'
        }
    ]
}

# 密码相关关键词模式
PASSWORD_KEYWORDS = {
    'variable_patterns': [
        r'.*password.*', r'.*pwd.*', r'.*pass.*', r'.*secret.*',
        r'.*key.*', r'.*token.*', r'.*auth.*', r'.*credential.*',
        r'.*api[_-]?key.*', r'.*access[_-]?key.*', r'.*secret[_-]?key.*',
        r'.*private[_-]?key.*', r'.*session[_-]?key.*', r'.*encryption[_-]?key.*',
        r'.*db[_-]?pass.*', r'.*database[_-]?pass.*', r'.*mysql[_-]?pass.*',
        r'.*postgres[_-]?pass.*', r'.*redis[_-]?pass.*', r'.*mongo[_-]?pass.*',
        r'.*ssh[_-]?key.*', r'.*ssl[_-]?key.*', r'.*cert[_-]?key.*'
    ],
    'function_patterns': [
        r'^password$', r'^pwd$', r'^pass$', r'^secret$',
        r'^key$', r'^token$', r'^auth$', r'^credential$',
        r'^api_key$', r'^access_key$', r'^secret_key$',
        r'^private_key$', r'^session_key$', r'^encryption_key$'
    ],
    'key_patterns': [
        r'^["\']password["\']$', r'^["\']pwd["\']$', r'^["\']pass["\']$',
        r'^["\']secret["\']$', r'^["\']key["\']$', r'^["\']token["\']$',
        r'^["\']auth["\']$', r'^["\']credential["\']$', r'^["\']api_key["\']$',
        r'^["\']access_key["\']$', r'^["\']secret_key["\']$', r'^["\']private_key["\']$'
    ]
}

# 密码强度检测模式
PASSWORD_STRENGTH_PATTERNS = {
    'weak_patterns': [
        r'^["\']?123456["\']?$', r'^["\']?password["\']?$', r'^["\']?admin["\']?$',
        r'^["\']?12345678["\']?$', r'^["\']?qwerty["\']?$', r'^["\']?123456789["\']?$',
        r'^["\']?12345["\']?$', r'^["\']?1234["\']?$', r'^["\']?111111["\']?$',
        r'^["\']?1234567["\']?$', r'^["\']?dragon["\']?$', r'^["\']?123123["\']?$',
        r'^["\']?baseball["\']?$', r'^["\']?abc123["\']?$', r'^["\']?football["\']?$',
        r'^["\']?monkey["\']?$', r'^["\']?letmein["\']?$', r'^["\']?696969["\']?$',
        r'^["\']?shadow["\']?$', r'^["\']?master["\']?$', r'^["\']?666666["\']?$',
        r'^["\']?qwertyuiop["\']?$', r'^["\']?123321["\']?$', r'^["\']?mustang["\']?$',
        r'^["\']?1234567890["\']?$', r'^["\']?michael["\']?$', r'^["\']?654321["\']?$',
        r'^["\']?pussy["\']?$', r'^["\']?superman["\']?$', r'^["\']?1qaz2wsx["\']?$',
        r'^["\']?7777777["\']?$', r'^["\']?fuckyou["\']?$', r'^["\']?121212["\']?$',
        r'^["\']?000000["\']?$', r'^["\']?qazwsx["\']?$', r'^["\']?123qwe["\']?$',
        r'^["\']?killer["\']?$', r'^["\']?trustno1["\']?$', r'^["\']?jordan["\']?$',
        r'^["\']?jennifer["\']?$', r'^["\']?zxcvbnm["\']?$', r'^["\']?asdfgh["\']?$',
        r'^["\']?hunter["\']?$', r'^["\']?buster["\']?$', r'^["\']?soccer["\']?$',
        r'^["\']?harley["\']?$', r'^["\']?batman["\']?$', r'^["\']?andrew["\']?$',
        r'^["\']?tigger["\']?$', r'^["\']?sunshine["\']?$', r'^["\']?iloveyou["\']?$',
        r'^["\']?fuckme["\']?$', r'^["\']?2000["\']?$', r'^["\']?charlie["\']?$',
        r'^["\']?robert["\']?$', r'^["\']?thomas["\']?$', r'^["\']?hockey["\']?$',
        r'^["\']?ranger["\']?$', r'^["\']?daniel["\']?$', r'^["\']?starwars["\']?$',
        r'^["\']?klaster["\']?$', r'^["\']?112233["\']?$', r'^["\']?george["\']?$',
        r'^["\']?asshole["\']?$', r'^["\']?computer["\']?$', r'^["\']?michelle["\']?$',
        r'^["\']?jessica["\']?$', r'^["\']?pepper["\']?$', r'^["\']?1111["\']?$',
        r'^["\']?zxcvbn["\']?$', r'^["\']?555555["\']?$', r'^["\']?11111111["\']?$',
        r'^["\']?131313["\']?$', r'^["\']?freedom["\']?$', r'^["\']?777777["\']?$',
        r'^["\']?pass["\']?$', r'^["\']?fuck["\']?$', r'^["\']?maggie["\']?$',
        r'^["\']?159753["\']?$', r'^["\']?aaaaaa["\']?$', r'^["\']?ginger["\']?$',
        r'^["\']?princess["\']?$', r'^["\']?joshua["\']?$', r'^["\']?cheese["\']?$',
        r'^["\']?amanda["\']?$', r'^["\']?summer["\']?$', r'^["\']?love["\']?$',
        r'^["\']?ashley["\']?$', r'^["\']?6969["\']?$', r'^["\']?nicole["\']?$',
        r'^["\']?chelsea["\']?$', r'^["\']?biteme["\']?$', r'^["\']?matthew["\']?$',
        r'^["\']?access["\']?$', r'^["\']?yankees["\']?$', r'^["\']?987654321["\']?$',
        r'^["\']?dallas["\']?$', r'^["\']?austin["\']?$', r'^["\']?thunder["\']?$',
        r'^["\']?taylor["\']?$', r'^["\']?matrix["\']?$', r'^["\']?minecraft["\']?$'
    ],
    'suspicious_patterns': [
        r'^["\']?.{0,5}["\']?$',  # 太短的密码
        r'^["\']?\d{6,}["\']?$',  # 纯数字
        r'^["\']?[a-zA-Z]{6,}["\']?$',  # 纯字母
        r'^["\']?test.*["\']?$',  # 测试密码
        r'^["\']?demo.*["\']?$',  # 演示密码
        r'^["\']?example.*["\']?$',  # 示例密码
        r'^["\']?temp.*["\']?$',  # 临时密码
        r'^["\']?default.*["\']?$',  # 默认密码
        r'^["\']?changeme.*["\']?$',  # 需要更改的密码
    ]
}

# 安全配置模式（白名单）
SAFE_CONFIGURATIONS = {
    'safe_variables': [
        r'^example_', r'^sample_', r'^test_', r'^demo_',
        r'^placeholder_', r'^dummy_', r'^mock_',
        r'^default_', r'^template_'
    ],
    'safe_values': [
        r'^["\']?$',  # 空字符串
        r'^["\']?["\']?$',  # 空字符串
        r'^["\']?None["\']?$',  # None值
        r'^["\']?CHANGE_ME["\']?$',  # 明显的占位符
        r'^["\']?YOUR_.*HERE["\']?$',  # 你的XXX在这里
        r'^["\']?SET_.*HERE["\']?$',  # 设置XXX在这里
        r'^["\']?REPLACE_.*["\']?$',  # 替换XXX
        r'^["\']?TODO.*["\']?$',  # TODO注释
        r'^["\']?FIXME.*["\']?$',  # FIXME注释
    ]
}


def detect_hardcoded_passwords(code, language='python'):
    """
    检测Python代码中硬编码密码漏洞

    Args:
        code: Python源代码字符串
        language: 语言类型，默认为'python'

    Returns:
        list: 检测结果列表
    """
    if language not in LANGUAGES:
        return []

    # 初始化解析器
    parser = Parser()
    parser.set_language(LANGUAGES[language])

    # 解析代码
    tree = parser.parse(bytes(code, 'utf8'))
    root = tree.root_node

    vulnerabilities = []

    # 检测各种类型的硬编码密码
    for query_info in HARDCODED_PASSWORD_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['var_name', 'key_name', 'kw_name', 'attr_name', 'func_name', 'module']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['password_value', 'encoded_value']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['assignment', 'dict_pair', 'kw_arg', 'call', 'attr_assignment',
                             'class_def'] and current_capture:
                    # 检查是否匹配密码模式
                    if is_password_related(current_capture, query_info):
                        vulnerability_details = analyze_password_vulnerability(current_capture, query_info)
                        if vulnerability_details:
                            vulnerabilities.append(vulnerability_details)

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_password_related(capture, query_info):
    """
    检查捕获的内容是否与密码相关
    """
    risk_type = query_info.get('risk_type', '')

    if risk_type == 'variable_assignment':
        var_name = capture.get('var_name', '')
        password_value = capture.get('password_value', '')
        return (is_password_variable(var_name) and
                not is_safe_configuration(var_name, password_value))

    elif risk_type == 'dict_pair':
        key_name = capture.get('key_name', '')
        password_value = capture.get('password_value', '')
        return (is_password_key(key_name) and
                not is_safe_configuration(key_name, password_value))

    elif risk_type == 'function_argument':
        kw_name = capture.get('kw_name', '')
        password_value = capture.get('password_value', '')
        return (is_password_function_arg(kw_name) and
                not is_safe_configuration(kw_name, password_value))

    elif risk_type == 'class_attribute':
        attr_name = capture.get('attr_name', '')
        password_value = capture.get('password_value', '')
        return (is_password_variable(attr_name) and
                not is_safe_configuration(attr_name, password_value))

    elif risk_type == 'base64_encoded':
        # 对于Base64编码，需要解码后检查
        encoded_value = capture.get('encoded_value', '')
        if encoded_value:
            try:
                # 移除引号并解码
                clean_value = encoded_value.strip('"\'')
                decoded_value = base64.b64decode(clean_value).decode('utf-8', errors='ignore')
                return is_suspicious_password(decoded_value)
            except:
                pass
        return False

    return False


def is_password_variable(var_name):
    """
    检查变量名是否与密码相关
    """
    var_text = var_name.lower()

    for pattern in PASSWORD_KEYWORDS['variable_patterns']:
        if re.match(pattern, var_text, re.IGNORECASE):
            return True

    return False


def is_password_key(key_name):
    """
    检查字典键是否与密码相关
    """
    key_text = key_name.lower().strip('"\'')

    for pattern in PASSWORD_KEYWORDS['key_patterns']:
        if re.match(pattern, key_text, re.IGNORECASE):
            return True

    return False


def is_password_function_arg(arg_name):
    """
    检查函数参数名是否与密码相关
    """
    arg_text = arg_name.lower()

    for pattern in PASSWORD_KEYWORDS['function_patterns']:
        if re.match(pattern, arg_text, re.IGNORECASE):
            return True

    return False


def is_suspicious_password(password_value):
    """
    检查密码值是否可疑
    """
    if not password_value:
        return False

    # 清理引号
    clean_value = password_value.strip('"\'')

    # 检查弱密码模式
    for pattern in PASSWORD_STRENGTH_PATTERNS['weak_patterns']:
        if re.match(pattern, clean_value, re.IGNORECASE):
            return True

    # 检查可疑模式
    for pattern in PASSWORD_STRENGTH_PATTERNS['suspicious_patterns']:
        if re.match(pattern, clean_value, re.IGNORECASE):
            return True

    return False


def is_safe_configuration(name, value):
    """
    检查是否是安全配置（白名单）
    """
    name_text = name.lower().strip('"\'')
    value_text = value.lower().strip('"\'')

    # 检查安全变量名
    for pattern in SAFE_CONFIGURATIONS['safe_variables']:
        if re.match(pattern, name_text, re.IGNORECASE):
            return True

    # 检查安全值
    for pattern in SAFE_CONFIGURATIONS['safe_values']:
        if re.match(pattern, value_text, re.IGNORECASE):
            return True

    return False


def analyze_password_vulnerability(capture, query_info):
    """
    分析密码漏洞详情
    """
    risk_type = query_info.get('risk_type', '')
    line = capture.get('line', 0)
    code_snippet = capture.get(f'{list(capture.keys())[-1]}_node', None)

    if code_snippet:
        code_text = code_snippet.text.decode('utf8')
    else:
        code_text = "无法获取代码片段"

    vulnerability_details = {
        'line': line,
        'code_snippet': code_text,
        'vulnerability_type': '硬编码密码',
        'severity': query_info.get('severity', '高危'),
        'risk_type': risk_type
    }

    # 根据风险类型设置具体消息
    if risk_type == 'variable_assignment':
        var_name = capture.get('var_name', '')
        password_value = capture.get('password_value', '')
        vulnerability_details['message'] = (
            f"变量 '{var_name}' 包含硬编码密码: {mask_password(password_value)}"
        )

    elif risk_type == 'dict_pair':
        key_name = capture.get('key_name', '')
        password_value = capture.get('password_value', '')
        vulnerability_details['message'] = (
            f"字典键 '{key_name}' 包含硬编码密码: {mask_password(password_value)}"
        )

    elif risk_type == 'function_argument':
        kw_name = capture.get('kw_name', '')
        password_value = capture.get('password_value', '')
        vulnerability_details['message'] = (
            f"函数参数 '{kw_name}' 包含硬编码密码: {mask_password(password_value)}"
        )

    elif risk_type == 'class_attribute':
        attr_name = capture.get('attr_name', '')
        password_value = capture.get('password_value', '')
        vulnerability_details['message'] = (
            f"类属性 '{attr_name}' 包含硬编码密码: {mask_password(password_value)}"
        )

    elif risk_type == 'base64_encoded':
        encoded_value = capture.get('encoded_value', '')
        try:
            clean_value = encoded_value.strip('"\'')
            decoded_value = base64.b64decode(clean_value).decode('utf-8', errors='ignore')
            vulnerability_details['message'] = (
                f"Base64编码的硬编码密码: {mask_password(decoded_value)} (编码值: {mask_password(encoded_value)})"
            )
        except:
            vulnerability_details['message'] = (
                f"Base64编码的潜在密码: {mask_password(encoded_value)}"
            )

    # 检查密码强度
    password_value = capture.get('password_value', '') or capture.get('encoded_value', '')
    if password_value and is_weak_password(password_value):
        vulnerability_details['message'] += " - 弱密码"
        vulnerability_details['severity'] = '严重'

    return vulnerability_details


def mask_password(password, visible_chars=2):
    """
    掩码密码，只显示前几个字符
    """
    if not password:
        return "***"

    clean_password = password.strip('"\'')
    if len(clean_password) <= visible_chars:
        return "***"

    return clean_password[:visible_chars] + '*' * (len(clean_password) - visible_chars)


def is_weak_password(password_value):
    """
    检查是否是弱密码
    """
    clean_value = password_value.strip('"\'')

    # 检查常见弱密码
    for pattern in PASSWORD_STRENGTH_PATTERNS['weak_patterns']:
        if re.match(pattern, clean_value, re.IGNORECASE):
            return True

    # 检查长度
    if len(clean_value) < 8:
        return True

    # 检查复杂性
    if (not re.search(r'[A-Z]', clean_value) or  # 没有大写字母
            not re.search(r'[a-z]', clean_value) or  # 没有小写字母
            not re.search(r'\d', clean_value) or  # 没有数字
            not re.search(r'[!@#$%^&*(),.?":{}|<>]', clean_value)):  # 没有特殊字符
        return True

    return False


def analyze_python_hardcoded_passwords(code_string):
    """
    分析Python代码字符串中的硬编码密码漏洞
    """
    return detect_hardcoded_passwords(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = '''
import base64

# 硬编码密码示例
def vulnerable_examples():
    # 1. 变量赋值中的密码
    password = "123456"
    db_password = "mysecretpassword123"
    api_key = "sk-1234567890abcdef"

    # 2. 字典中的密码
    config = {
        "username": "admin",
        "password": "admin123",
        "api_secret": "secret_key_here"
    }

    # 3. 函数参数中的密码
    connect_to_database(
        host="localhost",
        user="root", 
        password="root_password",
        database="mydb"
    )

    # 4. 类属性中的密码
    class DatabaseConfig:
        db_host = "localhost"
        db_user = "admin"
        db_pass = "P@ssw0rd!"
        encryption_key = "my_encryption_key_123"

    # 5. Base64编码的密码
    encoded_password = base64.b64encode(b"mysecretpassword").decode()
    decoded_password = base64.b64decode("bXlzZWNyZXRwYXNzd29yZA==")

    # 6. 弱密码示例
    weak_pass = "password"
    short_pass = "123"
    simple_pass = "abc123"

def safe_examples():
    # 安全示例 - 从环境变量获取
    import os
    db_password = os.getenv("DB_PASSWORD")
    api_key = os.environ.get("API_KEY")

    # 安全示例 - 配置文件
    from configparser import ConfigParser
    config = ConfigParser()
    config.read('config.ini')
    password = config.get('database', 'password')

    # 安全示例 - 空密码或占位符
    example_password = ""
    placeholder_password = "CHANGE_ME"
    template_password = "YOUR_PASSWORD_HERE"

    # 安全示例 - 测试配置
    test_password = "test_password"
    demo_api_key = "demo_key_123"

def connect_to_database(host, user, password, database):
    # 数据库连接逻辑
    pass

# 真实世界示例
class AWSConfig:
    aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
    aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

class DatabaseConnection:
    def __init__(self):
        self.connection_string = "postgresql://user:password@localhost/db"
        self.redis_password = "redis123"

class APIClient:
    def __init__(self):
        self.api_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        self.oauth_secret = "client_secret_here"

if __name__ == "__main__":
    vulnerable_examples()
    safe_examples()
'''

    print("=" * 70)
    print("Python硬编码密码漏洞检测")
    print("=" * 70)

    results = analyze_python_hardcoded_passwords(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个硬编码密码:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   风险类型: {vuln['risk_type']}")
            print(f"   严重程度: {vuln['severity']}")
            print("-" * 50)
    else:
        print("未检测到硬编码密码")