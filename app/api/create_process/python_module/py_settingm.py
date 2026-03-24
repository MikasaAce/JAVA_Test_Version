import os
import re
import sys
from tree_sitter import Language, Parser

# 假设已经配置了Python语言路径
from .config_path import language_path

# 加载Python语言
LANGUAGES = {
    'python': Language(language_path, 'python'),
}

# 定义设置操纵漏洞模式
CONFIG_MANIPULATION_VULNERABILITIES = {
    'python': [
        # 检测环境变量操作
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @os_module
                        attribute: (identifier) @env_method
                    )
                    arguments: (argument_list 
                        (_) @env_var
                        (_)? @env_value
                    )
                ) @call
            ''',
            'module_pattern': r'^os$',
            'method_pattern': r'^(putenv|setenv|unsetenv)$',
            'message': '环境变量修改操作'
        },
        # 检测os.environ直接赋值
        {
            'query': '''
                (assignment
                    left: (attribute
                        object: (attribute
                            object: (identifier) @os_module
                            attribute: (identifier) @environ_attr
                        )
                        attribute: (identifier) @env_key
                    )
                    right: (_) @env_value
                ) @assignment
            ''',
            'os_pattern': r'^os$',
            'environ_pattern': r'^environ$',
            'message': 'os.environ直接赋值'
        },
        # 检测配置字典修改
        {
            'query': '''
                (assignment
                    left: (subscript
                        object: (identifier) @config_dict
                        index: (_) @config_key
                    )
                    right: (_) @config_value
                ) @assignment
            ''',
            'dict_pattern': r'^(config|settings|app\.config|conf|cfg|CONFIG)$',
            'message': '配置字典修改'
        },
        # 检测配置对象属性修改
        {
            'query': '''
                (assignment
                    left: (attribute
                        object: (identifier) @config_obj
                        attribute: (identifier) @config_attr
                    )
                    right: (_) @config_value
                ) @assignment
            ''',
            'obj_pattern': r'^(config|settings|app|current_app|app_config)$',
            'attr_pattern': r'^[A-Z_][A-Z_0-9]*$',
            'message': '配置对象属性修改'
        },
        # 检测动态导入配置
        {
            'query': '''
                (call
                    function: (identifier) @import_func
                    arguments: (argument_list 
                        (_) @module_name
                    )
                ) @call
            ''',
            'func_pattern': r'^(__import__|import_module|exec|eval)$',
            'message': '动态导入配置模块'
        },
        # 检测配置文件加载
        {
            'query': '''
                (call
                    function: (attribute
                        object: (_) @file_obj
                        attribute: (identifier) @read_method
                    )
                    arguments: (argument_list) @args
                ) @call
            ''',
            'method_pattern': r'^(read|load|loads|safe_load|parse)$',
            'message': '配置文件加载操作'
        },
        # 检测不安全的配置反序列化
        {
            'query': '''
                (call
                    function: (identifier) @deserialize_func
                    arguments: (argument_list 
                        (_) @config_data
                    )
                ) @call
            ''',
            'func_pattern': r'^(pickle\.load|pickle\.loads|marshal\.load|marshal\.loads|yaml\.load)$',
            'message': '不安全的配置反序列化'
        },
        # 检测配置更新操作
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @config_obj
                        attribute: (identifier) @update_method
                    )
                    arguments: (argument_list 
                        (_) @update_data
                    )
                ) @call
            ''',
            'method_pattern': r'^(update|from_dict|from_json|from_yaml|from_pyfile)$',
            'message': '配置更新操作'
        },
        # 检测命令行参数解析
        {
            'query': '''
                (call
                    function: (identifier) @argparse_func
                    arguments: (argument_list 
                        (_)* @argparse_args
                    )
                ) @call
            ''',
            'func_pattern': r'^(ArgumentParser|parse_args|add_argument)$',
            'message': '命令行参数解析'
        },
        # 检测用户输入的配置设置
        {
            'query': '''
                (call
                    function: (attribute
                        object: (identifier) @config_obj
                        attribute: (identifier) @set_method
                    )
                    arguments: (argument_list 
                        (_) @config_key
                        (_) @config_value
                    )
                ) @call
            ''',
            'method_pattern': r'^(set|__setitem__|setdefault)$',
            'message': '配置设置方法调用'
        }
    ]
}

# 用户输入源模式（设置操纵相关）
CONFIG_USER_INPUT_SOURCES = {
    'query': '''
        [
            (call
                function: (identifier) @func_name
                arguments: (argument_list) @args
            )
            (call
                function: (attribute
                    object: (_) @obj
                    attribute: (identifier) @attr
                )
                arguments: (argument_list) @args
            )
        ] @call
    ''',
    'patterns': [
        {
            'func_pattern': r'^(input|raw_input)$',
            'message': '标准输入'
        },
        {
            'obj_pattern': r'^(flask|django|bottle)\.request$',
            'attr_pattern': r'^(args|form|values|data|json|files|get|post|cookies|headers)$',
            'message': 'Web请求参数'
        },
        {
            'obj_pattern': r'^request$',
            'attr_pattern': r'^(args|form|values|data|json|files|get|post|cookies|headers)$',
            'message': '请求对象参数'
        },
        {
            'obj_pattern': r'^(sys)$',
            'attr_pattern': r'^(argv)$',
            'message': '命令行参数'
        },
        {
            'obj_pattern': r'^os\.environ$',
            'attr_pattern': r'^(get|__getitem__)$',
            'message': '环境变量获取'
        },
        {
            'obj_pattern': r'^(argparse|parser)$',
            'attr_pattern': r'^(parse_args)$',
            'message': '命令行解析'
        }
    ]
}

# 敏感配置项模式
SENSITIVE_CONFIG_PATTERNS = {
    'security_settings': [
        'SECRET_KEY',
        'SECRET',
        'PASSWORD',
        'PWD',
        'API_KEY',
        'TOKEN',
        'AUTH',
        'CREDENTIAL',
        'PRIVATE_KEY',
        'PRIVATE',
        'ENCRYPTION_KEY',
        'SALT',
        'JWT_SECRET',
        'SESSION_KEY',
        'DATABASE_URL',
        'DB_PASSWORD',
        'REDIS_PASSWORD',
        'AWS_SECRET',
        'STRIPE_SECRET',
        'STRIPE_KEY',
        'PAYPAL_SECRET',
        'GITHUB_TOKEN',
        'SLACK_TOKEN',
        'DISCORD_TOKEN'
    ],
    'dangerous_settings': [
        'DEBUG',
        'TESTING',
        'DEVELOPMENT',
        'ENV',
        'ENVIRONMENT',
        'ALLOWED_HOSTS',
        'CORS_ORIGIN',
        'CSRF_ENABLED',
        'CSRF_SECRET',
        'WTF_CSRF_SECRET_KEY',
        'SESSION_COOKIE_SECURE',
        'SESSION_COOKIE_HTTPONLY',
        'PERMANENT_SESSION_LIFETIME',
        'MAX_CONTENT_LENGTH',
        'UPLOAD_FOLDER',
        'SQLALCHEMY_DATABASE_URI',
        'CELERY_BROKER_URL',
        'CACHE_REDIS_URL',
        'MAIL_PASSWORD',
        'SENTRY_DSN'
    ],
    'system_settings': [
        'PATH',
        'PYTHONPATH',
        'LD_LIBRARY_PATH',
        'HOME',
        'USER',
        'TMPDIR',
        'TEMP',
        'TMP'
    ]
}

# 配置验证模式
CONFIG_VALIDATION_PATTERNS = {
    'query': '''
        [
            (if_statement
                condition: (_) @condition
                consequence: (block) @consequence
            )
            (assert_statement
                argument: (_) @assert_condition
            )
            (call
                function: (identifier) @validation_func
                arguments: (argument_list (_)* @validation_args)
            )
        ] @validation
    ''',
    'patterns': [
        {
            'func_pattern': r'^(validate|check|verify|assert|ensure|sanitize)$',
            'message': '配置验证函数'
        },
        {
            'condition_pattern': r'(isinstance|type|in|not in|==|!=|startswith|endswith|isdigit|isalpha)',
            'message': '配置验证条件'
        }
    ]
}

def analyze_config_manipulation(code, language='python'):
    """
    检测Python代码中设置操纵漏洞

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
    config_operations = []  # 存储配置操作
    user_input_sources = []  # 存储用户输入源
    validation_operations = []  # 存储验证操作

    # 第一步：收集所有配置操作
    for query_info in CONFIG_MANIPULATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['env_method', 'os_module', 'environ_attr', 'env_key', 
                          'config_dict', 'config_obj', 'config_attr', 'import_func',
                          'read_method', 'deserialize_func', 'update_method', 
                          'argparse_func', 'set_method']:
                    name = node.text.decode('utf8')
                    current_capture[tag] = name
                    current_capture['node'] = node.parent
                    current_capture['line'] = node.start_point[0] + 1

                elif tag in ['env_var', 'env_value', 'config_key', 'config_value', 
                           'module_name', 'config_data', 'update_data']:
                    current_capture[tag] = node.text.decode('utf8')
                    current_capture[f'{tag}_node'] = node

                elif tag in ['call', 'assignment'] and current_capture:
                    # 检查是否匹配配置操作模式
                    module_pattern = query_info.get('module_pattern', '')
                    method_pattern = query_info.get('method_pattern', '')
                    os_pattern = query_info.get('os_pattern', '')
                    environ_pattern = query_info.get('environ_pattern', '')
                    dict_pattern = query_info.get('dict_pattern', '')
                    obj_pattern = query_info.get('obj_pattern', '')
                    attr_pattern = query_info.get('attr_pattern', '')
                    func_pattern = query_info.get('func_pattern', '')

                    module_match = True
                    method_match = True
                    os_match = True
                    environ_match = True
                    dict_match = True
                    obj_match = True
                    attr_match = True
                    func_match = True

                    if module_pattern and 'os_module' in current_capture:
                        module_match = re.match(module_pattern, current_capture['os_module'], re.IGNORECASE)

                    if method_pattern and 'env_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['env_method'], re.IGNORECASE)
                    elif method_pattern and 'read_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['read_method'], re.IGNORECASE)
                    elif method_pattern and 'update_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['update_method'], re.IGNORECASE)
                    elif method_pattern and 'set_method' in current_capture:
                        method_match = re.match(method_pattern, current_capture['set_method'], re.IGNORECASE)

                    if os_pattern and 'os_module' in current_capture:
                        os_match = re.match(os_pattern, current_capture['os_module'], re.IGNORECASE)

                    if environ_pattern and 'environ_attr' in current_capture:
                        environ_match = re.match(environ_pattern, current_capture['environ_attr'], re.IGNORECASE)

                    if dict_pattern and 'config_dict' in current_capture:
                        dict_match = re.match(dict_pattern, current_capture['config_dict'], re.IGNORECASE)

                    if obj_pattern and 'config_obj' in current_capture:
                        obj_match = re.match(obj_pattern, current_capture['config_obj'], re.IGNORECASE)

                    if attr_pattern and 'config_attr' in current_capture:
                        attr_match = re.match(attr_pattern, current_capture['config_attr'], re.IGNORECASE)

                    if func_pattern and 'import_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['import_func'], re.IGNORECASE)
                    elif func_pattern and 'deserialize_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['deserialize_func'], re.IGNORECASE)
                    elif func_pattern and 'argparse_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['argparse_func'], re.IGNORECASE)

                    if (module_match and method_match and os_match and environ_match and 
                        dict_match and obj_match and attr_match and func_match):
                        code_snippet = node.text.decode('utf8')

                        config_operations.append({
                            'type': 'config_operation',
                            'line': current_capture['line'],
                            'operation': current_capture.get('env_method', '') or 
                                       current_capture.get('import_func', '') or
                                       current_capture.get('read_method', '') or
                                       current_capture.get('deserialize_func', '') or
                                       current_capture.get('update_method', '') or
                                       current_capture.get('argparse_func', '') or
                                       current_capture.get('set_method', '') or 'assignment',
                            'config_key': current_capture.get('env_key', '') or 
                                        current_capture.get('config_key', '') or
                                        current_capture.get('env_var', '') or
                                        current_capture.get('config_attr', ''),
                            'config_value': current_capture.get('env_value', '') or 
                                          current_capture.get('config_value', '') or
                                          current_capture.get('module_name', '') or
                                          current_capture.get('config_data', '') or
                                          current_capture.get('update_data', ''),
                            'code_snippet': code_snippet,
                            'node': node,
                            'vulnerability_type': query_info.get('message', '设置操纵风险')
                        })
                    current_capture = {}

        except Exception as e:
            print(f"设置操纵查询错误 {query_info.get('message')}: {e}")
            continue

    # 第二步：收集用户输入源
    try:
        query = LANGUAGES[language].query(CONFIG_USER_INPUT_SOURCES['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['func_name', 'obj', 'attr']:
                name = node.text.decode('utf8')
                current_capture[tag] = name
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag == 'call' and current_capture:
                # 检查是否匹配用户输入模式
                for pattern_info in CONFIG_USER_INPUT_SOURCES['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    obj_pattern = pattern_info.get('obj_pattern', '')
                    attr_pattern = pattern_info.get('attr_pattern', '')

                    match = False
                    if func_pattern and 'func_name' in current_capture:
                        if re.match(func_pattern, current_capture['func_name'], re.IGNORECASE):
                            match = True
                    elif obj_pattern and attr_pattern and 'obj' in current_capture and 'attr' in current_capture:
                        if (re.match(obj_pattern, current_capture['obj'], re.IGNORECASE) and
                                re.match(attr_pattern, current_capture['attr'], re.IGNORECASE)):
                            match = True

                    if match:
                        code_snippet = node.text.decode('utf8')
                        user_input_sources.append({
                            'type': 'user_input',
                            'line': current_capture['line'],
                            'function': current_capture.get('func_name', ''),
                            'object': current_capture.get('obj', ''),
                            'attribute': current_capture.get('attr', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"用户输入源查询错误: {e}")

    # 第三步：收集验证操作
    try:
        query = LANGUAGES[language].query(CONFIG_VALIDATION_PATTERNS['query'])
        captures = query.captures(root)

        current_capture = {}
        for node, tag in captures:
            if tag in ['validation_func']:
                current_capture[tag] = node.text.decode('utf8')
                current_capture['node'] = node.parent
                current_capture['line'] = node.start_point[0] + 1

            elif tag in ['condition', 'assert_condition']:
                current_capture[tag] = node.text.decode('utf8')

            elif tag == 'validation' and current_capture:
                # 检查是否匹配验证模式
                for pattern_info in CONFIG_VALIDATION_PATTERNS['patterns']:
                    func_pattern = pattern_info.get('func_pattern', '')
                    condition_pattern = pattern_info.get('condition_pattern', '')

                    func_match = False
                    condition_match = False

                    if func_pattern and 'validation_func' in current_capture:
                        func_match = re.match(func_pattern, current_capture['validation_func'], re.IGNORECASE)

                    if condition_pattern and ('condition' in current_capture or 'assert_condition' in current_capture):
                        condition_text = current_capture.get('condition', '') or current_capture.get('assert_condition', '')
                        condition_match = re.search(condition_pattern, condition_text, re.IGNORECASE)

                    if func_match or condition_match:
                        code_snippet = node.text.decode('utf8')
                        validation_operations.append({
                            'type': 'validation',
                            'line': current_capture['line'],
                            'function': current_capture.get('validation_func', ''),
                            'condition': current_capture.get('condition', '') or current_capture.get('assert_condition', ''),
                            'code_snippet': code_snippet,
                            'node': node
                        })
                        break

                current_capture = {}

    except Exception as e:
        print(f"验证操作查询错误: {e}")

    # 第四步：分析设置操纵漏洞
    for config_op in config_operations:
        vulnerability_details = analyze_config_operation(config_op, user_input_sources, validation_operations)
        if vulnerability_details:
            vulnerabilities.extend(vulnerability_details)

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_config_operation(config_op, user_input_sources, validation_operations):
    """
    分析单个配置操作的安全问题
    """
    vulnerabilities = []
    code_snippet = config_op['code_snippet']
    line = config_op['line']
    operation = config_op['operation']
    config_key = config_op['config_key']
    config_value = config_op['config_value']

    # 检查直接用户输入
    if is_direct_user_input(config_op, user_input_sources):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '设置操纵',
            'severity': '高危',
            'message': f"{operation} 操作直接使用用户输入作为配置值"
        })

    # 检查敏感配置项
    elif is_sensitive_config(config_key):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '设置操纵',
            'severity': '严重',
            'message': f"{operation} 操作修改敏感配置项: {config_key}"
        })

    # 检查不安全的反序列化
    elif is_unsafe_deserialization(config_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '设置操纵',
            'severity': '高危',
            'message': f"{operation} 使用不安全的反序列化方法"
        })

    # 检查动态导入
    elif is_dynamic_import(config_op):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '设置操纵',
            'severity': '高危',
            'message': f"{operation} 使用动态导入可能加载恶意模块"
        })

    # 检查配置验证缺失
    elif not has_config_validation(config_op, validation_operations):
        vulnerabilities.append({
            'line': line,
            'code_snippet': code_snippet,
            'vulnerability_type': '设置操纵',
            'severity': '中危',
            'message': f"{operation} 操作缺少配置验证逻辑"
        })

    return vulnerabilities


def is_direct_user_input(config_op, user_input_sources):
    """
    检查配置值是否直接来自用户输入
    """
    config_value = config_op['config_value']
    
    # 检查常见的用户输入变量名
    user_input_vars = ['input', 'user_input', 'request', 'args', 'form', 'get', 
                      'post', 'data', 'json', 'files', 'argv', 'environ']
    for var in user_input_vars:
        if re.search(rf'\b{var}\b', config_value, re.IGNORECASE):
            return True

    # 检查是否匹配已知的用户输入源
    for source in user_input_sources:
        if source['node'] == config_op['node'] or is_child_node(config_op['node'], source['node']):
            return True

    return False


def is_sensitive_config(config_key):
    """
    检查配置项是否为敏感配置
    """
    if not config_key:
        return False
        
    config_key_str = str(config_key).strip('"\'').upper()
    
    # 检查安全设置
    for setting in SENSITIVE_CONFIG_PATTERNS['security_settings']:
        if setting in config_key_str:
            return True
            
    # 检查危险设置
    for setting in SENSITIVE_CONFIG_PATTERNS['dangerous_settings']:
        if setting in config_key_str:
            return True
            
    # 检查系统设置
    for setting in SENSITIVE_CONFIG_PATTERNS['system_settings']:
        if setting in config_key_str:
            return True
            
    return False


def is_unsafe_deserialization(config_op):
    """
    检查是否使用不安全的反序列化
    """
    operation = config_op['operation']
    return any(unsafe_method in operation for unsafe_method in 
              ['pickle.load', 'pickle.loads', 'marshal.load', 'marshal.loads', 'yaml.load'])


def is_dynamic_import(config_op):
    """
    检查是否使用动态导入
    """
    operation = config_op['operation']
    return any(dynamic_import in operation for dynamic_import in 
              ['__import__', 'import_module', 'exec', 'eval'])


def has_config_validation(config_op, validation_operations):
    """
    检查配置操作是否有验证逻辑
    """
    config_line = config_op['line']
    
    # 检查同一行或附近行是否有验证
    for validation in validation_operations:
        validation_line = validation['line']
        # 如果验证在配置操作之前或同一行
        if validation_line <= config_line:
            return True
            
    return False


def is_child_node(child, parent):
    """
    检查一个节点是否是另一个节点的子节点
    """
    node = child
    while node:
        if node == parent:
            return True
        node = node.parent
    return False


def analyze_config_manipulation_main(code_string):
    """
    主函数：分析Python代码字符串中的设置操纵漏洞
    """
    return analyze_config_manipulation(code_string, 'python')


# 示例使用
if __name__ == "__main__":
    # 测试Python代码
    test_python_code = """
import os
import pickle
import yaml
import importlib
from flask import Flask, request
import argparse

app = Flask(__name__)

# 不安全的设置操纵示例
def insecure_config_examples():
    # 环境变量操纵 - 高危
    user_env_var = request.args.get('env_var')
    user_env_value = request.args.get('env_value')
    os.putenv(user_env_var, user_env_value)  # 高危
    
    # os.environ直接赋值 - 高危
    os.environ[user_env_var] = user_env_value  # 高危
    
    # 配置字典修改 - 高危
    config_key = request.form.get('config_key')
    config_value = request.form.get('config_value')
    app.config[config_key] = config_value  # 高危
    
    # 配置对象属性修改 - 高危
    attr_name = request.json.get('attribute')
    attr_value = request.json.get('value')
    setattr(app.config, attr_name, attr_value)  # 高危
    
    # 动态导入 - 高危
    module_name = request.args.get('module')
    imported_module = __import__(module_name)  # 高危
    
    # 不安全的反序列化 - 严重
    user_data = request.files['config'].read()
    config_obj = pickle.loads(user_data)  # 严重
    
    # 不安全的YAML加载 - 高危
    yaml_config = request.form.get('yaml_config')
    config = yaml.load(yaml_config)  # 高危
    
    # 配置更新操作 - 高危
    update_data = request.get_json()
    app.config.update(update_data)  # 高危

# 相对安全的配置操作示例
def safe_config_examples():
    # 硬编码配置 - 安全
    os.putenv('DEBUG', 'False')  # 安全
    app.config['SECRET_KEY'] = 'hardcoded-secret'  # 安全
    
    # 经过验证的环境变量设置 - 安全
    allowed_env_vars = ['PATH', 'HOME', 'TEMP']
    env_var = request.args.get('env_var')
    if env_var in allowed_env_vars:
        os.putenv(env_var, 'safe_value')  # 安全
    
    # 安全的配置更新 - 安全
    safe_updates = {
        'DEBUG': False,
        'TESTING': True
    }
    app.config.update(safe_updates)  # 安全
    
    # 安全的反序列化 - 安全
    yaml_config = request.form.get('yaml_config')
    if validate_yaml(yaml_config):
        config = yaml.safe_load(yaml_config)  # 安全
    
    # 安全的动态导入 - 相对安全
    allowed_modules = ['math', 'json', 'datetime']
    module_name = request.args.get('module')
    if module_name in allowed_modules:
        imported_module = importlib.import_module(module_name)  # 相对安全

# 命令行配置示例
def command_line_config_examples():
    # 不安全的命令行解析
    parser = argparse.ArgumentParser()
    parser.add_argument('--config-file')  # 可能不安全
    args = parser.parse_args()
    
    if args.config_file:
        with open(args.config_file, 'r') as f:
            config = yaml.load(f)  # 高危
    
    # 安全的命令行解析
    safe_parser = argparse.ArgumentParser()
    safe_parser.add_argument('--debug', action='store_true')  # 安全
    safe_args = safe_parser.parse_args()
    
    if safe_args.debug:
        app.config['DEBUG'] = True  # 安全

# 配置验证函数
def validate_config_key(key):
    \"\"\"验证配置键是否安全\"\"\"
    allowed_keys = ['DEBUG', 'TESTING', 'HOST', 'PORT']
    return key in allowed_keys

def validate_yaml(yaml_content):
    \"\"\"验证YAML内容是否安全\"\"\"
    # 简单的安全检查
    dangerous_patterns = ['!!python', '__import__', 'os.system']
    for pattern in dangerous_patterns:
        if pattern in yaml_content:
            return False
    return True

# 混合示例
def mixed_examples():
    # 部分验证
    config_key = request.args.get('key')
    if config_key:  # 验证不充分
        app.config[config_key] = 'value'  # 高危
    
    # 使用安全函数
    user_key = request.form.get('key')
    if validate_config_key(user_key):
        app.config[user_key] = request.form.get('value')  # 相对安全
    
    # 直接修改敏感配置
    user_debug = request.args.get('debug')
    if user_debug == 'true':
        app.config['DEBUG'] = True  # 中危: 允许用户开启调试模式

# Flask配置示例
def flask_config_examples():
    # 从文件加载配置
    config_file = request.args.get('config_file', 'config.py')
    app.config.from_pyfile(config_file)  # 高危: 用户控制文件路径
    
    # 从对象加载配置
    config_class = request.args.get('config_class')
    if config_class:
        # 动态类加载 - 高危
        config_obj = __import__(f'config.{config_class}')
        app.config.from_object(config_obj)  # 高危
    
    # 从环境变量加载配置
    app.config.from_envvar('APP_CONFIG_FILE')  # 相对安全

if __name__ == "__main__":
    insecure_config_examples()
    safe_config_examples()
    command_line_config_examples()
    mixed_examples()
    flask_config_examples()
"""

    print("=" * 60)
    print("Python 设置操纵漏洞检测")
    print("=" * 60)

    results = analyze_config_manipulation_main(test_python_code)

    if results:
        print(f"检测到 {len(results)} 个设置操纵漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到设置操纵漏洞")