import os
import re
from tree_sitter import Language, Parser

from .config_path import language_path

# 加载JavaScript语言
LANGUAGES = {
    'javascript': Language(language_path, 'javascript'),
}

# 定义路径操纵漏洞模式
PATH_MANIPULATION_VULNERABILITIES = {
    'javascript': [
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (string) @path_arg)
                ) @call
            ''',
            'pattern': r'^(fs|path|child_process|exec|spawn)$',
            'property_pattern': r'^(readFile|writeFile|appendFile|exists|existsSync|readFileSync|writeFileSync|appendFileSync|exec|execSync|spawn|spawnSync)$',
            'message': '文件系统操作中使用字符串路径参数'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (string) @path_arg)
                ) @call
            ''',
            'pattern': r'^(require|import|fs\.|path\.|readFile|writeFile|appendFile|exists|exec|spawn)$',
            'message': '函数调用中使用字符串路径参数'
        },
        {
            'query': '''
                (call_expression
                    function: (member_expression
                        object: (identifier) @object
                        property: (property_identifier) @property
                    )
                    arguments: (arguments (template_string) @path_arg)
                ) @call
            ''',
            'pattern': r'^(fs|path|child_process|exec|spawn)$',
            'property_pattern': r'^(readFile|writeFile|appendFile|exists|existsSync|readFileSync|writeFileSync|appendFileSync|exec|execSync|spawn|spawnSync)$',
            'message': '文件系统操作中使用模板字符串路径参数'
        },
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (arguments (template_string) @path_arg)
                ) @call
            ''',
            'pattern': r'^(require|import|fs\.|path\.|readFile|writeFile|appendFile|exists|exec|spawn)$',
            'message': '函数调用中使用模板字符串路径参数'
        },
        {
            'query': '''
                (binary_expression
                    left: (_) @left
                    operator: "+"
                    right: (identifier) @right
                ) @binary
            ''',
            'message': '路径拼接操作使用字符串连接'
        },
        {
            'query': '''
                (binary_expression
                    left: (identifier) @left
                    operator: "+"
                    right: (_) @right
                ) @binary
            ''',
            'message': '路径拼接操作使用字符串连接'
        }
    ]
}


def detect_js_path_manipulation_vulnerabilities(code, language='javascript'):
    """
    检测JavaScript代码中路径操纵漏洞

    Args:
        code: JavaScript源代码字符串
        language: 语言类型，默认为'javascript'

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

    # 检测所有路径操作模式
    for query_info in PATH_MANIPULATION_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(query_info['query'])
            captures = query.captures(root)

            current_capture = {}
            for node, tag in captures:
                if tag in ['object', 'func_name', 'left', 'right']:
                    obj_name = node.text.decode('utf8')
                    pattern = query_info.get('pattern', '')
                    if not pattern or re.match(pattern, obj_name, re.IGNORECASE):
                        current_capture[tag] = {
                            'name': obj_name,
                            'node': node,
                            'line': node.start_point[0] + 1
                        }

                elif tag == 'property':
                    prop_name = node.text.decode('utf8')
                    prop_pattern = query_info.get('property_pattern', '')
                    if not prop_pattern or re.match(prop_pattern, prop_name, re.IGNORECASE):
                        current_capture[tag] = {
                            'name': prop_name,
                            'node': node,
                            'line': node.start_point[0] + 1
                        }

                elif tag in ['path_arg', 'call', 'binary'] and current_capture:
                    # 获取完整的代码片段
                    code_snippet = node.text.decode('utf8')

                    # 检查路径参数是否包含用户输入模式
                    if tag == 'path_arg':
                        path_value = code_snippet.strip('"\'`')
                        if is_potentially_unsafe_path(path_value):
                            vulnerabilities.append({
                                'line': node.start_point[0] + 1,
                                'message': f'路径操纵漏洞: {query_info["message"]}',
                                'code_snippet': code_snippet,
                                'vulnerability_type': '路径操纵',
                                'severity': '高危'
                            })

                    # 对于字符串连接操作，检查是否用于路径构建
                    elif tag == 'binary':
                        # 检查是否可能用于路径构建
                        if is_path_concatenation(current_capture):
                            vulnerabilities.append({
                                'line': node.start_point[0] + 1,
                                'message': f'路径操纵漏洞: {query_info["message"]}',
                                'code_snippet': code_snippet,
                                'vulnerability_type': '路径操纵',
                                'severity': '高危'
                            })

                    current_capture = {}

        except Exception as e:
            print(f"查询错误 {query_info.get('message')}: {e}")
            continue

    return sorted(vulnerabilities, key=lambda x: x['line'])


def is_potentially_unsafe_path(path_value):
    """
    检查路径是否可能不安全（包含用户输入模式）

    Args:
        path_value: 路径字符串

    Returns:
        bool: 是否可能不安全
    """
    # 检查是否包含路径遍历模式
    if re.search(r'(\.\./|\.\.\\|~/|\.\.)', path_value):
        return True

    # 检查是否包含可能的用户输入模式
    user_input_patterns = [
        r'\$\{.*\}',  # 模板字符串插值
        r'\+.*\+',  # 字符串连接
        r'process\.env\.',  # 环境变量
        r'req\.',  # 请求对象
        r'params\.',  # 参数
        r'query\.',  # 查询参数
        r'body\.',  # 请求体
        r'input',  # 输入相关
        r'user',  # 用户相关
    ]

    for pattern in user_input_patterns:
        if re.search(pattern, path_value, re.IGNORECASE):
            return True

    return False


def is_path_concatenation(capture_info):
    """
    检查字符串连接是否可能用于路径构建

    Args:
        capture_info: 捕获的信息

    Returns:
        bool: 是否可能用于路径构建
    """
    # 检查是否包含路径相关的变量名
    path_keywords = ['path', 'dir', 'file', 'url', 'src', 'dest']

    for key, info in capture_info.items():
        if key in ['left', 'right'] and 'name' in info:
            for keyword in path_keywords:
                if keyword in info['name'].lower():
                    return True

    return False


def analyze_js_code(code_string):
    """
    分析JavaScript代码字符串中的路径操纵漏洞

    Args:
        code_string: JavaScript源代码字符串

    Returns:
        list: 检测结果列表
    """
    return detect_js_path_manipulation_vulnerabilities(code_string, 'javascript')


# 示例使用
if __name__ == "__main__":
    # 测试JavaScript代码
    test_js_code = """
const fs = require('fs');
const path = require('path');

// 直接使用用户输入构建路径 - 不安全
function readUserFile(userInput) {
    // 漏洞：直接使用用户输入构建路径
    const filePath = `/data/${userInput}`;
    return fs.readFileSync(filePath, 'utf8');
}

// 使用路径连接 - 不安全
function readConfigFile(configName) {
    // 漏洞：使用字符串连接构建路径
    const configPath = '/config/' + configName + '.json';
    return fs.readFileSync(configPath, 'utf8');
}

// 使用环境变量 - 可能不安全
function readEnvFile() {
    // 潜在漏洞：使用环境变量构建路径
    const env = process.env.NODE_ENV || 'development';
    const envFilePath = `/config/${env}.json`;
    return fs.readFileSync(envFilePath, 'utf8');
}

// 使用路径模块但未正确清理 - 不安全
function joinPaths(userDir, fileName) {
    // 漏洞：虽然使用path.join，但用户输入可能包含相对路径
    return path.join('/base/dir', userDir, fileName);
}

// 安全示例：使用白名单验证
function readSafeFile(userInput) {
    // 安全：验证用户输入
    const allowedFiles = ['file1.txt', 'file2.txt'];
    if (!allowedFiles.includes(userInput)) {
        throw new Error('Invalid file name');
    }

    // 安全：使用path.join和固定基础路径
    const filePath = path.join('/safe/dir', userInput);
    return fs.readFileSync(filePath, 'utf8');
}

// 安全示例：使用path.resolve和规范化
function readSafeFile2(userInput) {
    // 安全：解析和规范化路径
    const basePath = path.resolve('/safe/dir');
    const fullPath = path.resolve(basePath, userInput);

    // 确保路径仍在基础目录内
    if (!fullPath.startsWith(basePath)) {
        throw new Error('Invalid path');
    }

    return fs.readFileSync(fullPath, 'utf8');
}

// 执行系统命令 - 不安全
function executeCommand(userInput) {
    // 高危漏洞：直接使用用户输入执行命令
    const { exec } = require('child_process');
    exec(`cat /logs/${userInput}`, (error, stdout, stderr) => {
        if (error) {
            console.error(error);
            return;
        }
        console.log(stdout);
    });
}

// 使用req参数 - 不安全
app.get('/download', (req, res) => {
    // 漏洞：直接使用查询参数作为路径
    const file = req.query.file;
    const filePath = path.join(__dirname, 'uploads', file);

    res.download(filePath);
});

// 模板字符串中的路径操作 - 不安全
function templatePath(userId, fileId) {
    const filePath = `/user/${userId}/files/${fileId}`;
    return fs.existsSync(filePath);
}
"""

    print("=" * 60)
    print("JavaScript路径操纵漏洞检测")
    print("=" * 60)

    results = analyze_js_code(test_js_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   严重程度: {vuln['severity']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
    else:
        print("未检测到路径操纵漏洞")