import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在配置中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# GJB 8114-2013 编码规范相关规则
GJB_CODING_STANDARD_RULES = {
    'cpp': [
        # R-1-1-1 禁止通过宏定义改变关键字和基本类型含义
        {
            'query': '''
                (preproc_def
                    name: (identifier) @macro_name
                    value: (_)? @macro_value
                ) @macro_def
                (#match? @macro_name "^(int|char|float|double|void|if|else|while|for|return|break|continue|switch|case|default|sizeof|typedef|struct|union|enum|const|volatile|static|extern|auto|register|signed|unsigned|long|short)$")
            ''',
            'message': 'GJB R-1-1-1: 禁止通过宏定义改变关键字含义'
        },
        # R-1-1-2 禁止重新定义已存在的标识符
        {
            'query': '''
                (declaration
                    declarator: (identifier) @var_name
                ) @var_decl
            ''',
            'message': 'GJB R-1-1-2: 标识符声明，需确保不重复定义'
        },
        # R-1-2-1 禁止使用单字符标识符（除了循环变量）
        {
            'query': '''
                (declaration
                    declarator: (identifier) @var_name
                ) @decl
                (#match? @var_name "^[a-zA-Z]$")
            ''',
            'message': 'GJB R-1-2-1: 单字符标识符，建议使用有意义的名称'
        },
        # R-4-2-1 建议变量命名采用驼峰式
        {
            'query': '''
                (declaration
                    declarator: (identifier) @var_name
                ) @decl
            ''',
            'message': 'GJB R-4-2-1: 变量命名应具有描述性，建议使用驼峰式'
        },
        # R-1-3-1 禁止在头文件中定义全局变量
        {
            'query': '''
                (declaration
                    (storage_class_specifier)? @storage
                    declarator: (identifier) @global_var
                ) @global_decl
                (#match? @storage "^extern$")
            ''',
            'message': 'GJB R-1-3-1: 全局变量声明，应在源文件中定义'
        },
        # R-1-4-1 禁止函数声明与定义不一致
        {
            'query': '''
                (function_declarator
                    declarator: (identifier) @func_name
                    parameters: (parameter_list) @params
                ) @func_decl
            ''',
            'message': 'GJB R-1-4-1: 函数声明，需确保与定义一致'
        },
        # R-1-5-1 禁止使用goto语句
        {
            'query': '''
                (goto_statement
                    label: (statement_identifier) @label
                ) @goto
            ''',
            'message': 'GJB R-1-5-1: 禁止使用goto语句'
        },
        # R-1-7-1 禁止在条件表达式中赋值
        {
            'query': '''
                (if_statement
                    condition: (assignment_expression) @assignment
                ) @if_with_assign
            ''',
            'message': 'GJB R-1-7-1: 禁止在条件表达式中赋值'
        },
        # R-1-8-1 禁止使用未初始化的变量
        {
            'query': '''
                (declaration
                    declarator: (identifier) @var_name
                ) @uninitialized_decl
            ''',
            'message': 'GJB R-1-8-1: 变量声明，建议进行初始化'
        },
        # R-1-9-1 禁止使用魔数（Magic Number）
        {
            'query': '''
                (integer_literal) @magic_number
                (#not-eq? @magic_number "0")
                (#not-eq? @magic_number "1")
            ''',
            'message': 'GJB R-1-9-1: 使用魔数，建议定义为常量'
        }
    ]
}

# 宏定义安全检测
MACRO_SAFETY_RULES = {
    'query': '''
        (preproc_function_def
            name: (identifier) @macro_name
            parameters: (preproc_params) @macro_params
        ) @function_macro
    ''',
    'message': 'GJB: 函数式宏定义，需注意参数安全'
}

# 注释规范检测
COMMENT_STANDARD = {
    'query': '''
        (comment) @comment
    ''',
    'message': 'GJB: 代码注释，应保持清晰和更新'
}

# 代码复杂度检测
CODE_COMPLEXITY = {
    'query': '''
        (function_definition
            body: (compound_statement) @function_body
        ) @function_def
    ''',
    'message': 'GJB: 函数定义，建议控制函数长度和复杂度'
}


def detect_cpp_gjb_coding_violations(code, language='cpp'):
    """
    检测C++代码中GJB 8114-2013编码规范规则违规
    
    Args:
        code: C++源代码字符串
        language: 语言类型，默认为'cpp'
    
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
    
    violations = []
    variable_names = {}  # 记录变量名和位置
    function_decls = {}  # 记录函数声明
    
    # 第一步：检测GJB编码规范规则
    for rule_info in GJB_CODING_STANDARD_RULES[language]:
        try:
            query = LANGUAGES[language].query(rule_info['query'])
            captures = query.captures(root)
            
            for node, tag in captures:
                if tag in ['macro_name', 'var_name', 'func_name', 'global_var', 'label', 'assignment', 'magic_number']:
                    name = node.text.decode('utf8') if tag != 'magic_number' else 'magic number'
                    
                    # 获取代码片段
                    code_snippet = get_code_snippet(node, code)
                    
                    # 特殊处理：检查是否重复定义标识符
                    if tag == 'var_name':
                        if name in variable_names:
                            violations.append({
                                'line': node.start_point[0] + 1,
                                'code_snippet': code_snippet,
                                'violation_type': '编码规范',
                                'severity': '低危',
                                'rule_id': 'R-1-1-2',
                                'message': f'重复定义标识符: {name} (之前定义在行 {variable_names[name]})'
                            })
                        else:
                            variable_names[name] = node.start_point[0] + 1
                    
                    # 特殊处理：检查单字符标识符
                    if tag == 'var_name' and re.match(r'^[a-zA-Z]$', name):
                        # 排除常见的循环变量
                        if name not in ['i', 'j', 'k', 'x', 'y', 'z']:
                            violations.append({
                                'line': node.start_point[0] + 1,
                                'code_snippet': code_snippet,
                                'violation_type': '编码规范',
                                'severity': '建议',
                                'rule_id': 'R-1-2-1',
                                'message': f'单字符标识符: {name}，建议使用有意义的名称'
                            })
                    
                    # 特殊处理：检查魔数
                    if tag == 'magic_number':
                        value = node.text.decode('utf8')
                        # 排除0和1这两个常用值
                        if value not in ['0', '1', '0.0', '1.0']:
                            violations.append({
                                'line': node.start_point[0] + 1,
                                'code_snippet': code_snippet,
                                'violation_type': '编码规范',
                                'severity': '建议',
                                'rule_id': 'R-1-9-1',
                                'message': f'使用魔数: {value}，建议定义为常量'
                            })
                    
                    # 其他编码规范违规
                    else:
                        severity = '低危'
                        if tag == 'macro_name':
                            severity = '中危'
                        elif tag == 'goto':
                            severity = '中危'
                        
                        violations.append({
                            'line': node.start_point[0] + 1,
                            'code_snippet': code_snippet,
                            'violation_type': '编码规范',
                            'severity': severity,
                            'rule_id': get_rule_id(rule_info),
                            'message': rule_info['message'] + f' ({name})'
                        })
        
        except Exception as e:
            print(f"GJB编码规范规则查询错误: {e}")
            continue
    
    # 第二步：检测宏定义安全问题
    try:
        query = LANGUAGES[language].query(MACRO_SAFETY_RULES['query'])
        captures = query.captures(root)
        
        for node, tag in captures:
            if tag == 'function_macro':
                code_snippet = get_code_snippet(node, code)
                violations.append({
                    'line': node.start_point[0] + 1,
                    'code_snippet': code_snippet,
                    'violation_type': '编码规范',
                    'severity': '中危',
                    'rule_id': 'GJB-宏定义',
                    'message': MACRO_SAFETY_RULES['message']
                })
    
    except Exception as e:
        print(f"宏定义安全检测错误: {e}")
    
    # 第三步：检测代码复杂度（简单版本）
    try:
        query = LANGUAGES[language].query(CODE_COMPLEXITY['query'])
        captures = query.captures(root)
        
        for node, tag in captures:
            if tag == 'function_body':
                # 计算函数体行数
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                function_length = end_line - start_line
                
                if function_length > 50:  # 函数超过50行
                    code_snippet = get_code_snippet(node, code, context_lines=1)
                    violations.append({
                        'line': start_line,
                        'code_snippet': code_snippet,
                        'violation_type': '编码规范',
                        'severity': '建议',
                        'rule_id': 'GJB-代码复杂度',
                        'message': f'函数过长 ({function_length} 行)，建议拆分为小函数'
                    })
    
    except Exception as e:
        print(f"代码复杂度检测错误: {e}")
    
    return sorted(violations, key=lambda x: x['line'])


def get_code_snippet(node, code, context_lines=2):
    """获取代码片段"""
    lines = code.split('\n')
    start_line = max(0, node.start_point[0] - context_lines)
    end_line = min(len(lines), node.end_point[0] + context_lines + 1)
    
    snippet = '\n'.join(lines[start_line:end_line])
    # 截断过长的代码片段
    if len(snippet) > 200:
        snippet = snippet[:200] + '...'
    
    return snippet


def get_rule_id(rule_info):
    """从规则信息中提取规则ID"""
    message = rule_info.get('message', '')
    match = re.search(r'R-\d+-\d+-\d+', message)
    if match:
        return match.group(0)
    return 'GJB-编码规范'


def analyze_cpp_gjb_coding(code_string):
    """
    分析C++代码字符串中的GJB编码规范规则违规
    """
    return detect_cpp_gjb_coding_violations(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>

// 错误的宏定义 - R-1-1-1
#define int INT32_T  // 违规：改变关键字含义
#define true 1       // 违规：改变关键字含义

using namespace std;

// 全局变量声明 - R-1-3-1
extern int global_var;  // 应在源文件中定义

// 函数声明
void test_function(int param);  // R-1-4-1：需与定义一致

void test_coding_violations() {
    // 单字符标识符 - R-1-2-1
    int a = 10;      // 违规：单字符标识符
    int b = 20;
    int index = 30;  // 正确：有意义的名称
    
    // 重复定义标识符 - R-1-1-2
    int value = 100;
    // int value = 200;  // 违规：重复定义（注释掉以测试其他规则）
    
    // 未初始化变量 - R-1-8-1
    int uninitialized;  // 违规：未初始化
    uninitialized = 50;
    
    // 魔数使用 - R-1-9-1
    int timeout = 5000;  // 违规：魔数
    const int TIMEOUT_MS = 5000;  // 正确：定义为常量
    
    // 在条件表达式中赋值 - R-1-7-1
    int x;
    if ((x = get_value()) > 0) {  // 违规：条件中赋值
        cout << "Positive" << endl;
    }
    
    // goto语句 - R-1-5-1
    int counter = 0;
    
start_loop:  // 标签
    if (counter < 10) {
        counter++;
        goto start_loop;  // 违规：使用goto
    }
    
    // 函数式宏定义
    #define MAX(a, b) ((a) > (b) ? (a) : (b))  // 潜在问题：参数多次求值
    
    // 使用魔数进行计算
    int result = 100 * 60 * 24;  // 违规：魔数
}

// 函数定义与声明不一致 - R-1-4-1
void test_function(int param1, int param2) {  // 违规：参数个数不一致
    // 长函数示例
    int local1 = 0;
    int local2 = 0;
    int local3 = 0;
    int local4 = 0;
    int local5 = 0;
    int local6 = 0;
    int local7 = 0;
    int local8 = 0;
    int local9 = 0;
    int local10 = 0;
    // ... 更多代码使函数变长
    // 当函数超过50行时，会触发复杂度警告
}

void safe_coding_practices() {
    // 正确的编码规范
    
    // 有意义的变量名
    int studentCount = 0;
    int maximumScore = 100;
    
    // 初始化变量
    int initializedValue = 0;
    
    // 使用常量而非魔数
    const int MAX_CONNECTIONS = 100;
    const int DEFAULT_TIMEOUT = 30000;  // 30秒
    
    int connections = MAX_CONNECTIONS;
    int timeout = DEFAULT_TIMEOUT;
    
    // 避免条件表达式中的赋值
    int value = get_value();
    if (value > 0) {
        cout << "Positive" << endl;
    }
    
    // 使用循环而非goto
    for (int i = 0; i < 10; i++) {
        cout << "Iteration: " << i << endl;
    }
    
    // 内联函数而非函数式宏
    inline int max(int a, int b) {
        return a > b ? a : b;
    }
    
    // 短小精悍的函数
    void process_data(int* data, int size) {
        // 函数体控制在合理长度内
        for (int i = 0; i < size; i++) {
            data[i] = data[i] * 2;
        }
    }
}

// 工具函数
int get_value() {
    return 42;
}

int main() {
    test_coding_violations();
    safe_coding_practices();
    return 0;
}
"""
    
    print("=" * 70)
    print("GJB 8114-2013 C++编码规范规则检测")
    print("=" * 70)
    
    results = analyze_cpp_gjb_coding(test_cpp_code)
    
    if results:
        print(f"检测到 {len(results)} 个GJB编码规范规则违规:")
        for i, violation in enumerate(results, 1):
            print(f"\n{i}. 行号 {violation['line']}")
            print(f"   规则: {violation['rule_id']}")
            print(f"   描述: {violation['message']}")
            print(f"   类型: {violation['violation_type']}")
            print(f"   严重程度: {violation['severity']}")
            print(f"   代码片段: {violation['code_snippet'][:100]}...")
    else:
        print("未检测到GJB编码规范规则违规")
    
    print("\n" + "=" * 70)