import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在配置中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# GJB 8114-2013 类型安全相关规则
GJB_TYPE_SAFETY_RULES = {
    'cpp': [
        # R-1-6-12 禁止在除法运算中出现被零除的情况
        {
            'query': '''
                (binary_expression
                    operator: "/"
                    right: (integer_literal) @denominator
                ) @division
                (#eq? @denominator "0")
            ''',
            'message': 'GJB R-1-6-12: 除法运算中被零除'
        },
        {
            'query': '''
                (binary_expression
                    operator: "/"
                    right: (float_literal) @denominator
                ) @division
                (#eq? @denominator "0.0")
            ''',
            'message': 'GJB R-1-6-12: 除法运算中被零除'
        },
        # R-1-12-4 禁止对无符号数进行>=0的比较
        {
            'query': '''
                (binary_expression
                    left: (identifier) @var_name
                    operator: ">="
                    right: (integer_literal) @zero
                ) @comparison
                (#eq? @zero "0")
            ''',
            'message': 'GJB R-1-12-4: 对无符号数进行>=0的比较（恒真）'
        },
        # R-2-4-5 禁止有符号整数与无符号整数混合运算
        {
            'query': '''
                (binary_expression
                    left: (_) @left_expr
                    operator: @operator
                    right: (_) @right_expr
                ) @binary_op
                (#any-of? @operator "+" "-" "*" "/" "%" "==" "!=" "<" "<=" ">" ">=" "&" "|" "^")
            ''',
            'message': 'GJB R-2-4-5: 有符号整数与无符号整数混合运算'
        },
        # R-1-6-13 禁止整数溢出
        {
            'query': '''
                (binary_expression
                    left: (integer_literal) @left_val
                    operator: "*"
                    right: (integer_literal) @right_val
                ) @multiplication
            ''',
            'message': 'GJB R-1-6-13: 整数乘法可能导致溢出'
        },
        # R-1-6-14 禁止使用位运算对有符号整数进行操作
        {
            'query': '''
                (binary_expression
                    left: (identifier) @left_var
                    operator: @operator
                    right: (_) @right_expr
                ) @bit_op
                (#any-of? @operator "<<" ">>" "&" "|" "^" "~")
            ''',
            'message': 'GJB R-1-6-14: 对有符号整数进行位运算'
        },
        # R-1-6-15 禁止隐式类型转换
        {
            'query': '''
                (assignment_expression
                    left: (identifier) @left_var
                    right: (_) @right_expr
                ) @assignment
            ''',
            'message': 'GJB R-1-6-15: 可能发生隐式类型转换'
        },
        # R-1-6-16 禁止浮点数与整数的直接比较
        {
            'query': '''
                (binary_expression
                    left: (_) @left_expr
                    operator: @operator
                    right: (_) @right_expr
                ) @comparison
                (#any-of? @operator "==" "!=" "<" "<=" ">" ">=")
            ''',
            'message': 'GJB R-1-6-16: 浮点数与整数直接比较可能导致精度问题'
        }
    ]
}

# 类型转换相关检测
TYPE_CAST_VULNERABILITIES = {
    'cpp': [
        # 检测危险的C风格类型转换
        {
            'query': '''
                (cast_expression
                    type: (_) @target_type
                    value: (_) @source_value
                ) @cast
            ''',
            'message': 'GJB: 使用C风格类型转换，建议使用static_cast等C++风格转换'
        },
        # 检测reinterpret_cast（最危险的转换）
        {
            'query': '''
                (call_expression
                    function: (template_function
                        name: (identifier) @func_name
                    )
                    arguments: (argument_list (_) @arg)
                ) @cast_call
                (#eq? @func_name "reinterpret_cast")
            ''',
            'message': 'GJB: 使用reinterpret_cast，这是最危险的类型转换'
        }
    ]
}

# 枚举类型安全检测
ENUM_TYPE_SAFETY = {
    'query': '''
        (enum_specifier
            name: (type_identifier) @enum_name
            enumerator_list: (enumerator_list) @enumerators
        ) @enum_def
    ''',
    'message': 'GJB: 枚举类型定义，需确保枚举值在有效范围内'
}


def detect_cpp_gjb_type_violations(code, language='cpp'):
    """
    检测C++代码中GJB 8114-2013类型安全规则违规
    
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
    
    # 第一步：检测GJB类型安全规则
    for rule_info in GJB_TYPE_SAFETY_RULES[language]:
        try:
            query = LANGUAGES[language].query(rule_info['query'])
            captures = query.captures(root)
            
            for node, tag in captures:
                if tag in ['division', 'comparison', 'multiplication', 'bit_op', 'assignment', 'binary_op']:
                    # 获取代码片段
                    code_snippet = get_code_snippet(node, code)
                    
                    # 特殊处理：检查除法是否被零除
                    if tag == 'division':
                        violations.append({
                            'line': node.start_point[0] + 1,
                            'code_snippet': code_snippet,
                            'violation_type': '类型安全',
                            'severity': '高危',
                            'rule_id': 'R-1-6-12',
                            'message': rule_info['message']
                        })
                    
                    # 特殊处理：检查无符号数>=0比较
                    elif tag == 'comparison' and 'zero' in rule_info.get('message', ''):
                        violations.append({
                            'line': node.start_point[0] + 1,
                            'code_snippet': code_snippet,
                            'violation_type': '类型安全',
                            'severity': '低危',
                            'rule_id': 'R-1-12-4',
                            'message': rule_info['message']
                        })
                    
                    # 其他类型安全违规
                    else:
                        violations.append({
                            'line': node.start_point[0] + 1,
                            'code_snippet': code_snippet,
                            'violation_type': '类型安全',
                            'severity': '中危',
                            'rule_id': get_rule_id(rule_info),
                            'message': rule_info['message']
                        })
        
        except Exception as e:
            print(f"GJB类型安全规则查询错误: {e}")
            continue
    
    # 第二步：检测类型转换问题
    for rule_info in TYPE_CAST_VULNERABILITIES[language]:
        try:
            query = LANGUAGES[language].query(rule_info['query'])
            captures = query.captures(root)
            
            for node, tag in captures:
                if tag in ['cast', 'cast_call']:
                    code_snippet = get_code_snippet(node, code)
                    
                    severity = '中危'
                    if 'reinterpret_cast' in rule_info.get('message', ''):
                        severity = '高危'
                    
                    violations.append({
                        'line': node.start_point[0] + 1,
                        'code_snippet': code_snippet,
                        'violation_type': '类型安全',
                        'severity': severity,
                        'rule_id': 'R-1-6-15',
                        'message': rule_info['message']
                    })
        
        except Exception as e:
            print(f"类型转换检测错误: {e}")
            continue
    
    # 第三步：检测枚举类型问题
    try:
        query = LANGUAGES[language].query(ENUM_TYPE_SAFETY['query'])
        captures = query.captures(root)
        
        for node, tag in captures:
            if tag == 'enum_def':
                code_snippet = get_code_snippet(node, code)
                violations.append({
                    'line': node.start_point[0] + 1,
                    'code_snippet': code_snippet,
                    'violation_type': '类型安全',
                    'severity': '低危',
                    'rule_id': 'GJB-枚举类型',
                    'message': ENUM_TYPE_SAFETY['message']
                })
    
    except Exception as e:
        print(f"枚举类型检测错误: {e}")
    
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
    return 'GJB-类型安全'


def analyze_cpp_gjb_type(code_string):
    """
    分析C++代码字符串中的GJB类型安全规则违规
    """
    return detect_cpp_gjb_type_violations(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <climits>

using namespace std;

void test_type_safety_violations() {
    // 1. 被零除 - R-1-6-12
    int a = 10;
    int b = 0;
    int result = a / b;  // 违规：被零除
    result = a / 0;      // 违规：被零除（字面量）
    
    // 2. 无符号数>=0比较 - R-1-12-4
    unsigned int u = 10;
    if (u >= 0) {  // 违规：恒真比较
        cout << "Always true" << endl;
    }
    
    // 3. 有符号与无符号混合运算 - R-2-4-5
    int signed_val = -1;
    unsigned int unsigned_val = 10;
    int mixed_result = signed_val + unsigned_val;  // 违规：混合运算
    
    // 4. 整数溢出 - R-1-6-13
    int max_int = INT_MAX;
    int overflow = max_int * 2;  // 违规：可能溢出
    
    // 5. 对有符号整数进行位运算 - R-1-6-14
    int signed_bit = -10;
    int shifted = signed_bit << 2;  // 违规：有符号数位运算
    
    // 6. 隐式类型转换 - R-1-6-15
    double d = 3.14;
    int i = d;  // 违规：隐式类型转换
    
    // 7. 浮点数与整数直接比较 - R-1-6-16
    float f = 0.1;
    if (f == 0) {  // 违规：浮点数与整数直接比较
        cout << "Equal" << endl;
    }
    
    // 8. 危险的类型转换
    void* void_ptr = &a;
    int* int_ptr = (int*)void_ptr;  // 违规：C风格类型转换
    int* reinterpreted = reinterpret_cast<int*>(void_ptr);  // 违规：reinterpret_cast
    
    // 9. 枚举类型潜在问题
    enum Color { RED, GREEN, BLUE };
    Color color = RED;
    color = static_cast<Color>(100);  // 潜在问题：枚举值越界
}

void safe_type_operations() {
    // 正确的类型安全操作
    
    // 1. 避免被零除
    int a = 10;
    int b = 2;
    if (b != 0) {
        int result = a / b;  // 安全：除数非零检查
    }
    
    // 2. 避免无符号数冗余比较
    unsigned int u = 10;
    if (u > 0) {  // 正确：有意义比较
        cout << "Positive" << endl;
    }
    
    // 3. 避免混合运算
    int signed_val = -1;
    unsigned int unsigned_val = 10;
    // 显式转换后再运算
    int safe_result = signed_val + static_cast<int>(unsigned_val);
    
    // 4. 检查溢出
    int max_int = INT_MAX;
    if (max_int > INT_MAX / 2) {
        // 处理溢出情况
    } else {
        int safe_mul = max_int * 2;
    }
    
    // 5. 使用无符号数进行位运算
    unsigned int bits = 10;
    unsigned int safe_shift = bits << 2;
    
    // 6. 显式类型转换
    double d = 3.14;
    int i = static_cast<int>(d);  // 正确：显式转换
    
    // 7. 浮点数比较使用容差
    float f = 0.1;
    float epsilon = 0.0001;
    if (abs(f - 0) < epsilon) {  // 正确：使用容差比较
        cout << "Approximately equal" << endl;
    }
    
    // 8. 使用安全的类型转换
    int value = 42;
    void* void_ptr = &value;
    // 优先使用static_cast
    int* safe_ptr = static_cast<int*>(void_ptr);
}

int main() {
    test_type_safety_violations();
    safe_type_operations();
    return 0;
}
"""
    
    print("=" * 70)
    print("GJB 8114-2013 C++类型安全规则检测")
    print("=" * 70)
    
    results = analyze_cpp_gjb_type(test_cpp_code)
    
    if results:
        print(f"检测到 {len(results)} 个GJB类型安全规则违规:")
        for i, violation in enumerate(results, 1):
            print(f"\n{i}. 行号 {violation['line']}")
            print(f"   规则: {violation['rule_id']}")
            print(f"   描述: {violation['message']}")
            print(f"   类型: {violation['violation_type']}")
            print(f"   严重程度: {violation['severity']}")
            print(f"   代码片段: {violation['code_snippet'][:100]}...")
    else:
        print("未检测到GJB类型安全规则违规")
    
    print("\n" + "=" * 70)