import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在配置中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# GJB 8114-2013 内存安全相关规则
GJB_MEMORY_SAFETY_RULES = {
    'cpp': [
        # R-1-12-14 禁止缓冲区读取操作越界
        {
            'query': '''
                (call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list (_)+ @args)
                ) @call
            ''',
            'func_pattern': r'^(memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|strncat|wcscat|wcsncat|sprintf|snprintf|vsprintf|vsnprintf|read|fread|recv|recvfrom)$',
            'message': 'GJB R-1-12-14: 缓冲区操作可能越界'
        },
        # R-1-6-1 禁止使用未初始化的指针
        {
            'query': '''
                (unary_expression
                    operator: "*"
                    argument: (identifier) @pointer_var
                ) @deref
            ''',
            'message': 'GJB R-1-6-1: 指针解引用，需确保指针已初始化'
        },
        # R-1-6-2 禁止指针运算导致越界访问
        {
            'query': '''
                (binary_expression
                    left: (identifier) @pointer_var
                    operator: "+"
                    right: (_) @offset
                ) @pointer_arithmetic
                (#match? @pointer_var "^[a-zA-Z_][a-zA-Z0-9_]*$")
            ''',
            'message': 'GJB R-1-6-2: 指针算术运算可能导致越界访问'
        },
        # R-1-6-3 禁止使用已释放的内存
        {
            'query': '''
                (call_expression
                    function: (identifier) @free_func
                    arguments: (argument_list (_) @ptr_arg)
                ) @free_call
            ''',
            'free_pattern': r'^(free|delete|delete\[\])$',
            'message': 'GJB R-1-6-3: 内存释放操作，需确保后续不再使用该内存'
        },
        # R-1-6-4 禁止重复释放内存
        {
            'query': '''
                (call_expression
                    function: (identifier) @free_func
                    arguments: (argument_list (identifier) @ptr_var)
                ) @free_call
            ''',
            'free_pattern': r'^(free|delete|delete\[\])$',
            'message': 'GJB R-1-6-4: 可能重复释放内存'
        },
        # R-1-6-5 禁止内存泄漏（malloc/new 后未释放）
        {
            'query': '''
                (call_expression
                    function: (identifier) @alloc_func
                    arguments: (argument_list) @args
                ) @alloc_call
            ''',
            'alloc_pattern': r'^(malloc|calloc|realloc|new|new\[\])$',
            'message': 'GJB R-1-6-5: 内存分配操作，需确保有对应的释放操作'
        },
        # R-1-12-1 禁止数组下标越界
        {
            'query': '''
                (subscript_expression
                    array: (identifier) @array_var
                    index: (_) @index
                ) @subscript
            ''',
            'message': 'GJB R-1-12-1: 数组访问，需确保下标在有效范围内'
        },
        # R-1-12-2 禁止栈溢出（检测大数组或递归）
        {
            'query': '''
                (declaration
                    declarator: (array_declarator
                        declarator: (identifier) @array_name
                        size: (integer_literal) @array_size
                    )
                ) @array_decl
                (#gte? @array_size "1000000")
            ''',
            'message': 'GJB R-1-12-2: 大数组声明可能导致栈溢出'
        }
    ]
}

# 字符串函数长度不匹配检测
STRING_FUNCTION_LENGTH_ISSUES = {
    'query': '''
        (call_expression
            function: (identifier) @func_name
            arguments: (argument_list
                (_) @dest_arg
                (_) @src_arg
                (_)? @size_arg
            )
        ) @call
    ''',
    'func_pattern': r'^(strncpy|strncat|memcpy|memmove|wcsncpy|wcsncat)$',
    'message': 'GJB: 字符串操作函数需确保目标缓冲区足够大'
}

# 用户输入相关操作检测
USER_INPUT_VULNERABILITIES = {
    'query': '''
        (call_expression
            function: (identifier) @input_func
            arguments: (argument_list (_)+ @args)
        ) @input_call
        . 
        (call_expression
            function: (identifier) @mem_func
            arguments: (argument_list (_)+ @mem_args)
        ) @mem_call
        (#match? @input_func "^(gets|scanf|fscanf|sscanf|cin|getline|recv|recvfrom|read)$")
        (#match? @mem_func "^(strcpy|strcat|memcpy|sprintf|wcscpy|wcscat)$")
    ''',
    'message': 'GJB: 用户输入后直接进行内存操作可能导致缓冲区溢出'
}


def detect_cpp_gjb_memory_violations(code, language='cpp'):
    """
    检测C++代码中GJB 8114-2013内存安全规则违规
    
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
    
    # 第一步：检测GJB内存安全规则
    for rule_info in GJB_MEMORY_SAFETY_RULES[language]:
        try:
            query = LANGUAGES[language].query(rule_info['query'])
            captures = query.captures(root)
            
            for node, tag in captures:
                if tag in ['func_name', 'pointer_var', 'free_func', 'alloc_func', 'array_var', 'array_name']:
                    name = node.text.decode('utf8')
                    
                    # 检查模式匹配
                    is_match = False
                    
                    if 'func_pattern' in rule_info and tag == 'func_name':
                        if re.match(rule_info['func_pattern'], name, re.IGNORECASE):
                            is_match = True
                    
                    elif 'free_pattern' in rule_info and tag == 'free_func':
                        if re.match(rule_info['free_pattern'], name, re.IGNORECASE):
                            is_match = True
                    
                    elif 'alloc_pattern' in rule_info and tag == 'alloc_func':
                        if re.match(rule_info['alloc_pattern'], name, re.IGNORECASE):
                            is_match = True
                    
                    # 对于其他标签，如果没有特定模式要求，也认为是匹配
                    elif not any(key in rule_info for key in ['func_pattern', 'free_pattern', 'alloc_pattern']):
                        is_match = True
                    
                    if is_match:
                        # 获取代码片段
                        code_snippet = get_code_snippet(node, code)
                        
                        # 特殊处理：检查数组大小是否过大
                        if tag == 'array_size' and 'array_size' in rule_info:
                            try:
                                size = int(name.strip())
                                if size >= 1000000:  # 1MB以上的数组可能栈溢出
                                    violations.append({
                                        'line': node.start_point[0] + 1,
                                        'code_snippet': code_snippet,
                                        'violation_type': '内存安全',
                                        'severity': '高危',
                                        'rule_id': 'R-1-12-2',
                                        'message': rule_info['message'] + f' (数组大小: {size})'
                                    })
                            except ValueError:
                                pass
                        else:
                            violations.append({
                                'line': node.start_point[0] + 1,
                                'code_snippet': code_snippet,
                                'violation_type': '内存安全',
                                'severity': '中危',
                                'rule_id': get_rule_id(rule_info),
                                'message': rule_info['message']
                            })
        
        except Exception as e:
            print(f"GJB内存安全规则查询错误: {e}")
            continue
    
    # 第二步：检测字符串函数长度不匹配
    try:
        query = LANGUAGES[language].query(STRING_FUNCTION_LENGTH_ISSUES['query'])
        captures = query.captures(root)
        
        for node, tag in captures:
            if tag == 'func_name':
                func_name = node.text.decode('utf8')
                if re.match(STRING_FUNCTION_LENGTH_ISSUES['func_pattern'], func_name, re.IGNORECASE):
                    code_snippet = get_code_snippet(node, code)
                    violations.append({
                        'line': node.start_point[0] + 1,
                        'code_snippet': code_snippet,
                        'violation_type': '内存安全',
                        'severity': '中危',
                        'rule_id': 'R-1-12-14',
                        'message': STRING_FUNCTION_LENGTH_ISSUES['message'] + f' (函数: {func_name})'
                    })
    
    except Exception as e:
        print(f"字符串函数长度检测错误: {e}")
    
    # 第三步：检测用户输入相关的内存操作
    try:
        query = LANGUAGES[language].query(USER_INPUT_VULNERABILITIES['query'])
        captures = query.captures(root)
        
        for node, tag in captures:
            if tag == 'input_call':
                code_snippet = get_code_snippet(node, code)
                violations.append({
                    'line': node.start_point[0] + 1,
                    'code_snippet': code_snippet,
                    'violation_type': '内存安全',
                    'severity': '高危',
                    'rule_id': 'R-1-12-14',
                    'message': USER_INPUT_VULNERABILITIES['message']
                })
    
    except Exception as e:
        print(f"用户输入相关内存操作检测错误: {e}")
    
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
    return 'GJB-内存安全'


def analyze_cpp_gjb_memory(code_string):
    """
    分析C++代码字符串中的GJB内存安全规则违规
    """
    return detect_cpp_gjb_memory_violations(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    # 测试C++代码
    test_cpp_code = """
#include <iostream>
#include <cstring>
#include <cstdlib>

using namespace std;

void test_memory_violations() {
    // 1. 未初始化的指针使用 - R-1-6-1
    int* uninitialized_ptr;
    *uninitialized_ptr = 10;  // 违规：使用未初始化的指针
    
    // 2. 缓冲区溢出 - R-1-12-14
    char buffer[10];
    char source[20] = "This is a long string";
    strcpy(buffer, source);  // 违规：缓冲区溢出
    
    // 3. 数组下标越界 - R-1-12-1
    int arr[5];
    arr[10] = 100;  // 违规：数组下标越界
    
    // 4. 内存泄漏 - R-1-6-5
    int* leaked_memory = new int[100];
    // 没有对应的delete操作
    
    // 5. 重复释放 - R-1-6-4
    int* ptr = new int;
    delete ptr;
    delete ptr;  // 违规：重复释放
    
    // 6. 使用已释放的内存 - R-1-6-3
    int* freed_ptr = new int;
    delete freed_ptr;
    *freed_ptr = 20;  // 违规：使用已释放的内存
    
    // 7. 指针算术越界 - R-1-6-2
    int array[5];
    int* p = array;
    p = p + 10;  // 违规：指针算术越界
    *p = 30;
    
    // 8. 大数组导致栈溢出 - R-1-12-2
    char large_buffer[1000000];  // 违规：大数组可能导致栈溢出
    
    // 9. 字符串操作长度不匹配
    char dest[10];
    strncpy(dest, "This is a very long string", 50);  // 违规：长度参数大于目标缓冲区
}

void safe_memory_operations() {
    // 正确的内存操作
    int* ptr = new int;
    *ptr = 10;
    delete ptr;
    ptr = nullptr;  // 置空防止误用
    
    // 安全的字符串操作
    char buffer[100];
    strncpy(buffer, "safe string", sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    
    // 安全的数组访问
    int arr[10];
    for (int i = 0; i < 10; i++) {
        arr[i] = i;
    }
}

int main() {
    test_memory_violations();
    safe_memory_operations();
    return 0;
}
"""
    
    print("=" * 70)
    print("GJB 8114-2013 C++内存安全规则检测")
    print("=" * 70)
    
    results = analyze_cpp_gjb_memory(test_cpp_code)
    
    if results:
        print(f"检测到 {len(results)} 个GJB内存安全规则违规:")
        for i, violation in enumerate(results, 1):
            print(f"\n{i}. 行号 {violation['line']}")
            print(f"   规则: {violation['rule_id']}")
            print(f"   描述: {violation['message']}")
            print(f"   类型: {violation['violation_type']}")
            print(f"   严重程度: {violation['severity']}")
            print(f"   代码片段: {violation['code_snippet'][:100]}...")
    else:
        print("未检测到GJB内存安全规则违规")
    
    print("\n" + "=" * 70)