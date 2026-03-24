import os
import re
from tree_sitter import Language, Parser

# 假设language_path已经在config_path中定义
from .config_path import language_path

# 加载C++语言
LANGUAGES = {
    'cpp': Language(language_path, 'cpp'),
}

# 定义MYBATIS SQL注入漏洞模式
MYBATIS_SQL_INJECTION_PATTERNS = {
    'cpp': [
        # 检测${}占位符
        {
            'pattern': r'\$\{[^}]+\}',
            'message': 'MYBATIS中使用${}占位符，存在SQL注入风险'
        },
        # 检测SQL字符串拼接
        {
            'pattern': r'[\'"][\s\S]*?\+[\s\S]*?(select|insert|update|delete|from|where|join|having|group by|order by)',
            'message': 'SQL语句字符串拼接，存在SQL注入风险'
        },
        # 检测危险函数调用
        {
            'pattern': r'(append|insert|format|sprintf|printf)\s*\(\s*[^)]*(select|insert|update|delete|from|where)',
            'message': '使用危险函数进行SQL拼接'
        }
    ]
}

# MYBATIS相关的SQL操作函数
MYBATIS_SQL_FUNCTIONS = [
    'selectOne', 'selectList', 'selectMap', 'insert', 'update', 'delete',
    'execute', 'query', 'queryForObject', 'queryForList', 'queryForMap',
    'sqlSession'
]

# 用户输入源函数
USER_INPUT_FUNCTIONS = [
    'getParameter', 'getAttribute', 'getQueryString', 'getenv', '_wgetenv',
    'GetCommandLine', 'GetCommandLineW', 'fgets', 'scanf', 'sscanf', 'getline',
    'gets', 'recv', 'recvfrom', 'recvmsg', 'cin'
]


def detect_mybatis_sql_injection(code, language='cpp'):
    """
    检测C++代码中MYBATIS SQL注入漏洞
    """
    vulnerabilities = []

    # 第一步：使用正则表达式检测明显的SQL注入模式
    for pattern_info in MYBATIS_SQL_INJECTION_PATTERNS[language]:
        pattern = pattern_info['pattern']
        matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)

        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            line_start = code.rfind('\n', 0, match.start()) + 1
            line_end = code.find('\n', match.start())
            if line_end == -1:
                line_end = len(code)

            code_snippet = code[line_start:line_end].strip()

            vulnerabilities.append({
                'line': line_number,
                'code_snippet': code_snippet,
                'vulnerability_type': 'MYBATIS SQL注入',
                'severity': '高危',
                'message': pattern_info['message']
            })

    # 第二步：检测MYBATIS SQL函数调用
    for func in MYBATIS_SQL_FUNCTIONS:
        pattern = rf'\b{func}\s*\([^)]*\)'
        matches = re.finditer(pattern, code, re.IGNORECASE)

        for match in matches:
            line_number = code[:match.start()].count('\n') + 1
            code_snippet = match.group(0)

            # 检查是否包含危险模式
            if any(dangerous_pattern in code_snippet for dangerous_pattern in ['${', '+', 'append', 'sprintf']):
                vulnerabilities.append({
                    'line': line_number,
                    'code_snippet': code_snippet,
                    'vulnerability_type': 'MYBATIS SQL注入',
                    'severity': '高危',
                    'message': f'MYBATIS函数 {func} 调用中包含危险模式'
                })

    # 第三步：检测用户输入与SQL操作的组合
    for input_func in USER_INPUT_FUNCTIONS:
        # 查找用户输入调用
        input_pattern = rf'\b{input_func}\s*\([^)]*\)'
        input_matches = re.finditer(input_pattern, code, re.IGNORECASE)

        for input_match in input_matches:
            input_line = code[:input_match.start()].count('\n') + 1
            input_snippet = input_match.group(0)

            # 在用户输入附近查找SQL操作
            for sql_func in MYBATIS_SQL_FUNCTIONS:
                sql_pattern = rf'\b{sql_func}\s*\([^)]*\)'
                sql_matches = re.finditer(sql_pattern, code, re.IGNORECASE)

                for sql_match in sql_matches:
                    sql_line = code[:sql_match.start()].count('\n') + 1
                    sql_snippet = sql_match.group(0)

                    # 如果SQL操作在用户输入附近（20行内）
                    if abs(sql_line - input_line) < 20:
                        # 检查SQL操作中是否包含用户输入的变量
                        vulnerabilities.append({
                            'line': sql_line,
                            'code_snippet': sql_snippet,
                            'vulnerability_type': 'MYBATIS SQL注入',
                            'severity': '高危',
                            'message': f'SQL操作 {sql_func} 附近有用户输入 {input_func}'
                        })

    return sorted(vulnerabilities, key=lambda x: x['line'])


def analyze_cpp_mybatis_sql_injection(code_string):
    """
    分析C++代码字符串中的MYBATIS SQL注入漏洞
    """
    return detect_mybatis_sql_injection(code_string, 'cpp')


# 示例使用
if __name__ == "__main__":
    test_cpp_code = """
#include <iostream>
#include <string>
#include <sqlSession.h>

using namespace std;

class UserMapper {
public:
    // 危险的${}占位符使用
    User selectUserById(string id) {
        string sql = "SELECT * FROM users WHERE id = ${userId}";
        return sqlSession.selectOne(sql);
    }

    // 字符串拼接SQL
    User selectUserByName(string name) {
        string sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return sqlSession.selectOne(sql);
    }

    // 安全的#{}占位符
    User selectUserByEmail(string email) {
        string sql = "SELECT * FROM users WHERE email = #{userEmail}";
        return sqlSession.selectOne(sql);
    }

    // 用户输入直接使用
    User vulnerableSelect() {
        string userInput;
        cin >> userInput;

        string sql = "SELECT * FROM users WHERE field = " + userInput;
        return sqlSession.selectOne(sql);
    }

    // StringBuilder拼接
    User selectWithStringBuilder(string condition) {
        StringBuilder sql;
        sql.append("SELECT * FROM users WHERE ");
        sql.append(condition);
        return sqlSession.selectList(sql.toString());
    }

    // sprintf格式化
    User selectWithSprintf(int age) {
        char sql[100];
        sprintf(sql, "SELECT * FROM users WHERE age > %d", age);
        return sqlSession.selectOne(string(sql));
    }
};

int main() {
    UserMapper mapper;
    string input;
    cin >> input;

    User user1 = mapper.selectUserById(input);
    User user2 = mapper.selectUserByName(input);
    User user3 = mapper.vulnerableSelect();

    return 0;
}
"""

    print("=" * 60)
    print("C++ MYBATIS SQL注入漏洞检测")
    print("=" * 60)

    results = analyze_cpp_mybatis_sql_injection(test_cpp_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet'][:100]}...")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到MYBATIS SQL注入漏洞")