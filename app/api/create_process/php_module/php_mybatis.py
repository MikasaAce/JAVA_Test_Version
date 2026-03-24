import re


def detect_mybatis_sql_injection(php_code):
    """
    MyBatis SQL注入漏洞检测主函数
    """
    vulnerabilities = []

    try:
        lines = php_code.split('\n')

        # 模式1: 检测${}字符串替换
        dollar_brace_pattern = r'\$\{[^}]+\}'

        # 模式2: 检测动态SQL标签
        dynamic_sql_tags = [
            r'<if[^>]*>',
            r'<choose[^>]*>',
            r'<when[^>]*>',
            r'<otherwise[^>]*>',
            r'<trim[^>]*>',
            r'<where[^>]*>',
            r'<set[^>]*>',
            r'<foreach[^>]*>'
        ]

        # 模式3: MyBatis注解
        mybatis_annotations = [
            r'@Select\s*\([^)]*\)',
            r'@Insert\s*\([^)]*\)',
            r'@Update\s*\([^)]*\)',
            r'@Delete\s*\([^)]*\)',
            r'@SelectProvider\s*\([^)]*\)'
        ]

        for i, line in enumerate(lines, 1):
            line_clean = line.strip()

            # 跳过空行和注释
            if not line_clean or line_clean.startswith('//') or line_clean.startswith('/*'):
                continue

            # 检测1: ${}字符串替换
            if re.search(dollar_brace_pattern, line):
                # 检查是否在SQL上下文中
                sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WHERE', 'FROM', 'SET', 'VALUES']
                if any(keyword in line.upper() for keyword in sql_keywords):
                    vulnerabilities.append({
                        'line': i,
                        'message': "检测到MyBatis ${}字符串替换 - SQL注入风险",
                        'code_snippet': line_clean,
                        'vulnerability_type': "MyBatis SQL注入 - ${}使用",
                        'severity': '高危'
                    })

            # 检测2: 动态SQL标签中的${}
            for tag_pattern in dynamic_sql_tags:
                if re.search(tag_pattern, line, re.IGNORECASE):
                    if '$' in line and '{' in line:
                        vulnerabilities.append({
                            'line': i,
                            'message': "检测到动态SQL标签中的${}使用",
                            'code_snippet': line_clean,
                            'vulnerability_type': "MyBatis SQL注入 - 动态SQL",
                            'severity': '中危'
                        })
                    break

            # 检测3: ORDER BY中的${}
            if 'ORDER BY' in line.upper() and '$' in line and '{' in line:
                vulnerabilities.append({
                    'line': i,
                    'message': "检测到ORDER BY动态排序使用${}",
                    'code_snippet': line_clean,
                    'vulnerability_type': "MyBatis SQL注入 - ORDER BY注入",
                    'severity': '高危'
                })

            # 检测4: LIKE查询中的${}
            if 'LIKE' in line.upper() and '$' in line and '{' in line:
                vulnerabilities.append({
                    'line': i,
                    'message': "检测到LIKE查询使用${}",
                    'code_snippet': line_clean,
                    'vulnerability_type': "MyBatis SQL注入 - LIKE查询注入",
                    'severity': '中危'
                })

            # 检测5: IN查询中的${}
            if 'IN' in line.upper() and '<foreach' in line and '$' in line and '{' in line:
                vulnerabilities.append({
                    'line': i,
                    'message': "检测到IN查询中的${}使用",
                    'code_snippet': line_clean,
                    'vulnerability_type': "MyBatis SQL注入 - IN查询注入",
                    'severity': '中危'
                })

            # 检测6: MyBatis注解中的${}
            for annotation_pattern in mybatis_annotations:
                if re.search(annotation_pattern, line):
                    if '$' in line and '{' in line:
                        vulnerabilities.append({
                            'line': i,
                            'message': "检测到MyBatis注解中的${}使用",
                            'code_snippet': line_clean,
                            'vulnerability_type': "MyBatis SQL注入 - 注解SQL",
                            'severity': '高危'
                        })
                    break

            # 检测7: bind标签中的字符串拼接
            if '<bind' in line and ('+' in line or 'concat' in line):
                vulnerabilities.append({
                    'line': i,
                    'message': "检测到bind标签中的字符串拼接",
                    'code_snippet': line_clean,
                    'vulnerability_type': "MyBatis SQL注入 - bind标签风险",
                    'severity': '中危'
                })

            # 检测8: SQL Provider模式
            if any(keyword in line for keyword in ['SqlProvider', 'Provider', 'buildSql']):
                if '+' in line or 'StringBuilder' in line or 'append' in line:
                    vulnerabilities.append({
                        'line': i,
                        'message': "检测到SQL Provider中的字符串拼接",
                        'code_snippet': line_clean,
                        'vulnerability_type': "MyBatis SQL注入 - SQL Provider",
                        'severity': '高危'
                    })

            # 检测9: 手动SQL拼接
            if any(keyword in line.upper() for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
                if '+' in line and any(user_input in line for user_input in ['param', 'request', 'get', 'post']):
                    vulnerabilities.append({
                        'line': i,
                        'message': "检测到手动SQL字符串拼接",
                        'code_snippet': line_clean,
                        'vulnerability_type': "MyBatis SQL注入 - 代码拼接",
                        'severity': '高危'
                    })

    except Exception as e:
        print(f"检测过程中发生错误: {e}")

    return vulnerabilities


# 测试代码
if __name__ == "__main__":
    test_php_code = '''<?php
// 测试 MyBatis SQL注入漏洞
// 模拟MyBatis XML配置文件内容

// 不安全的${}使用 - 高危
$xml1 = '<select id="getUser">
    SELECT * FROM users WHERE username = \\'${username}\\'
</select>';

$xml2 = '<select id="search">
    SELECT * FROM products WHERE name LIKE \\'%${keyword}%\\'
</select>';

// ORDER BY注入 - 高危
$xml3 = '<select id="getList">
    SELECT * FROM table ORDER BY ${orderBy} ${orderDir}
</select>';

// 动态SQL中的风险
$xml4 = '<select id="dynamicQuery">
    SELECT * FROM users
    <where>
        <if test="name != null">
            AND name = \\'${name}\\'
        </if>
        <if test="age != null">
            AND age = ${age}
        </if>
    </where>
</select>';

// foreach标签在IN查询中使用${}
$xml5 = '<select id="getByIds">
    SELECT * FROM users
    WHERE id IN
    <foreach collection="ids" item="id" open="(" separator="," close=")">
        ${id}
    </foreach>
</select>';

// bind标签中的字符串拼接
$xml6 = '<select id="search">
    <bind name="pattern" value="\\'%\\' + keyword + \\'%\\'"/>
    SELECT * FROM products WHERE name LIKE #{pattern}
</select>';

// 注解SQL中的${}使用
$java_code = '
@Select("SELECT * FROM users WHERE username = \\'${username}\\'")
User findByUsername(String username);
';

// SQL Provider中的字符串拼接
$provider_code = '
public String buildQuery(Map<String, Object> params) {
    String sql = "SELECT * FROM users WHERE 1=1";
    if (params.get("name") != null) {
        sql += " AND name = \\'" + params.get("name") + "\\'";
    }
    return sql;
}
';

// 相对安全的#{ }使用
$safe_xml = '<select id="safeQuery">
    SELECT * FROM users WHERE username = #{username}
</select>';

$safe_like = '<select id="safeSearch">
    SELECT * FROM products WHERE name LIKE CONCAT(\\'%\\', #{keyword}, \\'%\\')
</select>';

// 安全的动态排序
$safe_order = '<select id="safeOrder">
    SELECT * FROM table 
    ORDER BY 
    <choose>
        <when test="orderBy == \\'name\\'">name</when>
        <when test="orderBy == \\'age\\'">age</when>
        <otherwise>id</otherwise>
    </choose>
</select>';

// 安全的foreach使用
$safe_foreach = '<select id="safeInQuery">
    SELECT * FROM users
    WHERE id IN
    <foreach collection="ids" item="id" open="(" separator="," close=")">
        #{id}
    </foreach>
</select>';

// 正常业务逻辑
echo "应用程序代码";
?>
'''

    print("=" * 60)
    print("MyBatis SQL注入漏洞检测")
    print("=" * 60)

    results = detect_mybatis_sql_injection(test_php_code)

    if results:
        print(f"检测到 {len(results)} 个潜在漏洞:")
        for i, vuln in enumerate(results, 1):
            print(f"\n{i}. 行号 {vuln['line']}: {vuln['message']}")
            print(f"   代码片段: {vuln['code_snippet']}")
            print(f"   漏洞类型: {vuln['vulnerability_type']}")
            print(f"   严重程度: {vuln['severity']}")
    else:
        print("未检测到MyBatis SQL注入漏洞")