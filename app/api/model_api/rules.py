import javalang

def check_cookie_http_only(ast, lines):
    vulnerabilities = []
    for path, node in ast:
        if isinstance(node, javalang.tree.ClassCreator) and node.type.name == "Cookie":
            if not any(isinstance(child, javalang.tree.MethodInvocation) and child.member == "setHttpOnly" for _, child in node):
                vulnerabilities.append({
                    '漏洞类型': '未设置 HttpOnly 标志',
                    '行号': node.position.line if node.position else None
                })
    return vulnerabilities

def check_cookie_secure(ast, lines):
    vulnerabilities = []
    for path, node in ast:
        if isinstance(node, javalang.tree.ClassCreator) and node.type.name == "Cookie":
            if not any(isinstance(child, javalang.tree.MethodInvocation) and child.member == "setSecure" for _, child in node):
                vulnerabilities.append({
                    '漏洞类型': '未设置 Secure 标志',
                    '行号': node.position.line if node.position else None
                })
    return vulnerabilities

def check_cookie_same_site(ast, lines):
    vulnerabilities = []
    for path, node in ast:
        if isinstance(node, javalang.tree.ClassCreator) and node.type.name == "Cookie":
            if not any(isinstance(child, javalang.tree.MethodInvocation) and child.member == "setSameSite" for _, child in node):
                vulnerabilities.append({
                    '漏洞类型': '未设置 SameSite 属性',
                    '行号': node.position.line if node.position else None
                })
    return vulnerabilities

def detect_insecure_encryption(tree, lines):
    # 不安全的加密算法列表
    insecure_algorithms = ["DES", "DESede", "RC4", "Blowfish"] #DES,3DES,RC4,Blowfish
    vulnerabilities = []

    # 遍历AST
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):  # 检查方法调用
            if node.member == "getInstance":  # 检查方法名是否为getInstance
                for arg in node.arguments:  # 遍历方法参数
                    if isinstance(arg, javalang.tree.Literal) and arg.value.strip('"') in insecure_algorithms:
                        # 获取漏洞所在行号
                        line_number = node.position.line - 1  # AST的行号从1开始，列表索引从0开始
                        # 提取漏洞所在行的代码
                        line_code = lines[line_number].strip()
                        # 记录漏洞信息
                        vulnerabilities.append({
                            "漏洞类型": "不安全的加密算法",
                            "行号": node.position.line
                        })

    return vulnerabilities

def detect_insecure_hash(tree, lines):
    # 不安全的哈希算法列表
    insecure_algorithms = ["MD5", "SHA-1"]
    vulnerabilities = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "getInstance" and node.qualifier == "MessageDigest":
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.Literal) and arg.value.strip('"') in insecure_algorithms:
                        # 获取漏洞所在的行号
                        line_number = node.position.line if node.position else "Unknown"
                        # 提取漏洞所在行的代码
                        line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                        vulnerabilities.append({
                            "漏洞类型": "不安全的哈希算法",
                            "行号": line_number
                        })

    return vulnerabilities

def detect_insecure_random(tree, lines):
    vulnerabilities = []

    for path, node in tree:
        # 检测是否使用了 java.util.Random
        if isinstance(node, javalang.tree.ClassCreator):
            # 检查 node.type 是否存在且为 Random
            if hasattr(node, 'type') and hasattr(node.type, 'name') and node.type.name == "Random":
                # 检查 node.type 的 qualifier 是否存在且为 java.util
                if hasattr(node.type, 'qualifier') and node.type.qualifier is not None:
                    qualifier = ".".join(node.type.qualifier) if isinstance(node.type.qualifier, list) else node.type.qualifier
                    if "java.util" in qualifier:
                        # 获取漏洞所在的行号
                        line_number = find_line_by_context(lines, "new Random")
                        # 提取漏洞所在行的代码
                        line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                        vulnerabilities.append({
                            "漏洞类型": "不安全的随机数算法",
                            "行号": line_number
                        })
                # 如果没有 qualifier，但使用了 Random，可能是未显式导入 java.util
                elif not hasattr(node.type, 'qualifier'):
                    # 获取漏洞所在的行号
                    line_number = find_line_by_context(lines, "new Random")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    vulnerabilities.append({
                        "漏洞类型": "不安全的随机数算法",
                        "行号": line_number
                    })
        # 检测是否使用了 java.util.concurrent.ThreadLocalRandom
        elif isinstance(node, javalang.tree.MethodInvocation):
            # 检查是否调用了 ThreadLocalRandom.current()
            if hasattr(node, 'member') and node.member == "current":
                if hasattr(node, 'qualifier') and node.qualifier == "ThreadLocalRandom":
                    # 获取漏洞所在的行号
                    line_number = find_line_by_context(lines, "ThreadLocalRandom.current")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    vulnerabilities.append({
                        "漏洞类型": "不安全的随机数算法",
                        "行号": line_number
                    })
            # 检测是否使用了 Math.random()
            elif hasattr(node, 'member') and node.member == "random":
                if hasattr(node, 'qualifier') and node.qualifier == "Math":
                    # 获取漏洞所在的行号
                    line_number = find_line_by_context(lines, "Math.random")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    vulnerabilities.append({
                        "漏洞类型": "不安全的随机数算法",
                        "行号": line_number
                    })

    return vulnerabilities

def detect_unvalidated_redirect(tree, lines):
    vulnerabilities = []

    # 查找所有变量声明及其赋值
    variable_assignments = {}
    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclarator):  # 检查变量声明
            var_name = node.name
            if node.initializer:  # 检查变量是否有初始值
                if isinstance(node.initializer, javalang.tree.Literal):  # 初始值是字面量
                    variable_assignments[var_name] = "safe"
                elif isinstance(node.initializer, javalang.tree.MemberReference):  # 初始值是变量
                    if node.initializer.member == "args":  # 假设args是用户输入
                        variable_assignments[var_name] = "unsafe"
                    else:
                        variable_assignments[var_name] = "unknown"
                elif isinstance(node.initializer, javalang.tree.MethodInvocation):  # 初始值是方法返回值
                    variable_assignments[var_name] = "unknown"

    # 遍历AST，检测重定向漏洞
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):  # 检查方法调用
            if node.member in redirect_methods:  # 检查方法名是否为重定向相关方法
                for arg in node.arguments:  # 遍历方法参数
                    if isinstance(arg, javalang.tree.MemberReference):  # 检查参数是否为变量
                        var_name = arg.member
                        if var_name in variable_assignments:
                            if variable_assignments[var_name] == "unsafe":
                                # 获取漏洞所在行号
                                line_number = node.position.line - 1  # AST的行号从1开始，列表索引从0开始
                                # 提取漏洞所在行的代码
                                line_code = lines[line_number].strip()
                                # 记录漏洞信息
                                vulnerabilities.append({
                                    "漏洞类型": "未经检查的重定向",
                                    "行号": line_number
                                })
                            elif variable_assignments[var_name] == "unknown":
                                # 获取漏洞所在行号
                                line_number = node.position.line - 1
                                # 提取漏洞所在行的代码
                                line_code = lines[line_number].strip()
                                # 记录潜在漏洞信息
                                vulnerabilities.append({
                                    "漏洞类型": "未经检查的重定向",
                                    "行号": line_number
                                })

    return vulnerabilities

