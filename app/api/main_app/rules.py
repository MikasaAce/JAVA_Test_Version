import javalang
import esprima
import yaml

def parse_java_code(code):
    # 将代码按行分割，方便后续提取特定行的代码
    lines = code.splitlines()
    tree = javalang.parse.parse(code)
    return tree, lines

def find_line_by_context(lines, context):
    for i, line in enumerate(lines):
        if context in line:
            return i + 1  # 行号从 1 开始
    return "Unknown"

def check_sql_injection(ast, lines):
    vulnerabilities = []
    for path, node in ast:
        # 检查是否在创建SQL语句
        if isinstance(node, javalang.tree.MethodInvocation) and node.member == "createStatement":
            # 检查是否有字符串拼接操作
            for _, child in node:
                if isinstance(child, javalang.tree.BinaryOperation) and child.operator == "+":
                    vulnerabilities.append({
                        '漏洞类型': 'SQL Injection',
                        '行号': node.position.line if node.position else None
                    })
    return vulnerabilities

def detect_missing_httponly(ast, lines):
    tree = ast
    vulnerabilities = []

    # 遍历所有方法调用
    for path, node in tree.filter(javalang.tree.MethodInvocation):
        # 检查是否调用了 addCookie 方法
        if node.member == "addCookie" and node.arguments:
            cookie_arg = node.arguments[0]

            # 检查是否是变量引用类型
            if isinstance(cookie_arg, javalang.tree.MemberReference):
                cookie_var = cookie_arg.member
                httponly_set = False

                # 遍历所有方法调用，检查是否对该变量调用了 setHttpOnly
                for _, stmt in tree.filter(javalang.tree.MethodInvocation):
                    if (stmt.member == "setHttpOnly" and
                        isinstance(stmt.qualifier, str) and
                        stmt.qualifier == cookie_var):
                        httponly_set = True
                        break

                if not httponly_set:
                    vulnerabilities.append({
                        "漏洞类型": "Cookie Security: HTTPOnly not Set",
                        "行号": node.position.line if node.position else "Unknown",
                        "description": f"Cookie '{cookie_var}' does not have HTTPOnly attribute set."
                    })

            # 检查是否直接使用 new Cookie() 作为参数
            elif isinstance(cookie_arg, javalang.tree.ClassCreator):
                if cookie_arg.type.name == "Cookie":
                    vulnerabilities.append({
                        "漏洞类型": "Cookie Security: HTTPOnly not Set",
                        "行号": node.position.line if node.position else "Unknown",
                    })

    return vulnerabilities

def detect_log_forgery(ast, lines):
    """
    检测Java AST中的日志伪造漏洞。

    :param ast: Java AST对象
    :return: 包含潜在日志伪造漏洞的代码位置列表
    """

    def get_input_variables(ast):
        input_variables = set()
        input_functions = ['getRequestParameter', 'getFormData', 'getUrlParameter', 'readFileUpload', "nextLine",
                           "readLine"]
        # 第一次遍历：识别用户输入的变量
        for path, node in ast:
            if isinstance(node, javalang.tree.VariableDeclarator):
                variable_name = node.name
                if isinstance(node.initializer, javalang.tree.MethodInvocation):
                    if node.initializer.member in input_functions:
                        input_variables.add(variable_name)

        return input_variables

    def is_user_input(node, input_variable):
        is_input = False
        # 检查节点是否为变量引用或方法调用的结果
        if isinstance(node, javalang.tree.MemberReference):
            variable_name = node.member
            # 检查变量名是否来自用户输入
            if variable_name in input_variable:
                is_input = True
        elif isinstance(node, javalang.tree.MethodInvocation):
            # 检查是否为`String.format`等方法
            if node.member == 'format':
                for arg in node.arguments:
                    if is_user_input(arg):
                        is_input = True
        elif isinstance(node, javalang.tree.BinaryOperation):
            # 检查操作符是否为'+'
            if node.operator == '+':
                is_input = True
        return is_input

    vulnerabilities = []

    input_variables = get_input_variables(ast)


    # 遍历AST节点
    for path, node in ast:
        # 检查节点是否为方法调用
        if isinstance(node, javalang.tree.MethodInvocation):
            method_name = node.member
            # 检查是否为日志记录方法
            if method_name in ['info', 'severe', 'warning', 'fine']:
                # 检查参数是否包含用户输入
                for arg in node.arguments:
                    if is_user_input(arg, input_variables):
                        vulnerabilities.append({
                            '行号': node.position.line if node.position else None,  # 记录行号
                            '漏洞类型': 'Log Forging'
                        })

    return vulnerabilities



def detect_webpack_vulnerabilities(tree,lines):
    vulnerabilities = []

    # 遍历 AST 节点
    for path, node in tree:
        # 检测是否导出了 Webpack 配置
        if node.type == "ExpressionStatement" and \
           node.expression.type == "AssignmentExpression" and \
           node.expression.left.property.name == "exports":
            config = node.expression.right

            # 检测 mode 是否为 production
            if config.type == "ObjectExpression":
                for prop in config.properties:
                    if prop.key.name == "mode":
                        if prop.value.value != "production":
                            vulnerabilities.append({
                                "行号": prop.value.loc.start.line if prop.value.loc else None,
                                "漏洞类型": "Insecure Webpack Configuration",
                            })

                    # 检测 devtool 是否为不安全选项
                    if prop.key.name == "devtool":
                        if prop.value.value in ["eval", "inline-source-map", "eval-source-map", "cheap-eval-source-map", "cheap-module-eval-source-map", "inline-cheap-source-map", "inline-cheap-module-source-map"]:
                            vulnerabilities.append({
                                "行号": prop.value.loc.start.line if prop.value.loc else None,
                                "漏洞类型": "Insecure Webpack Configuration",
                            })

                    # 检测是否启用了最小化
                    if prop.key.name == "optimization":
                        if prop.value.type == "ObjectExpression":
                            for opt_prop in prop.value.properties:
                                if opt_prop.key.name == "minimize" and opt_prop.value.value is False:
                                    vulnerabilities.append({
                                        "行号": prop.value.loc.start.line if prop.value.loc else None,
                                        "漏洞类型": "Insecure Webpack Configuration",
                                    })

    return vulnerabilities

def detect_vite_config(ast,lines):
    issues = []

    # 遍历 AST 查找 mode、server.host 和 build.sourcemap 配置
    for path, node in ast:
        if node.type == 'ExportDefaultDeclaration' and \
           node.declaration.type == 'CallExpression' and \
           node.declaration.callee.name == 'defineConfig':
            config = node.declaration.arguments[0]
            for prop in config.properties:
                if prop.key.name == 'mode' and prop.value.value == 'development':
                    issues.append({
                        '行号': prop.value.loc.start.line if prop.value.loc else None,
                        '漏洞类型': 'Insecure Vite Configuration',
                    })
                if prop.key.name == 'server':
                    for server_prop in prop.value.properties:
                        if server_prop.key.name == 'host' and server_prop.value.value == '0.0.0.0':
                            issues.append({
                                '行号': server_prop.value.loc.start.line if server_prop.value.loc else None,
                                '漏洞类型': 'Insecure Vite Configuration',
                            })
                if prop.key.name == 'build':
                    for build_prop in prop.value.properties:
                        if build_prop.key.name == 'sourcemap' and build_prop.value.value == True:
                            issues.append({
                                '行号': build_prop.value.loc.start.line if build_prop.value.loc else None,
                                '漏洞类型': 'Insecure Vite Configuration',
                            })
    return issues

def detect_spring_boot_vulnerabilities(tree,lines):
    vulnerabilities = []

    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检查是否使用了 HTTP Basic 认证
            if node.member == "httpBasic":
                vulnerabilities.append({
                    "行号": node.position.line if node.position else None,
                    "漏洞类型": "Insecure Spring Boot Configuration",
                })

            # 检查是否未启用 HTTPS
            if node.member == "authorizeRequests":
                vulnerabilities.append({
                    "行号": node.position.line if node.position else None,
                    "漏洞类型": "Insecure Spring Boot Configuration",
                })

            # 检查是否未保护敏感端点（如 /actuator）
            if node.member == "antMatchers":
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.Literal) and "/actuator" in arg.value:
                        vulnerabilities.append({
                            "行号": node.position.line if node.position else None,
                            "漏洞类型": "Insecure Spring Boot Configuration",
                        })

        # 检查是否未禁用调试模式
        if isinstance(node, javalang.tree.Literal):
            if node.value == "true" and "debug" in path:
                vulnerabilities.append({
                    "行号": node.position.line if node.position else None,
                    "漏洞类型": "Insecure Spring Boot Configuration",
                })


    return vulnerabilities

def detect_robots_config_vulnerability(tree,lines):
    """
    基于 AST 检测 robots.txt 配置漏洞
    """
    vulnerabilities = []

    for path, node in tree:
        if isinstance(node, javalang.tree.VariableDeclarator) and node.name == "robotsContent":
            # 检查robotsContent的内容

            if "Disallow: /config" not in node.initializer.value or "Allow: /public" in node.initializer.value:
                vulnerabilities.append({
                    '漏洞类型': 'Insecure Robots Configuration',
                    '行号': node.position.line if node.position else None
                })
    return vulnerabilities

def detect_debug_mode_vulnerability(tree,lines):
    """
    基于 AST 检测调试模式开启漏洞
    """
    vulnerabilities = []

    for path, node in tree:
        # 检查是否调用了 setAdditionalProfiles 方法并传入了 "debug"
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "setAdditionalProfiles":
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.Literal) and arg.value == '"debug"':
                        vulnerabilities.append({
                            '漏洞类型': 'Debug Mode Enabled',
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
                            "漏洞类型": "Insecure Encryption",
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
                            "漏洞类型": "Insecure Hash",
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
                            "漏洞类型": "Insecure Random",
                            "行号": line_number
                        })
                # 如果没有 qualifier，但使用了 Random，可能是未显式导入 java.util
                elif not hasattr(node.type, 'qualifier'):
                    # 获取漏洞所在的行号
                    line_number = find_line_by_context(lines, "new Random")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    vulnerabilities.append({
                        "漏洞类型": "Insecure Random",
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
                        "漏洞类型": "Insecure Random",
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
                        "漏洞类型": "Insecure Random",
                        "行号": line_number
                    })

    return vulnerabilities

def detect_unvalidated_redirect(tree, lines):
    # 定义可能涉及重定向的关键方法
    redirect_methods = ["sendRedirect", "setHeader", "forward"]
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
                                    "漏洞类型": "Unvalidated Redirect",
                                    "行号": line_number
                                })
                            elif variable_assignments[var_name] == "unknown":
                                # 获取漏洞所在行号
                                line_number = node.position.line - 1
                                # 提取漏洞所在行的代码
                                line_code = lines[line_number].strip()
                                # 记录潜在漏洞信息
                                vulnerabilities.append({
                                    "漏洞类型": "Unvalidated Redirect",
                                    "行号": line_number
                                })

    return vulnerabilities

def MongoDB_detect(tree, lines):
    vulnerabilities = []
    db_methods = ["find", "update", "delete"]
    dangerous_operations = ["+", "format", "append"]
    for path, node in tree:
        if isinstance(node, javalang.tree.LocalVariableDeclaration):
            for declarator in node.declarators:
                if hasattr(declarator, 'initializer'):
                    initializer = declarator.initializer
                    # 检查初始值是否为 BinaryOperation
                    if isinstance(initializer, javalang.tree.BinaryOperation):
                        if initializer.operator in dangerous_operations:
                            line_number = node.position.line if hasattr(node, 'position') and node.position else 'unknown'
                            vulnerabilities.append({
                               "漏洞类型": "MongoDB injection",
                               "行号": line_number
                            })
                        # 递归检查 BinaryOperation 的操作数
                        for operand in [initializer.operandl, initializer.operandr]:
                            if isinstance(operand, javalang.tree.Identifier):
                                # 检查是否直接使用了用户输入
                                line_number = node.position.line if hasattr(node, 'position') and node.position else 'unknown'
                                vulnerabilities.append({
                                   "漏洞类型": "MongoDB injection",
                                   "行号": line_number
                                }) 
                            elif isinstance(operand, javalang.tree.BinaryOperation):
                                 if operand.operator in dangerous_operations:
                                     line_number = node.position.line if hasattr(node, 'position') and node.position else 'unknown'
                                     vulnerabilities.append({
                                        "漏洞类型": "MongoDB injection",
                                        "行号": line_number
                                     })
    return vulnerabilities

def SQL_Injection_Blind(tree, lines):
    vulnerabilities = []
    db_methods = ["executeQuery", "executeUpdate", "execute"]
    dangerous_operations = ["+", "format", "append"]
    for path, node in tree:
       if isinstance(node, javalang.tree.LocalVariableDeclaration):
        for declarator in node.declarators:
            if hasattr(declarator, 'initializer'):
                initializer = declarator.initializer
                if isinstance(initializer, javalang.tree.BinaryOperation):
                    if initializer.operator in dangerous_operations:
                        if hasattr(node, 'position') and node.position:
                           line_number=node.position.line
                           vulnerabilities.append({
                                "漏洞类型": "SQL blinds",
                                "行号": line_number
                           })
                    for operand in [initializer.operandl, initializer.operandr]:
                        if isinstance(operand, javalang.tree.MemberReference):
                            if hasattr(node, 'position') and node.position:
                               line_number=node.position.line
                               vulnerabilities.append({
                                    "漏洞类型": "SQL blinds",
                                    "行号": line_number
                               })
                        elif isinstance(operand, javalang.tree.BinaryOperation):
                            if operand.operator in dangerous_operations:
                                if hasattr(node, 'position') and node.position:
                                   line_number=node.position.line
                                   vulnerabilities.append({
                                        "漏洞类型": "SQL blinds",
                                        "行号": line_number
                                   })
       elif isinstance(node, javalang.tree.MethodInvocation):
            if node.member in db_methods:
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.BinaryOperation):
                        if arg.operator in dangerous_operations:
                           if hasattr(node, 'position') and node.position:
                              line_number=node.position.line
                              vulnerabilities.append({
                                   "漏洞类型": "SQL blinds",
                                   "行号": line_number
                              })
                    elif isinstance(arg, javalang.tree.MemberReference):
                        if hasattr(node, 'position') and node.position:
                           line_number=node.position.line
                           vulnerabilities.append({
                                "漏洞类型": "SQL blinds",
                                "行号": line_number                                
                           })
            return vulnerabilities

def Xquery_Injection(tree, lines):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member in ["prepareExpression", "prepareStatement", "executeQuery"]:
                # 找到 prepareExpression 后，遍历整个 AST 检查所有 BinaryOperation
                for path, sub_node in tree:
                    if isinstance(sub_node, javalang.tree.BinaryOperation):
                        if sub_node.operator == "+":
                            if isinstance(sub_node.operandl, javalang.tree.Literal) and isinstance(sub_node.operandr, javalang.tree.MemberReference):
                                # 检查 position 是否存在
                                if sub_node.position is not None:
                                    vulnerabilities.append({
                                        "漏洞类型": "XQuery Injection",
                                        "行号": sub_node.position.line
                                    })

    return vulnerabilities

def OGNL_expression_injection(tree, lines):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "getValue" and node.qualifier == "Ognl":
                # 检查是否直接使用了用户输入
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.MemberReference) and arg.member == "userInput":
                        vulnerabilities.append({
                            "漏洞类型": "OGNL Expression Injection",
                            "行号": node.position.line
                        })
    return vulnerabilities

def find_stored_xss_vulnerabilities(tree, lines):
    vulnerabilities = []

    for path, node in tree:
        # 检查是否有直接存储用户输入的操作
        if isinstance(node, javalang.tree.MethodInvocation):
            if hasattr(node, 'member'):
                # 检测 Map.put 操作
                if node.member == "put":
                    if hasattr(node, 'qualifier') and isinstance(node.qualifier, javalang.tree.MemberReference):
                        if node.qualifier.member in ["comments", "feedbacks", "reviews"]:
                            # 获取行号
                            line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                            # 如果行号为 Unknown，通过上下文定位
                            if line_number == "Unknown":
                                line_number = find_line_by_context(lines, f"{node.qualifier.member}.put(")
                            # 提取漏洞所在行的代码
                            line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                            vulnerabilities.append({
                                "漏洞类型": "Stored XSS - Unsafe Storage",
                                "行号": line_number
                            })
                # 检测 List.add 操作
                elif node.member == "add":
                    if hasattr(node, 'qualifier') and isinstance(node.qualifier, javalang.tree.MemberReference):
                        if node.qualifier.member in ["posts", "messages"]:
                            # 获取行号
                            line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                            # 如果行号为 Unknown，通过上下文定位
                            if line_number == "Unknown":
                                line_number = find_line_by_context(lines, f"{node.qualifier.member}.add(")
                            # 提取漏洞所在行的代码
                            line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                            vulnerabilities.append({
                                "漏洞类型": "Stored XSS - Unsafe Storage",
                                "行号": line_number
                            })

        # 检查是否有直接输出用户输入的操作
        if isinstance(node, javalang.tree.MethodInvocation):
            if hasattr(node, 'member'):
                # 检测 Map.get 操作
                if node.member == "get":
                    if hasattr(node, 'qualifier') and isinstance(node.qualifier, javalang.tree.MemberReference):
                        if node.qualifier.member in ["comments", "feedbacks", "reviews"]:
                            # 获取行号
                            line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                            # 如果行号为 Unknown，通过上下文定位
                            if line_number == "Unknown":
                                line_number = find_line_by_context(lines, f"{node.qualifier.member}.get(")
                            # 提取漏洞所在行的代码
                            line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                            vulnerabilities.append({
                                "漏洞类型": "Stored XSS - Unsafe Storage",
                                "行号": line_number
                            })
                # 检测 List 遍历输出操作
                elif node.member == "println":
                    if hasattr(node, 'qualifier') and node.qualifier == "System.out":
                        # 获取行号
                        line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                        # 如果行号为 Unknown，通过上下文定位
                        if line_number == "Unknown":
                            line_number = find_line_by_context(lines, "System.out.println(")
                        # 提取漏洞所在行的代码
                        line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                        vulnerabilities.append({
                            "漏洞类型": "Stored XSS - Unsafe Storage",
                            "行号": line_number
                        })

    return vulnerabilities

def find_dom_xss_vulnerabilities(tree, lines):
    vulnerabilities = []

    for path, node in tree:
        # 检查是否有直接使用用户输入操作 DOM 的代码
        if isinstance(node, javalang.tree.VariableDeclarator):
            if node.name == "script" or node.name == "userInput":
                # 获取行号
                line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                # 如果行号为 Unknown，通过上下文定位
                if line_number == "Unknown":
                    line_number = find_line_by_context(lines, f"String {node.name} =")
                # 提取漏洞所在行的代码
                line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                vulnerabilities.append({
                    "漏洞类型": "DOM XSS - Unsafe DOM Manipulation",
                    "行号": line_number
                })

        # 检查是否有直接使用用户输入的 JavaScript 代码
        if isinstance(node, javalang.tree.MethodInvocation):
            if hasattr(node, 'member') and node.member == "eval":
                if hasattr(node, 'qualifier') and node.qualifier == "engine":
                    # 获取行号
                    line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                    # 如果行号为 Unknown，通过上下文定位
                    if line_number == "Unknown":
                        line_number = find_line_by_context(lines, "engine.eval(")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    vulnerabilities.append({
                        "漏洞类型": "DOM XSS - Unsafe DOM Manipulation",
                        "行号": line_number
                    })

        # 检查是否有直接使用用户输入的 document.write
        if isinstance(node, javalang.tree.MethodInvocation):
            if hasattr(node, 'member') and node.member == "write":
                if hasattr(node, 'qualifier') and node.qualifier == "document":
                    # 获取行号
                    line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                    # 如果行号为 Unknown，通过上下文定位
                    if line_number == "Unknown":
                        line_number = find_line_by_context(lines, "document.write(")
                    # 提取漏洞所在行的代码
                    line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                    vulnerabilities.append({
                        "漏洞类型": "DOM XSS - Unsafe DOM Manipulation",
                        "行号": line_number
                    })

        # 检查是否有直接使用用户输入的 innerHTML
        if isinstance(node, javalang.tree.Assignment):
            if hasattr(node, 'member') and node.member == "innerHTML":
                # 获取行号
                line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                # 如果行号为 Unknown，通过上下文定位
                if line_number == "Unknown":
                    line_number = find_line_by_context(lines, "innerHTML =")
                # 提取漏洞所在行的代码
                line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                vulnerabilities.append({
                    "漏洞类型": "DOM XSS - Unsafe DOM Manipulation",
                    "行号": line_number
                })

        # 检查是否有直接使用用户输入的 href
        if isinstance(node, javalang.tree.Assignment):
            if hasattr(node, 'member') and node.member == "href":
                # 获取行号
                line_number = node.position.line if hasattr(node, 'position') and node.position else "Unknown"
                # 如果行号为 Unknown，通过上下文定位
                if line_number == "Unknown":
                    line_number = find_line_by_context(lines, "href =")
                # 提取漏洞所在行的代码
                line_code = lines[line_number - 1].strip() if line_number != "Unknown" else "Unknown"
                vulnerabilities.append({
                    "漏洞类型": "DOM XSS - Unsafe DOM Manipulation",
                    "行号": line_number
                })

    return vulnerabilities

def Spel_Injection(tree, lines):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "parseExpression":
                if len(node.arguments) > 0 and isinstance(node.arguments[0], javalang.tree.MemberReference):
                    line_number=node.position.line
                    vulnerabilities.append({
                        "漏洞类型": "Spel expression injection",
                        "行号": line_number
                    })
    return vulnerabilities


def Hibernate_Injection(tree, lines):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == 'createQuery':
                for path, arg in tree:
                    if isinstance(arg, javalang.tree.BinaryOperation):
                        if arg.operator == '+' and isinstance(arg.operandl, javalang.tree.Literal) and isinstance(arg.operandr, javalang.tree.MemberReference):
                            line_number = node.position.line
                            vulnerabilities.append({
                                "漏洞类型": "Hibernate injection",
                                "行号": line_number
                            })

    return vulnerabilities

def SQL_Injection(tree, lines):
    vulnerabilities = []
    for path, node in tree:
        # 检查变量声明和初始化
        if isinstance(node, javalang.tree.VariableDeclarator):
            if node.initializer and isinstance(node.initializer, javalang.tree.BinaryOperation):
                # 检查左操作数是否是字面量
                if isinstance(node.initializer.operandl.operandl, javalang.tree.Literal):
                    # 检查右操作数是否是成员引用
                    if isinstance(node.initializer.operandl.operandr, javalang.tree.MemberReference):
                        if "sql" in node.name.lower():
                            for parent_node in path:
                                if isinstance(parent_node, javalang.tree.LocalVariableDeclaration):
                                    vulnerabilities.append({
                                        "漏洞类型": "SQL Injection",
                                        "行号": parent_node.position.line
                                    })
                                    break


        # 检查方法调用
        elif isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "query" or node.member == "executeQuery":
                for arg in node.arguments:
                    # 检查参数是否是二元操作（字符串拼接）
                    if isinstance(arg, javalang.tree.BinaryOperation):
                        vulnerabilities.append({
                            "漏洞类型": "SQL Injection",
                            "行号": node.position.line
                        })

    return vulnerabilities

def JSON_Injection(tree, lines):
    vulnerabilities = []
    for path, node in tree:
        if isinstance(node, javalang.tree.MethodInvocation):
            if node.member == "put" and node.qualifier == "json":
                for arg in node.arguments:
                    if isinstance(arg, (javalang.tree.MemberReference, javalang.tree.Literal)):
                        if isinstance(arg, javalang.tree.MemberReference) and arg.member == "userInput":
                            vulnerabilities.append({
                                "漏洞类型": "JSON Injection",
                                "行号": node.position.line
                            })
                            break
                        elif isinstance(arg, javalang.tree.Literal) and not arg.value.isdigit():
                            vulnerabilities.append({
                                "漏洞类型": "JSON Injection",
                                "行号": node.position.line
                            })
                            break

    return vulnerabilities


def Nosql_Injection(tree, lines):
    vulnerabilities = []

    # 收集所有用户输入的变量
    user_input_vars = set()
    for path, node in tree:
        if isinstance(node, javalang.tree.FormalParameter):
            user_input_vars.add(node.name)

    # 遍历 AST，查找 NoSQL 注入漏洞
    for path, node in tree:
        # 检查是否是 ClassCreator 节点，且类型为 Document
        if isinstance(node, javalang.tree.ClassCreator) and node.type.name == "Document":
            # 遍历 ClassCreator 的参数
            for arg in node.arguments:
                # 检查参数是否是用户输入的变量
                if isinstance(arg, javalang.tree.MemberReference) and arg.member in user_input_vars:
                    vulnerabilities.append({
                        "漏洞类型": "Nosql Injection",
                        "行号": arg.position.line
                    })


    return vulnerabilities


def XML_entity_injection(tree, lines):
    vulnerabilities = []

    for path, node in tree:
        # 检查是否是 MethodInvocation 节点
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检查是否是 builder.parse(...) 调用
            if (
                    hasattr(node, 'qualifier') and node.qualifier == 'builder' and  # qualifier 是 'builder'
                    hasattr(node, 'member') and node.member == 'parse' and  # member 是 'parse'
                    hasattr(node, 'arguments') and node.arguments is not None  # 参数不为空
            ):
                # 检查参数是否是 ByteArrayInputStream
                for arg in node.arguments:
                    if isinstance(arg, javalang.tree.ClassCreator):
                        if (
                                hasattr(arg, 'type') and
                                isinstance(arg.type, javalang.tree.ReferenceType) and
                                arg.type.name == 'ByteArrayInputStream'
                        ):
                            vulnerabilities.append({
                                "漏洞类型": "XML entity injection",
                                "行号": node.position.line
                            })
    return vulnerabilities

def detect_LDAP_Injection(tree, lines):
    """
    检测LDAP注入漏洞
    """
    vulnerabilities = []

    def is_user_input(node, tree):
        """
        判断节点是否包含用户输入
        """
        if isinstance(node, javalang.tree.MethodInvocation):
            # 检查是否是 request.getParameter 的调用
            if node.member == "getParameter" and node.qualifier == "request":
                return True

        if isinstance(node, javalang.tree.BinaryOperation):
            # 检查是否是字符串拼接操作
            if node.operator == "+":
                return is_user_input(node.operandl, tree) or is_user_input(node.operandr, tree)

        if isinstance(node, javalang.tree.MemberReference):
            # 检查是否是用户输入的变量
            for path2, node2 in tree:
                if isinstance(node2, javalang.tree.VariableDeclarator):
                    if node2.name == node.member:
                        if node2.initializer and is_user_input(node2.initializer, tree):
                            return True
        return False


    # 遍历AST节点
    for path, node in tree:
        # 检查是否创建了 org.owasp.benchmark.helpers.LDAPManager 对象
        if isinstance(node, javalang.tree.ClassCreator):
            if (
                    node.type.name == 'org'
                    and node.type.sub_type.name == 'owasp'
                    and node.type.sub_type.sub_type.name == 'benchmark'
                    and node.type.sub_type.sub_type.sub_type.name == 'helpers'
                    and node.type.sub_type.sub_type.sub_type.sub_type.name == 'LDAPManager'
            ):

                # 判断是否有用户输入
                for path2, node2 in tree:
                    if isinstance(node2, javalang.tree.MethodInvocation):
                        for arg in node2.arguments:
                            if is_user_input(arg, tree):
                                vulnerabilities.append({
                                    '行号': node2.position.line if node2.position else None,
                                    '漏洞类型': 'LDAP Injection',
                                })


    return vulnerabilities

