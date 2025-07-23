from app.api.main_app.M_app import *

def get_level_EN_CN(vul_name):
    # 根据cwe_id获取危险等级
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                if vul_name:
                    name_sql = """select name_CN from subVulList where name_EN = %s"""
                    cursor.execute(name_sql, (vul_name,))
                data = cursor.fetchall()
                if data:
                    return data[0][0]
                else:
                    print("未能查询到中文名的漏洞类型",vul_name)
                    return "Vulnerability level not found"
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}{vul_name}")
    return "Error occurred while fetching vulnerability level"

def rule2_detection(arg):
    """通过自定义规则进行检测"""
    folder_path = arg['folder_path']
    item_id = arg['item_id']
    task_name = arg['task_name']
    language = arg['language']
    task_id = arg['task_id']

    try:
        file_path_list = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                # 如果文件以 .jar 结尾，则跳过该文件
                if not file.endswith('.jar'):
                    file_path_list.append(os.path.join(root, file))

        print(len(file_path_list))

        # 从数据库加载规则
        rows = load_rules()

        # 动态加载规则函数
        rules_module = importlib.import_module("rules")
        rules = []
        for row in rows:
            function_name = row["function_name"]
            if hasattr(rules_module, function_name):
                rules.append(getattr(rules_module, function_name))

        for i, path in enumerate(file_path_list):
            code = read_file(path)
            path = code['path']
            data = code['data']
            code_lines = data.splitlines()
            # 去除注释等信息
            if path.endswith('.java'):
                data_filter = filter_java_code(data)
                try:
                    print(path)
                    ast = javalang.parse.parse(data_filter)  # 将java代码转为AST
                except javalang.parser.JavaSyntaxError as e:
                    # 如果转换AST失败，记录错误并跳过该文件
                    print(f"Failed to parse {path} to AST: {e}")
                    continue
            elif path.endswith('.js'):
                # data_filter = filter_javascript_code(data)
                try:
                    ast = esprima.parseScript(data, {"loc": True})  # 将javascript代码转为AST
                except esprima.Error as e:
                    # 如果转换AST失败，记录错误并跳过该文件
                    print(f"Failed to parse {path} to AST: {e}")
                    continue

            vulnerabilities = []
            for rule in rules:
                try:
                    vulnerabilities.extend(rule(ast, code_lines))  # 调用规则函数
                except Exception as e:
                    # 捕获规则函数执行错误，并记录错误日志
                    print(f"Error in rule function '{rule.__name__}' for file {path}: {e}")
                    traceback.print_exc()  # 打印详细的错误堆栈信息
                    continue

            vuln_rules_list = get_custom_rules(language)
            print("自定义规则列表:", vuln_rules_list)
            custom_result = detect_vulnerabilities_with_strings(vuln_rules_list, code_lines) # 获取自定义规则的检测结果
            print("自定义规则扫描结果:", custom_result)
            vulnerabilities.extend(custom_result) # 将自定义规则的检测结果添加到总结果中

            print("规则检测结果：", vulnerabilities)
            for result in vulnerabilities:
                clean_func_list = get_clean_func(language, result['漏洞类型'])  # 获取清洁函数列表
                print("清洁函数列表:", clean_func_list)
                code_lines = data.splitlines()
                is_cleaned = is_sanitization_present(clean_func_list, code_lines)  # 判断这段代码中是否包含对应类型的清洁函数
                print("是否包含清洁函数:", is_cleaned)
                if is_cleaned is True:  # 如果包含对应的清洁函数
                    break
                else:
                    test_result = []
                    file_id = get_id('fileId', 'vulfile')
                    filename = os.path.basename(path)
                    vulnerability_name = result['漏洞类型']
                    # line_number = result['行号'] if type(result['行号']) == int else 0
                    # if 1 <= line_number <= len(code_lines):
                    #     Sink = code_lines[line_number - 1]
                    #     Enclosing_Method = code_lines[line_number - 1]
                    #     Source = code_lines[line_number - 1]
                    # else:
                    #     Sink = ''
                    #     Enclosing_Method = ''
                    #     Source = ''
                    line_number = result['爆发点行号'] if type(result['爆发点行号']) == int else 0
                    vul_line_number = result['爆发点函数行号'] if type(result['爆发点函数行号']) == int else 0
                    if 1 <= line_number <= len(code_lines):
                        Sink = code_lines[line_number - 1] # 漏洞爆发点
                        print("Sink:", Sink)
                    else:
                        Sink = ''
                    if 1 <= vul_line_number <= len(code_lines):
                        Enclosing_Method = code_lines[vul_line_number - 1] # 爆发点函数
                        print("Enclosing_Method:", Enclosing_Method)
                    else:
                        Enclosing_Method = ''
                    Source = '' # 缺陷源
                    test_result.append({
                        'filename': filename,
                        'file_path': path,
                        'cwe_id': '',
                        'vul_name': get_level_EN_CN(vulnerability_name),
                        'code': '',
                        'line_number': line_number,
                        'risk_level': '',
                        'repair_code': '',
                        'new_line_number': '',
                        'repair_status': '未修复',
                        'is_question': '是问题',
                        'model': '',
                        'Sink':Sink,
                        'Enclosing_Method':Enclosing_Method,
                        'Source':Source
                    })
                    vulfile_insert(task_id, file_id, test_result)

        return JsonResponse({"msg": "自定义规则扫描成功", "code": "200"})


    except Exception as e:
        # 捕获全局异常，并打印详细的错误堆栈信息
        print("An error occurred:")
        traceback.print_exc()  # 打印详细的错误堆栈信息

        return JsonResponse({"msg": "自定义规则扫描失败", "code": "500", "error": str(e)})

