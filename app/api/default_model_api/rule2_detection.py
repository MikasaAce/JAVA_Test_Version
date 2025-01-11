from app.api.main_app.M_app import *


def rule2_detection(arg):
    """通过自定义规则进行检测"""
    folder_path = arg['folder_name']
    item_id = arg['item_id']
    task_name = arg['task_name']
    language = arg['language']
    start_time = get_current_time()
    template = None

    check_result = check_task_name(task_name, item_id)
    if check_result:
        return JsonResponse({"msg": "任务名已存在，请修改任务名", "code": "500"})

    task_id = get_id('taskId', 'vuldetail')
    current_status = '正在检测'
    review_status = '未审核'
    detection_type = '自定义规则检测'
    high_num = 0
    medium_num = 0
    low_num = 0

    folder_path = get_file(folder_path, task_name)
    file_num, code_size, file_size = count_java_files(folder_path)

    if file_num == 0:
        return JsonResponse({'code': '500', 'msg': 'Error! No sample.'})

    vulnerability_detail = vuldetail_insert(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size, file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status, template)
    if vulnerability_detail.status_code == 500:
        return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})

    try:

        file_path_list = []
        for file in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file)
            file_path_list.append(file_path)

        print(file_path_list)

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

            print(vulnerabilities)
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
                    line_number = result['行号']
                    test_result.append({
                        'filename': filename,
                        'file_path': path,
                        'cwe_id': '',
                        'vul_name': vulnerability_name,
                        'code': '',
                        'line_number': line_number,
                        'risk_level': '',
                        'repair_code': '',
                        'new_line_number': '',
                        'repair_status': '未修复',
                        'is_question': '是问题',
                        'model': ''
                    })
                    vulfile_insert(task_id, file_id, test_result)
                    vul_name = vulnerability_name
                    cwe_id = ''
                    try:
                        vul_level = get_level(cwe_id, vul_name)  # 根据漏洞名称获取漏洞危险等级
                    except Exception as e:
                        # 捕获规则函数执行错误，并记录错误日志
                        print(f"Error in get level '{vul_name}'")
                        traceback.print_exc()  # 打印详细的错误堆栈信息
                        continue
                    if vul_level == '高危':
                        high_num += 1
                    elif vul_level == '中危':
                        medium_num += 1
                    elif vul_level == '低危':
                        low_num += 1

        end_time = get_current_time()
        start_time = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end_time = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        last_time = end_time - start_time
        hours, remainder = divmod(last_time.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        last_time_str = f"{hours}时{minutes}分{seconds}秒"

        current_status = '检测完成'
        vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, high_num, medium_num,
                                                low_num, code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, end_time, last_time_str, review_status)

        if vulnerability_detail.status_code == 200:
            return JsonResponse({"msg": "漏洞信息页面数据插入成功", "code": "200"})
        else:
            return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})

    except Exception as e:
        # 捕获全局异常，并打印详细的错误堆栈信息
        print("An error occurred:")
        traceback.print_exc()  # 打印详细的错误堆栈信息

        current_status = '检测失败'
        vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, 0, 0, review_status)

        if vulnerability_detail.status_code == 200:
            return JsonResponse({"msg": "规则扫描失败，漏洞信息页面数据插入成功", "code": "200", "error": str(e)})
        else:
            return JsonResponse({"msg": "规则扫描失败，漏洞信息页面数据插入错误", "code": "500", "error": str(e)})

