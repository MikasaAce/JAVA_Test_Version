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

def rule1_detection(arg):
    """只使用fortify扫描"""
    folder_path = arg['folder_path']
    item_id = arg['item_id']
    task_name = arg['task_name']
    template = arg['template']
    version = arg['version']
    language = arg['language']
    start_time = get_current_time()
    url_git = arg.get('url_git') or None   # 不存在或空串都变 None
    branch  = arg.get('branch')  or None   # 不存在或空串都变 None
    print(22222222)

    check_result = check_task_name(task_name, item_id)
    if check_result:
        return JsonResponse({"msg": "任务名已存在，请修改任务名", "code": "500"})

    folder_path = get_file_rule1(folder_path, task_name, language)
    file_num, code_size, file_size = count_java_files(folder_path)

    if file_num == 0:
        return JsonResponse({'code': '500', 'msg': 'Error! 文件夹为空！'})

    task_id = get_id('taskId', 'vuldetail')
    current_status = '正在检测'
    review_status = '未审核'
    detection_type = '规则扫描'
    high_num = 0
    medium_num = 0
    low_num = 0

    vulnerability_detail = vuldetail_insert_except_java(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size, file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status, branch, url_git, version)

    if vulnerability_detail.status_code == 500:
        return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})

    try:
        pid = os.getpid()
        print(f"当前进程的PID是: {pid}")
        result = update_pid(task_id, pid)
        if result == 'Success':
            print("pid插入成功")
        else:
            print("pid插入失败")
    except Exception as e:
        print(f"pid插入失败: {e}")

    try:
        run_fortify(folder_path, template, version)  # fortify扫描全部文件
        folder_name = os.path.basename(os.path.normpath(folder_path))  # 获取文件夹的名字
        pdf_file_path = os.path.join(folder_path, folder_name + '.pdf')  # 获取fortify扫描得到的pdf文件的路径
        print(pdf_file_path)
        if template != "Developer Workbook":
            result_list = location_fortify(folder_path, pdf_file_path, template)  # fortify扫描得到的结果列表
        else:
            result_list = location_fortify_3(folder_path, pdf_file_path)  # fortify扫描得到结果列表，只不过是Developer Workbook规范
            # print("*************************************")
            # print(result_list)
            # print("*************************************")
        for result in result_list:
            test_result = []
            file_id = get_id('fileId', 'vulfile')
            file_name = result['filename']
            file_path = os.path.join(folder_path, file_name)
            cwe_id = result['cwe_id']
            vul_name = result['vul_name']
            code = result['code']
            line_number = result['line_number']
            new_line_number = result['new_line_number']
            Sink = result['Sink']
            Enclosing_Method = result['Enclosing_Method']
            Source = result['Source']
            test_result.append({
                'filename': file_name,
                'file_path': file_path,
                'cwe_id': cwe_id,
                'vul_name': get_level_EN_CN(vul_name),
                'code': code,
                'line_number': line_number,
                'src_line_number': 0,
                'func_line_number': new_line_number,
                'risk_level': '',
                'repair_code': '',
                'new_line_number': new_line_number,
                'repair_status': '未修复',
                'is_question': '是问题',
                'Sink': Sink,
                'Enclosing_Method': Enclosing_Method,
                'Source': Source,
                'model': detection_type,
                'src_filename': file_name
            })
            vul_level = get_level(cwe_id, vul_name)  # 根据cweid或vul_name获取漏洞危险等级
            test_result[-1]['risk_level'] = vul_level
            vulfile_insert(task_id, file_id, test_result)  # 将扫描结果存入数据库文件表

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
                                                start_time, end_time, last_time_str, review_status)  # 将扫描结果存入数据库任务表

        if vulnerability_detail.status_code == 200:
            return JsonResponse({"msg": "规则扫描成功，漏洞信息页面数据插入成功", "code": "200"})
        else:
            return JsonResponse({"msg": "规则扫描成功，漏洞信息页面数据插入错误", "code": "500"})

    except Exception as e:
        current_status = '检测失败'
        print(e)
        vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, 0, 0, review_status)

        if vulnerability_detail.status_code == 200:
            return JsonResponse({"msg": "规则扫描失败，漏洞信息页面数据插入成功", "code": "200", "error": str(e)})
        else:
            return JsonResponse({"msg": "规则扫描失败，漏洞信息页面数据插入错误", "code": "500", "error": str(e)})