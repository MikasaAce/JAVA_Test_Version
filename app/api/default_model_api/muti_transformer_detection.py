from app.api.main_app.M_app import *
from app.api.muti_model_api.transformer_detection import *
from app.api.muti_model_api.model_api import *

def muti_transformer_detection(arg):
    """多分类模型扫描扫描"""
    folder_path = arg['folder_path']
    item_id = arg['item_id']
    task_name = arg['task_name']
    language = arg['language']

    start_time = get_current_time()

    check_result = check_task_name(task_name, item_id)
    if check_result:
        print("任务名已存在，请修改任务名")
        return JsonResponse({"msg": "任务名已存在，请修改任务名", "code": "500"})

    task_id = get_id('taskId', 'vuldetail')
    current_status = '正在检测'
    review_status = '未审核'
    detection_type = 'transformer模型多分类'
    template = ''


    high_num = 0
    medium_num = 0
    low_num = 0

    file_num = 0
    code_size = 0
    file_size = 0

    vulnerability_detail = vuldetail_insert(task_id, item_id, task_name, detection_type, high_num, medium_num, low_num, code_size, file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status, template)

    #folder_path = get_file(folder_path, task_name)
    file_num, code_size, file_size = count_files(folder_path, language)

    if file_num == 0:
        print('Error! 文件夹内不存在该语言的文件！')
        return JsonResponse({'code': '500', 'msg': 'Error! 文件夹内不存在该语言的文件！'})

    vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, high_num, medium_num, low_num,
                                            code_size,
                                            file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status)

    if vulnerability_detail.status_code == 500:
        return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})


    try:
        result = transformer_detection(folder_path)  # 调用多分类模型进行检测
        #print(result)
        print(len(result))

        for file_path, values in result.items():
            for value in values:
                test_result = []
                file_id = get_id('fileId', 'vulfile')
                file_path = value['file_path']
                file_name = file_path.split('/')[-1]
                vul_name = value['label']
                location = value['line_start_to_end']
                if vul_name == '无漏洞':
                    continue
                vul_level = get_level_CN(vul_name)  # 根据漏洞名称获取漏洞危险等级

                if vul_level == '高危':
                    high_num += 1
                elif vul_level == '中危':
                    medium_num += 1
                elif vul_level == '低危':
                    low_num += 1
                else:
                    print(f'危险等级异常！{vul_name}')
                    vul_level = '高危'
                    high_num += 1

                code, code_line = get_code(file_path, location)
                test_result.append({
                    'filename': file_name,
                    'file_path': file_path,
                    'vul_name': vul_name,
                    'code': '',
                    'line_number': str(location),
                    'risk_level': vul_level,
                    'repair_code': '',
                    'new_line_number': '',
                    'repair_status': '未修复',
                    'is_question': '是问题',
                    'model': detection_type,
                    'Sink': code_line,
                    'Enclosing_Method': code_line,
                    'Source': code_line
                })

                vulfile_insert(task_id, file_id, test_result)

        end_time = get_current_time()
        start_time = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end_time = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        last_time = end_time - start_time
        hours, remainder = divmod(last_time.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        last_time_str = f"{hours}时{minutes}分{seconds}秒"

        current_status = '检测完成'
        vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, high_num, medium_num, low_num,
                                                code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, end_time, last_time_str, review_status)

        if vulnerability_detail.status_code == 200:
            return JsonResponse({"msg": "漏洞信息页面数据插入成功", "code": "200"})
        else:
            return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})
    except Exception as e:
        print(e)
        current_status = '检测失败'
        vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, high_num, medium_num, low_num, code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, 0, 0, review_status)

        if vulnerability_detail.status_code == 200:
            return JsonResponse(
                {"msg": "多分类模型单独扫描失败，漏洞信息页面数据插入成功", "code": "500", "error": str(e)})
        else:
            return JsonResponse(
                {"msg": "多分类模型单独扫描失败，漏洞信息页面数据插入错误", "code": "500", "error": str(e)})