from app.api.muti_model_api.model_api import *


def create_task(arg):
    """多分类模型扫描扫描"""
    folder_path = arg['folder_path']
    item_id = arg['item_id']
    task_name = arg['task_name']
    template = arg['template']
    version = arg['version']
    language = arg['language']
    branch = arg['branch']
    current_status = arg['current_status']
    model = arg['model']
    deepseek = arg['deepseek']
    url_git = arg.get('url_git')          # 或 arg.get('url_git') or None
    start_time = get_current_time()

    check_result = check_task_name(task_name, item_id)
    if check_result:
        print("任务名已存在，请修改任务名")
        return JsonResponse({"msg": "任务名已存在，请修改任务名", "code": "500"})

    task_id = get_id('taskId', 'vuldetail')
    #current_status = '正在检测'
    review_status = '未审核'
    detection_type = str([model, deepseek])
    template = f'{template} {version}'


    high_num = 0
    medium_num = 0
    low_num = 0

    file_num = 0
    code_size = 0
    file_size = 0

    if branch: #如果branch不为空
        vulnerability_detail = vuldetail_insert2(task_id, item_id, task_name, detection_type, high_num, medium_num,
                                                low_num, code_size, file_size,
                                                file_num, current_status,
                                                start_time, 0, 0, review_status, branch)
    else:
        vulnerability_detail = vuldetail_insert(task_id, item_id, task_name, detection_type, high_num, medium_num, 
        								   low_num, code_size, file_size,
                                                file_num, current_status,
                                                start_time, 0, 0, review_status)


    file_num, code_size, file_size = count_files(folder_path, language)

    if file_num == 0:
        print('Error! 文件夹内不存在该语言的文件！')
        current_status = '检测失败'
        vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, high_num, medium_num,
                                                low_num,
                                                code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, 0, 0, review_status)
        return JsonResponse({'code': '500', 'msg': 'Error! 文件夹内不存在该语言的文件！'})

    vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, high_num, medium_num, low_num,
                                            code_size,
                                            file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status)

    if vulnerability_detail.status_code == 500:
        return JsonResponse({"msg": "任务创建失败", "code": "500"})
    else:
        return JsonResponse({"msg": "任务创建成功", "code": "200", "task_id": task_id, "start_time": start_time})

