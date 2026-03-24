from app.api.main_app.M_app import *
from app.api.muti_model_api.transformer_detection import *

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)
def convert_size(size_bytes):
    """
    将文件大小转换为合适的单位（如 KB、MB）。

    参数:
    size_bytes (int): 文件大小（字节）。

    返回:
    str: 转换后的文件大小和单位。
    """
    if size_bytes == 0:
        return "0 B"
    power = 2 ** 10  # 1024
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    index = int(math.floor(math.log(size_bytes, power)))
    size = round(size_bytes / power ** index, 2)
    return f"{size} {units[index]}"


def count_files(folder_path, language):
    """
    统计指定目录下的指定语言的文件个数、代码总行数和文件占用空间大小。

    参数:
    folder_path (str): 目录路径。
    language (str): 文件语言（如 'java'），或 'all' 表示所有文件。

    返回:
    tuple: 包含文件个数、代码总行数和文件占用空间大小的元组。
    """
    file_count = 0
    total_lines = 0
    total_size = 0

    # 遍历目录及其子目录
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            # 检查文件扩展名
            if language != 'all' and language != 'mixed' and not file.endswith(f'.{language}') and not file.endswith('.xml'):
                continue

            file_path = os.path.join(root, file)

            # 检测文件编码格式
            try:
                with open(file_path, 'rb') as f:
                    raw_data = f.read()
                    result = chardet.detect(raw_data)
                    encoding = result['encoding']
            except (OSError, IOError) as e:
                print(f"无法读取文件 {file_path}: {e}")
                continue

            # 计算代码总行数和文件大小
            try:
                file_count += 1
                total_size += os.path.getsize(file_path)
                with open(file_path, 'r', encoding=encoding) as f:
                    total_lines += sum(1 for _ in f)
            except UnicodeDecodeError as e:
                print(f"无法解码文件 {file_path}: {e}")
                continue
            except (OSError, IOError) as e:
                print(f"无法处理文件 {file_path}: {e}")
                continue

    # 转换文件大小
    size_str = convert_size(total_size)

    return file_count, f"{total_lines} 行", size_str


def get_code(file_path, location=None):
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        encoding = result['encoding']

    with open(file_path, 'r', encoding=encoding) as f:
        code = f.read()

    code_line = ''

    if location:
        code_lines = code.splitlines()
        start_line = location[0] - 1  # 起始行
        code_line = code_lines[start_line]  # 默认值

        # 从起始行开始向下遍历
        for line in code_lines[start_line:]:
            if line.strip().startswith(('public', 'private', 'protected')):
                code_line = line
                break

    return code, code_line

def muti_transformer_detection(req):
    """多分类模型扫描扫描"""
    folder_path = req.POST['folder_path']
    item_id = req.POST['item_id']
    task_name = req.POST['task_name']
    language = req.POST['language']

    start_time = get_current_time()

    check_result = check_task_name(task_name, item_id)
    if check_result:
        print("任务名已存在，请修改任务名")
        return JsonResponse({"msg": "任务名已存在，请修改任务名", "code": "500"})

    task_id = get_id('taskId', 'vuldetail')
    current_status = '正在检测'
    review_status = '未审核'
    detection_type = 'transformer模型多分类'



    high_num = 0
    medium_num = 0
    low_num = 0

    file_num = 0
    code_size = 0
    file_size = 0

    vulnerability_detail = vuldetail_insert(task_id, item_id, task_name, detection_type, high_num, medium_num, low_num, code_size, file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status)

    #folder_path = get_file(folder_path, task_name)
    print(folder_path, language)
    file_num, code_size, file_size = count_files(folder_path, language)
    print(file_num, code_size, file_size)

    if file_num == 0:
        print('Error! 文件夹内不存在该语言的文件！')
        review_status = '检测失败'
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



def index(req):
    method = req.POST["method"]
    if method == "decompression":
        return decompress_file(req)
    elif method == 'muti_transformer_detection':
        return muti_transformer_detection(req)
    else:
        return HttpResponse(f"method error! {method}")