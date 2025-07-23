from app.api.database_utils.web import *
from app.api.muti_model_api.transformer_detection import *

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

def muti_detection(arg):
    """多分类模型扫描扫描"""
    folder_path = arg['folder_path']
    item_id = arg['item_id']
    task_name = arg['task_name']
    language = arg['language']
    task_id = arg['task_id']


    high_num = 0
    medium_num = 0
    low_num = 0
    detection_type = '默认策略'

    try:
        result = transformer_detection(folder_path)  # 调用多分类模型进行检测

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

        return JsonResponse({"msg": "多分类模型扫描成功", "code": "200"})

    except Exception as e:
        print(e)
        return JsonResponse({"msg": "多分类模型扫描失败", "code": "500", "error": str(e)})