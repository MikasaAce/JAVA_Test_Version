import json

from app.api.default_model_api.muti_transformer_detection import *
from app.api.default_model_api.rule1_detection import *
from app.api.default_model_api.rule2_detection import *
from app.api.default_model_api.create_task import *
from app.api.default_model_api.update_task import *

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)


def default_model_api(req):
    folder_path = req.POST['folder_path']
    item_id = req.POST['item_id']
    task_name = req.POST['task_name']
    template = req.POST['template']
    version = req.POST['version']
    language = req.POST['language']
    branch = req.POST.get('branch')

    arg = {
        'folder_path': folder_path,
        'item_id': item_id,
        'task_name': task_name,
        'template': template,
        'version': version,
        'language': language,
        'branch': branch,
    }
    if language == 'java':
        data = create_task(arg)
        data = json.loads(data.content.decode('utf-8'))

        if data['code'] == "200":
            arg['task_id'] = data['task_id']
            arg['start_time'] = data['start_time']
        else:
            return HttpResponse(JsonResponse(data))

        result1 = muti_detection(arg)  # 多分类模型扫描
        result2 = rule2_detection(arg)  # 自定义规则
        result1 = json.loads(result1.content.decode('utf-8'))
        result2 = json.loads(result2.content.decode('utf-8'))
        print(result2)
        if result1['code'] == "200" and result2['code'] == "200":
            arg['current_status'] = '检测完成'
            update_task(arg)
            return HttpResponse(JsonResponse({"msg": "默认策略扫描成功！", 'code': '200'}))

        elif result1['code'] == "200" and result2['code'] != "200":
            arg['current_status'] = '检测失败'
            update_task(arg)
            return HttpResponse(JsonResponse({"msg": "多分类模型扫描成功，自定义规则扫描失败！", 'code': '500'}))

        elif result1['code'] != "200" and result2['code'] == "200":
            arg['current_status'] = '检测失败'
            update_task(arg)
            return HttpResponse(JsonResponse({"msg": "多分类模型扫描失败，自定义规则扫描成功！", 'code': '500'}))
        else:
            print('默认策略扫描失败或异常终止！')
            arg['current_status'] = '检测失败'
            update_task(arg)
            return HttpResponse(JsonResponse({"msg": "默认策略扫描失败或异常终止！", 'code': '500'}))
    else:
        result = rule1_detection(arg)  # fortify扫描
        return HttpResponse(result)


def index(req):
    method = req.POST["method"]
    if method == 'default_model_api':
        return default_model_api(req)
    else:
        return HttpResponse(f"method error! {method}")