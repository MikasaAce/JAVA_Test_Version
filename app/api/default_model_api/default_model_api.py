from app.api.default_model_api.muti_transformer_detection import *
from app.api.default_model_api.rule1_detection import *
from app.api.default_model_api.rule2_detection import *

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

    arg = {
        'folder_path': folder_path,
        'item_id': item_id,
        'task_name': task_name,
        'template': template,
        'version': version,
        'language': language
    }

    rule1_detection(arg)
    rule2_detection(arg)
    muti_transformer_detection(arg)

def index(req):
    method = req.POST["method"]
    if method == "decompression":
        return default_model_api(req)
    elif method == 'muti_transformer_detection':
        return muti_transformer_detection(req)
    else:
        return HttpResponse(f"method error! {method}")