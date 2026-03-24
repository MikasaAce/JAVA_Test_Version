import json
import os
from multiprocessing import Process, Queue
from datetime import datetime

from app.api.authorization.authorization import decrypt
from app.api.create_process.muti_transformer_detection import *
from app.api.create_process.rule1_detection import *
from app.api.create_process.rule2_detection import *
from app.api.create_process.create_task import *
from app.api.create_process.update_task import *
from app.api.create_process.mixed_detection import *
from app.api.main_app.M_app import clone_git_repository_1
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
import threading
import queue

from app.api.ccn.processCCN import calculate_ccn

# 设置启动方法为 'spawn'
multiprocessing.set_start_method('spawn', force=True)  # 使用 force=True 可以覆盖已有的设置（仅在需要时）

import warnings

# 忽略所有警告
warnings.filterwarnings("ignore")


# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class QueueProcessor:
    def __init__(self, max_workers=3, queue_size=100):
        self.q = queue.Queue(maxsize=queue_size)  # 设置队列最大容量
        self.stop_event = threading.Event()
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.thread = threading.Thread(target=self.process_queue, daemon=True)
        self.thread.start()
        self.results = {}  # 存储任务结果，键为 (item_id, task_name)

    def process_queue(self):
        while not self.stop_event.is_set():
            try:
                current = self.q.get(timeout=3)  # 设置超时避免忙等待
                # 提交任务到线程池，并存储 Future 对象
                future = self.executor.submit(self.process_task, current)
                key = (current['item_id'], current['task_name'])  # 复合键
                self.results[key] = future  # 以复合键存储 Future
                self.q.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"处理队列时出错: {e}")

    def process_task(self, task):
        result = create_process(task)  # 确保 create_process 函数已定义
        return result
        # try:
        #     result = create_process(task)  # 确保 create_process 函数已定义
        #     return result
        # except Exception as e:
        #     logging.error(f"处理任务时出错 (任务ID: {task.get('item_id', '未知')}, 任务名称: {task.get('task_name', '未知')}): {e}")
        #     raise  # 重新抛出异常，以便 Future 捕获

    def add_to_queue(self, item):
        try:
            self.q.put(item, timeout=5)  # 设置添加任务的超时时间
        except queue.Full:
            logging.error("任务队列已满，无法添加新任务")

    def get_task_result(self, item_id, task_name):
        """获取任务结果"""
        key = (item_id, task_name)  # 复合键
        if key in self.results:
            future = self.results[key]
            try:
                return future.result(timeout=1)  # 设置超时时间
            except Exception as e:
                return f"任务执行失败: {e}"
        return "任务键不存在"

    def stop(self):
        self.stop_event.set()
        self.thread.join()
        self.executor.shutdown(wait=True)  # 等待所有任务完成
        logging.info("队列处理器已停止")


@lru_cache(maxsize=1)
def get_process_num():
    path = "../../../License"

    # 获取当前脚本所在的目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # 将工作目录切换到脚本所在目录
    os.chdir(script_dir)
    # current_dir = os.getcwd()  # 获取当前工作目录
    # print("当前工作目录:", current_dir)
    with open(path, "r", encoding="utf-8") as f:
        en_data = f.read()
    de_data = decrypt(en_data)

    tuple_data = eval(de_data.split("<process_split>")[-1].split("</process_split>")[0])
    task_num, process_num = tuple_data  # 获取元组中的值
    print(f"当前最大任务数：{task_num}，最大进程数：{process_num}")

    return task_num, process_num

task_num, process_num = get_process_num()
processor = QueueProcessor(max_workers=task_num)
from datetime import datetime
import tempfile

# def create_queue_git(req):
#     item_id = req.POST['item_id']
#     item_name = req.POST['item_name']
#     template = req.POST['template']
#     version = req.POST['version']
#     language = req.POST['language'].lower()
#     url_git_file_path = req.POST.get('url_git', None)
#     branch = req.POST.get('branch')
#     model = req.POST['model']
#     deepseek = req.POST['deepseek']
#     access_token = req.POST['access_token']
#     username = req.POST['username']
#     password = req.POST['password']
#
#     print(11111111111111111)
#
#     # url_git_file_path应该是一个txt文件地址
#     if not url_git_file_path:
#         return HttpResponse(JsonResponse({"msg": "缺少相应文件", 'code': '400'}))
#
#     try:
#         response = requests.get(url_git_file_path, stream=True)
#         response.raise_for_status()  # 检查HTTP错误
#
#         # 创建临时文件
#         with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
#             for chunk in response.iter_content(chunk_size=8192):
#                 tmp_file.write(chunk)
#             tmp_path = tmp_file.name
#
#         # 检查文件类型并读取内容
#         if tmp_path.endswith('.txt'):
#             with open(tmp_path, 'r') as f:
#                 content = f.read()
#
#         os.unlink(tmp_path)
#         git_urls = []
#         for line in content.splitlines():
#             line = line.strip()
#             if not line:
#                 continue
#
#             if re.match(r'^(https?://|git@|ssh://)', line) and ('.git' in line or ':' in line):
#                 git_urls.append(line)
#             else:
#                 return HttpResponse(JsonResponse({"msg": "不正确的url格式", 'code': '400'}))
#
#         if not git_urls:
#             return HttpResponse(JsonResponse({"msg": "文件中没有发现url地址", 'code': '400'}))
#     except Exception as e:
#         traceback.print_exc()
#         print(e)
#
#     for git_url in git_urls:
#         task_id = get_id('taskId', 'vuldetail')
#         start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#         folder_path = clone_git_repository_1(gitlab_url=git_url, access_token=access_token, item_name=item_name, user_name=username, password=password)
#         task_name = git_url.split["http://gitlab.fenqile.com"][-1].split[".git"][0].replace("/", "_")
#         if folder_path:
#             orgin_arg = {
#                 'folder_path': folder_path,
#                 'item_id': item_id,
#                 'task_name': task_name,
#                 'template': template,
#                 'version': version,
#                 'language': language,
#                 'branch': branch,
#                 'model': model,
#                 'task_id': task_id,
#                 'deepseek': deepseek,
#                 'start_time': start_time,
#                 'url_git': git_url,
#                 'current_status': '正在排队'
#             }
#             # processor.add_to_queue(orgin_arg)
#             print(orgin_arg)

def create_queue(req):
    folder_path = req.POST['folder_path']
    item_id = req.POST['item_id']
    task_name = req.POST['task_name']
    template = req.POST['template']
    version = req.POST['version']
    language = req.POST['language'].lower()
    url_git = req.POST.get('url_git', None)
    branch = req.POST.get('branch')
    model = req.POST['model']
    deepseek = req.POST['deepseek']

    #直接检查task_name是否重复
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    check_sql = """
    SELECT COUNT(*) FROM vuldetail 
    WHERE itemId = %s AND taskname = %s
    """
    cursor.execute(check_sql, (item_id, task_name))
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    
    if count > 0:
        return JsonResponse({
            "msg": f"任务名称'{task_name}'已存在，请使用不同的名称",
            "code": "400"
        })

    task_id = get_id('taskId', 'vuldetail')
    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    orgin_arg = {
        'folder_path': folder_path,
        'item_id': item_id,
        'task_name': task_name,
        'template': template,
        'version': version,
        'language': language,
        'branch': branch,
        'model': model,
        'task_id': task_id,
        'deepseek': deepseek,
        'start_time': start_time,
        'current_status': '正在排队'
    }
    if url_git:
        orgin_arg['url_git'] = url_git

    if language == 'java' and model != 'fortify':
        data = create_task(orgin_arg)
        data = json.loads(data.content.decode('utf-8'))
        print(data['code'])
        if data['code'] == "200":
            orgin_arg['task_id'] = data['task_id']
            orgin_arg['start_time'] = data['start_time']

    if language == 'mixed':
        print(654321)
        data = create_task(orgin_arg)
        data = json.loads(data.content.decode('utf-8'))
        print(data['code'])
        if data['code'] == "200":
            orgin_arg['task_id'] = data['task_id']
            orgin_arg['start_time'] = data['start_time']

    calculate_ccn(orgin_arg)

    processor.add_to_queue(orgin_arg)

    result = processor.get_task_result(item_id, task_name)

    return HttpResponse(JsonResponse({"msg": "扫描成功", 'code': '200'}))

# 分割列表的函数
def split_list(data, num_chunks):
    # 如果 num_chunks 大于 data 的长度，则只切成 len(data) 片
    num_chunks = min(num_chunks, len(data))

    # 计算每个子列表的大小
    chunk_size = len(data) // num_chunks
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    # 如果列表长度不能被整除，最后一个子列表可能比其他子列表长
    if len(chunks) > num_chunks:
        chunks[-2].extend(chunks[-1])
        chunks = chunks[:-1]

    return chunks


# 创建进程的函数
def create_processes(target_func, chunks):
    processes = []
    for i, chunk in enumerate(chunks):

        p = Process(target=target_func, args=(chunk, str(target_func), i + 1, len(chunks)))  # 传入子列表、进程ID和队列
        p.start()
        processes.append(p)
    return processes


def get_filePath(folder_path):
    file_path = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".java") or file.endswith(".xml"):
                file_path.append(os.path.join(root, file))

    return file_path


def get_filePath_java(folder_path):
    file_path = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".java"):
                file_path.append(os.path.join(root, file))

    return file_path


def get_filePath_mixed(folder_path):
    file_path = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".cpp") or file.endswith(".c") or file.endswith(".js") or file.endswith(".py")  or file.endswith(".php"):
                file_path.append(os.path.join(root, file))

    return file_path


# 读取文件夹下的所有xml文件
def get_xml(folder_path):
    xml_path = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(".xml"):
                xml_path.append(os.path.join(root, file))

    return xml_path

def create_process(task):
    folder_path = task['folder_path']
    item_id = task['item_id']
    task_name = task['task_name']
    template = task['template']
    version = task['version']
    language = task['language']
    branch = task.get('branch')
    model = task['model']
    deepseek = task['deepseek']
    task_id = task['task_id']
    start_time = task['start_time']

    orgin_arg = {
        'folder_path': folder_path,
        'item_id': item_id,
        'task_name': task_name,
        'template': template,
        'version': version,
        'language': language,
        'branch': branch,
        'model': model,
        'task_id': task_id,
        'start_time': start_time,
        'current_status': '正在检测'
    }
    if task.get('url_git'):
        url_git = task['url_git']
        orgin_arg['url_git'] = url_git
    print(orgin_arg)

    tra_folder_path = folder_path
    file_path_lists_java = get_filePath_java(tra_folder_path)

    if file_path_lists_java:
        print("java")
        language = "java"

    print(model)

    if language == "mixed":
        print(11223333333333333333333333444)
        update_task(orgin_arg)
        mixed_process_num = 1

        processes = []

        print(folder_path)
        file_path_lists = get_filePath_mixed(folder_path)
        print(file_path_lists)

        if file_path_lists:
            file_path_list = split_list(file_path_lists, mixed_process_num)
            print(file_path_list)
            xml_list = get_xml(folder_path)  # 获取文件夹下的所有xml文件（列表）
            arg_list = []
            for file_path in file_path_list:
                print("正在检测", file_path)
                arg = {
                    'file_path': file_path,
                    'item_id': item_id,
                    'task_name': task_name,
                    'template': template,
                    'version': version,
                    'language': language,
                    'branch': branch,
                    'task_id': orgin_arg['task_id'],
                    'start_time': orgin_arg['start_time'],
                    'xml_list': xml_list,
                }
                arg_list.append(arg)

                processes.extend(create_processes(rule3_detection, arg_list))

            # 等待所有进程完成
            for p in processes:
                p.join()

            if deepseek == 'true':
                result = deepseek_False(orgin_arg['task_id'])
                if result == "success":
                    print("大模型降误报成功")

            orgin_arg['current_status'] = '检测完成'
            update_task(orgin_arg)
            return HttpResponse(JsonResponse({"msg": "扫描成功", 'code': '200'}))

    if language == 'java' and model == 'r4':
        update_task(orgin_arg)
        rule_process_num = process_num

        processes = []
        file_path_lists = get_filePath(folder_path)
        xml_list = get_xml(folder_path)  # 获取文件夹下的所有xml文件（列表）

        # arg_list = []
        # for file_path in file_path_list:
        #     arg = {
        #         'file_path': file_path,
        #         'item_id': item_id,
        #         'task_name': task_name,
        #         'template': template,
        #         'version': version,
        #         'language': language,
        #         'branch': branch,
        #         'task_id': orgin_arg['task_id'],
        #         'start_time': orgin_arg['start_time'],
        #         'xml_list': xml_list,
        #     }
        #     arg_list.append(arg)
        if file_path_lists != []:
            file_path_list = split_list(file_path_lists, rule_process_num)
            arg_list = []
            for file_path in file_path_list:
                arg = {
                    'file_path': file_path,
                    'item_id': item_id,
                    'task_name': task_name,
                    'template': template,
                    'version': version,
                    'language': language,
                    'branch': branch,
                    'task_id': orgin_arg['task_id'],
                    'start_time': orgin_arg['start_time'],
                    'xml_list': xml_list,
                }
                arg_list.append(arg)

            processes.extend(create_processes(rule2_detection, arg_list))

        # 等待所有进程完成
        for p in processes:
            p.join()

        result = deepseek_scan(task_id, file_path_lists, xml_list)

        orgin_arg['current_status'] = '检测完成'
        update_task(orgin_arg)
        return HttpResponse(JsonResponse({"msg": "扫描成功", 'code': '200'}))


    elif language == 'java' and model != 'fortify':
        print(11111111111111111111111111111)
        update_task(orgin_arg)
        model_process_num = 5
        rule_process_num = process_num
        # 创建进程列表
        processes = []
        print(33333333333333333333333333)

        file_path_lists = get_filePath(folder_path)
        if model == "small_model":
            # 调用小模型
            file_path_list = split_list(file_path_lists, model_process_num)
            arg_list = []
            for file_path in file_path_list:
                arg = {
                    'file_path': file_path,
                    'item_id': item_id,
                    'task_name': task_name,
                    'template': template,
                    'version': version,
                    'language': language,
                    'branch': branch,
                    'task_id': orgin_arg['task_id'],
                    'start_time': orgin_arg['start_time'],
                }
                arg_list.append(arg)

            # 子函数1：创建三个进程，分别处理三个子列表
            processes.extend(create_processes(muti_detection, arg_list))
        elif model == "rule":
            print(22222222222222222222222)
            file_path_list = split_list(file_path_lists, rule_process_num)
            xml_list = get_xml(folder_path) # 获取文件夹下的所有xml文件（列表）
            arg_list = []
            for file_path in file_path_list:
                print("正在检测", file_path)
                arg = {
                    'file_path': file_path,
                    'item_id': item_id,
                    'task_name': task_name,
                    'template': template,
                    'version': version,
                    'language': language,
                    'branch': branch,
                    'task_id': orgin_arg['task_id'],
                    'start_time': orgin_arg['start_time'],
                    'xml_list': xml_list,
                }
                arg_list.append(arg)

            processes.extend(create_processes(rule2_detection, arg_list))

        # 等待所有进程完成
        print("0721")
        for p in processes:
            p.join()
        print("787878")
        if deepseek == 'true':
            result = deepseek_False(orgin_arg['task_id'])
            print("66666")
            if result == "success":
                print("大模型降误报成功")

        orgin_arg['current_status'] = '检测完成'
        update_task(orgin_arg)
        return HttpResponse(JsonResponse({"msg": "扫描成功", 'code': '200'}))
    else:
        result = rule1_detection(orgin_arg)  # fortify扫描
        return HttpResponse(result)

# from oauth2_provider.decorators import protected_resource
# @protected_resource()
def index(req):
    method = req.POST["method"]
    if method == 'create_queue':
        return create_queue(req)
    # elif method == 'create_queue_git':
    #     return  create_queue_git(req)
    else:
        return HttpResponse(f"method error! {method}")

