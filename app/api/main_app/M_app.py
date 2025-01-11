import datetime
import shlex
import subprocess
import tarfile
import time
import uuid
import zipfile
import javalang
import importlib
import traceback
import esprima
from urllib.request import urlopen
from django.http import StreamingHttpResponse, JsonResponse
from multiprocessing import Process, Queue, Semaphore

import math
import py7zr
import rarfile
import os
import shutil
import json
import signal
import glob
import random
import sys
from neo4j import GraphDatabase

from app.api.model_api.large_model_detection import *
from app.api.model_api.fortify_detection import *
from app.api.model_api.transformer_detection import *
from app.api.config.config import *

csv_dir = '/home/public/JAVA_gf/app/static/csv_temp'
csv_path = '/home/public/JAVA_gf/app/static/csv_temp'
import_path = '/var/lib/neo4j/import/'
node_path = '/var/lib/neo4j/import/nodes_CALL_cypher.csv'
edge_path = '/var/lib/neo4j/import/edges_CALL_cypher.csv'

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)

# 本设置作用是将默认相对路径设为本文件夹路径
# 在未指定这三个参数的情况下，会默认搜索 “ templates ” 文件夹下的页面模板
# 默认搜索 “ static ” 文件夹的CSS JS等静态配置
# 直接修改template_folder参数，免去了修改HTML文件中各个相关文件的路径

file_save_path = data_class.file_save_path
processed_file_save_path = data_class.processed_file_save_path

task_list = []


def start_process(arg):
    # 这里的 arg 应该是一个字典，包含 'api' 和 'arg' 两个键
    func = globals()[arg['api']]
    arg = arg['arg']

    worker_process = Process(target=func, args=(arg,))

    try:
        worker_process.start()  # 启动进程
        worker_process.join()  # 等待进程完成
        print('任务执行完成')
    except Exception as e:
        print(f'任务处理失败: {e}')


param_queue = Queue()


def create_queue(req):
    try:
        arg = req.POST['arg']
        arg = json.loads(arg)
        param_queue.put(arg)
        print(f'队列当前任务数：{param_queue.qsize()}')
        return JsonResponse({'code': '200', 'msg': '任务插入队列成功！'})
    except Exception as e:
        return JsonResponse({'code': '500', 'msg': f'任务插入队列失败：{e}！'})


def create_process():
    global task_list
    sem = Semaphore(1)
    t = 1
    while True:
        try:
            if param_queue.qsize() > 0:
                print('监听到新建任务，正在创建进程')
                # 使用信号量保护全局变量
                with sem:
                    task = param_queue.get()
                    task_list.append(task)
                    start_process(task)
        except Exception as e:
            print(f'任务处理失败: {e}')

        time.sleep(t)


def get_file(folder_path, task_name):
    """提取项目下所有Java文件并处理。"""
    java_file_list = []
    for root, sub_dirs, file_names in os.walk(folder_path):
        for file_name in file_names:
            java_file_list.append(os.path.join(root, file_name))

    item_name = os.path.basename(os.path.dirname(folder_path))
    folder_name = f"{os.path.basename(folder_path)}_s"
    new_folder_path = os.path.join(file_save_path, item_name, task_name, folder_name)
    # print(new_folder_path)
    if os.path.exists(new_folder_path):
        shutil.rmtree(new_folder_path)

    os.makedirs(new_folder_path, exist_ok=True)

    for file in java_file_list:
        if not os.path.isfile(file):
            print(f'文件路径错误: {file}')
            continue
        shutil.copy(file, os.path.join(new_folder_path, os.path.basename(file)))

    shutil.rmtree(folder_path)

    if new_folder_path.endswith("_s"):
        folder_path = new_folder_path.rstrip("_s")

    os.rename(new_folder_path, folder_path)

    return folder_path


def get_current_time():
    """获取当前时间并返回格式化的字符串。"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def count_java_files(directory_path):
    """
    统计指定目录下的 .java 文件个数、代码总行数和文件占用空间大小
    :param directory_path: 目录路径
    :return: 一个包含 .java 文件个数、代码总行数和文件占用空间大小的元组

    2025.1.3 修改
    内容:因为要检测js文件,所以我把筛选的逻辑去掉了

    2025.01.07 新增一个版本，可见muti_model_api/model_api下的count_files
    可针对指定语言进行筛选
    """
    java_file_count = 0
    total_lines = 0
    total_size = 0

    # 遍历目录及其子目录
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            # if file.endswith('.java'):

            file_path = os.path.join(root, file)

            # 检测文件编码格式
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                result = chardet.detect(raw_data)
                encoding = result['encoding']

            # 计算代码总行数
            try:
                java_file_count += 1
                # 计算文件占用空间大小
                total_size += os.path.getsize(file_path)
                with open(file_path, 'r', encoding=encoding) as f:
                    total_lines += sum(1 for _ in f)
            except:
                continue

    power = 2 ** 10  # 1024
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    index = int(total_size and math.floor(math.log(total_size, power)))
    total_size = round(total_size / power ** index, 2)

    return java_file_count, f"{total_lines} 行", f"{total_size} {units[index]}"


def get_unique_folder_name(base_path, folder_name):
    """生成唯一的文件夹名。"""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    random_suffix = str(uuid.uuid4())
    unique_folder_name = f"{folder_name}_{timestamp}_{random_suffix}"
    return os.path.join(base_path, unique_folder_name)


def decompress_file(req):
    """解压上传的压缩文件并保存到指定路径。"""
    uploaded_file = req.FILES.get('file', None)
    item_name = req.POST['item_name']
    folder_name, file_extension = os.path.splitext(uploaded_file.name)
    file_extension = file_extension.lstrip('.').lower()

    base_path = os.path.join(processed_file_save_path, item_name)
    unique_folder_path = get_unique_folder_name(base_path, folder_name)

    os.makedirs(unique_folder_path, exist_ok=True)
    print(f"Path '{unique_folder_path}' created.")

    try:
        if file_extension in ['zip', 'tar', 'rar', '7z']:
            if file_extension == 'zip':
                with zipfile.ZipFile(uploaded_file) as zip_file:
                    zip_file.extractall(unique_folder_path)
            elif file_extension == 'tar':
                with tarfile.TarFile(uploaded_file) as tar_file:
                    tar_file.extractall(unique_folder_path)
            elif file_extension == 'rar':
                with rarfile.RarFile(uploaded_file) as rar_file:
                    rar_file.extractall(unique_folder_path)
            elif file_extension == '7z':
                with py7zr.SevenZipFile(uploaded_file, 'r') as seven_zip_file:
                    seven_zip_file.extractall(unique_folder_path)

            return JsonResponse({'code': '200', 'msg': '解压文件成功', 'folder_name': unique_folder_path})
        else:
            # 处理普通文件
            with open(os.path.join(unique_folder_path, uploaded_file.name), 'wb') as f:
                for chunk in uploaded_file.chunks():
                    f.write(chunk)

            return JsonResponse({'code': '200', 'msg': '文件上传成功', 'folder_name': unique_folder_path})
    except Exception as e:
        return JsonResponse({'code': '500', 'msg': f'解压文件出现错误: {str(e)}'})


def clone_or_pull_project(project_url, project_path, access_token, max_retries=3):
    """克隆或拉取Git项目。"""
    retries = 0
    while retries < max_retries:
        try:
            print('正在拉取或克隆:', project_url)

            command = shlex.split(f'git -C "{project_path}" pull' if os.path.exists(
                project_path) else f'git clone {project_url} {project_path}')
            env = os.environ.copy()
            env['GITLAB_API_PRIVATE_TOKEN'] = access_token

            result_code = subprocess.run(command, capture_output=True, text=True, env=env)

            if result_code.returncode == 0:
                return True, "成功克隆或拉取项目"
            else:
                raise subprocess.CalledProcessError(result_code.returncode, command, result_code.stderr)
        except subprocess.CalledProcessError as e:
            retries += 1
            if retries < max_retries:
                print(f"克隆或拉取项目失败，重试次数：{retries}")
            else:
                return False, f"克隆或拉取项目失败，已达到最大重试次数 ({max_retries})", e.stderr
        except Exception as e:
            return False, "Error: %s" % str(e)

    return False, f"克隆或拉取项目失败，已达到最大重试次数 ({max_retries})"


def fetch_gitlab_projects(gitlab_url, access_token, download_path):
    """从GitLab拉取项目。"""
    fetched_projects = []

    if '.git' in gitlab_url:
        project_url = gitlab_url
        project_path = os.path.join(download_path, gitlab_url.split('/')[-1].replace('.git', ''))
        try:
            result = clone_or_pull_project(project_url, project_path, access_token)
            if result[0]:
                fetched_projects.append((project_url, project_path))
                print("克隆或拉取项目成功：", project_url)
            else:
                print("克隆或拉取项目失败")
                print("错误输出:", result[1])
        except Exception as e:
            print("Error on %s: %s" % (project_url, str(e)))
    else:
        gitlab_address = gitlab_url.split('://')[1]
        for index in range(1, 11):
            url = f"http://{gitlab_address}/api/v4/projects?private_token={access_token}&per_page=100&page={index}&order_by=name"
            all_projects = urlopen(url)
            all_projects_dict = json.loads(all_projects.read().decode(encoding='UTF-8'))
            if not all_projects_dict:
                break
            for project in all_projects_dict:
                project_url = project['http_url_to_repo'].replace(project['http_url_to_repo'].split('/')[2],
                                                                  project['http_url_to_repo'].split('/')[2] + ':8083')
                project_path = os.path.join(download_path, project['path_with_namespace'])

                try:
                    result = clone_or_pull_project(project_url, project_path, access_token)
                    if result[0]:
                        fetched_projects.append((project_url, project_path))
                        print("克隆或拉取项目成功：", project_url)
                    else:
                        print("克隆或拉取项目失败")
                        print("错误输出:", result[1])
                except Exception as e:
                    print("Error on %s: %s" % (project_url, str(e)))

    return fetched_projects


def clone_git_repository(req):
    """克隆GitLab仓库。"""
    gitlab_url = req.POST['url']
    access_token = req.POST['token']
    item_name = req.POST['item_name']

    base_path = os.path.join(processed_file_save_path, item_name)
    download_directory = get_unique_folder_name(base_path, 'git_task')

    projects = fetch_gitlab_projects(gitlab_url, access_token, download_directory)
    print(projects)

    if projects:
        project_url, storage_path = projects[0]
        print("项目URL:", project_url)
        print("存储路径:", storage_path)
        return JsonResponse({'code': '200', 'msg': '拉取文件成功', 'folder_name': storage_path})
    else:
        return JsonResponse({"error": "拉取失败", "code": "500"})


def clone_or_pull_svn(svn_url, svn_path, username, password, max_retries=3, timeout=100):
    """克隆或拉取SVN项目。"""
    retries = 0
    while retries < max_retries:
        try:
            print('正在拉取或克隆:', svn_url)

            # 检查svn_path是否存在，如果存在则使用svn update，否则使用svn checkout
            if os.path.exists(svn_path):
                command = ['svn', 'update', svn_path, '--non-interactive', '--username', username, '--password',
                           password]
                print('更新项目:', svn_url)
            else:
                command = ['svn', 'checkout', svn_url, svn_path, '--non-interactive', '--username', username,
                           '--password', password]
                print('克隆项目:', svn_url)

            result_code = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            print(result_code)

            if result_code.returncode == 0:
                return True, "成功克隆或拉取项目"
            else:
                raise subprocess.CalledProcessError(result_code.returncode, command, result_code.stderr)
        except subprocess.TimeoutExpired:
            retries += 1
            if retries < max_retries:
                print(f"克隆或拉取项目超时，正在重试，重试次数：{retries}")
                continue
            else:
                return False, f"克隆或拉取项目超时，已达到最大重试次数 ({max_retries})"
        except subprocess.CalledProcessError as e:
            retries += 1
            if retries < max_retries:
                print(f"克隆或拉取项目失败，重试次数：{retries}")
            else:
                return False, f"克隆或拉取项目失败，已达到最大重试次数 ({max_retries}), 错误输出: {e.stderr}"
        except Exception as e:
            return False, f"Error: {str(e)}"

    return False, f"克隆或拉取项目失败，已达到最大重试次数 ({max_retries})"


def fetch_svn_projects(svn_url, username, password, download_path):
    """从SVN服务器拉取项目。"""
    fetched_projects = []

    if svn_url.endswith('/'):
        svn_path = os.path.join(download_path, svn_url.split('/')[-2])
        try:
            result = clone_or_pull_svn(svn_url, svn_path, username, password)
            if result[0]:
                fetched_projects.append((svn_url, svn_path))
                print("克隆或拉取项目成功：", svn_url)
            else:
                print("克隆或拉取项目失败")
                print("错误输出:", result[1])
        except Exception as e:
            print("Error on %s: %s" % (svn_url, str(e)))
    else:
        for index in range(1, 11):
            url = f"{svn_url}?username={username}&password={password}&list_projects=true&page={index}"
            try:
                all_projects = urlopen(url)
                all_projects_dict = json.loads(all_projects.read().decode(encoding='UTF-8'))
                if not all_projects_dict:
                    break
                for project in all_projects_dict:
                    svn_path = os.path.join(download_path, project['name'])
                    try:
                        result = clone_or_pull_svn(project['url'], svn_path, username, password)
                        if result[0]:
                            fetched_projects.append((project['url'], svn_path))
                            print("克隆或拉取项目成功：", project['url'])
                        else:
                            print("克隆或拉取项目失败")
                            print("错误输出:", result[1])
                    except Exception as e:
                        print("Error on %s: %s" % (project['url'], str(e)))
            except Exception as e:
                print(f"Error fetching projects on page {index}: {str(e)}")
                break  # 停止分页拉取，因为当前页出现问题

    return fetched_projects


def clone_svn_repository(req):
    """克隆SVN仓库。"""
    svn_url = req.POST['url']
    username = req.POST['username']
    password = req.POST['password']
    item_name = req.POST['item_name']

    base_path = os.path.join(processed_file_save_path, item_name)
    download_directory = get_unique_folder_name(base_path, 'svn_task')

    projects = fetch_svn_projects(svn_url, username, password, download_directory)
    print(projects)

    if projects:
        project_url, storage_path = projects[0]
        print("项目URL:", project_url)
        print("存储路径:", storage_path)
        return JsonResponse({'code': '200', 'msg': '拉取文件成功', 'folder_name': storage_path})
    else:
        return JsonResponse({"error": "拉取失败", "code": "500"})


def deepseek_detection(req):
    """进行深度检测。"""
    folder_path = req.POST['folder_name']
    item_id = req.POST['item_id']
    task_name = req.POST['task_name']
    model_name = req.POST['model_name']
    start_time = get_current_time()

    check_result = check_task_name(task_name, item_id)
    if check_result:
        return JsonResponse({"msg": "任务名已存在，请修改任务名", "code": "500"})

    task_id = get_id('taskId', 'vuldetail')
    current_status = '正在检测'
    review_status = '未审核'

    if model_name == 'deepseek-1.3b':
        detection_type = 'deepseek1.3b检测'
    elif model_name == 'deepseek-6.7b':
        detection_type = 'deepseek6.7b修复'
    elif model_name == 'qwen-7b':
        detection_type = 'qwen7b检测'
    else:
        return JsonResponse({'code': '500', 'msg': 'Error! Model does not exist.'})

    vulnerability_detail = vuldetail_insert(task_id, item_id, task_name, detection_type, 0, 0, 0, 0, 0, 0,
                                            current_status,
                                            start_time, 0, 0, review_status)
    if vulnerability_detail.status_code == 500:
        return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})

    folder_path = get_file(folder_path, task_name)
    file_num = len(os.listdir(folder_path))
    code_size, file_size = get_folder_status(folder_path)

    if file_num == 0:
        return JsonResponse({'code': '500', 'msg': 'Error! No sample.'})

    vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size, file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status)
    if vulnerability_detail.status_code == 500:
        return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})

    test_result = []
    file_path_list = []
    for file in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file)
        file_path_list.append(file_path)

    result_list = location_deepseek(file_path_list, model_name)

    for result in result_list:
        file_id = get_id('fileId', 'vulfile')
        file_path = result['文件路径']
        filename = os.path.basename(file_path)
        for issue in result['结果']:
            vulnerability_name = issue['漏洞类型']
            code = issue['源代码']
            test_result.append({
                'filename': filename,
                'file_path': file_path,
                'cwe_id': vulnerability_name,
                'code': code,
                'line_number': '',
                'risk_level': '',
                'repair_code': '',
                'new_line_number': '',
                'repair_status': '未修复',
                'is_question': '是问题',
                'model': model_name
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
    vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, file_num, 0, 0, code_size,
                                            file_size,
                                            file_num, current_status,
                                            start_time, end_time, last_time_str, review_status)

    if vulnerability_detail.status_code == 200:
        return JsonResponse({"msg": "漏洞信息页面数据插入成功", "code": "200"})
    else:
        return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})


def deepseek_repair(req):
    """修复漏洞。"""
    file_id = req.POST['file_id']
    task_id = req.POST['task_id']
    code = req.POST['code']
    vultype = req.POST['vultype']
    model_name = req.POST['model_name']
    detection_type = 'repair'

    try:
        result = getLLM_deepseek2(code, vultype, model_name, detection_type)
        repair_code = result['response']
        code_location = get_location(code, repair_code)

        vulfile_update(task_id, file_id, repair_code, str(code_location))

        return JsonResponse({"msg": "修复信息修改成功", "code": "200"})
    except Exception as e:
        return JsonResponse({"msg": "修复失败", "code": "500", "error": str(e)})


def copy_java_files_with_label_one(json_path, vul_directory):
    """将json文件中标签为1（有漏洞）的文件，存放在一个新的目录下，以便fortify下一步扫描"""
    # 读取JSON文件
    with open(json_path, 'r', encoding='utf-8') as json_file:
        data = json.load(json_file)

    num = 0
    # 遍历每一条数据
    for item in data:
        file_path = item['file_path']
        try:
            label = item['label']
        except:
            label = ''

        # 如果标签为1，则复制文件到目标目录
        if label == 1:
            # 获取文件名
            file_name = os.path.basename(file_path)
            # 构建目标路径
            target_path = os.path.join(vul_directory, file_name)
            # 复制文件
            shutil.copy(str(file_path), str(target_path))
            num += 1

    return num


def fortify_01_detection(req):
    """fortify和01组合扫描"""
    folder_path = req.POST['folder_path']
    item_id = req.POST['item_id']
    task_name = req.POST['task_name']
    model_name = int(req.POST['model_name'])  # model_name == 0,01模型先扫;model_name == 1,fortify先扫
    template = req.POST['template']
    version = req.POST['version']
    # print(arg)
    # folder_path = arg['folder_path']
    # item_id = arg['item_id']
    # task_name = arg['task_name']
    # model_name = int(arg['model_name'])  # model_name == 0,01模型先扫;model_name == 1,fortify先扫
    # template = arg['template']
    # version = arg['version']
    start_time = get_current_time()

    global task_list
    global lock

    check_result = check_task_name(task_name, item_id)
    if check_result:
        print("任务名已存在，请修改任务名")
        return JsonResponse({"msg": "任务名已存在，请修改任务名", "code": "500"})

    task_id = get_id('taskId', 'vuldetail')
    current_status = '正在检测'
    review_status = '未审核'
    if model_name == 0:
        detection_type = '组合扫描-1'  # 01模型先扫
    elif model_name == 1:
        detection_type = '组合扫描-2'  # fortify先扫
    elif model_name == 2:
        detection_type = '组合扫描-3'  # 只用01扫描
    else:
        return JsonResponse({'code': '500', 'msg': 'Error! Model does not exist.'})

    vulnerability_detail = vuldetail_insert(task_id, item_id, task_name, detection_type, 0, 0, 0, 0, 0,
                                            0, current_status,
                                            start_time, 0, 0, review_status, version)

    folder_path = get_file(folder_path, task_name)
    file_num, code_size, file_size = count_java_files(folder_path)

    if file_num == 0:
        print('Error! 文件夹内不存在该语言的文件！')
        return JsonResponse({'code': '500', 'msg': 'Error! 文件夹内不存在该语言的文件！'})

    high_num = 0
    medium_num = 0
    low_num = 0

    vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, file_num, 0, 0,
                                            code_size,
                                            file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status)

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

    if model_name == 0:  # 01模型先扫
        try:
            result = model_detection(folder_path, task_name)  # 调用0-1模型进行检测
            vul_directory = os.path.join(folder_path, task_name + '_vul')  # 有漏洞的文件目录
            if not os.path.exists(vul_directory):  # 判断文件夹是否存在
                os.makedirs(vul_directory)
            num = copy_java_files_with_label_one(result['json_path'],
                                                 vul_directory)  # 将json文件中标签为1（有漏洞）的文件，存放在vul_directory下
            print(f'01模型认为有漏洞的代码文件数为：{num}')
            if num != 0:  # 如果0-1模型扫出来的漏洞数量不为0
                run_fortify(vul_directory, template, version)  # 运行fortify检测有漏洞的文件
                folder_name = os.path.basename(os.path.normpath(vul_directory))
                # print(folder_name)
                pdf_file_path = os.path.join(str(vul_directory), folder_name + '.pdf')
                # print(pdf_file_path)
                if template != "Developer Workbook":
                    result_list = location_fortify(folder_path, pdf_file_path, template)  # fortify扫描得到的结果列表
                else:
                    result_list = location_fortify_3(folder_path,
                                                     pdf_file_path)  # fortify扫描得到结果列表，只不过是Developer Workbook规范
                if len(result_list) > 0:
                    for result in result_list:
                        test_result = []
                        file_id = get_id('fileId', 'vulfile')
                        file_name = result['filename']
                        file_path = os.path.join(folder_path, file_name)
                        cwe_id = result['cwe_id']
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
                            'code': code,
                            'line_number': line_number,
                            'risk_level': '',
                            'repair_code': '',
                            'new_line_number': new_line_number,
                            'repair_status': '未修复',
                            'is_question': '是问题',
                            'Sink': Sink,
                            'Enclosing_Method': Enclosing_Method,
                            'Source': Source,
                            'model': detection_type
                        })
                        level = get_level(cwe_id)
                        if level == '高危':
                            high_num += 1
                        elif level == '中危':
                            medium_num += 1
                        elif level == '低危':
                            low_num += 1
                        vulfile_insert(task_id, file_id, test_result)

            end_time = get_current_time()
            start_time = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            end_time = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            last_time = end_time - start_time
            hours, remainder = divmod(last_time.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            last_time_str = f"{hours}时{minutes}分{seconds}秒"

            current_status = '检测完成'
            vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, high_num, medium_num,
                                                    low_num,
                                                    code_size,
                                                    file_size,
                                                    file_num, current_status,
                                                    start_time, end_time, last_time_str, review_status)

            if vulnerability_detail.status_code == 200:
                return JsonResponse({"msg": "漏洞信息页面数据插入成功", "code": "200"})
            else:
                return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})

        except Exception as e:
            current_status = '检测失败'
            vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size,
                                                    file_size,
                                                    file_num, current_status,
                                                    start_time, 0, 0, review_status)
            if vulnerability_detail.status_code == 200:
                return JsonResponse(
                    {"msg": "01-first扫描失败，漏洞信息页面数据插入成功", "code": "200", "error": str(e)})
            else:
                return JsonResponse(
                    {"msg": "01-first扫描失败，漏洞信息页面数据插入错误", "code": "500", "error": str(e)})

    elif model_name == 1:  # fortify先扫
        try:
            run_fortify(folder_path, template, version)  # fortify扫描全部文件
            folder_name = os.path.basename(os.path.normpath(folder_path))
            pdf_file_path = os.path.join(folder_path, folder_name + '.pdf')
            if template != "Developer Workbook":
                result_list = location_fortify(folder_path, pdf_file_path, template)  # fortify扫描得到的结果列表
            else:
                result_list = location_fortify_3(folder_path, pdf_file_path)  # fortify扫描得到结果列表，只不过是Developer Workbook规范
            vul_directory = os.path.join(folder_path, 'vul_directory')
            # 确保漏洞目录目录存在
            if not os.path.exists(vul_directory):
                os.makedirs(vul_directory)
            # 将fortify扫描出来有漏洞的文件存放在vul_directory中
            for result in result_list:
                file_name = result['filename']
                # 构建目标路径
                target_path = os.path.join(vul_directory, file_name)
                # 复制文件
                shutil.copy(os.path.join(folder_path, file_name), target_path)

            if len(os.listdir(vul_directory)) != 0:  # 如果fortify检测出来的漏洞数不为0
                print(vul_directory)
                result = model_detection(vul_directory, task_name)  # 调用0-1模型进行检测
                # 读取json文件
                with open(result['json_path'], 'r') as f:
                    json_data = json.load(f)

                # 创建一个文件名到结果的映射
                file_name_list = []
                # 删除label为0的文件信息
                for item in json_data:
                    if item['label'] == 0:
                        file_name = os.path.basename(item['file_path'])
                        file_name_list.append(file_name)

                for result in result_list:
                    if result['filename'] in file_name_list:
                        result_list.remove(result)

                # print(result_list)
                for result in result_list:
                    test_result = []
                    file_id = get_id('fileId', 'vulfile')
                    file_name = result['filename']
                    file_path = os.path.join(folder_path, file_name)
                    cwe_id = result['cwe_id']
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
                        'code': code,
                        'line_number': line_number,
                        'risk_level': '',
                        'repair_code': '',
                        'new_line_number': new_line_number,
                        'repair_status': '未修复',
                        'is_question': '是问题',
                        'Sink': Sink,
                        'Enclosing_Method': Enclosing_Method,
                        'Source': Source,
                        'model': detection_type
                    })
                    level = get_level(cwe_id)
                    if level == '高危':
                        high_num += 1
                    elif level == '中危':
                        medium_num += 1
                    elif level == '低危':
                        low_num += 1
                    vulfile_insert(task_id, file_id, test_result)

            end_time = get_current_time()
            start_time = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            end_time = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            last_time = end_time - start_time
            hours, remainder = divmod(last_time.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            last_time_str = f"{hours}时{minutes}分{seconds}秒"

            current_status = '检测完成'
            vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, high_num, medium_num,
                                                    low_num,
                                                    code_size,
                                                    file_size,
                                                    file_num, current_status,
                                                    start_time, end_time, last_time_str, review_status)

            if vulnerability_detail.status_code == 200:
                return JsonResponse({"msg": "漏洞信息页面数据插入成功", "code": "200"})
            else:
                return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})
        except Exception as e:
            current_status = '检测失败'
            vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size,
                                                    file_size,
                                                    file_num, current_status,
                                                    start_time, 0, 0, review_status)

            if vulnerability_detail.status_code == 200:
                return JsonResponse(
                    {"msg": "规则-first扫描失败，漏洞信息页面数据插入成功", "code": "200", "error": str(e)})
            else:
                return JsonResponse(
                    {"msg": "规则-first扫描失败，漏洞信息页面数据插入错误", "code": "500", "error": str(e)})

    elif model_name == 2:  # 01单独扫描
        try:
            result = model_detection(folder_path, task_name)  # 调用0-1模型进行检测

            print(result)
            if result['code'] == 500:
                current_status = '检测失败'
                vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size,
                                                        file_size,
                                                        file_num, current_status,
                                                        start_time, 0, 0, review_status)

                if vulnerability_detail.status_code == 200:
                    return JsonResponse({"code": "500", "msg": f"检测失败，漏洞信息页面数据插入成功: {result['msg']}"})
                else:
                    return JsonResponse({"code": "500", "msg": f"检测失败，漏洞信息页面数据插入错误: {result['msg']}"})

            # 读取json文件
            with open(result['json_path'], 'r') as f:
                json_data = json.load(f)

            # 创建一个文件名到结果的映射
            path_list = []
            # 删除label为0的文件信息
            for item in json_data:
                if item['label'] == 1:
                    filename = os.path.basename(item['file_path'])
                    path_list.append(filename)

            result_rules = query_for_vul(folder_path)
            result_list = []
            # 只有规则和01同时认为有漏洞的文件，我才认为真的有漏洞
            for result in result_rules:
                filename = result['filename']
                if filename in path_list:
                    result_list.append({
                        'filename': filename,
                        'cwe_id': '',
                        'vul_name': result['vul_name'],
                        'code': result['code'],
                        'line_number': '',
                        'new_line_number': result['new_line_number'],
                    })

            for result in result_list:
                test_result = []
                file_id = get_id('fileId', 'vulfile')
                file_name = result['filename']
                file_path = os.path.join(folder_path, file_name)
                cwe_id = ''
                vul_name = result['vul_name']
                code = result['code']
                line_number = result['line_number']
                new_line_number = result['new_line_number']
                test_result.append({
                    'filename': file_name,
                    'file_path': file_path,
                    'cwe_id': cwe_id,
                    'vul_name': vul_name,
                    'code': code,
                    'line_number': line_number,
                    'risk_level': '',
                    'repair_code': '',
                    'new_line_number': new_line_number,
                    'repair_status': '未修复',
                    'is_question': '是问题',
                    'model': detection_type
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
            vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, file_num, 0, 0,
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
            vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size,
                                                    file_size,
                                                    file_num, current_status,
                                                    start_time, 0, 0, review_status)

            if vulnerability_detail.status_code == 200:
                return JsonResponse(
                    {"msg": "01单独扫描扫描失败，漏洞信息页面数据插入成功", "code": "200", "error": str(e)})
            else:
                return JsonResponse(
                    {"msg": "01单独扫描扫描失败，漏洞信息页面数据插入错误", "code": "500", "error": str(e)})


#
# def deepseek_chat(req):
#    """聊天/生成。"""
#    prompt = req.POST['prompt']
#    model_name = 'deepseek-6.7b'
#    try:
#        result = deepseek_chat2(prompt, model_name)
#        response_content = result['response']
#        return JsonResponse({"msg": "聊天信息返回成功", "code": "200", "response": response_content})
#    except Exception as e:
#        return JsonResponse({"msg": "聊天信息返回失败", "code": "500", "error": str(e)})
#
def deepseek_chat(req):
    """聊天/生成。"""
    prompt = req.GET.get('prompt', '')
    model_name = 'deepseek-6.7b'
    try:
        def stream_generator():
            result = deepseek_chat3(prompt, model_name)
            for chunk in result:
                if chunk == '':
                    break
                yield f"data: {chunk}\n\n"

        return StreamingHttpResponse(stream_generator(), content_type='text/event-stream')
    except Exception as e:
        return JsonResponse({"msg": "聊天信息返回失败", "code": "500", "error": str(e)})


def fortify_only(req):
    """只使用fortify扫描"""
    folder_path = req.POST['folder_path']
    item_id = req.POST['item_id']
    task_name = req.POST['task_name']
    model_name = req.POST['model_name']  # fortify
    template = req.POST['template']
    version = req.POST['version']
    start_time = get_current_time()

    check_result = check_task_name(task_name, item_id)
    if check_result:
        return JsonResponse({"msg": "任务名已存在，请修改任务名", "code": "500"})

    folder_path = get_file(folder_path, task_name)
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

    vulnerability_detail = vuldetail_insert(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size, file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status, version)
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
            print("*************************************")
            print(result_list)
            print("*************************************")
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
                'vul_name': vul_name,
                'code': code,
                'line_number': line_number,
                'risk_level': '',
                'repair_code': '',
                'new_line_number': new_line_number,
                'repair_status': '未修复',
                'is_question': '是问题',
                'Sink': Sink,
                'Enclosing_Method': Enclosing_Method,
                'Source': Source,
                'model': detection_type
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
        vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, 0, 0, review_status)

        if vulnerability_detail.status_code == 200:
            return JsonResponse({"msg": "规则扫描失败，漏洞信息页面数据插入成功", "code": "200", "error": str(e)})
        else:
            return JsonResponse({"msg": "规则扫描失败，漏洞信息页面数据插入错误", "code": "500", "error": str(e)})


def fortify_LLM(req):
    """fortify+LLM组合扫描"""
    folder_path = req.POST['folder_path']
    item_id = req.POST['item_id']
    task_name = req.POST['task_name']
    model_name = req.POST['model_name']  # qwen-7b or deepseek-6.7b
    template = req.POST['template']
    version = req.POST['version']
    start_time = get_current_time()

    check_result = check_task_name(task_name, item_id)
    if check_result:
        return JsonResponse({"msg": "任务名已存在，请修改任务名", "code": "500"})

    folder_path = get_file(folder_path, task_name)
    file_num = len(os.listdir(folder_path))
    code_size, file_size = get_folder_status(folder_path)

    if file_num == 0:
        return JsonResponse({'code': '500', 'msg': 'Error! 文件夹为空！'})

    task_id = get_id('taskId', 'vuldetail')
    current_status = '正在检测'
    review_status = '未审核'

    detection_type = 'mix'

    vulnerability_detail = vuldetail_insert(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size, file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status, template)
    if vulnerability_detail.status_code == 500:
        return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})

    try:
        run_fortify(folder_path, template, version)  # fortify扫描全部文件
        folder_name = os.path.basename(os.path.normpath(folder_path))
        pdf_file_path = os.path.join(folder_path, folder_name + '.pdf')
        if template != "Developer Workbook":
            result_list = location_fortify(folder_path, pdf_file_path, template)  # fortify扫描得到的结果列表
        else:
            result_list = location_fortify_3(folder_path, pdf_file_path)  # fortify扫描得到结果列表，只不过是Developer Workbook规范

        if result_list:  # 如果fortify检测出来的漏洞数不为0
            for result in result_list:
                vultype = result['cwe_id']
                code = result['code']
                response = getLLM_deepseek2(code, vultype, model_name, detection_type)  # 获取大模型的检测结果
                # print(result)
                text = response['response']
                label = get_label(text)  # 从大模型的检测结果中获取是否存在相应的安全漏洞
                # print(label)
                if label == '是':
                    test_result = []
                    file_id = get_id('fileId', 'vulfile')
                    file_name = result['filename']
                    # print(file_name)
                    file_path = os.path.join(folder_path, file_name)
                    cwe_id = result['cwe_id']
                    code = result['code']
                    line_number = result['line_number']
                    new_line_number = result['new_line_number']
                    test_result.append({
                        'filename': file_name,
                        'file_path': file_path,
                        'cwe_id': cwe_id,
                        'code': code,
                        'line_number': line_number,
                        'risk_level': '',
                        'repair_code': '',
                        'new_line_number': new_line_number,
                        'repair_status': '未修复',
                        'is_question': '是问题',
                        'model': detection_type
                    })
                    vulfile_insert(task_id, file_id, test_result)  # 将扫描结果存入数据库文件表

        end_time = get_current_time()
        start_time = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end_time = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        last_time = end_time - start_time
        hours, remainder = divmod(last_time.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        last_time_str = f"{hours}时{minutes}分{seconds}秒"

        current_status = '检测完成'
        vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, file_num, 0, 0, code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, end_time, last_time_str, review_status)  # 将扫描结果存入数据库任务表

        if vulnerability_detail.status_code == 200:
            return JsonResponse({"msg": "规则+LLM扫描成功，漏洞信息页面数据插入成功", "code": "200"})
        else:
            return JsonResponse({"msg": "规则+LLM扫描成功，漏洞信息页面数据插入错误", "code": "500"})

    except Exception as e:
        current_status = '检测失败'
        vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, 0, 0, review_status)

        if vulnerability_detail.status_code == 200:
            return JsonResponse({"msg": "规则+LLM扫描失败，漏洞信息页面数据插入成功", "code": "200", "error": str(e)})
        else:
            return JsonResponse({"msg": "规则+LLM扫描失败，漏洞信息页面数据插入错误", "code": "500", "error": str(e)})


def custom_rescan(req):
    """使用自定义规则重新扫描"""
    folder_path = req.POST['folder_path']
    item_id = req.POST['item_id']
    item_name = req.POST['item_name']
    task_name = req.POST['task_name']
    model_name = req.POST['model_name']
    template = req.POST['template']
    version = req.POST['version']
    custom_rule = req.POST['custom_rule']

    start_time = get_current_time()

    rescan_path = '/home/public/JAVA_gf/app/static/DATA_Rescan'
    rescan_sign = '_r'

    new_folder_path = os.path.join(rescan_path, item_name, task_name + rescan_sign)

    shutil.rmtree(new_folder_path)

    os.makedirs(new_folder_path, exist_ok=True)

    java_file_list = []
    for root, sub_dirs, file_names in os.walk(folder_path):
        for file_name in file_names:
            if file_name.endswith('.java'):
                java_file_list.append(os.path.join(root, file_name))

    for file in java_file_list:
        if not os.path.isfile(file):
            print(f'文件路径错误: {file}')
            continue
        shutil.copy(file, os.path.join(new_folder_path, os.path.basename(file)))

    folder_path = new_folder_path

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

    new_task_id = task_id
    new_task_name = task_name + '_r'

    vulnerability_detail = vuldetail_insert(new_task_id, item_id, new_task_name, detection_type, 0, 0, 0, code_size,
                                            file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status, version)
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
        run_custom_fortify(folder_path, template, version, 1, custom_rule, 0, [])  # 自定义fortify扫描全部文件
        folder_name = os.path.basename(os.path.normpath(folder_path))  # 获取文件夹的名字
        pdf_file_path = os.path.join(folder_path, folder_name + '.pdf')  # 获取fortify扫描得到的pdf文件的路径
        if template != "Developer Workbook":
            result_list = location_fortify(folder_path, pdf_file_path, template)  # fortify扫描得到的结果列表
        else:
            result_list = location_fortify_3(folder_path, pdf_file_path)  # fortify扫描得到结果列表，只不过是Developer Workbook规范
        for result in result_list:
            test_result = []
            file_id = get_id('fileId', 'vulfile')
            file_name = result['filename']
            file_path = os.path.join(folder_path, file_name)
            cwe_id = result['cwe_id']
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
                'code': code,
                'line_number': line_number,
                'risk_level': '',
                'repair_code': '',
                'new_line_number': new_line_number,
                'repair_status': '未修复',
                'is_question': '是问题',
                'Sink': Sink,
                'Enclosing_Method': Enclosing_Method,
                'Source': Source,
                'model': detection_type
            })

            vulfile_insert(new_task_id, file_id, test_result)  # 将扫描结果存入数据库文件表
            vul_level = get_level(cwe_id)  # 根据cweid获取漏洞危险等级
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
        vulnerability_detail = vuldetail_update(new_task_id, item_id, new_task_name, detection_type, high_num,
                                                medium_num,
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
        vulnerability_detail = vuldetail_update(new_task_id, item_id, new_task_name, detection_type, 0, 0, 0, code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, 0, 0, review_status)

        if vulnerability_detail.status_code == 200:
            return JsonResponse({"msg": "规则扫描失败，漏洞信息页面数据插入成功", "code": "200", "error": str(e)})
        else:
            return JsonResponse({"msg": "规则扫描失败，漏洞信息页面数据插入错误", "code": "500", "error": str(e)})


def fortify_filter(req):
    """只使用fortify扫描"""
    folder_path = req.POST['folder_path']
    item_id = req.POST['item_id']
    task_name = req.POST['task_name']
    model_name = req.POST['model_name']  # fortify
    template = req.POST['template']
    version = req.POST['version']
    filter_file = req.POST['filter_file']
    start_time = get_current_time()

    check_result = check_task_name(task_name, item_id)
    if check_result:
        return JsonResponse({"msg": "任务名已存在，请修改任务名", "code": "500"})

    folder_path = get_file(folder_path, task_name)
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

    vulnerability_detail = vuldetail_insert(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size, file_size,
                                            file_num, current_status,
                                            start_time, 0, 0, review_status, version)
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
        run_fortify(folder_path, template, version, 0, [], 1, filter_file)  # fortify扫描全部文件
        folder_name = os.path.basename(os.path.normpath(folder_path))  # 获取文件夹的名字
        pdf_file_path = os.path.join(folder_path, folder_name + '.pdf')  # 获取fortify扫描得到的pdf文件的路径
        if template != "Developer Workbook":
            result_list = location_fortify(folder_path, pdf_file_path, template)  # fortify扫描得到的结果列表
        else:
            result_list = location_fortify_3(folder_path, pdf_file_path)  # fortify扫描得到结果列表，只不过是Developer Workbook规范
        for result in result_list:
            test_result = []
            file_id = get_id('fileId', 'vulfile')
            file_name = result['filename']
            file_path = os.path.join(folder_path, file_name)
            cwe_id = result['cwe_id']
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
                'code': code,
                'line_number': line_number,
                'risk_level': '',
                'repair_code': '',
                'new_line_number': new_line_number,
                'repair_status': '未修复',
                'is_question': '是问题',
                'Sink': Sink,
                'Enclosing_Method': Enclosing_Method,
                'Source': Source,
                'model': detection_type
            })
            vulfile_insert(task_id, file_id, test_result)  # 将扫描结果存入数据库文件表
            vul_level = get_level(cwe_id)  # 根据cweid获取漏洞危险等级
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
        vulnerability_detail = vuldetail_update(task_id, item_id, task_name, detection_type, 0, 0, 0, code_size,
                                                file_size,
                                                file_num, current_status,
                                                start_time, 0, 0, review_status)

        if vulnerability_detail.status_code == 200:
            return JsonResponse({"msg": "规则扫描失败，漏洞信息页面数据插入成功", "code": "200", "error": str(e)})
        else:
            return JsonResponse({"msg": "规则扫描失败，漏洞信息页面数据插入错误", "code": "500", "error": str(e)})


def manage_process(req):
    # 操作进程(暂停、继续、终止)
    taskid = req.POST['taskid']
    status = req.POST['status']
    # 根据taskid获得pid
    pid = get_pid(taskid)

    try:
        if status == '检测暂停':
            os.kill(pid, signal.SIGSTOP)
            result = update_status(taskid, status)
            print(f"进程 {pid} 已暂停。数据库检测状态修改：{result}")
            return JsonResponse({"msg": "进程已暂停", "code": "200"})
        elif status == '正在检测':
            os.kill(pid, signal.SIGCONT)
            result = update_status(taskid, status)
            print(f"进程 {pid} 已继续。数据库检测状态修改：{result}")
            return JsonResponse({"msg": "进程已继续", "code": "200"})
        elif status == '检测终止':
            os.kill(pid, signal.SIGTERM)
            result = update_status(taskid, status)
            print(f"进程 {pid} 已终止。数据库检测状态修改：{result}")
            return JsonResponse({"msg": "进程已终止", "code": "200"})
        else:
            return JsonResponse({"msg": "无效的状态", "code": "400", "error": f"无效的状态: {status}"})
    except ProcessLookupError:
        return JsonResponse({"msg": "进程不存在", "code": "404", "error": f"进程 {pid} 不存在。"})
    except PermissionError:
        return JsonResponse({"msg": "没有权限执行操作", "code": "403", "error": f"没有权限执行操作。"})
    except Exception as e:
        return JsonResponse({"msg": "执行操作时发生错误", "code": "500", "error": str(e)})


def get_xml(req):
    """获取xml文件并保存到指定路径"""
    uploaded_xml = req.FILES.get('xml_file', None)
    file_name, file_extension = os.path.splitext(uploaded_xml.name)
    file_extension = file_extension.lstrip('.').lower()

    folder_path = '/home/public/JAVA_gf/app/static/custom_rules/'

    try:
        if file_extension == 'xml':
            with open(os.path.join(folder_path, uploaded_xml.name), 'wb') as f:
                for chunk in uploaded_xml.chunks():
                    f.write(chunk)
            return JsonResponse({'code': '200', 'msg': '文件上传成功', 'folder_name': folder_path})
        else:
            return JsonResponse({'code': '500', 'msg': '文件格式错误', 'folder_name': folder_path})
    except Exception as e:
        return JsonResponse({'code': '500', 'msg': f'上传文件出现错误: {str(e)}'})


class Cleardb:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def delete_all(self):
        result = self.driver.execute_query("""MATCH (n) OPTIONAL MATCH (n)-[r]-() DELETE n,r""")
        return result


class Query:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def query_not_sent_over_ssl(self):
        result_1 = self.driver.execute_query(
            """MATCH (n:CALL{NAME:"<operator>.assignment"}) WHERE n.CODE CONTAINS "new Cookie" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        result_2 = self.driver.execute_query(
            """MATCH (n:CALL{NAME:"<operator>.assignment"}) WHERE n.CODE CONTAINS "new Cookie" MATCH (m:CALL{NAME:"setSecure"}) WHERE (n)-[*..2]-(m) AND toLower(m.CODE) CONTAINS "true" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        return result_1, result_2

    def query_hardcoded_password(self):
        result = self.driver.execute_query(
            """MATCH (n:CALL),(m:IDENTIFIER) WHERE (n.NAME = "<operator>.assignment" AND toLower(m.NAME) CONTAINS "password" AND (n)-[]-(m)) OR toLower(n.NAME) CONTAINS "password" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        return result

    def query_http_only_not_set(self):
        result_1 = self.driver.execute_query(
            """MATCH (n:CALL) WHERE n.CODE CONTAINS "new Cookie" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        result_2 = self.driver.execute_query(
            """MATCH (n:CALL) WHERE n.CODE CONTAINS "new Cookie" MATCH (m:CALL{NAME:"setHttpOnly"}) WHERE (n)-[*..2]-(m) AND toLower(m.CODE) CONTAINS "true" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        return result_1, result_2

    def query_json_injection(self):
        result = self.driver.execute_query(
            """MATCH (n:CALL) WHERE n.CODE CONTAINS "objectMapper.readValue" RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        return result

    def query_query_unsafe_json_deserialization(self):
        result_1 = self.driver.execute_query(
            """MATCH (n:CALL{NAME:"parseObject"})-[r:ARGUMENT]->(m:IDENTIFIER) RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        result_2 = self.driver.execute_query(
            """MATCH (n:CALL{NAME:"parseObject"})-[:ARGUMENT]->(m:IDENTIFIER) MATCH (l:LOCAL) WHERE l.NAME = m.NAME RETURN DISTINCT n.LINE_NUMBER,n.CODE,n.SOURCEFILE""")
        return result_1, result_2


class ModifyNode:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def modify_node_source(self, source_filename):
        rand_offset = random.randint(0, 999999999)
        cypher_clause = f'MATCH (n) WHERE n.SOURCEFILE IS NULL SET n.SOURCEFILE = "{source_filename}", n.id = n.id + {rand_offset} RETURN n'
        # noinspection PyTypeChecker
        result = self.driver.execute_query(cypher_clause)
        return result


def clear_database():
    clear_db = Cleardb("bolt://127.0.0.1:7687", "neo4j", "password")
    query_result = clear_db.delete_all()
    clear_db.close()


def set_sourcefile(filename):
    set_source = ModifyNode("bolt://127.0.0.1:7687", "neo4j", "password")
    query_result = set_source.modify_node_source(filename)
    set_source.close()


def copy_file(source_path):
    if os.path.exists(source_path):
        files = os.listdir(import_path)
        for file in files:
            os.remove(import_path + file)
        files = os.listdir(source_path)
        for file in files:
            shutil.copy(source_path + file, import_path)
    else:
        print('指定目录不存在')


def import_file():
    node_list = glob.glob(node_path)

    for node in node_list:
        print(node)
        import_node = f'/usr/share/cypher-shell/bin/cypher-shell -u neo4j -p password -f {node}'
        os.system(import_node)

    edge_list = glob.glob(edge_path)

    for edge in edge_list:
        print(edge)
        import_edge = f'/usr/share/cypher-shell/bin/cypher-shell -u neo4j -p password -f {edge}'
        os.system(import_edge)


def gen_csv_from(dir_path):
    if os.path.exists(csv_path):
        shutil.rmtree(csv_path)
    os.mkdir(csv_path)

    for filepath, dirs, filenames in os.walk(dir_path):
        for filename in filenames:
            if os.path.splitext(filename)[1] == '.java':
                command_parse = '/home/public/joern/joern-cli/joern-parse ' + os.path.join(filepath, filename)
                command_export = '/home/public/joern/joern-cli/joern-export --repr=all --format=neo4jcsv --out ' + os.path.join(
                    csv_path, filename)
                if os.path.exists(os.path.join(filepath, filename)):
                    os.system(command_parse)
                    if os.path.exists(os.path.join(csv_path, filename)):
                        print("Remove origin")
                        shutil.rmtree(os.path.join(csv_path, filename))
                    os.system(command_export)
                else:
                    print("Dir not found")


def query_for_vul(folder_path):
    gen_csv_from(folder_path)
    clear_database()
    for dir_name in os.listdir(csv_dir):
        print(dir_name)
        copy_file(os.path.join(csv_dir, dir_name + '/'))
        import_file()
        set_sourcefile(os.path.basename(dir_name))

    querying = Query("bolt://127.0.0.1:7687", "neo4j", "password")

    test_result = []
    # Cookie Security: Cookie not Sent Over SSL
    print('Cookie Security: Cookie not Sent Over SSL:')
    total = 0
    final_result = []
    query_result_1, query_result_2 = querying.query_not_sent_over_ssl()
    # querying.close()
    query_result_line = []
    query_result_code = []
    query_result_filename = []
    for record in query_result_1[0]:
        query_result_line.append(record.data()['n.LINE_NUMBER'])
        query_result_code.append(record.data()['n.CODE'])
        query_result_filename.append(record.data()['n.SOURCEFILE'])
    for record in query_result_2[0]:
        query_result_line.remove(record.data()['n.LINE_NUMBER'])
        query_result_code.remove(record.data()['n.CODE'])
        query_result_filename.remove(record.data()['n.SOURCEFILE'])
    if query_result_line:
        for record in query_result_line:
            print(
                f'Cookie Security: Cookie not Sent Over SSL   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
            total += 1
            final_result.append((record, query_result_code[query_result_line.index(record)],
                                 query_result_filename[query_result_line.index(record)]))
            test_result.append({
                'filename': query_result_filename[query_result_line.index(record)],
                'vul_name': 'Cookie Security: Cookie not Sent Over SSL',
                'code': query_result_code[query_result_line.index(record)],
                'new_line_number': record,
            })

    print(total)
    print(final_result)

    # Password Management: Hardcoded Password
    print('Password Management: Hardcoded Password:')
    total = 0
    final_result = []
    query_result = querying.query_hardcoded_password()
    # querying.close()
    query_result_line = []
    query_result_code = []
    query_result_filename = []
    for record in query_result[0]:
        query_result_line.append(record.data()['n.LINE_NUMBER'])
        query_result_code.append(record.data()['n.CODE'])
        query_result_filename.append(record.data()['n.SOURCEFILE'])
    if query_result_line:
        for record in query_result_line:
            print(
                f'Password Management: Hardcoded Password   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
            total += 1
            final_result.append((record, query_result_code[query_result_line.index(record)],
                                 query_result_filename[query_result_line.index(record)]))
            test_result.append({
                'filename': query_result_filename[query_result_line.index(record)],
                'vul_name': 'Password Management: Hardcoded Password',
                'code': query_result_code[query_result_line.index(record)],
                'new_line_number': record,
            })

    print(total)
    print(final_result)

    # Cookie Security: HTTPOnly not Set
    print('Cookie Security: HTTPOnly not Set:')
    total = 0
    final_result = []
    query_result_1, query_result_2 = querying.query_http_only_not_set()
    # querying.close()
    query_result_line = []
    query_result_code = []
    for record in query_result_1[0]:
        query_result_line.append(record.data()['n.LINE_NUMBER'])
        query_result_code.append(record.data()['n.CODE'])
        query_result_filename.append(record.data()['n.SOURCEFILE'])
    for record in query_result_2[0]:
        query_result_line.remove(record.data()['n.LINE_NUMBER'])
        query_result_code.remove(record.data()['n.CODE'])
        query_result_filename.remove(record.data()['n.SOURCEFILE'])
    if query_result_line:
        for record in query_result_line:
            query_result_line.remove(record)
            print(
                f'Cookie Security: HTTPOnly not Set   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
            total += 1
            final_result.append((record, query_result_code[query_result_line.index(record)],
                                 query_result_filename[query_result_line.index(record)]))
            test_result.append({
                'filename': query_result_filename[query_result_line.index(record)],
                'vul_name': 'Cookie Security: HTTPOnly not Set',
                'code': query_result_code[query_result_line.index(record)],
                'new_line_number': record,
            })

    print(total)
    print(final_result)

    # JSON Injection
    print('JSON Injection:')
    total = 0
    final_result = []
    query_result = querying.query_json_injection()
    # querying.close()
    query_result_line = []
    query_result_code = []
    query_result_filename = []
    for record in query_result[0]:
        query_result_line.append(record.data()['n.LINE_NUMBER'])
        query_result_code.append(record.data()['n.CODE'])
        query_result_filename.append(record.data()['n.SOURCEFILE'])
    if query_result_line:
        for record in query_result_line:
            print(
                f'JSON Injection   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
            total += 1
            final_result.append((record, query_result_code[query_result_line.index(record)],
                                 query_result_filename[query_result_line.index(record)]))
            test_result.append({
                'filename': query_result_filename[query_result_line.index(record)],
                'vul_name': 'JSON Injection',
                'code': query_result_code[query_result_line.index(record)],
                'new_line_number': record,
            })

    print(total)
    print(final_result)

    # Dynamic Code Evaluation: Unsafe JSON Deserialization
    print('Dynamic Code Evaluation: Unsafe JSON Deserialization:')
    total = 0
    final_result = []
    query_result_1, query_result_2 = querying.query_query_unsafe_json_deserialization()
    query_result_line = []
    query_result_code = []
    for record in query_result_1[0]:
        query_result_line.append(record.data()['n.LINE_NUMBER'])
        query_result_code.append(record.data()['n.CODE'])
        query_result_filename.append(record.data()['n.SOURCEFILE'])
    for record in query_result_2[0]:
        query_result_line.remove(record.data()['n.LINE_NUMBER'])
        query_result_code.remove(record.data()['n.CODE'])
        query_result_filename.remove(record.data()['n.SOURCEFILE'])
    if query_result_line:
        for record in query_result_line:
            print(
                f'Dynamic Code Evaluation: Unsafe JSON Deserialization   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
            total += 1
            final_result.append((record, query_result_code[query_result_line.index(record)],
                                 query_result_filename[query_result_line.index(record)]))
            test_result.append({
                'filename': query_result_filename[query_result_line.index(record)],
                'vul_name': 'Dynamic Code Evaluation: Unsafe JSON Deserialization',
                'code': query_result_code[query_result_line.index(record)],
                'new_line_number': record,
            })

    print(total)
    print(final_result)

    querying.close()
    return test_result


# def query_for_vul(req):
#     folder_path = req.POST['folder_path']
#
#     gen_csv_from(folder_path)
#     clear_database()
#     for dir_name in os.listdir(csv_dir):
#         print(dir_name)
#         copy_file(os.path.join(csv_dir, dir_name + '/'))
#         import_file()
#         set_sourcefile(os.path.basename(dir_name))
#
#     querying = Query("bolt://127.0.0.1:7687", "neo4j", "password")
#
#     test_result = []
#     # Cookie Security: Cookie not Sent Over SSL
#     print('Cookie Security: Cookie not Sent Over SSL:')
#     total = 0
#     final_result = []
#     query_result_1, query_result_2 = querying.query_not_sent_over_ssl()
#     # querying.close()
#     query_result_line = []
#     query_result_code = []
#     query_result_filename = []
#     for record in query_result_1[0]:
#         query_result_line.append(record.data()['n.LINE_NUMBER'])
#         query_result_code.append(record.data()['n.CODE'])
#         query_result_filename.append(record.data()['n.SOURCEFILE'])
#     for record in query_result_2[0]:
#         query_result_line.remove(record.data()['n.LINE_NUMBER'])
#         query_result_code.remove(record.data()['n.CODE'])
#         query_result_filename.remove(record.data()['n.SOURCEFILE'])
#     if query_result_line:
#         for record in query_result_line:
#             print(
#                 f'Cookie Security: Cookie not Sent Over SSL   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
#             total += 1
#             final_result.append((record, query_result_code[query_result_line.index(record)],query_result_filename[query_result_line.index(record)]))
#             test_result.append({
#                 'filename': query_result_filename[query_result_line.index(record)],
#                 'vul_name': 'Cookie Security: Cookie not Sent Over SSL',
#                 'code': query_result_code[query_result_line.index(record)],
#                 'new_line_number': record,
#             })
#
#     print(total)
#     print(final_result)
#
#     # Password Management: Hardcoded Password
#     print('Password Management: Hardcoded Password:')
#     total = 0
#     final_result = []
#     query_result = querying.query_hardcoded_password()
#     # querying.close()
#     query_result_line = []
#     query_result_code = []
#     query_result_filename = []
#     for record in query_result[0]:
#         query_result_line.append(record.data()['n.LINE_NUMBER'])
#         query_result_code.append(record.data()['n.CODE'])
#         query_result_filename.append(record.data()['n.SOURCEFILE'])
#     if query_result_line:
#         for record in query_result_line:
#             print(
#                 f'Password Management: Hardcoded Password   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
#             total += 1
#             final_result.append((record, query_result_code[query_result_line.index(record)],query_result_filename[query_result_line.index(record)]))
#             test_result.append({
#                 'filename': query_result_filename[query_result_line.index(record)],
#                 'vul_name': 'Password Management: Hardcoded Password',
#                 'code': query_result_code[query_result_line.index(record)],
#                 'new_line_number': record,
#             })
#
#     print(total)
#     print(final_result)
#
#     # Cookie Security: HTTPOnly not Set
#     print('Cookie Security: HTTPOnly not Set:')
#     total = 0
#     final_result = []
#     query_result_1, query_result_2 = querying.query_http_only_not_set()
#     # querying.close()
#     query_result_line = []
#     query_result_code = []
#     for record in query_result_1[0]:
#         query_result_line.append(record.data()['n.LINE_NUMBER'])
#         query_result_code.append(record.data()['n.CODE'])
#         query_result_filename.append(record.data()['n.SOURCEFILE'])
#     for record in query_result_2[0]:
#         query_result_line.remove(record.data()['n.LINE_NUMBER'])
#         query_result_code.remove(record.data()['n.CODE'])
#         query_result_filename.remove(record.data()['n.SOURCEFILE'])
#     if query_result_line:
#         for record in query_result_line:
#             query_result_line.remove(record)
#             print(
#                 f'Cookie Security: HTTPOnly not Set   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
#             total += 1
#             final_result.append((record, query_result_code[query_result_line.index(record)],query_result_filename[query_result_line.index(record)]))
#             test_result.append({
#                 'filename': query_result_filename[query_result_line.index(record)],
#                 'vul_name': 'Cookie Security: HTTPOnly not Set',
#                 'code': query_result_code[query_result_line.index(record)],
#                 'new_line_number': record,
#             })
#
#     print(total)
#     print(final_result)
#
#     # JSON Injection
#     print('JSON Injection:')
#     total = 0
#     final_result = []
#     query_result = querying.query_json_injection()
#     # querying.close()
#     query_result_line = []
#     query_result_code = []
#     query_result_filename = []
#     for record in query_result[0]:
#         query_result_line.append(record.data()['n.LINE_NUMBER'])
#         query_result_code.append(record.data()['n.CODE'])
#         query_result_filename.append(record.data()['n.SOURCEFILE'])
#     if query_result_line:
#         for record in query_result_line:
#             print(
#                 f'JSON Injection   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
#             total += 1
#             final_result.append((record, query_result_code[query_result_line.index(record)],query_result_filename[query_result_line.index(record)]))
#             test_result.append({
#                 'filename': query_result_filename[query_result_line.index(record)],
#                 'vul_name': 'JSON Injection',
#                 'code': query_result_code[query_result_line.index(record)],
#                 'new_line_number': record,
#             })
#
#     print(total)
#     print(final_result)
#
#     # Dynamic Code Evaluation: Unsafe JSON Deserialization
#     print('Dynamic Code Evaluation: Unsafe JSON Deserialization:')
#     total = 0
#     final_result = []
#     query_result_1, query_result_2 = querying.query_query_unsafe_json_deserialization()
#     query_result_line = []
#     query_result_code = []
#     for record in query_result_1[0]:
#         query_result_line.append(record.data()['n.LINE_NUMBER'])
#         query_result_code.append(record.data()['n.CODE'])
#         query_result_filename.append(record.data()['n.SOURCEFILE'])
#     for record in query_result_2[0]:
#         query_result_line.remove(record.data()['n.LINE_NUMBER'])
#         query_result_code.remove(record.data()['n.CODE'])
#         query_result_filename.remove(record.data()['n.SOURCEFILE'])
#     if query_result_line:
#         for record in query_result_line:
#             print(
#                 f'Dynamic Code Evaluation: Unsafe JSON Deserialization   Line: {record}  Code: {query_result_code[query_result_line.index(record)]} From: {query_result_filename[query_result_line.index(record)]}')
#             total += 1
#             final_result.append((record, query_result_code[query_result_line.index(record)],query_result_filename[query_result_line.index(record)]))
#             test_result.append({
#                 'filename': query_result_filename[query_result_line.index(record)],
#                 'vul_name': 'Dynamic Code Evaluation: Unsafe JSON Deserialization',
#                 'code': query_result_code[query_result_line.index(record)],
#                 'new_line_number': record,
#             })
#
#     print(total)
#     print(final_result)
#
#     querying.close()
#     print(test_result)
#     return HttpResponse("调用成功", status=200)

def rule_detection(req):
    """通过自定义规则进行检测"""
    folder_path = req.POST['folder_name']
    item_id = req.POST['item_id']
    task_name = req.POST['task_name']
    language = req.POST['language']
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
                    ast = esprima.parseScript(data,{"loc":True})  # 将javascript代码转为AST
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
            #print("自定义规则列表:", vuln_rules_list)
            custom_result = detect_vulnerabilities_with_strings(vuln_rules_list, code_lines) # 获取自定义规则的检测结果
            #print("自定义规则扫描结果:", custom_result)
            vulnerabilities.extend(custom_result) # 将自定义规则的检测结果添加到总结果中

            print(vulnerabilities)
            for result in vulnerabilities:
                clean_func_list = get_clean_func(language, result['漏洞类型'])  # 获取清洁函数列表
                #print("清洁函数列表:",clean_func_list)
                code_lines = data.splitlines()
                is_cleaned = is_sanitization_present(clean_func_list,code_lines) # 判断这段代码中是否包含对应类型的清洁函数
                #print("是否包含清洁函数:",is_cleaned)
                if is_cleaned is True: # 如果包含对应的清洁函数
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
                        vul_level = get_level(cwe_id,vul_name)  # 根据漏洞名称获取漏洞危险等级
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

def load_rules():
    """
    从数据库加载规则
    """

    # 将 rules.py 所在目录添加到 sys.path
    sys.path.append("/home/public/JAVA_gf/app/api/main_app")

    rows = get_rule_function_name()

    # 动态加载规则函数
    rules_module = importlib.import_module("rules")
    rules = []
    for row in rows:
        function_name = row["function_name"]
        if function_name is not None and function_name != "":
            #print("function_name:" + function_name)
            if hasattr(rules_module, function_name):
                rules.append({
                    "function_name": function_name,
                    "function": getattr(rules_module, function_name)
                })
    #print(rules)
    return rules

def is_sanitization_present(clean_func_list, code):
    """
    检查代码中是否存在清洁函数调用
    """
    # 如果 clean_func_list 为空，直接返回 False
    if not clean_func_list:
        return False

    # 构建正则表达式来匹配清洁函数的调用
    sanitization_pattern = re.compile(rf'\b({"|".join(clean_func_list)})\s*\(')

    # 检查代码行中是否存在匹配的清洁函数调用
    for line in code:
        if sanitization_pattern.search(line):
            return True

    return False

def detect_vulnerabilities_with_strings(vuln_rules_list, code):
    """
    利用字符串匹配规则实现漏洞检测

    :param vuln_rules_list: 漏洞规则列表，每个规则是一个字典，包含 'name' 和 'pattern' 字段
                      例如: [{"name": "Replace CRLF", "pattern": 'replace("\\r\\n","");'}]
    :param code: 代码内容的列表，每个元素是一行代码
    :return: 漏洞检测结果列表，每个结果是一个字典，包含规则名称、匹配内容和行号
    """
    # 如果规则列表为空，直接返回空结果
    if not vuln_rules_list:
        return []

    results = []  # 用于存储检测结果

    # 遍历每一行代码
    for line_no, line in enumerate(code, start=1):
        # 遍历所有规则
        for rule in vuln_rules_list:
            # 如果规则字符串在代码行中找到，则记录结果
            if rule['pattern'] in line:
                results.append({
                    "漏洞类型": rule['name'],
                    "行号": line_no,
                })

    return results


def index(req):
    method = req.POST["method"]
    if method == "decompression":
        return decompress_file(req)
    elif method == "clone_git_repository":
        return clone_git_repository(req)
    elif method == 'deepseek_detection':
        return deepseek_detection(req)
    elif method == 'deepseek_repair':
        return deepseek_repair(req)
    elif method == 'fortify_01_detection':
        return fortify_01_detection(req)
    elif method == 'deepseek_chat':
        return deepseek_chat(req)
    elif method == 'fortify_only':
        return fortify_only(req)
    elif method == 'fortify_LLM':
        return fortify_LLM(req)
    elif method == 'create_process':
        return create_process()
    elif method == 'create_queue':
        return create_queue(req)
    elif method == 'deepseek_chat2':
        return deepseek_chat2(req)
    elif method == 'clone_svn_repository':
        return clone_svn_repository(req)
    elif method == 'custom_rescan':
        return custom_rescan(req)
    elif method == 'fortify_filter':
        return fortify_filter(req)
    elif method == 'manage_process':
        return manage_process(req)
    elif method == 'get_xml':
        return get_xml(req)
    elif method == 'rule_detection':
        return rule_detection(req)
    # elif method == 'query_for_vul':
    #     return query_for_vul(req)
    else:
        return HttpResponse("method error! ")