import asyncio
import datetime
import shlex
import subprocess
import tarfile
import time
import uuid
import zipfile
from io import StringIO
import re
import javalang
import importlib
import traceback
import esprima
from urllib.request import urlopen
from django.http import StreamingHttpResponse, JsonResponse
from multiprocessing import Process, Queue, Semaphore
from javalang.tokenizer import LexerError
import pandas as pd
import tempfile
import math
import py7zr
import rarfile
import os
import shutil
import json
import signal
import glob
import random
import string
import sys
from neo4j import GraphDatabase

from app.api.model_api.large_model_detection import *
from app.api.model_api.fortify_detection import *
from app.api.model_api.transformer_detection import *
from app.api.config.config import *

import multiprocessing
from multiprocessing import Pool


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

def get_file_rule1(folder_path, task_name, language):
    """提取项目下指定编程语言的文件并处理。"""
    # 定义所有支持的编程语言及其对应的文件扩展名
    language_extensions = {
        "java": [".java"],
        "android": [".kt"],
        "javascript": [".js"],
        "objective-c": [".m", ".h"],
        "go": [".go"],
        "python": [".py"],
        "c/c++": [".c",".cpp"],
        "php": [".php"],
        "ruby": [".rb"],
        "sql": [".sql"]
    }

    # 检查传入的 language 是否支持
    if language not in language_extensions:
        raise ValueError(f"不支持的语言类型: {language}。支持的语言类型为: {list(language_extensions.keys())}")

    # 获取目标语言的扩展名
    target_extensions = language_extensions[language]

    # 存储符合条件的文件路径
    target_file_list = []

    # 遍历文件夹，筛选出符合条件的文件
    for root, sub_dirs, file_names in os.walk(folder_path):
        for file_name in file_names:
            file_extension = os.path.splitext(file_name)[1].lower()  # 获取文件扩展名并转为小写
            if file_extension in target_extensions:
                target_file_list.append(os.path.join(root, file_name))

    # 生成新的文件夹路径
    item_name = os.path.basename(os.path.dirname(folder_path))
    folder_name = f"{os.path.basename(folder_path)}_s"
    new_folder_path = os.path.join(file_save_path, item_name, task_name, folder_name)

    # 如果目标文件夹已存在，则删除
    if os.path.exists(new_folder_path):
        shutil.rmtree(new_folder_path)

    # 创建新的文件夹
    os.makedirs(new_folder_path, exist_ok=True)

    # 复制符合条件的文件到新文件夹
    for file in target_file_list:
        if not os.path.isfile(file):
            print(f'文件路径错误: {file}')
            continue
        shutil.copy(file, os.path.join(new_folder_path, os.path.basename(file)))

    # 删除原始文件夹
    shutil.rmtree(folder_path)

    # 如果新文件夹路径以 "_s" 结尾，去掉 "_s"
    if new_folder_path.endswith("_s"):
        folder_path = new_folder_path.rstrip("_s")

    # 重命名新文件夹
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

def process_excel_and_extract_git_urls(req):
    """
    处理上传的Excel文件并提取Git地址及相关信息（使用pandas）
    
    参数:
        req: Django请求对象，包含上传的文件
    
    返回:
        JsonResponse: 包含提取的Git地址列表和相关信息或错误信息的JSON响应
    """
    # 获取上传的文件
    uploaded_file = req.FILES.get('file', None)
    if not uploaded_file:
        return JsonResponse({'code': '400', 'msg': '未找到上传文件'})
    
    # 检查文件扩展名
    file_name = uploaded_file.name.lower()
    if not (file_name.endswith('.xlsx') or file_name.endswith('.xls')):
        return JsonResponse({'code': '400', 'msg': '仅支持Excel文件(.xlsx, .xls)'})
    
    # 创建临时文件保存上传的Excel
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx')
    
    try:
        # 将上传的文件内容写入临时文件
        with open(temp_file.name, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
        
        # 使用pandas读取Excel文件
        # 读取Excel文件，不将第一行作为表头
        df = pd.read_excel(temp_file.name, header=None)
        
        
        # 提取所有行的数据
        git_repos = []
        for index, row in df.iterrows():
            # 获取第一列：Git地址
            git_url = row[0]
            
            # 检查是否是有效的Git地址
            if isinstance(git_url, str) and ('http' in git_url or 'git' in git_url or 'gitee' in git_url):
                # 清理可能的多余空格
                cleaned_url = git_url.strip()
                
                # 获取第二列：分支(branch)，默认为空字符串
                branch = str(row[1]) if len(row) > 1 and pd.notna(row[1]) else ""
                
                # 获取第三列：账号(username)，默认为空字符串
                username = str(row[2]) if len(row) > 2 and pd.notna(row[2]) else ""
                
                # 获取第四列：密码(password)，默认为空字符串
                password = str(row[3]) if len(row) > 3 and pd.notna(row[3]) else ""
                
                # 添加到结果列表
                git_repos.append({
                    'git_url': cleaned_url,
                    'branch': branch.strip(),
                    'username': username.strip(),
                    'password': password.strip(),
                    'row_number': index + 1  # 添加行号便于定位
                })
        
        # 返回结果
        return JsonResponse({
            'code': '200', 
            'git_repos': git_repos,
            'count': len(git_repos),
            'msg': f'成功提取 {len(git_repos)} 个Git仓库信息'
        })
        
    except Exception as e:
        return JsonResponse({'code': '500', 'msg': f'处理Excel文件时出错: {str(e)}'})
    
    finally:
        # 清理临时文件
        try:
            os.unlink(temp_file.name)
        except:
            pass
def decompress_file(req):
    """解压上传的压缩文件并保存到指定路径。"""
    uploaded_file = req.FILES.get('file', None)
    item_name = req.POST['item_name']
    folder_name, file_extension = os.path.splitext(uploaded_file.name)
    file_extension = file_extension.lstrip('.').lower()


    base_path = os.path.join(processed_file_save_path, item_name)
    unique_folder_path = get_unique_folder_name(base_path, folder_name)

    print(f"base_path:{base_path}\n unique_folder_path:{unique_folder_path}")

    os.makedirs(unique_folder_path, exist_ok=True)
    print(f"Path '{unique_folder_path}' created.")

    try:
        if file_extension in ['zip', 'tar', 'rar', '7z', 'jar', 'war']:
            if file_extension in ['zip', 'jar', 'war']:
                with zipfile.ZipFile(uploaded_file) as zip_file:
                    print("Extracting files from ZIP...")

                    # 先整体解压（可选，如果不需要可以删除）
                    try:
                        zip_file.extractall(unique_folder_path)
                    except Exception as e:
                        print(f"Warning: Could not extract all files due to: {e}")

                    # 逐个文件解压，遇到错误则跳过
                    for file in zip_file.namelist():
                        print("Processing file:", file)

                        try:
                            # 尝试 UTF-8 解码文件名
                            try:
                                file_name = file.encode('cp437').decode('utf-8')
                                print("Decoded (UTF-8):", file_name)
                            except UnicodeDecodeError:
                                # 如果 UTF-8 失败，尝试 GBK 解码
                                file_name = file.encode('cp437').decode('gbk')
                                print("Decoded (GBK):", file_name)

                            # 解压单个文件
                            zip_file.extract(file, unique_folder_path)

                            # 重命名文件（仅当文件名解码成功时）
                            original_path = os.path.join(unique_folder_path, file)
                            new_path = os.path.join(unique_folder_path, file_name)

                            if os.path.exists(original_path):
                                os.rename(original_path, new_path)
                                print(f"Successfully extracted and renamed: {file_name}")
                            else:
                                print(f"Warning: File not found after extraction: {file}")

                        except Exception as e:
                            print(f"Error processing file '{file}': {e}")
                            print("Skipping this file and continuing...")
                            continue  # 跳过当前文件，继续下一个
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


def clone_or_pull_project(project_url, project_path, access_token, branch=None, max_retries=3):
    """克隆或拉取Git项目，支持指定分支。"""
    retries = 0
    while retries < max_retries:
        try:
            print('正在拉取或克隆:', project_url)
            print('目标分支:', branch if branch else '默认分支')

            if os.path.exists(project_path):
                # 项目已存在，执行拉取
                if branch:
                    # 切换到指定分支并拉取
                    commands = [
                        f'git -C "{project_path}" fetch origin',
                        f'git -C "{project_path}" checkout {branch}',
                        f'git -C "{project_path}" pull origin {branch}'
                    ]
                else:
                    # 拉取当前分支
                    commands = [f'git -C "{project_path}" pull']
            else:
                # 项目不存在，执行克隆
                if branch:
                    # 克隆指定分支
                    commands = [f'git clone -b {branch} {project_url} "{project_path}"']
                else:
                    # 克隆默认分支
                    commands = [f'git clone {project_url} "{project_path}"']

            # 执行命令
            env = os.environ.copy()
            env['GITLAB_API_PRIVATE_TOKEN'] = access_token
            
            for command in commands:
                print(f"执行命令: {command}")
                result = subprocess.run(
                    shlex.split(command), 
                    capture_output=True, 
                    text=True, 
                    env=env
                )
                if result.returncode != 0:
                    raise subprocess.CalledProcessError(result.returncode, command, result.stderr)

            return True, "成功克隆或拉取项目"

        except subprocess.CalledProcessError as e:
            retries += 1
            if retries < max_retries:
                print(f"克隆或拉取项目失败，重试次数：{retries}")
                print(f"错误信息: {e.stderr}")
                time.sleep(2)  # 等待后重试
            else:
                return False, f"克隆或拉取项目失败，已达到最大重试次数 ({max_retries})", e.stderr
        except Exception as e:
            return False, f"Error: {str(e)}"

    return False, f"克隆或拉取项目失败，已达到最大重试次数 ({max_retries})"


def fetch_gitlab_projects(gitlab_url, access_token, download_path,branch=None):
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
    username = req.POST['username']
    password = req.POST['password']
    folder_path = req.POST['folder_path']
    branch = req.POST['branch']
    url_git = gitlab_url # 保留原始url

    base_path = os.path.join(processed_file_save_path, item_name)
    download_directory = get_unique_folder_name(base_path, 'git_task')
    project_name_match = re.search(r'/([^/]+?)(\.git)?$', url_git)
    if project_name_match:
        base_project_name = project_name_match.group(1)
    else:
        base_project_name = item_name
    
    # 生成17位时间戳（10位秒 + 7位微秒）
    current_time = time.time()
    integer_part = int(current_time)  # 10位整数部分
    fractional_part = int((current_time - integer_part) * 10**7)  # 7位小数部分
    timestamp_str = f"{integer_part}{fractional_part:07d}"
    
    # 使用时间戳代替随机字符串
    project_name = f"{base_project_name}_{timestamp_str}"

    if username and password:  # 更Pythonic的判断方式
        if gitlab_url.startswith('http://'):
            base_url = gitlab_url.split('http://')[-1]
            gitlab_url = f'http://{username}:{password}@{base_url}'
        elif gitlab_url.startswith('https://'):
            base_url = gitlab_url.split('https://')[-1]
            gitlab_url = f'https://{username}:{password}@{base_url}'
        else:
            # 如果没有协议前缀，默认使用http
            gitlab_url = f'http://{username}:{password}@{gitlab_url}'

    print(gitlab_url)
    projects = fetch_gitlab_projects(gitlab_url, access_token, download_directory,branch)
    print(projects)

    if projects:
        project_url, storage_path = projects[0]
        print("项目URL:", project_url)
        print("存储路径:", storage_path)
        return JsonResponse({'code': '200', 'msg': '拉取文件成功', 'folder_name': storage_path, 'url_git': url_git, 'branch': branch,'project_name': project_name})
    else:
        return JsonResponse({"error": "拉取失败", "code": "500"})

def clone_git_repositories(req):
    """克隆多个GitLab仓库。"""
    try:
        # 获取参数
        gitlab_urls = req.POST.get('urls', '')  # 多个URL用逗号分隔
        access_token = req.POST.get('token')
        item_name = req.POST.get('item_name')
        username = req.POST.get('username')
        password = req.POST.get('password')
        branch = req.POST.get('branch', 'main')
        
        # 参数验证
        if not all([gitlab_urls, item_name]):
            return JsonResponse({"error": "缺少必要参数", "code": "400"})
        
        # 分割URL字符串为列表
        url_list = [url.strip() for url in gitlab_urls.split(',') if url.strip()]
        if not url_list:
            return JsonResponse({"error": "未提供有效的仓库URL", "code": "400"})
        
        # 准备基础路径
        base_path = os.path.join(processed_file_save_path, item_name)
        os.makedirs(base_path, exist_ok=True)
        used_names = {}
        results = []
        
        # 循环处理每个仓库URL
        for i, gitlab_url in enumerate(url_list):
            # 在循环开始时初始化变量
            repo_name = None
            base_name = None
            download_directory = None
            
            try:
                # 从URL中提取基础仓库名称
                base_name = gitlab_url.split('/')[-1].replace('.git', '')
                
                # 生成17位时间戳
                current_time = time.time()
                integer_part = int(current_time)  # 10位整数部分
                fractional_part = int((current_time - integer_part) * 10**7)  # 7位小数部分
                timestamp_str = f"{integer_part}{fractional_part:07d}"
                
                # 处理重复名称
                if base_name in used_names:
                    count = used_names[base_name] + 1
                    used_names[base_name] = count
                    repo_name = f"{base_name}{count}_{timestamp_str}"
                else:
                    used_names[base_name] = 0  # 初始计数为0，表示第一次出现
                    repo_name = f"{base_name}_{timestamp_str}"  # 修正：第一次出现不加计数
                
                download_directory = get_unique_folder_name(base_path, repo_name)
                os.makedirs(download_directory, exist_ok=True)
                
                # 构建认证URL
                auth_url = gitlab_url
                if username and password:
                    if gitlab_url.startswith('http://'):
                        auth_url = gitlab_url.replace('http://', f'http://{username}:{password}@')
                    elif gitlab_url.startswith('https://'):
                        auth_url = gitlab_url.replace('https://', f'https://{username}:{password}@')
                    else:
                        auth_url = f'http://{username}:{password}@{gitlab_url}'
                
                # 使用原有逻辑获取项目
                projects = fetch_gitlab_projects(auth_url, access_token, download_directory, branch)
                
                if projects:
                    project_url, storage_path = projects[0]
                    results.append({
                        'url': gitlab_url,
                        'success': True,
                        'name': repo_name,  # 使用处理后的名称
                        'folder': storage_path
                    })
                else:
                    results.append({
                        'url': gitlab_url,
                        'success': False,
                        'name': repo_name,  # 使用处理后的名称
                        'message': '获取项目失败'
                    })
                    
            except Exception as e:
                # 如果repo_name未定义，创建一个默认名称
                if repo_name is None:
                    if base_name:
                        # 使用base_name作为后备
                        repo_name = f"{base_name}_error_{i}"
                    else:
                        # 使用URL的一部分作为后备
                        try:
                            # 尝试从URL中提取名称
                            url_part = gitlab_url.split('/')[-1][:20] if gitlab_url else f"repo_{i}"
                            repo_name = f"{url_part}_error"
                        except:
                            repo_name = f"repository_{i}_error"
                
                results.append({
                    'url': gitlab_url,
                    'success': False,
                    'name': repo_name,  # 现在repo_name一定有值
                    'message': f'处理过程中出错: {str(e)}'
                })
        
        return JsonResponse({
            'code': '200', 
            'msg': '处理完成',
            'results': results
        })
            
    except Exception as e:
        return JsonResponse({
            "error": f"处理请求时出错: {str(e)}", 
            "code": "500"
        })

def clone_git_repository_1(**kwargs):
    """克隆GitLab仓库。"""
    gitlab_url = kwargs['gitlab_url']
    access_token = kwargs['access_token']
    item_name = kwargs['item_name']
    username = kwargs['username']
    password = kwargs['password']

    base_path = os.path.join(processed_file_save_path, item_name)
    download_directory = get_unique_folder_name(base_path, 'git_task')

    if username != '' and password != '':
        gitlab_url = 'http://' + username + ':' + password + '@' + gitlab_url.split('http://')[-1]

    print(gitlab_url)
    projects = fetch_gitlab_projects(gitlab_url, access_token, download_directory)
    print(projects)

    if projects:
        project_url, storage_path = projects[0]
        return storage_path
    else:
        return 0

    # if projects:
    #     project_url, storage_path = projects[0]
    #     print("项目URL:", project_url)
    #     print("存储路径:", storage_path)
    #     return JsonResponse({'code': '200', 'msg': '拉取文件成功', 'folder_name': storage_path, 'url_git': gitlab_url, 'branch': branch})
    # else:
    #     return JsonResponse({"error": "拉取失败", "code": "500"})

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


# def deepseek_chat(req):
#     """聊天/生成。"""
#     prompt = req.GET.get('prompt', '')
#     model_name = 'deepseek-6.7b'
#     try:
#         def stream_generator():
#             result = deepseek_chat3(prompt, model_name)
#             for chunk in result:
#                 if chunk == '':
#                     break
#                 yield f"data: {chunk}\n\n"
#
#         return StreamingHttpResponse(stream_generator(), content_type='text/event-stream')
#     except Exception as e:
#         return JsonResponse({"msg": "聊天信息返回失败", "code": "500", "error": str(e)})

def deepseek_chat(req):
    """聊天/生成。"""
    prompt = req.POST['prompt']
    key = req.POST['key']

    response = deepseek_chat3(prompt, key)

    return StreamingHttpResponse(response, content_type='text/event-stream')

# def deepseek_chat2(req):
#     """聊天/生成。"""
#     id = req.POST['id']
#     code = req.POST['code']
#     vultype = req.POST['vultype']
#     model_name = 'deepseek-14b'
#
#     async def get_response(code, vultype):
#         try:
#             result = await deepseek_chat6(code, vultype)
#             print(3)
#             print(result)
#             return result
#         except Exception as e:
#             print(f"读取流式响应时出错: {e}")
#             return None
#
#     try:
#         full_response = asyncio.run(get_response(code, vultype))
#         # 生成结束后打印完整内容
#         #print("完整生成内容：", full_response)
#         try:
#             update_Interpretation(id, full_response)
#             return JsonResponse({"msg": "代码解析返回成功", "data": full_response, "code": "200"})
#         except Exception as e:
#             return JsonResponse({"msg": "代码解析插入失败", "code": "500", "error": str(e)})
#     except Exception as e:
#         return JsonResponse({"msg": "代码解析返回失败", "code": "500", "error": str(e)})

# def deepseek_chat2(req):
#     """聊天/生成。"""
#     id = req.POST['id']
#     code = req.POST['code']
#     vultype = req.POST['vultype']
#     model_name = 'deepseek-14b'
#
#     async def get_response(code, vultype):
#         try:
#             result = await deepseek_chat6(code, vultype)
#             full_response = ""  # 用于存储完整的生成内容
#             # 使用 async for 读取流式响应
#             async for chunk in result:
#                 if chunk:  # 只发送非空内容
#                     if isinstance(chunk, bytes):  # 如果 chunk 是字节类型
#                         chunk = chunk.decode("utf-8")  # 解码为字符串
#                     full_response = json.loads(chunk)['content'].encode("utf-8").decode("utf-8")  # 添加到完整内容中
#             return full_response
#         except Exception as e:
#             print(f"读取流式响应时出错: {e}")
#             return None
#
#     try:
#         full_response = asyncio.run(get_response(code, vultype))
#         # 生成结束后打印完整内容
#         # print("完整生成内容：", full_response)
#         try:
#             update_Interpretation(id, full_response)
#             return JsonResponse({"msg": "代码解析返回成功", "data": full_response, "code": "200"})
#         except Exception as e:
#             return JsonResponse({"msg": "代码解析插入失败", "code": "500", "error": str(e)})
#     except Exception as e:
#         return JsonResponse({"msg": "代码解析返回失败", "code": "500", "error": str(e)})
# # 封装队列和标志位
# from threading import Thread, Event
# from queue import Queue
# # 确保导入 queue 模块
# import queue
# class QueueProcessor:
#     def __init__(self):
#         self.q = Queue()
#         self.flag = Event()  # 使用 Event 替代 flag
#         self.stop_event = Event()
#         self.thread = Thread(target=self.process_queue, daemon=True)
#         self.thread.start()
#
#     def process_queue(self):
#         while not self.stop_event.is_set():
#             try:
#                 current = self.q.get(timeout=3)  # 设置超时避免忙等待
#                 if current['detection_type'] == 'repair':
#                     response = deepseek_repair(current)
#                     repair_code = response
#                     code_location = get_location(current['code'], repair_code)
#                     vulfile_update(current['task_id'], current['file_id'], repair_code, str(code_location))
#                 else:
#                     response = deepseek_chat2(current)
#                     update_Interpretation(current['id'], response)
#                 self.q.task_done()
#             except queue.Empty:
#                 continue
#             except Exception as e:
#                 # 记录错误日志
#                 print(f"处理队列时出错: {e}")
#
#     def add_to_queue(self, item):
#         self.q.put(item)
#
#     def stop(self):
#         self.stop_event.set()
#         self.thread.join()
#
# # 全局实例
# processor = QueueProcessor()
#
# def create_queue_deepseek(request):
#     try:
#         arg = json.loads(request.POST['arg'])
#         processor.add_to_queue(arg)
#         return JsonResponse({"msg": "已加入到队列", "code": "200"})
#     except json.JSONDecodeError:
#         return JsonResponse({"msg": "无效的 JSON", "code": "400"}, status=400)
#     except KeyError:
#         return JsonResponse({"msg": "缺少参数 'arg'", "code": "400"}, status=400)
# @lru_cache(maxsize=1)
# def process_queue():
#     global flag
#     while True:
#         if q.qsize() >= 1:
#             print(f'正在监听，当前队列长度为{q.qsize()}')
#         if not q.empty() and flag:
#             flag = False
#             current = q.get()
#             q.put(current)
#             # print(current)
#             if current['detection_type'] == 'repair':
#                 response = deepseek_repair(current)
#                 repair_code = response
#                 code_location = get_location(current['code'], repair_code)
#
#                 vulfile_update(current['task_id'], current['file_id'], repair_code, str(code_location))
#             else:
#                 response = deepseek_chat2(current)
#                 update_Interpretation(current['id'], response)
#                 print(1232132131231)
#
#             q.get()
#             flag = True
#
#         time.sleep(3)
#
#
# q = Queue()
# flag = True
# def create_queue_deepseek(req):
#     arg = json.loads(req.POST['arg'])
#
#     q.put(arg)
#     print("已加入到队列")
#     print(f"当前队列数{q.qsize()}")
#     process_queue()
#
#     return JsonResponse({"msg": "已加入到队列", "code": "200"})

    # if detection_type == 'repair':
    #     response = deepseek_repair(arg)
    # else:
    #     response = deepseek_chat2(arg)
    #
    # current = q.get()
    # #print(current)
    # try:
    #     if current['detection_type'] == 'repair':
    #         repair_code = response
    #         code_location = get_location(current['code'], repair_code)
    #
    #         vulfile_update(current['task_id'], current['file_id'], repair_code, str(code_location))
    #     else:
    #         update_Interpretation(current['id'], response)
    #     return JsonResponse({"msg": "大模型调用成功", "code": "200"})
    # except Exception as e:
    #     print(f"大模型调用失败: {e}")
    #     return JsonResponse({"msg": "大模型调用失败", "code": "500", "error": str(e)})
from openai import OpenAI

# def deepseek_chat(req):
#     """聊天/生成。"""
#     prompt = req.GET.get('prompt', '')
#     model_name = 'deepseek-6.7b'
#     try:
#         def stream_generator():
#             result = deepseek_chat3(prompt, model_name)
#             for chunk in result:
#                 if chunk == '':
#                     break
#                 yield f"data: {chunk}\n\n"
#
#         return StreamingHttpResponse(stream_generator(), content_type='text/event-stream')
#     except Exception as e:
#         return JsonResponse({"msg": "聊天信息返回失败", "code": "500", "error": str(e)})

def deepseek_chat2(req):
    """聊天/生成。"""
    id = req.POST['id']
    code = req.POST['code']
    vultype = req.POST['vultype']
    model_name = 'deepseek-14b'
    sink = req.POST['Sink']

    response = deepseek_chat6(id, code, vultype,sink)
  

    return StreamingHttpResponse(response, content_type='text/event-stream')

def deepseek_repair(req):
    """修复漏洞。"""

    file_id = req.POST['file_id']
    task_id = req.POST['task_id']
    code = req.POST['code']
    vultype = req.POST['vultype']
    model_name = req.POST['model_name']
    sink_line = req.POST.get('sink_line', '')
    src_line = req.POST.get('src_line', '')
    detection_type = 'repair'

    response = getLLM_deepseek3(task_id, file_id, code, vultype, model_name, detection_type, sink_line, src_line)

    return StreamingHttpResponse(response, content_type='text/event-stream')

@lru_cache(maxsize=1024)
def read_file_cached(filepath):
    # 读取文件内容
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return None

def process_result(result):
    """处理单个结果的函数"""
    try:
        record_id = result['id']
        filepath = result['filepath']
        vultype = result['vultype']

        # 读取文件内容
        code = read_file_cached(result['filepath'])
        if not code:
            return False

        # 调用大模型判断误报
        if deepseek_chat7(code, vultype) == False:
            if not delete_by_id(record_id):
                print(f"删除记录 ID 为 {record_id} 失败")
                return False
            else:
                print(f"成功删除记录 ID 为 {record_id}")
                return True
        else:
            print(f"记录 ID 为 {record_id} 未被判定为误报")
            return True

    except FileNotFoundError:
        print(f"文件未找到: {filepath}")
        return False
    except Exception as e:
        print(f"处理记录 ID 为 {result['id']} 时发生错误: {e}")
        return False

def deepseek_False(taskid):
    """降低误报，使用多进程并行处理"""
    num_processes = 10  # 定义进程数
    print('正在获取任务文件!')
    results = get_info_taskid(taskid)
    print("文件:", results)
    if results is None:
        return True
    if len(results) < num_processes:
        num_processes = len(results)
    print(f"新建{num_processes}进程")

    # 创建进程池
    with Pool(processes=num_processes) as pool:
        # 使用 tqdm 显示进度条
        with tqdm(total=len(results), desc="扫描进度") as pbar:
            success_list = []
            for result in pool.imap(process_result, results):
                success_list.append(result)
                pbar.update(1)  # 更新进度条

    # 检查所有任务是否成功
    return all(success_list)

def deepseek_scan(task_id, file_path_lists, xml_list):
    """使用多进程并行处理"""
    num_processes = 10  # 定义进程数
    print('正在获取任务文件')
    if len(file_path_lists) + len(xml_list) < num_processes:
        num_processes = len(file_path_lists) + len(xml_list)
    print(f"并行扫描新建{num_processes}进程")

    if not file_path_lists and not xml_list:
        print(f"该任务文件为空")
        return False

    args = []
    for file_path in file_path_lists:
        args.append({
            "task_id": task_id,
            "file_path": file_path
        })
    for file_path in xml_list:
        args.append({
            "task_id": task_id,
            "file_path": file_path
        })

    print('\n\n\n\n\n\n\n\n')
    print(args)

    # 创建进程池
    with Pool(processes=num_processes) as pool:
        # 使用 tqdm 显示进度条
        with tqdm(total=len(args), desc="扫描进度") as pbar:
            success_list = []
            for result in pool.imap(deepseek_scan_result, args):
                success_list.append(result)
                pbar.update(1)  # 更新进度条

    print('\n\n\n\n\n\n\n\n')
    print(success_list)
    # 检查所有任务是否成功
    return all(success_list)

def deepseek_scan_result(args):
    temp_response = ""
    file_name = os.path.basename(args["file_path"])
    temp_result = ""
    if file_name.endswith(".java"):
        try:
            # 读取文件内容
            code = read_file_cached(args["file_path"])

            if not code:
                return False

            response = deepseek_chat8(code)
            print(response,'\n')
            think = response.split("</think>")[0]
            response2 = response.split("</think>")[-1]
            print(response2,'\n')
            #调别人的api用下面的，并把上面的注释掉
            #response2 = response.split("###")[0].strip()
            response2 = response2.replace("json\n", "").replace("\n```", "")
            print(response2,'\n')
            #response2 = response2.replace("```json\n", "").replace("\n```", "").strip()

            response2 = json.loads(response2)
            print(response2,'\n')
            #print(response2)
            temp_response = response2

            try:
                result = find_code_position(code, response2["爆发点"])
                print(result,'\n')
                line_number = str([result["start_line"], result["start_line"]])
                line_number1 = int(result["start_line"])
            except:
                line_number = ""
                line_number1 = 0
            print(line_number,'\n')
            print(line_number1,'\n')

            id_vul = {
                  "CWE-798": "硬编码凭证",
                  "CWE-643": "XPath注入",
                  "CWE-918": "服务器端请求伪造",
                  "CWE-079": "跨站脚本：反射型",
                  "CWE-089": "SQL注入",
                  "CWE-022": "路径遍历",
                  "CWE-078": "命令注入",
                  "CWE-400": "拒绝服务",
                  "CWE-117": "日志伪造",
                  "CWE-203": "登录接口错误提示",
                  "CWE-284": "拦截器放行策略",
                  "CWE-862": "接口授权校验",
                  "CWE-494": "文件上传安全",
                  "CWE-307": "暴力破解",
                  "CWE-308": "短信安全",
                  "CWE-434": "未对上传的压缩文件进行安全检查",
                  "CWE-999": "下载漏洞",
                  "CWE-779": "访问控制"
            }

            vul_name = id_vul[response2["漏洞类型"]]
            code_context = get_code_context(code, line_number1, 15)
            test_result = [{
                'filename': os.path.basename(args["file_path"]),
                'file_path': args["file_path"],
                'cwe_id': response2["漏洞类型"],
                'vul_name': vul_name,
                'code': code_context,
                'line_number': line_number,
                'src_line_number': None,
                'func_line_number': None,
                'risk_level': '',
                'repair_code': '',
                'new_line_number': '',
                'repair_status': '未修复',
                'is_question': '是问题',
                'model': '',
                'Sink': response2["爆发点"],
                'Enclosing_Method': response2["爆发点函数"],
                'Source': response2["缺陷源"],
                # 'Interpretation':think
            }]

            temp_result = test_result
            #print(test_result)
            file_id = get_id('fileId', 'vulfile')

            if is_insert(file_id, test_result):
                vulfile_insert(args["task_id"], file_id, test_result)
            else:
                vulfile_insert(args["task_id"], file_id, test_result)

            return True
        except Exception as e:
            print(f"错误: {e}")
            print(temp_response)
            print(file_name)
            return False
    elif file_name.endswith(".xml"):
        try:
            # 读取文件内容
            code = read_file_cached(args["file_path"])

            if not code:
                return False

            response = deepseek_chat9(code)
            think = response.split("</think>")[0]
            response2 = response.split("</think>")[-1]
            response2 = response2.replace("json\n", "").replace("\n```", "")

            response2 = json.loads(response2)
            # print(response2)
            temp_response = response2

            try:
                result = find_code_position(code, response2["爆发点"])
                line_number = str([result["start_line"], result["start_line"]])
            except:
                line_number = ""

            id_vul = {
                "CWE-611": "XML外部实体注入（XXE）",
                "CWE-776": "XML炸弹（Billion Laughs）",
                "CWE-643": "XPath注入",
                "CWE-502": "不安全的反序列化",
                "CWE-827": "未受控的命名空间绑定",
                "CWE-838": "DTD校验绕过",
                "CWE-176": "字符集编码漏洞",
            }
            vul_name = id_vul[response2["漏洞类型"]]
            code_context = get_code_context(code, line_number, 50)
            test_result = [{
                'filename': os.path.basename(args["file_path"]),
                'file_path': args["file_path"],
                'cwe_id': response2["漏洞类型"],
                'vul_name': vul_name,
                'code': code_context,
                'line_number': line_number,
                'src_line_number': None,
                'func_line_number': None,
                'risk_level': '',
                'repair_code': '',
                'new_line_number': '',
                'repair_status': '未修复',
                'is_question': '是问题',
                'model': '',
                'Sink': response2["爆发点"],
                'Enclosing_Method': response2["解析器配置"],
                'Source': response2["缺陷源"],
                # 'Interpretation':think
            }]

            temp_result = test_result
            # print(test_result)
            file_id = get_id('fileId', 'vulfile')

            if is_insert(file_id, test_result):
                vulfile_insert(args["task_id"], file_id, test_result)
            else:
                vulfile_insert(args["task_id"], file_id, test_result)

            return True
        except Exception as e:
            print(f"错误: {e}")
            print(temp_response)
            print(file_name)
            return False


def get_code_context(code, line_number, context_lines=50):
    """
    获取 code 中指定行号上下各 context_lines 行的代码。

    :param code: 完整代码字符串
    :param line_number: 目标行号（1-based）
    :param context_lines: 上下各取多少行
    :return: 上下文代码字符串
    """
    lines = code.splitlines()  # 按行分割成列表
    total_lines = len(lines)

    # 转换为 0-based 索引（注意行号从 1 开始）
    target_idx = line_number - 1

    # 计算起始和结束行索引（确保不越界）
    start_idx = max(0, target_idx - context_lines)
    end_idx = min(total_lines, target_idx + context_lines + 1)  # +1 是为了包含结束行

    # 提取上下文行
    context = lines[start_idx:end_idx]

    # 重新组合成字符串（保留换行符）
    return "\n".join(context)

def find_code_position(full_code, code_snippet):
    """
    查找代码片段在完整代码中的位置（行号范围）
    支持跨行匹配且保持行号准确性

    参数:
        full_code (str): 完整代码
        code_snippet (str): 要查找的代码片段

    返回:
        dict: {
            'found': bool,
            'start_line': int,  # 起始行号(1-based)
            'end_line': int,    # 结束行号
            'matched_code': str # 实际匹配的原始代码
        } 或 None (未找到时)
    """

    def normalize_line(line):
        """标准化单行：移除空格和制表符"""
        return line.replace(" ", "").replace("\t", "")

    # 预处理完整代码
    full_lines = full_code.splitlines()
    norm_full_lines = [normalize_line(line) for line in full_lines]
    norm_full = "".join(norm_full_lines)  # 连接所有标准化行

    # 预处理代码片段
    norm_snippet = normalize_line(code_snippet)

    # 在标准化完整代码中查找
    start_pos = norm_full.find(norm_snippet)
    if start_pos == -1:
        return None

    # 计算行号
    start_line = 1
    end_line = len(full_lines)
    current_pos = 0

    # 计算起始行号
    for i, line in enumerate(norm_full_lines, 1):
        current_pos += len(line)
        if current_pos > start_pos:
            start_line = i
            break

    # 计算结束行号
    remaining_chars = len(norm_snippet)
    matched_lines = []

    for i in range(start_line - 1, len(full_lines)):
        line = full_lines[i]
        norm_line = norm_full_lines[i]

        # 计算当前行贡献的匹配字符数
        if i == start_line - 1:
            # 第一行可能只匹配部分
            chars_needed = len(norm_line) - (current_pos - start_pos)
        else:
            chars_needed = len(norm_line)

        if remaining_chars <= chars_needed:
            matched_lines.append(line)
            end_line = i + 1
            break
        else:
            matched_lines.append(line)
            remaining_chars -= chars_needed

    return {
        'found': True,
        'start_line': start_line,
        'end_line': end_line,
        'matched_code': '\n'.join(matched_lines)
    }


def get_info_taskid(taskid):
    """根据taskid获取该任务下所有文件的信息"""
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 固定执行 taskid 查询，移除 vul_name 相关逻辑
                sql = """SELECT id, filepath, vultype FROM vulfile WHERE taskid = %s"""
                cursor.execute(sql, (taskid,))

                data = cursor.fetchall()
                if data:
                    # 动态获取字段名，构造字典列表
                    columns = [column[0] for column in cursor.description]
                    result = [dict(zip(columns, row)) for row in data]
                    return result
                else:
                    return None  # 明确返回空值
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}")  # 移除 vul_name 引用
        return None  # 保持返回类型一致
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

def delete_by_id(id):
    # 根据id删除vulfile中的记录
    sql = "delete from vulfile where id = %s"

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, (id,))
                conn.commit()
        return True
    except Exception as e:
        print(f"提交出错\n: {e}")
        conn.rollback()
        return False

# 最终版本，暂时注释
# def deepseek_chat2(args):
#     """聊天/生成。"""
#     id = args['id']
#     code = args['code']
#     vultype = args['vultype']
#     model_name = 'deepseek-14b'
#
#     # id = req.POST['id']
#     # code = req.POST['code']
#     # vultype = req.POST['vultype']
#     # model_name = 'deepseek-14b'
#
#     try:
#         result = deepseek_chat6(model_name, code, vultype)
#         full_response = ""  # 用于存储完整的生成内容
#         for chunk in result:
#             if chunk:  # 只发送非空内容
#                 full_response += chunk  # 将每个 chunk 添加到完整内容中
#         # 生成结束后打印完整内容
#         return full_response
#     except Exception as e:
#         return False
#
#
# def deepseek_repair(args):
#     """修复漏洞。"""
#     file_id = args['file_id']
#     task_id = args['task_id']
#     code = args['code']
#     vultype = args['vultype']
#     model_name = 'deepseek-14b'
#     # file_id = req.POST['file_id']
#     # task_id = req.POST['task_id']
#     # code = req.POST['code']
#     # vultype = req.POST['vultype']
#     # model_name = req.POST['model_name']
#     detection_type = 'repair'
#
#     try:
#         result = getLLM_deepseek3(code, vultype, model_name, detection_type)
#         full_response = ""  # 用于存储完整的生成内容
#         for chunk in result:
#             if chunk:  # 只发送非空内容
#                 full_response += chunk  # 将每个 chunk 添加到完整内容中
#
#         return full_response
#     except Exception as e:
#         return False



# def deepseek_chat2(args):
#     """聊天/生成。"""
#     id = args['id']
#     code = args['code']
#     vultype = args['vultype']
#     model_name = 'deepseek-14b'
#
#     # id = req.POST['id']
#     # code = req.POST['code']
#     # vultype = req.POST['vultype']
#     # model_name = 'deepseek-14b'
#
#     try:
#         result = deepseek_chat6(model_name, code, vultype)
#         full_response = ""  # 用于存储完整的生成内容
#         for chunk in result:
#             if chunk:  # 只发送非空内容
#                 full_response += chunk  # 将每个 chunk 添加到完整内容中
#         # 生成结束后打印完整内容
#         # print("完整生成内容：", full_response)
#         try:
#             update_Interpretation(id, full_response)
#             return JsonResponse({"msg": "代码解析返回成功", "data": full_response, "code": "200"})
#         except Exception as e:
#             return JsonResponse({"msg": "代码解析插入失败", "code": "500", "error": str(e)})
#     except Exception as e:
#         return JsonResponse({"msg": "代码解析返回失败", "code": "500", "error": str(e)})
#
# def deepseek_repair(args):
#     """修复漏洞。"""
#     file_id = args['file_id']
#     task_id = args['task_id']
#     code = args['code']
#     vultype = args['vultype']
#     model_name = args['model_name']
#     # file_id = req.POST['file_id']
#     # task_id = req.POST['task_id']
#     # code = req.POST['code']
#     # vultype = req.POST['vultype']
#     # model_name = req.POST['model_name']
#     detection_type = 'repair'
#
#     try:
#         result = getLLM_deepseek3(code, vultype, model_name, detection_type)
#         full_response = ""  # 用于存储完整的生成内容
#         for chunk in result:
#             if chunk:  # 只发送非空内容
#                 full_response += chunk  # 将每个 chunk 添加到完整内容中
#         repair_code = full_response
#         code_location = get_location(code, repair_code)
#
#         vulfile_update(task_id, file_id, repair_code, str(code_location))
#
#         return JsonResponse({"msg": "修复信息修改成功", "code": "200"})
#     except Exception as e:
#         return JsonResponse({"msg": "修复失败", "code": "500", "error": str(e)})


# def deepseek_repair(req):
#     """修复漏洞。"""
#     file_id = req.POST['file_id']
#     task_id = req.POST['task_id']
#     code = req.POST['code']
#     vultype = req.POST['vultype']
#     model_name = req.POST['model_name']
#     detection_type = 'repair'
#
#     async def get_response(code, vultype):
#         try:
#             result = await getLLM_deepseek3(code, vultype, model_name, detection_type)
#             full_response = ""  # 用于存储完整的生成内容
#             # 使用 async for 读取流式响应
#             async for chunk in result.body_iterator:
#                 if chunk:  # 只发送非空内容
#                     if isinstance(chunk, bytes):  # 如果 chunk 是字节类型
#                         chunk = chunk.decode("utf-8")  # 解码为字符串
#                     full_response = json.loads(chunk)['content'].encode("utf-8").decode("utf-8")  # 添加到完整内容中
#             return full_response
#         except Exception as e:
#             print(f"读取流式响应时出错: {e}")
#             return None
#
#     try:
#         result = asyncio.run(get_response(code, vultype))
#         code_location = get_location(code, str(result))
#
#         vulfile_update(task_id, file_id, result, str(code_location))
#
#         return JsonResponse({"msg": "修复信息修改成功", "code": "200"})
#     except Exception as e:
#         return JsonResponse({"msg": "修复失败", "code": "500", "error": str(e)})


def vulfile_detail(id):
    # 连接数据库
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    # 定义 SQL 查询
    sql = """SELECT filepath, vultype, location FROM vulfile WHERE id = %s"""

    # 确保连接有效
    conn.ping(reconnect=True)

    # 执行查询
    cursor.execute(sql, (id,))

    # 获取列名
    row_headers = [x[0] for x in cursor.description]

    # 获取查询结果
    data = cursor.fetchall()

    # 关闭游标和连接
    cursor.close()
    conn.close()

    # 将查询结果转换为字典列表
    result = []
    for row in data:
        result.append(dict(zip(row_headers, row)))

    # 返回字典形式的结果
    return result

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
        #print(pdf_file_path)
        if template != "Developer Workbook":
            result_list = location_fortify(folder_path, pdf_file_path, template)  # fortify扫描得到的结果列表
        else:
            result_list = location_fortify_3(folder_path, pdf_file_path)  # fortify扫描得到结果列表，只不过是Developer Workbook规范
            #print("*************************************")
            #print(result_list)
            #print("*************************************")
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
                                            start_time, 0, 0, review_status)
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
                except (javalang.parser.JavaSyntaxError, LexerError) as e:
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
                    vulnerability_name_CN = get_chinese(vulnerability_name)
                    line_number = result['行号'] if type(result['行号']) == int else 0
                    if 1 <= line_number <= len(code_lines):
                        Sink = code_lines[line_number - 1]
                        Enclosing_Method = code_lines[line_number - 1]
                        Source = code_lines[line_number - 1]
                    else:
                        Sink = ''
                        Enclosing_Method = ''
                        Source = ''
                    test_result.append({
                        'filename': filename,
                        'file_path': path,
                        'cwe_id': '',
                        'vul_name': vulnerability_name_CN,
                        'code': '',
                        'line_number': line_number,
                        'risk_level': '',
                        'repair_code': '',
                        'new_line_number': '',
                        'repair_status': '未修复',
                        'is_question': '是问题',
                        'model': '',
                        'Sink':Sink,
                        'Enclosing_Method':Enclosing_Method,
                        'Source':Source
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
    sys.path.append("../../../app/api/main_app")

    rows = get_rule_function_name()
    #print(rows)

    # 动态加载规则函数
    try:
        rules_module = importlib.import_module("rules")
        rules = []
    except Exception as e:
        print(e)
    for row in rows:
        #print(row)
        function_name = row["function_name"]
        if function_name is not None and function_name != "":
            # print("function_name:" + function_name)
            if hasattr(rules_module, function_name):
                rules.append({
                    "function_name": function_name,
                    "function": getattr(rules_module, function_name)
                })
    #print("所有的规则:",rules)
    return rules
def is_sanitization_present(clean_func_list, code):
    """
    检查代码中是否存在清洁函数调用
    """
    # 如果 clean_func_list 为空，直接返回 False
    if not clean_func_list:
        return False
    # 构建正则表达式来匹配清洁函数的调用
    #sanitization_pattern = re.compile(rf'\b({"|".join(clean_func_list)})\s*\(')
    # 使用正则表达式匹配函数名
    match = re.search(r'public\s+\w+\s+(\w+)\(', code)
    if match:
      extracted_func_name = match.group(1)
      return extracted_func_name in clean_func_list


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
        print("执行自定义规则检测------------")
        for rule in vuln_rules_list:
            # 如果规则字符串在代码行中找到，则记录结果
            if rule['pattern'] in line:
                results.append({
                    "漏洞类型": rule['name'],
                    "爆发点函数行号": line_no,
                    "爆发点行号": line_no,
                    "缺陷源": line_no,
                    "缺陷源内容": '',
                	"缺陷源文件": '',
                	"爆发点函数名": ''  # 新增字段
                })

    print(results)
    return results


def index(req):
    method = req.POST["method"]
    if method == "decompression":
        return decompress_file(req)
    if method == "decompression_excel":
        return process_excel_and_extract_git_urls(req)
    elif method == "clone_git_repository":
        return clone_git_repository(req)
    elif method == "clone_git_repositories":
        return clone_git_repositories(req)
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
    # elif method== 'create_queue_deepseek':
    #     return create_queue_deepseek(req)
    # elif method == 'query_for_vul':
    #     return query_for_vul(req)
    else:
        return HttpResponse("method error! ")