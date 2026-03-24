import os

import chardet
import difflib
import json
import re
import torch

from functools import lru_cache

from openai import OpenAI
from peft import PeftModel
from transformers import AutoTokenizer, AutoModelForCausalLM
from app.api.model_api.encrypt_decrypt import *
from app.api.database_utils.web import *
from vllm import LLM, AsyncEngineArgs, AsyncLLMEngine, SamplingParams
import uuid
import uvicorn

from pydantic import BaseModel
from starlette.responses import StreamingResponse

import warnings
import tree_sitter
import socket


# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)

warnings.filterwarnings("ignore", category=FutureWarning)

########################################################################################################################
#   基于大模型进行定位和修复
########################################################################################################################
global model, tokenizer

def get_host_ip():
    """
    查询本机ip地址
    :return: ip
    """
    global s
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception as e:
        # 捕获异常并返回默认值或进行其他处理
        print(f"无法获取IP地址: {e}")
        ip = "0.0.0.0"  # 默认值
    finally:
        if 's' in globals():
            s.close()

    return ip
ip = get_host_ip()


def delete_key(response):
    str_step1 = "step1:根据[代码]内容，判断其中是否存在安全漏洞。以\"漏洞类型: \"开头，如果不存在漏洞，则显示\"漏洞类型: 无漏洞\"。"
    str_step2 = "step2:描述这段[代码]的含义，以\"代码描述: \"开头。"
    str_step3 = "step3:如果存在漏洞，提供这段[代码]中存在的漏洞信息，以\"漏洞信息: \"开头，如果不存在漏洞，则显示\"漏洞信息: 这段代码不存在漏洞，无漏洞信息\"。"
    str_step4 = "step4:如果存在漏洞，提供漏洞修复建议，以\"修复建议: \"开头，如果不存在漏洞，则显示\"修复建议: 这段代码不存在漏洞，无修复建议 \"。"
    str_step5 = "step5:如果存在漏洞，给出修复后的代码片段，代码片段以Markdown格式返回，以\"修复后的代码片段: \"开头，如果不存在漏洞，则显示\"修复后的代码片段: 这段代码不存在漏洞，无修复后的代码片段\"。"
    str_step6 = "step6:如果存在漏洞，描述修复后的代码中是如何修复漏洞的，以\"修复过程: \"开头，如果不存在漏洞，则显示\"修复过程: 这段代码不存在漏洞，无修复过程\"。"

    response = response.replace(str_step1, "")
    response = response.replace(str_step2, "")
    response = response.replace(str_step3, "")
    response = response.replace(str_step4, "")
    response = response.replace(str_step5, "")
    response = response.replace(str_step6, "")

    return response


# 去除关键词
def remove_prefix(string, keywords):
    pattern = r"^(?:{})".format("|".join(map(re.escape, keywords)))
    lines = string.splitlines()
    processed_lines = [re.sub(pattern, "", line).strip() for line in lines]
    return "\n".join(processed_lines)


# 关键词替换
def replace_keywords_at_line_start(string, keywords, new_keywords):
    keyword_dict = dict(zip(keywords, new_keywords))
    for keyword, new_keyword in keyword_dict.items():
        pattern = r"^(?:{})".format(re.escape(keyword))
        string = re.sub(pattern, new_keyword, string, flags=re.MULTILINE)
    return string


# 规范化回答
def process_response(response):
    response = delete_key(response)
    lines = [line for line in response.splitlines() if line.strip()]
    response = "\n".join(lines)

    keywords = ["step1:", "step2:", "step3:", "step4:", "step5:", "step6:"]
    response = remove_prefix(response, keywords)

    key = ["漏洞类型:", "代码描述:", "漏洞信息:", "修复建议:", "修复后的代码片段:", "修复过程:"]
    new_key = ["一. 漏洞类型:", "\n二. 代码描述:", "\n三. 漏洞信息:", "\n四. 修复建议:", "\n五. 修复后的代码片段:",
               "\n六. 修复过程:"]

    response = replace_keywords_at_line_start(response, key, new_key)

    return response


# 匹配漏洞类型
def extract_vulnerability_type(string):
    pattern = r"一\. 漏洞类型:(.*?)\n"
    match = re.search(pattern, string, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def extract_vulnerability(string):
    pattern = r"漏洞类型:(.*?)\n"
    match = re.search(pattern, string, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def read_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        encode = chardet.detect(data)
        encoding = encode['encoding']
    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
        data = f.read()
        data = {'path': file_path, 'data': data}
    return data


def location_deepseek(path_list, model_name):
    # 调用模型检测
    response_lists = getLLM_deepseek(path_list, model_name)

    for data in response_lists:
        path = data['path']
        result_list = {
            '文件路径': path,
            '结果': []
        }
        for data in data['result']:
            code = data['data']
            response = data['response']
            # 规范化字符串
            try:  # 提取漏洞类型
                vuln_type = extract_vulnerability(response)
            except:
                vuln_type = '其他'

            result = {
                '漏洞类型': vuln_type,
                '源代码': code if code else '',
            }
            # print(result)
            result_list['结果'].append(result)

        yield result_list


@lru_cache(maxsize=1)
def loadLLM_deepseek(model_name):
    # 加密密钥
    mac_address = get_mac_address()
    key = generate_key(mac_address)
    with open('key.dll', 'wb') as f:
        f.write(key)
    mac_address = get_mac_address()
    key = generate_key(mac_address)
    print(key)
    with open('key.dll', 'rb') as f:
        k = f.read()
    if k != key:
        print("MAC地址未授权！拒绝访问")
        return False
    else:
        if model_name == 'deepseek-1.3b':
            print('使用deepseek-1.3b模型')
            model_path = "/home/public/deepseek/deepseek-coder-1.3b-instruct"
            tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(model_path, trust_remote_code=True, torch_dtype=torch.bfloat16,
                                                         device_map='auto')

            sftrain_dir = "/home/public/JAVA/model/checkpoint-1.3b/"
            model = PeftModel.from_pretrained(model, sftrain_dir)
            # 预测时将训练参数全部关闭
            model.requires_grad_(False)  # fix all params
            # 将所有参数转化为bfloat16格式
            model = model.bfloat16()  # cast all params to bfloat16

            # encrypt_model(model, key, 'small_enmodel')
            # model = decrypt_model(key, 'small_enmodel')

            return model, tokenizer

        elif model_name == 'deepseek-6.7b':
            print('使用deepseek6.7b模型')
            model_path = "/home/public/deepseek/deepseek-coder-6.7b-instruct/model"
            tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(model_path, trust_remote_code=True, torch_dtype=torch.bfloat16,
                                                         device_map='auto')

            sftrain_dir = "/home/public/deepseek/checkpoint/basic_knowledge_6.7b/checkpoint-400/"
            model = PeftModel.from_pretrained(model, sftrain_dir)
            # 预测时将训练参数全部关闭
            model.requires_grad_(False)  # fix all params
            # 将所有参数转化为bfloat16格式
            model = model.bfloat16()  # cast all params to bfloat16

            # encrypt_model(model, key, 'large_enmodel')
            # model = decrypt_model(key, 'large_enmodel')

            return model, tokenizer

        elif model_name == 'deepseek-14b':
            print('使用deepseek14b模型')
            model_path = "/home/public/model/deepseek-R1-qwen-14B"
            tokenizer = AutoTokenizer.from_pretrained(model_path)
            model = AutoModelForCausalLM.from_pretrained(
                model_path,
                load_in_8bit=True,
                torch_dtype=torch.bfloat16,
                device_map='auto',
            )

            # sftrain_dir = "/home/public/deepseek/checkpoint/basic_knowledge_6.7b/checkpoint-400/"
            # model = PeftModel.from_pretrained(model, sftrain_dir)
            # # 预测时将训练参数全部关闭
            # model.requires_grad_(False)  # fix all params
            # # 将所有参数转化为bfloat16格式
            # model = model.bfloat16()  # cast all params to bfloat16

            # encrypt_model(model, key, 'large_enmodel')
            # model = decrypt_model(key, 'large_enmodel')

            return model, tokenizer

        elif model_name == 'qwen-7b':
            print('使用qwen7b模型')
            # model_path = "/home/public/qwen/qwen2-7b-instruct"
            model_path = '/home/public/model/deepseek-R1-qwen-14B'
            tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(model_path, trust_remote_code=True, torch_dtype=torch.bfloat16,
                                                         device_map='auto')

            # sftrain_dir = "/home/public/deepseek/checkpoint/basic_knowledge_6.7b/checkpoint-400/"
            # model = PeftModel.from_pretrained(model, sftrain_dir)
            # # 预测时将训练参数全部关闭
            # model.requires_grad_(False)  # fix all params
            # # 将所有参数转化为bfloat16格式
            # model = model.bfloat16()  # cast all params to bfloat16

            return model, tokenizer


def display_tree(src_bytes, cursor, node_text=True):
    result = []

    if cursor.node.type == 'method_declaration':
        if node_text:
            code = src_bytes[cursor.node.start_byte: cursor.node.end_byte].decode('utf-8')
            result.append(code.strip())
        else:
            result.append(cursor.node.type)

    if cursor.goto_first_child():
        result.extend(display_tree(src_bytes, cursor, node_text=node_text))
        cursor.goto_parent()

    while cursor.goto_next_sibling():
        result.extend(display_tree(src_bytes, cursor, node_text=node_text))

    return result


# 切片
def split_code(data):
    # 构建语言库
    # 获取py 文件所在目录
    current_path = os.path.dirname(__file__)
    # 把这个目录设置成工作目录
    os.chdir(current_path)
    print(os.getcwd())
    tree_sitter.Language.build_library(
        # 语言库的文件名
        'build/my-languages.so',

        # 使用的语法定义文件
        ["vendor/tree-sitter-java-master"]
    )

    # 加载所需的语言库
    JAVA_LANGUAGE = tree_sitter.Language('build/my-languages.so', 'java')

    # 使用语言库解析 Java 代码
    parser = tree_sitter.Parser()
    parser.set_language(JAVA_LANGUAGE)

    tree = parser.parse(bytes(data, 'utf8'))  # 将代码转换为字节流
    cursor = tree.walk()
    result = display_tree(bytes(data, 'utf8'), cursor)

    return result


def filter_java_code(java_code):
    # 去除导包信息
    # java_code = re.sub(r'^\s*import\s+.*?;\s*', '', java_code, flags=re.MULTILINE)

    # 去除单行和多行注释
    # java_code = re.sub(r'//.*?(\n|$)', '', java_code)  # 单行注释
    # java_code = re.sub(r'/\*.*?\*/', '', java_code, flags=re.DOTALL)  # 多行注释

    # 去除多余的空行
    # java_code = re.sub(r'\n\s*\n+', '\n', java_code)

    def replace_chinese_chars(code):
        # 定义中文字符到英文字符的映射
        chinese_to_english = {
            '，': ',',  # 中文逗号 -> 英文逗号
            '。': '.',  # 中文句号 -> 英文句号
            '！': '!',  # 中文感叹号 -> 英文感叹号
            '？': '?',  # 中文问号 -> 英文问号
            '；': ';',  # 中文分号 -> 英文分号
            '：': ':',  # 中文冒号 -> 英文冒号
            '“': '"',  # 左双引号 -> 英文双引号
            '”': '"',  # 右双引号 -> 英文双引号
            '‘': "'",  # 左单引号 -> 英文单引号
            '’': "'",  # 右单引号 -> 英文单引号
            '（': '(',  # 左括号 -> 英文左括号
            '）': ')',  # 右括号 -> 英文右括号
            '【': '[',  # 左中括号 -> 英文左中括号
            '】': ']',  # 右中括号 -> 英文右中括号
            '《': '<',  # 左书名号 -> 英文小于号
            '》': '>',  # 右书名号 -> 英文大于号
        }

        # 遍历映射表，逐个替换
        for chinese_char, english_char in chinese_to_english.items():
            code = code.replace(chinese_char, english_char)

        return code

    # 英文字符 -> 中文字符
    java_code = replace_chinese_chars(java_code)

    # 将反斜杠替换为正斜杠
    java_code = java_code.replace('\\', '/')

    return java_code


def get_prompt(model_name, data):
    if model_name == 'deepseek-6.7b':
        prompt = f"""
假设你是软件安全领域的专家。下面让我们一步步严格地按照[步骤]，针对[代码]内容，生成相应的回复。

[步骤]
step1:根据[代码]内容，判断其中是否存在安全漏洞。以"漏洞类型: "开头，如果不存在漏洞，则显示"漏洞类型: 无漏洞"。
step2:描述这段[代码]的含义，以"代码描述: "开头。
step3:如果存在漏洞，提供这段[代码]中存在的漏洞信息，以"漏洞信息: "开头，如果不存在漏洞，则显示"漏洞信息: 这段代码不存在漏洞，无漏洞信息"。
step4:如果存在漏洞，提供漏洞修复建议，以"修复建议: "开头，如果不存在漏洞，则显示"修复建议: 这段代码不存在漏洞，无修复建议 "。
step5:如果存在漏洞，给出修复后的代码片段，代码片段以Markdown格式返回，以"修复后的代码片段: "开头，如果不存在漏洞，则显示"修复后的代码片段: 这段代码不存在漏洞，无修复后的代码片段"。
step6:如果存在漏洞，描述修复后的代码中是如何修复漏洞的，以"修复过程: "开头，如果不存在漏洞，则显示"修复过程: 这段代码不存在漏洞，无修复过程"。

[代码]
{data}
"""
        return prompt
    elif model_name == 'deepseek-1.3b':
        prompt = f"""
假设你是软件安全领域的专家。下面让我们一步步严格地按照[步骤]，针对[代码]内容，生成相应的回复。

[步骤]
step1:根据[代码]内容，判断其中是否存在安全漏洞。以"漏洞类型: "开头，如果不存在漏洞，则显示"漏洞类型: 无漏洞"。
step2:如果存在漏洞，提供这段[代码]中存在的漏洞信息，以"漏洞信息: "开头，如果不存在漏洞，则显示"漏洞信息: 这段代码不存在漏洞，无漏洞信息"。
step3:如果存在漏洞，提供漏洞修复建议，以"修复建议: "开头，如果不存在漏洞，则显示"修复建议: 这段代码不存在漏洞，无修复建议 "。

[代码]
{data}
"""
        return prompt
    elif model_name == 'qwen-7b':
        prompt = f"""
假设你是软件安全领域的专家。下面让我们一步步严格地按照[步骤]，针对[代码]内容，生成相应的回复。

[步骤]
step1:根据[代码]内容，判断其中是否存在安全漏洞。以"漏洞类型: "开头，如果不存在漏洞，则显示"漏洞类型: 无漏洞"。
step2:描述这段[代码]的含义，以"代码描述: "开头。
step3:如果存在漏洞，提供这段[代码]中存在的漏洞信息，以"漏洞信息: "开头，如果不存在漏洞，则显示"漏洞信息: 这段代码不存在漏洞，无漏洞信息"。
step4:如果存在漏洞，提供漏洞修复建议，以"修复建议: "开头，如果不存在漏洞，则显示"修复建议: 这段代码不存在漏洞，无修复建议 "。
step5:如果存在漏洞，给出修复后的代码片段，代码片段以Markdown格式返回，以"修复后的代码片段: "开头，如果不存在漏洞，则显示"修复后的代码片段: 这段代码不存在漏洞，无修复后的代码片段"。
step6:如果存在漏洞，描述修复后的代码中是如何修复漏洞的，以"修复过程: "开头，如果不存在漏洞，则显示"修复过程: 这段代码不存在漏洞，无修复过程"。

[代码]
{data}
"""
        return prompt
    else:
        return False


def getLLM_deepseek(path_list, model_name):
    model, tokenizer = loadLLM_deepseek(model_name)

    for i, path in enumerate(path_list):
        code = read_file(path)
        path = code['path']
        data = code['data']
        # 去除注释等信息
        data_filter = filter_java_code(data)
        # 切片
        data_split = split_code(data_filter)
        if not data_split:
            return False

        result_list = {
            'path': path,
            'result': []
        }

        for code in data_split:
            prompt = get_prompt(model_name, code)
            content = [
                {
                    'role': 'user',
                    'content': prompt,
                }
            ]

            inputs = tokenizer.apply_chat_template(content, add_generation_prompt=True, return_tensors="pt").to(
                model.device)

            max_new_tokens = 128

            if model_name == 'deepseek-6.7b':
                max_new_tokens = 3200
            elif model_name == 'deepseek-1.3b':
                max_new_tokens = 32
            elif model_name == 'qwen-7b':
                max_new_tokens = 3200

            outputs = model.generate(inputs, max_new_tokens=max_new_tokens, do_sample=False, num_return_sequences=1,
                                     eos_token_id=tokenizer.eos_token_id)

            decoded_output = tokenizer.decode(outputs[0][len(inputs[0]):], skip_special_tokens=True)
            result = {
                'data': code,
                'response': decoded_output,
            }
            result_list['result'].append(result)
        yield result_list


# async def getLLM_deepseek3(code, vultype, model_name, detection_type):  # 调用大模型进行修复/降误报
#     """使用 vLLM 调用模型，并流式输出生成的文本。"""
#     # 初始化引擎和采样参数
#     engine_args = {
#         "model": "/home/public/model/deepseek-R1-qwen-14B",
#         "trust_remote_code": True,
#         "dtype": 'bfloat16',
#         "enforce_eager": True,
#         "max_model_len": 8192,
#         "tensor_parallel_size": 2,
#         "gpu_memory_utilization": 0.9
#     }
#     sampling_params = initialize_sampling_params()
#
#     # 加载模型和分词器
#     engine_args_tuple = tuple(engine_args.items())
#     # llm = loadvLLM_deepseek(engine_args_tuple)
#     tokenizer = AutoTokenizer.from_pretrained(engine_args["model"])
#
#     if detection_type == 'repair':
#         prompt = get_prompt2(code, vultype)
#     elif detection_type == 'mix':
#         prompt = get_prompt3(code, vultype)
#
#     messages = tokenizer.apply_chat_template(
#         [{"role": "user", "content": prompt}],
#         tokenize=False,
#         add_generation_prompt=True
#     )
#
#     # 返回流式响应
#     return StreamingResponse(
#         generate_stream_response(llm, messages, sampling_params),
#         media_type="text/event-stream")

# def getLLM_deepseek3(code, vultype, model_name, detection_type):  # 调用大模型进行修复/降误报
#     llm = loadvLLM_deepseek()
#
#     tokenizer = AutoTokenizer.from_pretrained("/home/public/model/deepseek-R1-qwen-14B")
#     if detection_type == 'repair':
#         prompt = get_prompt2(code, vultype)
#     elif detection_type == 'mix':
#         prompt = get_prompt3(code, vultype)
#
#     content = [
#         {
#             'role': 'user',
#             'content': prompt,
#         }
#     ]
#
#     inputs = tokenizer.apply_chat_template(
#         content,
#         tokenize=False,
#         add_generation_prompt=True
#     )
#
#     # 设置初始化采样参数
#     sampling_params = SamplingParams(temperature=0.2, top_p=0.7, top_k=50, max_tokens=3200)
#
#     outputs = llm.generate(inputs, sampling_params)
#
#     response = ""
#     # 使用流式生成
#     for output in outputs:
#         generated_text = output.outputs[0].text
#         response += generated_text
#
#
#     result = {
#         'data': code,
#         'response': response,
#     }
#
#     return result
# def getLLM_deepseek2(code, vultype, model_name,detection_type):  # 调用大模型进行修复/降误报
#     model, tokenizer = loadLLM_deepseek(model_name)
#
#     if detection_type == 'repair':
#         prompt = get_prompt2(code, vultype)
#     elif detection_type == 'mix':
#         prompt = get_prompt3(code, vultype)
#     content = [
#         {
#             'role': 'user',
#             'content': prompt,
#         }
#     ]
#
#     inputs = tokenizer.apply_chat_template(content, add_generation_prompt=True, return_tensors="pt").to(
#         model.device)
#
#     max_new_tokens = 3200
#
#     outputs = model.generate(inputs, max_new_tokens=max_new_tokens, do_sample=False, num_return_sequences=1,
#                              eos_token_id=tokenizer.eos_token_id)
#
#     decoded_output = tokenizer.decode(outputs[0][len(inputs[0]):], skip_special_tokens=True)
#     result = {
#         'data': code,
#         'response': decoded_output,
#     }
#
#     # 清除显存占用
#     del model
#     del tokenizer
#     torch.cuda.empty_cache()
#
#     return result

def get_prompt2(code, vultype, sink_line, src_line):  # 针对修复生成提示词
    prompt = f"""请用**极简思考**的方式修复以下代码的{vultype}漏洞：

**要求：**
- 思考过程：3-5句话，直接点明问题核心和修复方案
- 输出：修复后代码代码片段，50行以内
- 主要关注爆发点处的代码{sink_line}和缺陷源处的代码{src_line}

代码：
{code}
"""
    return prompt


# def get_prompt2(code, vultype):  # 针对修复生成提示词
#     vul_name = get_vulname(vultype)
#     prompt = f"""
# 假设你是软件安全领域的专家。下面让我们严格地按照[要求]，针对[代码片段]和[漏洞类型]，生成相应的回复。
#
# [漏洞类型]
# {vul_name}
#
# [代码]
# {code}
#
# [要求]
# step1:根据以上[代码]和[漏洞类型]的内容，给出针对这个[漏洞类型]的解释，以"解释："开头。
# step2:根据以上[代码]和[漏洞类型]的内容，给出针对这个[漏洞类型]修复后的正确代码，以"修复后代码： "开头。
# step3:针对你给出的修复后的代码，给出详细的解释，以"如何修复："开头。
# """
#     return prompt

def get_prompt3(code, vultype):  # 针对降误报生成提示词
    vul_name = get_vulname(vultype)
    prompt = f"""
假设你是软件安全领域的专家。下面让我们一步步严格地按照[步骤]，针对[代码]内容，生成相应的回复。

[步骤]
step1:描述这段[代码]的含义，回复以"描述: "开头。 
step2:根据[代码]内容，判断其中是否存在{vul_name}这种漏洞类型，回复以"是否存在安全漏洞:"开头只需回答[是]或[否]

[代码]
{code}
"""
    return prompt


def deepseek_chat2(prompt, model_name):  # 调用大模型进行对话/生成
    model, tokenizer = loadLLM_deepseek(model_name)

    content = [
        {'role': 'user',
         'content': """
             你是一个代码生成以及代码安全方面的专家，请根据以下[需求]进行回答
             [需求]：""" + prompt
         }
    ]

    inputs = tokenizer.apply_chat_template(content, add_generation_prompt=True, return_tensors="pt").to(
        model.device)

    max_new_tokens = 3200

    outputs = model.generate(inputs, max_new_tokens=max_new_tokens, do_sample=False, num_return_sequences=1,
                             eos_token_id=tokenizer.eos_token_id)

    decoded_output = tokenizer.decode(outputs[0][len(inputs[0]):], skip_special_tokens=True)
    result = {
        'response': decoded_output,
    }
    return result

#  ***********旧版本**************
# def deepseek_chat3(prompt, model_name):
#     """调用大模型进行对话/生成，并逐块返回生成的文本。"""
#     model, tokenizer = loadLLM_deepseek(model_name)
#
#     content = [
#         {'role': 'user',
#          'content': """
#              你是一个代码生成以及代码安全方面的专家，请根据以下[需求]进行回答
#              [需求]：""" + prompt
#          }
#     ]
#
#     inputs = tokenizer.apply_chat_template(content, add_generation_prompt=True, return_tensors="pt").to(
#         model.device)
#
#     max_new_tokens = 3200
#     max_length = inputs.shape[-1] + max_new_tokens
#
#     # 逐块生成文本
#     current_length = inputs.shape[-1]
#
#     while current_length < max_length:
#         outputs = model.generate(inputs, max_new_tokens=1, do_sample=False, num_return_sequences=1,
#                                  eos_token_id=tokenizer.eos_token_id)
#         new_token = outputs[0, -1].unsqueeze(0)
#         decoded_output = tokenizer.decode(new_token, skip_special_tokens=True)
#         # print(repr(decoded_output))
#         if decoded_output == '':
#             yield decoded_output
#         yield decoded_output
#         new_token = new_token.unsqueeze(0)
#         inputs = torch.cat([inputs, new_token], dim=-1)
#         current_length += 1

# **************新版本对话********************
def get_logic_prompt():
    prompt = """请你分析以下这段代码：
# 角色指令
你是一个**高级静态代码分析引擎**，专门检测以下类型的逻辑漏洞：
- 登录接口错误提示
- 拦截器放行策略 
- 接口授权校验
- 文件上传安全

# 输出规范
**必须** 按照以下格式输出，禁止自由发挥：

漏洞类型: XXX
描述：代码中产生该漏洞的地方和产生的原因
修复建议：修复该漏洞的方法（文字描述）

# 漏洞检测规则
## 登录接口错误提示：  
- 检查认证失败时是否返回“用户名错误”“密码错误”等明确提示，错误码是否统一。  
- 修复建议：统一提示为“用户名或密码错误”，错误码保持一致。  

## 拦截器放行策略：  
- 检查拦截器是否启用，是否放行敏感接口（如getUserInfoById），路径匹配是否仅支持精确匹配。  
- 修复建议：使用通配符匹配路径，移除敏感接口白名单，启用拦截器组件。  

## 接口授权校验：  
- 检查是否仅通过注解控制授权，未带注解的接口是否缺少认证拦截。  
- 修复建议：添加全局认证流程，注解仅用于豁免场景。  

## 文件上传安全：  
- 检查是否使用原始文件名、文件类型/大小校验是否严格，是否存在未过滤的系统命令调用。  
- 修复建议：重命名文件，使用白名单校验类型，避免用户输入直接拼接命令。  

## 防暴力破解：  
- 检查 应用系统是否根据实际业务需求，在身份认证失败一定次数后限制认证(不仅包括密码输入错误导致的身份认证失败，也应包括CVV2等其他敏感信息输入错误导致的身份认证失败)。  
- 修复建议：实现失败计数器与锁定机制，统一错误信息，增加额外防御。

## 上传的压缩文件进行安全检查：  
- 检查服务端是否允许上传压缩文件，服务端是否对上传的压缩包大小进行检查、能否对超过大小限制的包进行抛弃处理，服务端是否对没有对上传的压缩包解压后文件名进行检查，对包含“.”、“/”等特殊字符的文件进行抛弃处理，服务端是否对文件类型进行检查，除了通过文件的后缀来判断是否是对应格式外，还要通过检查文件头的方式来检查是否是对应格式的文件。  
- 修复建议：压缩文件大小控制，文件名安全过滤，文件类型双重验证，安全解压流程。

## 下载漏洞：  
- 检查系统是否这样进行下载功能的安排：在系统服务端对可以下载的文件指定对应的ID编号值。 当用户访问有文件下载的业务时，服务端将文件对应的ID值返回到客户端。 用户请求下载文件时，客户端将文件对应ID发送到服务端，服务端识别此ID对应的文件并将其返回给用户。  
- 修复建议：强制引入服务端映射层，客户端只传递安全标识符，服务端严格校验，安全的文件读取。 

## 访问控制：  
- 检查系统是否实现如下功能：应用系统为主体（客户、用户、程序等）分配访问权限标识时，不能仅采用非私密静态信息（如：客户账号、客户编号、客户微信号等），应采用通过具备一定复杂度、私密性、动态变化、基于密钥运算生成等特征动态信息（如B/S模式的SessionID），防范攻击者通过遍历猜解、信息窃取等手段非法获取主体的访问权限标识，并冒充主体实施非法访问。  
- 修复建议：生成动态标识，服务端验证逻辑，安全增强措施。  

# 特别要求
- 禁止添加免责声明或模糊表述（如"可能存在问题"）  
- 若代码中未提供足够信息（如未展示全局配置、关键组件缺失等）导致无法验证规则，视为不确定问题，不检测相应规则  
- 仅针对提供的代码片段进行检测，不涉及外部依赖或未展示的配置文件
- 仅输出最有可能的一个漏洞类型

代码：

"""
    return prompt

def deepseek_chat3(prompt, key):
    """使用 vLLM 调用模型，并流式输出生成的文本。"""
    # 构造输入内容
    #prompt = f"""请你分析下面代码，并判断其是否存在{vultype}这种类型的漏洞，如果存在，则根据给出的爆发点代码，指出缺陷源代码，按照如下格式输出，[爆发点代码]：{sink};[缺陷源代码]：[缺陷源所在行的代码]，思考过程要尽可能的简洁，并且限制在100字以内，要更注重结论，代码：\n{code}"""

    openai_api_key = "EMPTY"
    openai_api_base = f"http://{ip}:8000/v1"

    client = OpenAI(
        api_key=openai_api_key,
        base_url=openai_api_base,
    )

    # 发起流式请求
    if key == "1":
        chat_response = client.chat.completions.create(
            model="qwen3-4b",  # 模型名称
            messages=[
                {"role": "system", "content": get_logic_prompt()},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            top_p=0.7,
            max_tokens=8196,
            stream=True,  # 启用流式输出
        )
    else:
        chat_response = client.chat.completions.create(
            model="deepseek",  # 模型名称
            messages=[
                {"role": "system", "content": "你是一个强大的AI工具，请你用中文回答下面问题"},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            top_p=0.7,
            max_tokens=8196,
            stream=True,  # 启用流式输出
        )

    # 逐步处理流式响应
    full_response = ""  # 用于收集完整响应
    for chunk in chat_response:
        if chunk.choices[0].delta.content:  # 检查是否有新内容
            response_chunk = chunk.choices[0].delta.content
            full_response += response_chunk  # 将每个 chunk 拼接到完整响应中
            yield response_chunk  # 流式输出当前 chunk

    update_Interpretation(id, full_response)

def deepseek_chat4(prompt, model_name):
    """调用大模型进行对话/生成，并逐块返回生成的文本。"""
    model, tokenizer = loadLLM_deepseek(model_name)

    content = [
        {'role': 'user',
         'content': """
             你是一个代码生成以及代码安全方面的专家，请根据以下[需求]进行回答
             [需求]：""" + prompt
         }
    ]

    inputs = tokenizer.apply_chat_template(content, add_generation_prompt=True, return_tensors="pt").to(model.device)

    def stream_generate(model, tokenizer, inputs, max_new_tokens=2000, do_sample=False, num_return_sequences=1,
                        eos_token_id=None):
        input_ids = inputs
        with torch.no_grad():
            for _ in range(max_new_tokens):
                outputs = model(input_ids)
                next_token_logits = outputs.logits[:, -1, :]
                next_token = torch.argmax(next_token_logits, dim=-1).unsqueeze(-1)

                # 将生成的token添加到输入中
                input_ids = torch.cat([input_ids, next_token], dim=-1)

                # 解码并输出
                generated_text = tokenizer.decode(input_ids[0], skip_special_tokens=True)
                yield generated_text

                # 如果生成了结束符，停止生成
                if next_token.item() == eos_token_id:
                    break

    # 流式生成并输出
    eos_token_id = tokenizer.eos_token_id
    instruction_length = len(tokenizer.decode(inputs[0], skip_special_tokens=True))
    for text in stream_generate(model, tokenizer, inputs, max_new_tokens=2000, do_sample=False, num_return_sequences=1,
                                eos_token_id=eos_token_id):
        if len(text) > instruction_length:
            yield text[instruction_length:]


def deepseek_chat5(model_name, code, vultype):
    """调用大模型进行对话/生成，并逐块返回生成的文本。"""
    model, tokenizer = loadLLM_deepseek(model_name)

    # 构造输入内容
    prompt = f"""你是一名代码审计的专家，你的任务是解释下面这段代码，并判断其是否存在{vultype}这种类型的漏洞,代码：{code}"""
    messages = [
        {"role": "system",
         "content": "You are a helpful and harmless assistant. You are Qwen developed by Alibaba. You should think step-by-step."},
        {"role": "user", "content": prompt}
    ]
    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )

    # 使用 tokenizer 编码
    inputs = tokenizer([text], return_tensors="pt").to(model.device)
    input_ids = inputs["input_ids"]

    max_new_tokens = 2048
    current_length = input_ids.shape[-1]
    total_max_length = current_length + max_new_tokens

    while current_length < total_max_length:
        # 调用模型生成
        outputs = model.generate(
            input_ids=input_ids,
            max_new_tokens=1,  # 每次生成一个 token，逐步生成
            temperature=0.6,
            top_p=0.7,
            top_k=50,
            eos_token_id=tokenizer.eos_token_id,
        )

        # 获取新生成的 token
        new_token = outputs[0, -1].unsqueeze(0)  # 逐个获取新生成的 token
        decoded_output = tokenizer.decode(new_token, skip_special_tokens=True)

        # 如果生成结束标记，停止生成
        if new_token.item() == tokenizer.eos_token_id:
            break

        # 逐块发送生成的 token
        yield decoded_output

        # 将新生成的 token 拼接到输入中
        new_token = new_token.unsqueeze(0)  # 将 new_token 转换为二维张量
        input_ids = torch.cat([input_ids, new_token], dim=-1)
        current_length += 1


# @lru_cache(maxsize=1)
# def loadvLLM_deepseek():
#     # 加载模型，确保路径正确，并使用多张 GPU
#     llm = LLM(
#         model="/home/public/model/deepseek-R1-qwen-14B",
#         trust_remote_code=True,
#         max_model_len=8192,
#         #quantization="int8",
#         tensor_parallel_size=2  # 使用 2 张 GPU
#     )
#
#     return llm
#
# def deepseek_chat6(model_name, code, vultype):
#     """使用 vLLM 调用模型，并流式输出生成的文本。"""
#     llm = loadvLLM_deepseek()
#     # 构造输入内容
#     #prompt = f"""你是一名代码审计的专家，你的任务是解释下面这段代码，并判断其是否存在{vultype}这种类型的漏洞,代码：{code}"""
#     prompt = f"""请你分析下面代码，并判断其是否存在{vultype}这种类型的漏洞，思考过程要尽可能的简洁，并且限制在100字以内，要更注重结论，代码：\n{code}"""
#     #prompt = f"""请你分析下面代码，并判断其是否存在{vultype}这种类型的漏洞，不输出思考过程，只输出结论，且存在漏洞，输出：1，不存在漏洞，输出：0，代码：\n{code}"""
#
#     # prompt = f"""请你分析下面代码，并判断其是否存在{vultype}漏洞 ，注意思考过程尽量简洁，请仔细检查，有些情况可能不执行，注重结论/ **""" + \
#     #          f"""代码：""" + \
#     #          f"""{code}"""
#
# #     prompt = f"""作为代码审计专家，请严格按照以下要求分析代码是否存在【{vultype}】漏洞，思考过程不超过100字：
# #
# # 1. **核心结论优先**：
# #    - 存在漏洞 → 结论：存在
# #    - 不存在漏洞 → 结论：不存在
# #
# # 2. **关键分析步骤**（最多3点，每点不超过20 字）：
# #    - 检查是否包含{vultype}漏洞的典型模式
# #    - 验证漏洞代码是否被触发执行
# #    - 确认外部输入是否影响漏洞路径
# #
# # 3. **特别注意事项**：
# #    - 若存在漏洞代码但未被调用，结论应为【不存在】
# #    - 若依赖未初始化的变量/配置，视为【存在】
# #
# # 请按此格式分析代码：
# # 代码：{code}"""
#
#     messages = [
#         {"role": "user", "content": prompt}
#     ]
#     tokenizer = AutoTokenizer.from_pretrained("/home/public/model/deepseek-R1-qwen-14B")
#     messages = tokenizer.apply_chat_template(
#         messages,
#         tokenize=False,
#         add_generation_prompt=True
#     )
#     # 设置初始化采样参数
#     sampling_params = SamplingParams(temperature=0.2, top_p=0.7, top_k=50, max_tokens=8192)
#
#     outputs = llm.generate(messages, sampling_params)
#
#
#     for output in outputs:
#         generated_text = output.outputs[0].text
#         yield generated_text  # 逐块返回生成的文本

def deepseek_chat6(id, code, vultype,sink):
    """使用 vLLM 调用模型，并流式输出生成的文本。"""
    # 构造输入内容
    prompt = f"""请你分析下面代码，并判断其是否存在{vultype}这种类型的漏洞，如果存在，则根据给出的爆发点代码，指出缺陷源代码，按照如下格式输出，[爆发点]：{sink};[缺陷源]：[缺陷源所在行的代码]，思考过程要尽可能的简洁，并且限制在100字以内，要更注重结论，代码：\n{code}"""

    openai_api_key = "EMPTY"
    openai_api_base = f"http://{ip}:8000/v1"

    print(33333)

    client = OpenAI(
        api_key=openai_api_key,
        base_url=openai_api_base,
    )


    print(22222)

    # 发起流式请求
    chat_response = client.chat.completions.create(
        model="deepseek",  # 模型名称
        messages=[
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        top_p=0.7,
        max_tokens=8196,
        stream=True,  # 启用流式输出
    )
    print(11111)
    # 逐步处理流式响应
    full_response = ""  # 用于收集完整响应
    for chunk in chat_response:
        if chunk.choices[0].delta.content:  # 检查是否有新内容
            response_chunk = chunk.choices[0].delta.content
            full_response += response_chunk  # 将每个 chunk 拼接到完整响应中
            yield response_chunk  # 流式输出当前 chunk

    update_Interpretation(id, full_response)

def deepseek_chat7(code, vultype):
    """使用 vLLM 调用模型，判断该漏洞类型是否是误报。"""
    # 构造输入内容
    prompt = f"""请你分析下面的代码是否存在漏洞，如果存在则只输出1，如果不存在则只输出0，请严格按照要求输出结果，代码：\n{code}"""

    openai_api_key = "EMPTY"
    openai_api_base = f"http://{ip}:8000/v1"

    client = OpenAI(
        api_key=openai_api_key,
        base_url=openai_api_base,
    )

    chat_response = client.chat.completions.create(
        model="deepseek",  # 模型名称
        messages=[
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        top_p=0.7,
        max_tokens=1024,
        stream=False,  # 启用流式输出
    )
    # 获取完整响应
    full_response = chat_response.choices[0].message.content
    print(full_response)
    # 提取</think>后面的数字0或1
    result = re.search(r"</think>\s*([01])", full_response)

    print(result is not None and result.group(1) == "1" if result else False)

    return result is not None and result.group(1) == "1" if result else False

def deepseek_chat8(code):
    """使用 vLLM 调用模型"""
    # 构造输入内容
    prompt = r"""请你分析以下这段代码：
    # 角色指令
    你是一个**高级静态代码分析引擎**，专门检测以下类型的安全漏洞：
    - **CWE-798**：访问控制
    - **CWE-643**：XPath注入  
    - **CWE-918**：服务端请求伪造（SSRF）  
    - **CWE-079**：跨站脚本攻击（XSS）  
    - **CWE-089**：SQL注入  
    - **CWE-022**：下载漏洞  
    - **CWE-078**：操作系统命令注入  
    - **CWE-400**：拒绝服务（DoS） 
    - **CWE-117**：日志伪造
    - **CWE-203**：登录接口错误提示
    - **CWE-284**：拦截器放行策略
    - **CWE-862**：接口授权校验
    - **CWE-494**：文件上传安全    
    - **CWE-307**：暴力破解
    - **CWE-308**：短信安全
    - **CWE-434**：未对上传的压缩文件进行安全检查
    - **CWE-999**：下载漏洞
    - **CWE-779**：访问控制
    # 输出规范
    **必须** 按照以下JSON格式输出，禁止自由发挥：
    ```
    {
        "漏洞类型": "CWE-XXX",
        "风险等级": "高危/中危/低危",
        ”缺陷源“："程序中未经验证的外部输入数据，即漏洞的源头的代码片段，禁止使用中文表述，不要使用文字表述，仅使用代码中所的截取的内容，如果无缺陷源，输出为‘/’ （例如：String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;）"，
        "爆发点": "最终执行危险操作的位置，即漏洞被触发的关键点的代码片段，禁止使用中文表述，不要使用文字表述，仅使用代码中所的截取的内容（例如： fis = new java.io.FileInputStream(new java.io.File(fileName))）",
        "爆发点函数": "漏洞被触发的关键点所在的函数，禁止使用中文表述，不要使用文字表述，仅使用代码中所的截取的内容，如果无爆发点函数，输出为‘/’ （例如：public void login(HttpServletRequest request)）",
    }
    ```

    # 漏洞检测规则
    ## CWE-798 访问控制
    1. 检测模式：密码、API密钥、私钥等敏感信息直接写在代码中  
    2. 关键词：`password=`、`secret_key`、`BEGIN RSA PRIVATE KEY`  
    3. 风险提升条件：生产环境代码  

    ## CWE-643 XPath注入
    1. 检测模式：未参数化的XPath查询语句  
    2. 高危函数：`evaluate()`、`selectNodes()`  
    3. 特征：用户输入直接拼接到XPath表达式  

    ## CWE-918 SSRF（服务端请求伪造）
    1. 检测模式：用户可控的URL请求  
    2. 高危函数：`fetch()`、`HttpClient`、`curl_exec()`  
    3. 风险目标：`internal`、`169.254.169.254`（云元数据API）  

    ## CWE-079 XSS（跨站脚本）
    1. 检测模式：未过滤的反射型/DOM型XSS漏洞  
    2. 高危上下文：`innerHTML`、`document.write()`  
    3. 必须检查：输出编码是否完备  

    ## CWE-089 SQL注入
    1. 检测模式：拼接式SQL查询语句  
    2. 高危函数：`execute()`、`query()`  
    3. 标记所有非参数化查询  

    ## CWE-022 下载漏洞
    1. 检测模式：用户输入直接用于文件路径操作  
    2. 高危函数：`open()`、`include()`  
    3. 检测路径穿越符号：`../`、`~/`  

    ## CWE-078 命令注入
    1. 检测模式：用户输入拼接到系统命令中  
    2. 高危函数：`exec()`、`system()`  
    3. 标记包含`$`、`|`、`;`的调用  

    ## CWE-400 拒绝服务（DoS）
    1. 检测模式：循环/递归无终止条件、大文件上传无限制、正则表达式拒绝服务（ReDoS）
    2. 高危函数：`while(true)`、`Thread.sleep()`、`Pattern.compile()` 
    3. 风险提升条件：缺乏速率限制/超时机制
    4. 特征代码：`ArrayList.add()`无限循环、复杂正则表达式`(a+)+`

    ## CWE-117 日志伪造
    1. 检测模式：未过滤用户输入直接写入日志
    2. 高危函数：`logger.info()`、`System.out.println()`  
    3. 风险特征：
       - 日志包含CRLF注入（\r\n）
       - 记录敏感数据（密码、会话ID）
       - 可伪造日志条目
    4. 必须检查：日志内容是否经过清洗处理

    ## CWE-203 登录接口错误提示
    1. 检测模式：检查认证失败时是否返回“用户名错误”“密码错误”等明确提示，错误码是否统一  
    2. 高危函数：`userExists()`、`printStackTrace()`  
    3. 特征：检查统一提示是否为“用户名或密码错误”，错误码保持一致

    ## CWE-284 拦截器放行策略
    1. 检测模式：检查拦截器是否启用，是否放行敏感接口（如getUserInfoById），路径匹配是否仅支持精确匹配  
    2. 高危函数：`getUserInfoById()`
    3. 特征：是否使用通配符匹配路径，移除敏感接口白名单，启用拦截器组件

    ## CWE-862 接口授权校验
    1. 检测模式：检查是否仅通过注解控制授权，未带注解的接口缺少认证拦截  
    2. 高危函数：`deleteUser()`    

    ## CWE-494 文件上传安全
    1. 检测模式：检查是否使用原始文件名、文件类型/大小校验是否严格，是否存在未过滤的系统命令调用  
    2. 高危函数：`FileOutputStream()`、`renameTo()`  

    ## CWE-308 短信安全
    1. 检测模式：短信验证码没有安全措施，没有随机生成、没有限制短信发送频率、没有限制短信验证码有效时间、没有限制同一手机号码短信验证失败的次数。  
    2. 高危函数：`getSmsCode()`、`getByPhone()`、`login()`

    ## CWE-307 暴力破解
    1. 检测模式：应用系统应根据实际业务需求，在身份认证失败一定次数后没有限制认证(不仅包括密码输入错误导致的身份认证失败，也应包括CVV2等其他敏感信息输入错误导致的身份认证失败)。  
    2. 高危函数：`generateRandomCode()`、`sendSmsCode()`、`loginByPwd()`

    ## CWE-434 未对上传的压缩文件进行安全检查
    1. 检测模式：1.在服务端允许上传压缩文件。 2.在服务端没有对上传的压缩包大小进行检查，没有对超过大小限制的包进行抛弃处理。 3.在服务端没有对上传的压缩包解压后文件名进行检查，没有对包含“.”、“/”等特殊字符的文件进行抛弃处理。4. 没有对文件类型进行检查，除了通过文件的后缀来判断是否是对应格式外，还要通过检查文件头的方式来检查是否是对应格式的文件。  
    2. 高危函数：`getRuntime()`、`getSize()`  

    ## CWE-999 下载漏洞
    1. 检测模式：系统没有这样进行下载功能的安排：在系统服务端对可以下载的文件指定对应的ID编号值。 当用户访问有文件下载的业务时，服务端将文件对应的ID值返回到客户端。 用户请求下载文件时，客户端将文件对应ID发送到服务端，服务端识别此ID对应的文件并将其返回给用户。  
    2. 高危函数：`validateAccess()`、`fileService.downloadFile()`

    ## CWE-779 访问控制
    1. 检测模式：未能实现如下功能：应用系统为主体（客户、用户、程序等）分配访问权限标识时，不能仅采用非私密静态信息（如：客户账号、客户编号、客户微信号等），应采用通过具备一定复杂度、私密性、动态变化、基于密钥运算生成等特征动态信息（如B/S模式的SessionID），防范攻击者通过遍历猜解、信息窃取等手段非法获取主体的访问权限标识，并冒充主体实施非法访问。  
    2. 高危函数：`randomUUID()`

    # 特别要求
    1. 对不确定的漏洞标记`"风险等级": "潜在风险"`  
    2. 对高误报模式（如复杂正则表达式）需二次确认  
    3. 优先引用以下标准：  
       - OWASP Top 10 2021  
       - MITRE ATT&CK T1190  
       - CWE官方示例  
    4. 禁止添加免责声明或模糊表述（如"可能存在问题"）  
    5. 缺陷源、爆发点、爆发点函数中仅使用代码中片段，禁止使用中文表述，仅使用源代码中所的截取的内容作为缺陷源、爆发点、爆发点函数，如果是xml文件，视作无缺陷源和爆发点函数，对应的输出为'/'
    6. 禁止使用中文表述，只给出对应代码行即可，如果没有找到则回答‘/’  
    """

    openai_api_key = "EMPTY"
    openai_api_base = f"http://{ip}:8000/v1"

    client = OpenAI(
        api_key=openai_api_key,
        base_url=openai_api_base,
    )

    chat_response = client.chat.completions.create(
        model="deepseek",  # 模型名称
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"请你分析以下这段代码：\n{code}"},
        ],
        temperature=0.2,
        top_p=0.7,
        max_tokens=1024,
        stream=False,  # 启用流式输出
        frequency_penalty=0.1,  # 轻微抑制重复短语
        presence_penalty=0.1  # 轻微鼓励新术语

    )

    # 获取完整响应
    full_response = chat_response.choices[0].message.content
    print(full_response)
    print("111===")
    return full_response

def deepseek_chat11(code):# 调别人的api
    """使用 vLLM 调用模型"""
    # 构造输入内容
    prompt = r"""请你分析以下这段代码：
    # 角色指令
    你是一个**高级静态代码分析引擎**，专门检测以下类型的安全漏洞：
    - **CWE-798**：硬编码凭证（密码、API密钥等）  
    - **CWE-643**：XPath注入  
    - **CWE-918**：服务端请求伪造（SSRF）  
    - **CWE-079**：跨站脚本攻击（XSS）  
    - **CWE-089**：SQL注入  
    - **CWE-022**：路径遍历  
    - **CWE-078**：操作系统命令注入  
    - **CWE-400**：拒绝服务（DoS） 
    - **CWE-117**：日志伪造
    - **CWE-203**：登录接口错误提示
    - **CWE-284**：拦截器放行策略
    - **CWE-862**：接口授权校验
    - **CWE-494**：文件上传安全    
    - **CWE-307**：暴力破解
    - **CWE-308**：短信安全
    - **CWE-434**：未对上传的压缩文件进行安全检查 
    - **CWE-999**：下载漏洞
    - **CWE-779**：访问控制
    # 输出规范
    **必须** 按照以下JSON格式输出，禁止自由发挥：
    ```
    {
        "漏洞类型": "CWE-XXX",
        "风险等级": "高危/中危/低危",
        ”缺陷源“："程序中未经验证的外部输入数据，即漏洞的源头的代码片段，禁止使用中文表述，仅使用代码中所的截取的内容，如果无缺陷源，输出为‘/’  例如：String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;）"，
        "爆发点": "最终执行危险操作的位置，即漏洞被触发的关键点的代码片段，禁止使用中文表述，仅使用代码中所的截取的内容（例如： fis = new java.io.FileInputStream(new java.io.File(fileName))）",
        "爆发点函数": "漏洞被触发的关键点所在的函数，禁止使用中文表述，仅使用代码中所的截取的内容，如果是无爆发点函数，输出为‘/’  （例如：public void login(HttpServletRequest request)）",
    }
    ```

    # 漏洞检测规则
    ## CWE-798 硬编码凭证
    1. 检测模式：密码、API密钥、私钥等敏感信息直接写在代码中  
    2. 关键词：`password=`、`secret_key`、`BEGIN RSA PRIVATE KEY`  
    3. 风险提升条件：生产环境代码  

    ## CWE-643 XPath注入
    1. 检测模式：未参数化的XPath查询语句  
    2. 高危函数：`evaluate()`、`selectNodes()`  
    3. 特征：用户输入直接拼接到XPath表达式  

    ## CWE-918 SSRF（服务端请求伪造）
    1. 检测模式：用户可控的URL请求  
    2. 高危函数：`fetch()`、`HttpClient`、`curl_exec()`  
    3. 风险目标：`internal`、`169.254.169.254`（云元数据API）  

    ## CWE-079 XSS（跨站脚本）
    1. 检测模式：未过滤的反射型/DOM型XSS漏洞  
    2. 高危上下文：`innerHTML`、`document.write()`  
    3. 必须检查：输出编码是否完备  

    ## CWE-089 SQL注入
    1. 检测模式：拼接式SQL查询语句  
    2. 高危函数：`execute()`、`query()`  
    3. 标记所有非参数化查询  

    ## CWE-022 路径遍历
    1. 检测模式：用户输入直接用于文件路径操作  
    2. 高危函数：`open()`、`include()`  
    3. 检测路径穿越符号：`../`、`~/`  

    ## CWE-078 命令注入
    1. 检测模式：用户输入拼接到系统命令中  
    2. 高危函数：`exec()`、`system()`  
    3. 标记包含`$`、`|`、`;`的调用  

    ## CWE-400 拒绝服务（DoS）
    1. 检测模式：循环/递归无终止条件、大文件上传无限制、正则表达式拒绝服务（ReDoS）
    2. 高危函数：`while(true)`、`Thread.sleep()`、`Pattern.compile()` 
    3. 风险提升条件：缺乏速率限制/超时机制
    4. 特征代码：`ArrayList.add()`无限循环、复杂正则表达式`(a+)+`

    ## CWE-117 日志伪造
    1. 检测模式：未过滤用户输入直接写入日志
    2. 高危函数：`logger.info()`、`System.out.println()`  
    3. 风险特征：
       - 日志包含CRLF注入（\r\n）
       - 记录敏感数据（密码、会话ID）
       - 可伪造日志条目
    4. 必须检查：日志内容是否经过清洗处理

    ## CWE-203 登录接口错误提示
    1. 检测模式：错误码不统一  
    2. 高危函数：`userExists()`、`printStackTrace()`  

    ## CWE-284 拦截器放行策略
    1. 检测模式：拦截器没启用，放行敏感接口  
    2. 高危函数：`getUserInfoById()`

    ## CWE-862 接口授权校验
    1. 检测模式：仅通过注解控制授权，未带注解的接口缺少认证拦截  
    2. 高危函数：`deleteUser()`    

    ## CWE-494 文件上传安全
    1. 检测模式：使用原始文件名，存在未过滤的系统命令调用  
    2. 高危函数：`FileOutputStream()`、`renameTo()`  

    ## CWE-308 短信安全
    1. 检测模式：短信验证码没有安全措施，没有随机生成、没有限制短信发送频率、没有限制短信验证码有效时间、没有限制同一手机号码短信验证失败的次数。  
    2. 高危函数：`getSmsCode()`、`getByPhone()`  

    ## CWE-307 暴力破解
    1. 检测模式：应用系统应根据实际业务需求，在身份认证失败一定次数后没有限制认证(不仅包括密码输入错误导致的身份认证失败，也应包括CVV2等其他敏感信息输入错误导致的身份认证失败)。  
    2. 高危函数：`generateRandomCode()`、`sendSmsCode()` 

    ## CWE-434 未对上传的压缩文件进行安全检查
    1. 检测模式：1.在服务端允许上传压缩文件。 2.在服务端没有对上传的压缩包大小进行检查，没有对超过大小限制的包进行抛弃处理。 3.在服务端没有对上传的压缩包解压后文件名进行检查，没有对包含“.”、“/”等特殊字符的文件进行抛弃处理。4. 没有对文件类型进行检查，除了通过文件的后缀来判断是否是对应格式外，还要通过检查文件头的方式来检查是否是对应格式的文件。  
    2. 高危函数：`getRuntime()`、`getSize()`  

    ## CWE-999 下载漏洞
    1. 检测模式：系统没有这样进行下载功能的安排：在系统服务端对可以下载的文件指定对应的ID编号值。 当用户访问有文件下载的业务时，服务端将文件对应的ID值返回到客户端。 用户请求下载文件时，客户端将文件对应ID发送到服务端，服务端识别此ID对应的文件并将其返回给用户。  
    2. 高危函数：`validateAccess()`

    ## CWE-779 访问控制
    1. 检测模式：未能实现如下功能：应用系统为主体（客户、用户、程序等）分配访问权限标识时，不能仅采用非私密静态信息（如：客户账号、客户编号、客户微信号等），应采用通过具备一定复杂度、私密性、动态变化、基于密钥运算生成等特征动态信息（如B/S模式的SessionID），防范攻击者通过遍历猜解、信息窃取等手段非法获取主体的访问权限标识，并冒充主体实施非法访问。  
    2. 高危函数：`randomUUID()`

    # 特别要求
    1. 对不确定的漏洞标记`"风险等级": "潜在风险"`  
    2. 对高误报模式（如复杂正则表达式）需二次确认  
    3. 优先引用以下标准：  
       - OWASP Top 10 2021  
       - MITRE ATT&CK T1190  
       - CWE官方示例  
    4. 禁止添加免责声明或模糊表述（如"可能存在问题"）
    5. 缺陷源、爆发点、爆发点函数中仅使用代码中片段，禁止使用中文表述，仅使用源代码中所的截取的内容作为缺陷源、爆发点、爆发点函数，如果是xml文件，视作无缺陷源和爆发点函数，对应的输出为'/'
    6. 禁止使用中文表述，只给出对应代码行即可，如果没有找到则回答‘/’   
    """

    #openai_api_key = "DASHSCOPE_API_KEY"
    #openai_api_base = f"https://dashscope.aliyuncs.com/compatible-mode/v1"

    client = OpenAI(
        api_key=os.getenv("DASHSCOPE_API_KEY"),
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )

    completion = client.chat.completions.create(
        model="qwen3-plus",  # 模型名称
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"请你分析以下这段代码：\n{code}"},
        ],
        #换成plus要把下面的代码注释掉
#        extra_body={"enable_thinking": False},


    )

    # 获取完整响应
    full_response = completion.choices[0].message.content
    print(full_response)
    print(type(full_response))
    print("111===")
    return full_response


def deepseek_chat9(code):
    """使用 vLLM 调用模型"""
    # 构造输入内容
    prompt = r"""请你分析以下XML文件内容：
    # 角色指令
    你是一个**高级XML安全分析引擎**，专门检测以下类型的安全漏洞：
    - **CWE-611**：XML外部实体注入（XXE）  
    - **CWE-776**：XML炸弹（Billion Laughs）  
    - **CWE-643**：XPath注入  
    - **CWE-502**：不安全的反序列化  
    - **CWE-827**：未受控的命名空间绑定  
    - **CWE-838**：DTD校验绕过  
    - **CWE-176**：字符集编码漏洞

    # 输出规范
    **必须** 按照以下JSON格式输出，禁止自由发挥：
    ```
    {
        "漏洞类型": "CWE-XXX",
        "风险等级": "高危/中危/低危",
        "缺陷源": "漏洞起源的具体元素/属性，禁止使用中文表述，仅使用代码中所的截取的内容，如果未找到，则输出“/”（例如：<!ENTITY xxe SYSTEM \"file:///etc/passwd\">）",
        "爆发点": "触发漏洞的关键位置，禁止使用中文表述，仅使用代码中所的截取的内容，如果未找到，则输出“/”（例如：<user>&xxe;</user>）",
        "解析器配置": "不安全的解析参数，禁止使用中文表述，仅使用代码中所的截取的内容，如果未找到，则输出“/”（例如：setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", false)）"
    }
    ```

    # 漏洞检测规则
    ## CWE-611 XXE（XML外部实体注入）
    1. 检测模式：DOCTYPE声明包含外部实体  
    2. 高危关键词：`SYSTEM`、`PUBLIC`、`ENTITY`  
    3. 风险目标：`file://`、`http://`、`ftp://`协议  
    4. 必检配置：是否禁用DTD/外部实体解析

    ## CWE-776 XML炸弹（Billion Laughs）
    1. 检测模式：指数级嵌套的实体定义  
    2. 特征模式：`&lol9;`多级嵌套引用  
    3. 风险指标：单实体引用深度超过3层

    ## CWE-643 XPath注入
    1. 检测模式：未参数化的XPath表达式  
    2. 高危属性：`select=`、`evaluate=`  
    3. 特征代码：`concat(//user[@name='`, `$input`)`

    ## CWE-502 不安全的反序列化
    1. 检测模式：包含可执行类的定义  
    2. 高危元素：`<object>`、`<void>`标签  
    3. 风险特征：`method=\"execute\"`、`class=\"java.lang.Runtime\"`

    ## CWE-827 未受控的命名空间绑定
    1. 检测模式：默认命名空间被覆盖  
    2. 高危特征：`xmlns=\"http://attacker.com/evil\"`  
    3. 风险指标：同名标签跨命名空间混淆

    ## CWE-838 DTD校验绕过
    1. 检测模式：#FIXED属性被覆盖  
    2. 高危模式：`<!ATTLIST price unit CDATA #FIXED \"USD\">` + `<price unit=\"EUR\">`  
    3. 防御缺失：未使用XSD校验

    ## CWE-176 字符集编码漏洞
    1. 检测模式：非标准编码声明  
    2. 高危特征：`encoding=\"UTF-7\"`、`BOM`异常  
    3. 风险行为：多编码混合解析

    # 特别要求
    1. 对以下高危模式立即标记为高危：
       - 同时存在`SYSTEM`实体和`file://`协议  
       - XML文档深度超过10层嵌套  
       - 包含`<!ENTITY %`参数实体声明
    
    2. 优先引用以下标准：
       - OWASP XXE Prevention Cheat Sheet  
       - CWE官方XML示例  
       - XML 1.1安全规范

    3. 对以下情况标记"风险等级": "潜在风险"：
       - 未明确设置XML解析器安全配置  
       - 使用已弃用的DTD特性  
       - 包含`<!NOTATION>`声明

    4. 必须标注具体行号（例如：缺陷源@L12，爆发点@L45）

    5. 禁止接受以下危险配置：
       - `setExpandEntityReferences(true)`  
       - `setFeature("http://xml.org/sax/features/external-general-entities", true)`
    """

    openai_api_key = "EMPTY"
    openai_api_base = f"http://{ip}:8000/v1"

    client = OpenAI(
        api_key=openai_api_key,
        base_url=openai_api_base,
    )

    chat_response = client.chat.completions.create(
        model="deepseek",  # 模型名称
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"请你分析以下这段代码：\n{code}"},
        ],
        temperature=0.2,
        top_p=0.7,
        max_tokens=1024,
        stream=False,  # 启用流式输出
        frequency_penalty=0.1,  # 轻微抑制重复短语
        presence_penalty=0.1  # 轻微鼓励新术语

    )

    # 获取完整响应
    full_response = chat_response.choices[0].message.content

    return full_response

def getLLM_deepseek3(task_id, file_id, code, vultype, model_name, detection_type, sink_line, src_line):  # 调用大模型进行修复/降误报
    """使用 vLLM 调用模型，并流式输出生成的文本。"""
    prompt = ""
    if detection_type == 'repair':
        prompt = get_prompt2(code, vultype, sink_line, src_line)
    elif detection_type == 'mix':
        prompt = get_prompt3(code, vultype)

    openai_api_key = "EMPTY"
    openai_api_base = f"http://{ip}:8000/v1"

    client = OpenAI(
        api_key=openai_api_key,
        base_url=openai_api_base,
    )

    # 发起流式请求
    chat_response = client.chat.completions.create(
        model="deepseek",  # 模型名称
        messages=[
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        top_p=0.7,
        max_tokens=8196,
        stream=True,  # 启用流式输出
    )
    # 逐步处理流式响应
    full_response = ""  # 用于收集完整响应
    for chunk in chat_response:
        if chunk.choices[0].delta.content:  # 检查是否有新内容
            response_chunk = chunk.choices[0].delta.content
            full_response += response_chunk  # 将每个 chunk 拼接到完整响应中
            yield response_chunk  # 流式输出当前 chunk

    vulfile_update(task_id, file_id, full_response, str(0))


# vllm + 流式输出
# @lru_cache(maxsize=1)
# def loadvLLM_deepseek(engine_args_tuple):
#     # 将元组转换回字典
#     engine_args = dict(engine_args_tuple)
#     # 加载模型，确保路径正确，并使用多张 GPU
#     llm = AsyncLLMEngine.from_engine_args(AsyncEngineArgs(**engine_args))
#     return llm

# engine_args = {
#     "model": "/home/public/model/deepseek-R1-qwen-14B",
#     "trust_remote_code": True,
#     "dtype": 'bfloat16',
#     "enforce_eager": True,
#     "max_model_len": 8192,
#     "tensor_parallel_size": 2,
#     "gpu_memory_utilization": 0.9
# }
#
# llm = AsyncLLMEngine.from_engine_args(AsyncEngineArgs(**engine_args))

# @lru_cache(maxsize=1)
# def get_VLLM():
#     engine_args = {
#         "model": "/home/public/model/deepseek-R1-qwen-14B",
#         "trust_remote_code": True,
#         "dtype": 'bfloat16',
#         "enforce_eager": True,
#         "max_model_len": 8192,
#         "tensor_parallel_size": 2,
#         "gpu_memory_utilization": 0.9
#     }
#     sampling_params = SamplingParams(
#         temperature=0.6,
#         top_p=0.7,
#         max_tokens=2048,
#         repetition_penalty=1.0,
#         stop_token_ids=None,  # 根据具体需求设置
#         skip_special_tokens=True
#     )
#     llm = AsyncLLMEngine.from_engine_args(AsyncEngineArgs(**engine_args))
#     tokenizer = AutoTokenizer.from_pretrained(engine_args["model"])
#
#     return llm, tokenizer, sampling_params
#
#
# def build_prompt(code: str, vultype: str):
#     """构造输入内容。"""
#     prompt = f"""请你分析下面代码，并判断其是否存在{vultype}这种类型的漏洞，思考过程要尽可能的简洁，并且限制在100字以内，要更注重结论，代码：\n{code}"""
#
#     # prompt = f"""请你分析下面代码，并判断其是否存在{vultype}漏洞 ，注意思考过程尽量简洁，请仔细检查，有些情况可能不执行，注重结论/ **""" + \
#     #          f"""代码：""" + \
#     #          f"""{code}"""
#
#     return prompt
#
#
# async def generate_stream_response(llm, messages, sampling_params):
#     """流式生成响应内容。"""
#     request_id = f"chatcmpl-{uuid.uuid4().hex}"
#     result_generator = llm.generate(
#         messages,
#         sampling_params=sampling_params,
#         request_id=request_id,
#         lora_request=None,
#     )
#
#     async for result in result_generator:
#         generated_text = result.outputs[0].text
#         yield json.dumps({'success': True, 'content': generated_text}) + '\n'
#
# async def deepseek_chat6(code: str, vultype: str):
#     """使用 vLLM 调用模型，并流式输出生成的文本。"""
#     llm, tokenizer, sampling_params = get_VLLM()
#
#     # 构造输入内容
#     prompts = build_prompt(code, vultype)
#     messages = tokenizer.apply_chat_template(
#         [{"role": "user", "content": prompts}],
#         tokenize=False,
#         add_generation_prompt=True
#     )
#
#     # 返回流式响应
#     return generate_stream_response(llm, messages, sampling_params)
#
#     # # 返回流式响应
#     # return StreamingResponse(
#     #     generate_stream_response(llm, messages, sampling_params),
#     #     media_type="text/event-stream")

# async def getLLM_deepseek3(code, vultype, model_name, detection_type):  # 调用大模型进行修复/降误报
#     """使用 vLLM 调用模型，并流式输出生成的文本。"""
#     # 初始化引擎和采样参数
#     llm, tokenizer, sampling_params = get_VLLM()
#
#     if detection_type == 'repair':
#         prompt = get_prompt2(code, vultype)
#     elif detection_type == 'mix':
#         prompt = get_prompt3(code, vultype)
#
#     messages = tokenizer.apply_chat_template(
#         [{"role": "user", "content": prompt}],
#         tokenize=False,
#         add_generation_prompt=True
#     )
#
#     # 返回流式响应
#     return generate_stream_response(llm, messages, sampling_params)

# 获取最相似的行
def find_most_similar_string(string, text):
    lines = text.splitlines()
    similarity_scores = []

    for i, line in enumerate(lines, start=1):
        line = line.strip()
        similarity_score = difflib.SequenceMatcher(None, string, line).ratio()
        similarity_scores.append((similarity_score, line, i))

    max_similarity_score = max(similarity_scores, key=lambda x: x[0])[0]
    most_similar_lines = [(line, score, index) for score, line, index in similarity_scores if
                          score == max_similarity_score]

    return most_similar_lines


# 获取中位数
def find_median(nums):
    sorted_nums = sorted(nums)
    n = len(sorted_nums)

    if n % 2 == 1:
        median = sorted_nums[n // 2]
    else:
        mid_right = n // 2
        mid_left = mid_right - 1
        if mid_left < 0:
            mid_left = 0
        median = (sorted_nums[mid_left] + sorted_nums[mid_right]) / 2

    return median


# deepseek获取定位
def get_location(source_code, repair_code):
    #    time1 = datetime.now().time()
    lines = repair_code.splitlines()
    repair_code_len = len(lines)
    location = []
    # print(source_code)
    # print(repair_code)
    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        line = line.strip()
        most_similar_lines = find_most_similar_string(line, source_code)
        for line, score, index in most_similar_lines:  # 字符串，分数， 行号
            # print(f"Line: {index}, Score: {score}, Content: {line}")
            if score > 0.5 and line.strip() != '{' and line.strip() != '}':
                location.append(index)

    location = list(set(location))
    location = sorted(location)
    print(location)
    loc_temp = location
    if len(location) != 0:
        median = find_median(location)

        location = [l for l in location if median - repair_code_len <= l <= median + repair_code_len]
    if len(location) == 0:
        location = loc_temp
    return location


# 正则匹配提取修复后结果中的代码部分
def extract_java_code(text):
    pattern = r'\s*```java(.*)```'
    matches = re.findall(pattern, text, re.DOTALL)
    if not matches:
        pattern = r'\s*```java(.*)'
        matches = re.findall(pattern, text, re.DOTALL)
    java_code = '\n'.join(matches)
    return java_code


# 正则匹配，获取是否存在安全漏洞
def get_label(text):
    # 定义正则表达式模式
    pattern = r"是否存在安全漏洞: (\是|否)"

    # 使用正则表达式进行匹配
    match = re.search(pattern, text)

    if match:
        result = match.group(1)
        return result
    else:
        return '未找到匹配项'