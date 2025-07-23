import os

import chardet
import difflib
import json
import re
import torch

from functools import lru_cache
from peft import PeftModel
from transformers import AutoTokenizer, AutoModelForCausalLM
from app.api.model_api.encrypt_decrypt import *
from app.api.database_utils.web import *

import warnings
import tree_sitter

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)

warnings.filterwarnings("ignore", category=FutureWarning)

########################################################################################################################
#   基于大模型进行定位和修复
########################################################################################################################
global model, tokenizer


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
    with open(file_path, 'r', encoding=encoding) as f:
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

        elif model_name == 'qwen-7b':
            print('使用qwen7b模型')
            #model_path = "/home/public/qwen/qwen2-7b-instruct"
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
    java_code = re.sub(r'^\s*import\s+.*?;\s*', '', java_code, flags=re.MULTILINE)

    # 去除单行和多行注释
    java_code = re.sub(r'//.*?(\n|$)', '', java_code)  # 单行注释
    java_code = re.sub(r'/\*.*?\*/', '', java_code, flags=re.DOTALL)  # 多行注释

    # 去除多余的空行
    java_code = re.sub(r'\n\s*\n+', '\n', java_code)

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


def getLLM_deepseek2(code, vultype, model_name, detection_type):  # 调用大模型进行修复/降误报
    model, tokenizer = loadLLM_deepseek(model_name)

    if detection_type == 'repair':
        prompt = get_prompt2(code, vultype)
    elif detection_type == 'mix':
        prompt = get_prompt3(code, vultype)
    content = [
        {
            'role': 'user',
            'content': prompt,
        }
    ]

    inputs = tokenizer.apply_chat_template(content, add_generation_prompt=True, return_tensors="pt").to(
        model.device)

    max_new_tokens = 3200

    outputs = model.generate(inputs, max_new_tokens=max_new_tokens, do_sample=False, num_return_sequences=1,
                             eos_token_id=tokenizer.eos_token_id)

    decoded_output = tokenizer.decode(outputs[0][len(inputs[0]):], skip_special_tokens=True)
    result = {
        'data': code,
        'response': decoded_output,
    }

    # 清除显存占用
    del model
    del tokenizer
    torch.cuda.empty_cache()

    return result


def get_prompt2(code, vultype):  # 针对修复生成提示词
    vul_name = get_vulname(vultype)
    prompt = f"""
假设你是软件安全领域的专家。下面让我们严格地按照[要求]，针对[代码片段]和[漏洞类型]，生成相应的回复。

[漏洞类型]
{vul_name}

[代码]
{code}

[要求]
step1:根据以上[代码]和[漏洞类型]的内容，给出针对这个[漏洞类型]的解释，以"解释："开头。
step2:根据以上[代码]和[漏洞类型]的内容，给出针对这个[漏洞类型]修复后的正确代码，以"修复后代码： "开头。
step3:针对你给出的修复后的代码，给出详细的解释，以"如何修复："开头。
"""
    return prompt


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


def deepseek_chat3(prompt, model_name):
    """调用大模型进行对话/生成，并逐块返回生成的文本。"""
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
    max_length = inputs.shape[-1] + max_new_tokens

    # 逐块生成文本
    current_length = inputs.shape[-1]

    while current_length < max_length:
        outputs = model.generate(inputs, max_new_tokens=1, do_sample=False, num_return_sequences=1,
                                 eos_token_id=tokenizer.eos_token_id)
        new_token = outputs[0, -1].unsqueeze(0)
        decoded_output = tokenizer.decode(new_token, skip_special_tokens=True)
        # print(repr(decoded_output))
        if decoded_output == '':
            yield decoded_output
        yield decoded_output
        new_token = new_token.unsqueeze(0)
        inputs = torch.cat([inputs, new_token], dim=-1)
        current_length += 1


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