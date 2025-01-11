import chardet
import numpy as np
import pandas as pd
from torch.utils.data import TensorDataset, DataLoader
from sklearn.metrics import precision_recall_fscore_support
from transformers import AutoTokenizer, AutoModel
import subprocess
import re
import json
from tqdm import tqdm  # 导入 tqdm 库
from functools import lru_cache
from app.api.config.config import *
from app.api.model_api.transformer_model import *
from app.api.model_api.unixcoder import UniXcoder

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)



def cleanup():
    # 获取当前进程的 PID
    current_pid = os.getpid()

    # 使用 nvidia-smi 查找与当前进程相关的 CUDA 进程
    result = subprocess.run(['nvidia-smi', '--query-compute-apps=pid,memname --format=csv,noheader,nounits'],
                            capture_output=True, text=True)
    for line in result.stdout.strip().split('\n'):
        # 使用逗号作为分隔符，并检查拆分后的列表长度
        parts = line.split(',')
        if len(parts) == 2:
            pid, name = parts
            # 检查进程名是否包含当前脚本的名称，并杀死相关的 CUDA 进程
            if name.find(__file__) != -1:
                print(f"Killing CUDA process: {pid}")
                os.system(f'kill {pid}')


@lru_cache(maxsize=1)
def get_model(model_name, device):
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name).to(device)
    return tokenizer, model


def code_features_gen(code_text):
    tokenizer, model = get_model(Codegen_path, small_model_device)
    tokenizer.add_special_tokens({'pad_token': '[PAD]'})

    # 使用分词器对代码文本进行编码处理
    code_encodings = tokenizer(code_text, truncation=True, padding=True, return_tensors="pt").to(small_model_device)

    with torch.no_grad():
        outputs = model(**code_encodings)

    code_features = outputs.last_hidden_state

    # 最后一个隐藏状态的平均值
    code_vector = code_features.mean(dim=1)

    code_features = code_vector.detach().cpu().numpy()[0].tolist()

    return code_features


def code_features_unix(model, code_text):
    # 使用分词器对代码文本进行编码处理
    code_encodings = model.tokenize([code_text],max_length=1000,mode="<encoder-only>")
    code_encodings = torch.tensor(code_encodings).to(small_model_device)
    
    tokens_embeddings, code_vector = model(code_encodings)
    #print(outputs)
    #print(code_vector.shape)
    #code_features = outputs.last_hidden_state

    # print('codegen:', code_vector.shape)

    code_features = code_vector.detach().cpu().numpy()[0].tolist()

    return code_features

model = UniXcoder("/home/public/project_XSY/project/unixcoder-base")
model.to(small_model_device)
    
model.tokenizer.add_special_tokens({'pad_token': '[PAD]'})

def extract_features(programtext):
    #features = code_features_gen(programtext)  # 1024维
    features = code_features_unix(model, programtext)  # 768维
    
    return features


def clean_text(content):
    # 去除单行注释
    # 去除Java中的导包语句和package语句
    content = re.sub(r'import\s+.*?;', '', content)
    content = re.sub(r'package\s+.*?;', '', content)
    content = re.sub(r'@WebServlet.*', '', content)

    # 去除单行注释
    #content = re.sub(r'//.*', '', content)
    # 去除多行注释
    #content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)

    # # 去除多余的空格
    # content = re.sub(r'[ \t]+', ' ', content)
    # # 去除非ASCII字符
    # content = re.sub(r'[^\x00-\x7F]+', '', content)
    content = re.sub(r'\n\s*\n', '\n', content)
    # 去除前导和尾随空白字符
    content = content.strip()

    return content

def clean_text2(content):
    # 去除单行注释
    content = re.sub(r'//.*', '', content)
    # 去除多行注释
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    # 去除前导和尾随空白字符
    content = content.strip()
    # 去除多余的空格
    content = re.sub(r'[ \t]+', ' ', content)
    # 去除非ASCII字符
    content = re.sub(r'[^\x00-\x7F]+', '', content)

    return content

def getfeatures(json_file_path):
    with open(json_file_path, 'r', encoding='utf-8') as file:
        json_data = json.load(file)

    results = []
    failed_files = []  # 用于记录构造特征失败的文件名

    print(f'json长度: {len(json_data)}')
    for item in tqdm(json_data):
        file_path = item['file_path']
        programtext = item['code_extrac']

        try:
            feature = extract_features(programtext)
            if feature is not None:
                results.append({
                    'file_path': file_path,
                    'feature': feature
                })
            else:
                print('特征为空')
                failed_files.append(file_path)  # 记录构造特征失败的文件名
        except Exception as e:
            print(f"Error occurred while processing item: {e}")
            failed_files.append(file_path)  # 记录构造特征失败的文件名
    with open(json_file_path, 'w', encoding='utf-8') as file:
        json.dump(results, file, ensure_ascii=False, indent=4)

    # 注册清理函数，确保在脚本结束时执行
    import atexit
    atexit.register(cleanup)


# 构造数据
class getDataset(torch.utils.data.Dataset):
    def __init__(self, data, file_path):
        self.data = data
        self.file_path = file_path

    def __len__(self):
        return len(self.data)

    def __getitem__(self, index):
        x = self.data[index]
        file_path = self.file_path[index]
        return x, file_path


def model_test(model, loader, json_path):
    """0-1模型扫描"""
    num = 0
    n = 0
    y_pred = []
    y_prob = []
    file_path_list = []
    model.eval()
    with torch.no_grad():
        for data in tqdm(loader):
            x, file_path = data

            x = x.to(small_model_device)
            #print(x)
            
            out = model(x)

            prob = torch.softmax(out, dim=1)  # 应用 softmax 函数
            _, predicted = torch.max(out, 1)
            print(predicted)
            y_pred.extend(predicted.cpu().numpy())
            y_prob.extend(prob.cpu().numpy())  # 保存softmax概率

            file_path_list.extend(file_path)

    with open(json_path, 'r', encoding='utf-8') as file:
        data = json.load(file)

    file_name_to_index = {item['file_path']: i for i, item in enumerate(data)}

    for i, file in enumerate(file_path_list):
        index = file_name_to_index.get(file)
        data[index]['label'] = int(y_pred[i])
        data[index]['probability'] = y_prob[i].tolist()

    with open(json_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=4)


def data_to_json(input_directory, output_json_file):
    """将待检测代码处理为json格式"""
    java_files_content = []
    for root, dirs, files in os.walk(input_directory):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as programfile:
                        program = programfile.read()
                        encode_type = chardet.detect(program)  # 得到文件的编码格式

                    with open(file_path, 'r', encoding=encode_type["encoding"]) as f:
                        content = f.read()
                        content = clean_text(content)
                        #content = clean_text2(content)
                    if content == '' or content == '\n':
                        continue
                    java_files_content.append({
                        'file_path': file_path,
                        'code_extrac': content
                    })
                except Exception as e:
                    print(f'Failed to convert data to json: {str(e)}')
                    continue

    with open(output_json_file, 'w', encoding='utf-8') as json_file:
        json.dump(java_files_content, json_file, ensure_ascii=False, indent=4)


def model_detection(test_folder_path, task_name):
    """利用0-1模型进行扫描，并将结果存在json文件中，1为有漏洞，0为无漏洞"""
    print('正在加载模型')
    # 加载模型
    try:
        model_state_dict = torch.load(transformer_path, map_location=lambda storage, loc: storage.cuda(0))
        #model = Transformer(d_model=1024, num_heads=8, d_ff=2048, num_layers=6, num_classes=2).to(small_model_device)
        model = Transformer(d_model=768, num_heads=8, d_ff=2048, num_layers=6, num_classes=2).to(small_model_device)
        model.load_state_dict(model_state_dict)  # 将状态字典加载到模型中
    except Exception as e:
        print(f'Failed to load model: {str(e)}')
        return {'code': 500, 'msg': f'Failed to load model: {str(e)}'}

    print('正在处理数据')
    # 将待检测代码转换为json文件
    json_path = os.path.join(test_folder_path, f'{task_name}.json')  # 生成json文件的输出路径
    try:
        data_to_json(test_folder_path, json_path)
    except Exception as e:
        print(f'Failed to convert data to JSON: {str(e)}')
        return {'code': 500, 'msg': f'Failed to convert data to JSON: {str(e)}'}

    print('正在构建特征')
    # 构造特征
    try:
        getfeatures(json_path)
    except Exception as e:
        print(f'Failed to generate features: {str(e)}')
        return {'code': 500, 'msg': f'Failed to generate features: {str(e)}'}

    # 数据类型转换
    print('正在转换数据格式')
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # 提取第一列
        features = [item['feature'] for item in data]
        # print(features)
        X = np.array(features, dtype=np.float32)  # 确保特征矩阵是数值类型
        file_path = [item['file_path'] for item in data]  # 文件路径

        X_tensor = torch.as_tensor(X, dtype=torch.float32).to(small_model_device)
    except Exception as e:
        print(f'Failed to convert format: {str(e)}')
        return {'code': 500, 'msg': f'Failed to convert format: {str(e)}'}

    print('正在创建数据迭代器')
    try:
        # 使用TensorDataset将特征和标签组合为PyTorch数据集对象
        test_dataset = getDataset(X_tensor, file_path)
        # 使用DataLoader创建数据加载器
        test_loader = DataLoader(test_dataset, batch_size=128, shuffle=False, drop_last=False)
    except Exception as e:
        print(f'Failed to create data iterator: {str(e)}')
        return {'code': 500, 'msg': f'Failed to create data iterator: {str(e)}'}

    # 使用模型进行检测，并将标签和概率分布存放在原json文件中
    print('正在进行扫描')
    try:
        model_test(model, test_loader, json_path)
        print('0-1模型扫描成功！')
    except Exception as e:
        print(f'Model test failed:  {str(e)}')
        return {'code': 500, 'msg': f'Model test failed: {str(e)}'}

    # 清理模型占用的显存
    del model  # 删除对模型的引用
    torch.cuda.empty_cache()  # 清空缓存

    # 注册清理函数，确保在脚本结束时执行
    import atexit
    atexit.register(cleanup)

    return {'code': 200, 'json_path': json_path}
