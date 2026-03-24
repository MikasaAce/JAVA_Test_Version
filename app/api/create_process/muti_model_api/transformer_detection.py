import json
from collections import Counter

import torch.optim as optim

from sklearn.metrics import precision_recall_fscore_support

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
import logging
import datetime
from tqdm import tqdm

import pandas as pd
from sklearn.model_selection import train_test_split
import numpy as np
from sklearn.metrics import confusion_matrix
from collections import defaultdict
from app.api.config.config import *
from app.api.create_process.muti_model_api.get_feature import *
from app.api.create_process.muti_model_api.split_code import *
from app.api.create_process.muti_model_api.model import *

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)

# 构造数据集
class getDataset(Dataset):
    def __init__(self, file_path, code, feature, line_start_to_end):
        self.file_path = file_path
        self.code = code
        self.feature = feature
        self.line_start_to_end = line_start_to_end

        # 初始化时检查长度是否一致
        if len(self.file_path) != len(self.code) or len(self.file_path) != len(self.feature) or len(self.file_path) != len(self.line_start_to_end):
            raise ValueError("file_path, code, line_start_to_end and feature must have the same length")

    def __len__(self):
        return len(self.file_path)

    def __getitem__(self, index):
        file_path = self.file_path[index]
        code = self.code[index]
        feature = self.feature[index]
        line_start_to_end = self.line_start_to_end[index]

        return file_path, code, feature, line_start_to_end


def custom_collate_fn(batch):
    """
    自定义 collate_fn，确保 line_start_to_end 保持为列表。
    """
    file_path = [item[0] for item in batch]
    code = [item[1] for item in batch]
    feature = torch.stack([item[2] for item in batch])
    line_start_to_end = [item[3] for item in batch]

    return file_path, code, feature, line_start_to_end


# 模型准确率计算
def model_test(model, test_loader, index_to_dict):
    file_path_list = []
    code_list = []
    pred_label = []
    line_start_to_end_list = []

    model.eval()
    with torch.no_grad():
        for file_path, code, feature_tensor, line_start_to_end in test_loader:
            # 将数据移动到指定设备
            feature_tensor = feature_tensor.to(small_model_device)

            # 模型推理
            outputs = model(feature_tensor)
            predicted = (outputs > 0.5).int()  # 二值化预测结果

            # 将结果存储到列表
            file_path_list.extend(file_path)
            code_list.extend(code)
            pred_label.extend(predicted.cpu().numpy().tolist())  # 转换为列表存储
            line_start_to_end_list.extend(line_start_to_end)

    result = {}
    for file_path, code, pre_label, line_start_to_end in zip(file_path_list, code_list, pred_label, line_start_to_end_list):
        if file_path not in result:
            result[file_path] = []

        for i, item in enumerate(pre_label):
            if item == 1:
                label = index_to_dict[i]

                result[file_path].append({
                    "file_path": file_path,
                    "code": code,
                    "label": label,
                    "line_start_to_end": line_start_to_end
                })


    return result


def load_data(data, key):
    result = []
    for item in data:
        result.append(item[key])

    return result


def load_model(muti_transformer_path, num_classes):
    # 加载模型状态字典
    model_state_dict = torch.load(muti_transformer_path, map_location=lambda storage, loc: storage.cuda(0))

    model = Transformer(d_model=768, num_heads=8, d_ff=2048, num_layers=6, num_classes=num_classes, dropout=0.5).to(small_model_device)
    model.load_state_dict(model_state_dict)  # 将状态字典加载到模型中

    return model

def transformer_detection(file_path):
    #print(f'使用 {str(small_model_device)}')
    #print('正在进行数据切片')
    data_split = split_code(file_path)
    #print('正在进行特征提取')
    data_feature = extract_features(data_split)
    #print('正在获取类型字典映射关系')
    dict_to_index = {'无漏洞': 0, 'Cookies安全：不通过SSL发送cookie': 1, '日志伪造': 2, 'Open重定向': 3,
                     '日志伪造(调试)': 4,
                     'HTTP响应拆分': 5, '跨站脚本：反射型': 6, '服务器端请求伪造': 7,
                     '动态解析代码：不安全的JSON反序列化': 8,
                     '动态解析代码：不安全的反序列化': 9, '拒绝服务：格式字符串': 10, 'HTTP参数污染': 11, '资源注入': 12,
                     '路径操纵': 13, '拒绝服务': 14, '命令注入': 15, '拒绝服务：正则表达式': 16}

    index_to_dict = {value: key for key, value in dict_to_index.items()}

    # 加载模型
    #print('正在加载模型')
    model = load_model(muti_transformer_path, len(index_to_dict))

    #print('正在加载数据')

    test_data = []
    for file_path, values in data_feature.items():
        test_data.extend(values)

    file_path = load_data(test_data, 'file_path')
    code = load_data(test_data, 'code')
    feature = load_data(test_data, 'feature')
    line_start_to_end = load_data(test_data, 'line_start_to_end')

    # 转换测试集为Tensor
    feature_tensor = torch.as_tensor(feature, dtype=torch.float32).to(small_model_device)

    test_dataset = getDataset(file_path, code, feature_tensor, line_start_to_end)

    test_loader = DataLoader(test_dataset, batch_size=256, shuffle=False, drop_last=False, collate_fn=custom_collate_fn)

    #print('正在扫描')
    result = model_test(model, test_loader, index_to_dict)
    #print('扫描完成')

    return result



