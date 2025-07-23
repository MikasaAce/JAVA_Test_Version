from tqdm import tqdm
from functools import lru_cache
from app.api.config.config import *
from app.api.muti_model_api.model import *
from app.api.muti_model_api.unixcoder import UniXcoder

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)


@lru_cache(maxsize=1)
def get_model():
    model = UniXcoder(unixcoder_path)
    model.to(small_model_device)

    model.tokenizer.add_special_tokens({'pad_token': '[PAD]'})

    return model


def code_features_unix(code_text):
    # 加载预训练的 unixcoder 模型和分词器
    model = get_model()
    # 使用分词器对代码文本进行编码处理
    code_encodings = model.tokenize([code_text], max_length=1000, mode="<encoder-only>")
    code_encodings = torch.tensor(code_encodings).to(small_model_device)

    tokens_embeddings, code_vector = model(code_encodings)

    code_features = code_vector.detach().cpu().numpy()[0].tolist()

    return code_features


def extract_features(data):
    num = 0
    for file_path, values in tqdm(data.items()):
        for i, value in enumerate(values):
            feature = code_features_unix(value['code'])
            data[file_path][i]['feature'] = feature
            num += 1

    print(f'对{len(data)}个文件进行特征提取，共得到{num}个特征向量')
    return data




