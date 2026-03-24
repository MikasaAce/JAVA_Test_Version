import os

import json
import os

import chardet
import tree_sitter
from tqdm import tqdm
import sys

sys.setrecursionlimit(100000)  # 增加递归深度限制
import warnings

# 忽略所有警告
warnings.filterwarnings("ignore")


# 全局初始化 tree-sitter 解析器
JAVA_LANGUAGE = None
PARSER = None

def initialize_parser():
    """
    初始化 tree-sitter 解析器。

    返回:
    parser (tree_sitter.Parser): 初始化后的解析器。
    """
    global JAVA_LANGUAGE, PARSER
    # 获取py 文件所在目录
    current_path = os.path.dirname(__file__)

    # 把这个目录设置成工作目录
    os.chdir(current_path)

    if PARSER is None:
        # 构建语言库
        tree_sitter.Language.build_library(
            'build/my-languages.so',
            ["vendor/tree-sitter-java-master"]
        )

        # 加载所需的语言库
        JAVA_LANGUAGE = tree_sitter.Language('build/my-languages.so', 'java')

        # 使用语言库解析 Java 代码
        PARSER = tree_sitter.Parser()
        PARSER.set_language(JAVA_LANGUAGE)

    return PARSER


def extract_functions(src_bytes, cursor):
    """
    递归提取所有函数片段及其起始和结束行号。

    参数:
    src_bytes (bytes): 代码字节流。
    cursor (tree_sitter.TreeCursor): 树游标。

    返回:
    result (list): 包含函数代码和行号范围的字典列表。
    """
    result = []
    if cursor.node.type == 'method_declaration':
        # 计算函数的起始行号和结束行号
        start_line_num = src_bytes[:cursor.node.start_byte].count(b'\n') + 1
        end_line_num = src_bytes[:cursor.node.end_byte].count(b'\n') + 1
        # 提取函数代码
        code = src_bytes[cursor.node.start_byte: cursor.node.end_byte].decode('utf-8')
        # 添加到结果列表
        result.append({
            'code': code,
            'line_start_to_end': [start_line_num, end_line_num]
        })

    # 递归遍历子节点
    if cursor.goto_first_child():
        result.extend(extract_functions(src_bytes, cursor))
        cursor.goto_parent()

    # 递归遍历兄弟节点
    while cursor.goto_next_sibling():
        result.extend(extract_functions(src_bytes, cursor))

    return result


def split_code_into_functions(file_path):
    """
    将代码切分成函数片段。

    参数:
    file_path (str): Java 文件路径。

    返回:
    result (list): 包含函数代码和行号范围的字典列表。
    """
    # 检测文件编码
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        encoding = result['encoding']

    # 尝试解码文件内容
    try:
        code = raw_data.decode(encoding)
    except UnicodeDecodeError:
        #print(f"无法解码文件 {file_path}，尝试使用 UTF-8 编码")
        code = raw_data.decode('utf-8', errors='replace')

    # 初始化解析器
    parser = initialize_parser()
    # 解析代码
    tree = parser.parse(bytes(code, 'utf8'))
    cursor = tree.walk()
    # 提取所有函数片段
    result = extract_functions(bytes(code, 'utf8'), cursor)
    return result



def split_code(file_path):
    """
    遍历文件夹中的所有 Java 文件，提取函数片段并保存到字典中。

    参数:
    folder_path (str): 文件夹路径。

    返回:
    data (dict): 包含文件路径和函数片段的字典。
    """
    data = {}
    num = 0
    # 遍历文件夹中的所有文件
    for file in file_path:
        if file.endswith('.java'):
            result = split_code_into_functions(file)

            if result:
                # 将函数片段存储到字典中
                data[file] = []
                for item in result:
                    data[file].append({
                        'file_path': file,
                        'code': item['code'],
                        'line_start_to_end': item['line_start_to_end']
                    })
                    num += 1
    #print(f'对{len(data)}个文件进行切片，共得到{num}片')
    return data


