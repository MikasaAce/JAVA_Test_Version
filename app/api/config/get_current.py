import os


def get_current_working_directory():
    """
    获取当前工作目录
    :return: 当前工作目录的路径
    """
    cwd = os.getcwd()
    return cwd

# # 示例调用
# current_directory = get_current_working_directory()
# print(f"当前工作目录: {current_directory}")

def get_current_file_directory():
    """
    获取当前文件所在目录
    :return: 当前文件所在目录的路径
    """
    current_file_directory = os.path.dirname(os.path.abspath(__file__))
    return current_file_directory

# # 示例调用
# current_directory = get_current_file_directory()
# print(f"当前文件所在目录: {current_directory}")

def set_cwd():
    """
    将当前文件所在目录设置为工作目录
    """
    # 获取当前文件所在目录
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # 将当前文件所在目录设置为工作目录
    os.chdir(script_dir)

    # 打印当前工作目录以确认
    print(f"当前工作目录已设置为: {os.getcwd()}")


# 示例调用
set_cwd()

def list_custom_modules():
    """
    列出当前工作目录及其子目录中的所有自定义模块
    """
    current_dir = os.getcwd()
    print(f"当前工作目录: {current_dir}")

    print("当前工作目录及其子目录中的所有自定义模块:")
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            if file.endswith('.py') and file != '__init__.py':
                module_name = os.path.splitext(file)[0]
                module_path = os.path.join(root, file)
                print(f"模块名: {module_name}, 路径: {module_path}")

# 示例调用
list_custom_modules()