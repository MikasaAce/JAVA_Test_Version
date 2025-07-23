# config.py
import os
import socket

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)


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


# base_path = r'/home2/JAVA_Test_Version/app/static/DATA_new_M'
base_path = r'/home2/Vul_Data'
lizard_path = r'/home2/Vul_Data/DATA_lizard' 

# 过滤后文件保存路径
file_save_path = os.path.join(base_path, 'item')
# 解压后文件保存路径
processed_file_save_path = os.path.join(base_path, 'processed')
# 生成的pdf的保存路径
pdf_save_path = r'/home2/JAVA_Test_Version/static/Export_PDF'
# 日志文件保存路径
LOG_DIR = '/home2/JAVA_Test_Version/app/static/DATA_new_M/log'
# 获取当前主机ip
HOST_IP = get_host_ip()
# 小模型调用路径
Codegen_path = '/home/public/project_XSY/project/codegen-350M-mono'
#transformer_path = '/home/gjx/model1113/CodeGen_0.9997.model'
#transformer_path = '/home/gjx/model1112/CodeGen_0.9961.model'
#transformer_path = '/home/public/project_XSY/project/project_xsy/model/real/codegen0.8527.model'
#transformer_path = '/home/muti_train/ALL/model/unixcoder_0.9925.model'
transformer_path = '/home/muti_train/ALL/model/Unixcoder_0.9921.model'
#transformer_path = '/home/muti_train/ALL/model/Unixcoder_0.9923.model'
#transformer_path = '/home/gjx/unixcoder/model1114/UnixCoder_0.9974.model'
#transformer_path = '/home/gjx/CodeGen_0.9448.model'

unixcoder_path = '/home/public/project_XSY/project/unixcoder-base'
muti_transformer_path = 'model/unixcoder_0.7899.model'
small_model_device = 'cuda:0'
# 大模型调用路径

# 数据库连接配置
config = {
    "host": "0.0.0.0",
    "port": 3307,
    "database": "vul_test",
    "charset": "utf8",
    "user": "root",
    "passwd": "Li@123456"
}