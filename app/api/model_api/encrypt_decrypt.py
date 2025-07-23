import base64
import hashlib
import os
import pickle
import subprocess

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)


# 获取mac地址
def get_mac_address():
    command = "ifconfig | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    output, _ = process.communicate()
    mac_address = output.decode().strip()
    return mac_address


# 生成密钥
def generate_key(mac_address):
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=mac_address.encode(),
        backend=default_backend()
    )
    key = kdf.derive(mac_address.encode())

    # 将密钥进行 URL 安全的 Base64 编码
    key = base64.urlsafe_b64encode(key)
    return key


def encrypt_model(model, key, model_name):
    serialized_model = pickle.dumps(model)
    # 使用 SHA-256 哈希函数调整密钥长度为 32 字节
    hashed_key = hashlib.sha256(key).digest()
    # 创建AES加密器
    cipher = AES.new(hashed_key, AES.MODE_ECB)

    # 加密模型
    encrypted_model = cipher.encrypt(pad(serialized_model, AES.block_size))
    # 存储加密后的模型到文件
    with open('/datadir/' + model_name + '/encrypted_model.bin', 'wb') as file:
        file.write(encrypted_model)

    return encrypted_model


# 解密模型
def decrypt_model(key, model_name):
    # 从文件加载加密模型
    with open('/datadir/' + model_name + '/encrypted_model.bin', 'rb') as file:
        encrypted_data = file.read()
    # 解密模型
    # 使用 SHA-256 哈希函数调整密钥长度为 32 字节
    hashed_key = hashlib.sha256(key).digest()
    # 创建AES加密器
    cipher = AES.new(hashed_key, AES.MODE_ECB)
    decrypted_model = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    # 反序列化模型
    decrypted_model = pickle.loads(decrypted_model)
    return decrypted_model
