from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from datetime import datetime

# 密钥必须是16字节（128位）、24字节（192位）或32字节（256位）
KEY = b'thisisasecretkey'  # 16字节密钥


def encrypt(plaintext):
    # 创建AES加密器
    cipher = AES.new(KEY, AES.MODE_CBC)

    # 填充明文，使其长度为16字节的倍数
    padded_plaintext = pad(plaintext.encode(), AES.block_size)

    # 加密
    ciphertext = cipher.encrypt(padded_plaintext)

    # 将初始化向量（IV）和密文编码为Base64字符串
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    encrypted = base64.b64encode(ciphertext).decode('utf-8')

    return iv + ':' + encrypted


def decrypt(encrypted_text):
    # 解码Base64字符串
    iv, encrypted = encrypted_text.split(':')
    iv = base64.b64decode(iv)
    encrypted = base64.b64decode(encrypted)

    # 创建AES解密器
    cipher = AES.new(KEY, AES.MODE_CBC, iv)

    # 解密
    decrypted = cipher.decrypt(encrypted)

    # 去除填充
    plaintext = unpad(decrypted, AES.block_size).decode('utf-8')

    return plaintext


## 示例使用
## 获取当前时间
#now = datetime.now()
## 激活码到期时间
#auto_time = "2024-09-30"
## 格式化输出
#formatted_time = str(now.strftime("%Y-%m-%d"))
#text = f'当前日期：{formatted_time} 激活码到期：{auto_time}'
#encrypted_text = encrypt(text)
#print("Encrypted:", encrypted_text)
#
#decrypted_text = decrypt(encrypted_text)
#print("Decrypted:", decrypted_text)
