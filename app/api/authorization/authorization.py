import os
import shutil

import psutil
import platform
from Crypto.Cipher import AES

import subprocess
from Crypto.Util.Padding import pad, unpad
import base64
import datetime

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


def get_disk_serial_numbers_linux():
    # 存储硬盘序列号的列表
    serial_numbers = []

    # 使用 lsblk 命令获取硬盘序列号
    try:
        result = subprocess.run(['lsblk', '-o', 'SERIAL', '-n'], capture_output=True, text=True)
        if result.returncode == 0:
            result = [item for item in result.stdout.strip().split('\n') if item]
            serial_numbers.extend(result)
    except FileNotFoundError:
        pass

    return serial_numbers


def get_disk_serial_numbers_macos():
    # 存储硬盘序列号的列表
    serial_numbers = []

    # 使用 diskutil 命令获取硬盘序列号
    try:
        result = subprocess.run(['diskutil', 'list', '-plist'], capture_output=True, text=True)
        if result.returncode == 0:
            import plistlib
            plist = plistlib.loads(result.stdout.encode())
            for disk in plist['AllDisksAndPartitions']:
                if 'VolumeName' in disk:
                    serial_numbers.append(disk['VolumeName'])
    except FileNotFoundError:
        pass

    return serial_numbers


def get_disk_serial_numbers():
    system = platform.system()
    #print(system)
    if system == 'Linux':
        return get_disk_serial_numbers_linux()
    elif system == 'Darwin':  # macOS
        return get_disk_serial_numbers_macos()
    else:
        raise NotImplementedError(f"Unsupported operating system: {system}")


def get_mac_addresses():
    # 获取所有网络接口信息
    interfaces = psutil.net_if_addrs()

    # 存储 MAC 地址的字典
    mac_addresses = {}

    # 遍历每个网络接口
    for interface_name, addresses in interfaces.items():
        for address in addresses:
            # 检查地址类型是否为 MAC 地址
            if address.family == psutil.AF_LINK and address.address != '00:00:00:00:00:00':
                mac_addresses[interface_name] = address.address

    return mac_addresses


def authorization_request():
    authorization_request = ''
    # 获取并打印所有网卡的 MAC 地址
    mac_addresses = get_mac_addresses()
    for interface, mac in mac_addresses.items():
        authorization_request += '<mac_split>' + mac + '</mac_split>'
        #print(f"Interface: {interface}, MAC Address: {mac}")

    # 获取并打印硬盘序列号
    serial_numbers = get_disk_serial_numbers()
    for serial in serial_numbers:
        authorization_request += '<serial_split>' + serial + '</serial_split>'
        #print(f"Disk Serial Number: {serial}")

    #print(authorization_request)
    #print(encrypt(authorization_request))
    return encrypt(authorization_request)


def authorization_response(time, en_authorization_request):
    authorization_request = decrypt(en_authorization_request)
    authorization_response = authorization_request + '<time_split>' + time + '</time_split>'
    en_authorization_response = encrypt(authorization_response)


def check():
    while True:
        if not os.path.exists('License'):
            request = authorization_request()
            print(f"""
该系统尚未授权，请按照以下步骤操作：
1. 联系管理员。
2. 发送请求码。
3. 获取激活码。
请求码：{request}""")
            while True:
                response = input('请输入激活码：')
                try:
                    de_response = decrypt(response)
                except:
                    print('授权码无效或已过期！请重新获取授权码！')
                    break
                de_request = decrypt(request)
                now = datetime.datetime.now().strftime("%Y-%m-%d")
                if de_response.split('<time_split>')[0] == de_request and de_response.split('<time_split>')[-1].split('/<time_split>')[0] >= now:
                    with open('License', 'w', encoding='utf-8') as f:
                        f.write(response)
                    return
                else:
                    print('授权码无效或已过期！请重新获取授权码！')
        else:
            with open('License', 'r', encoding='utf-8') as f:
                response = f.read()
            request = authorization_request()
            try:
                de_response = decrypt(response)
            except:
                print('授权码无效或已过期！请重新获取授权码！')
                return
            de_request = decrypt(request)
            now = datetime.datetime.now().strftime("%Y-%m-%d")
            if de_response.split('<time_split>')[0] == de_request and de_response.split('<time_split>')[-1].split('/<time_split>')[0] >= now:
                return
            else:
                print('授权码无效或已过期！请重新获取授权码！')
                os.remove('License')


