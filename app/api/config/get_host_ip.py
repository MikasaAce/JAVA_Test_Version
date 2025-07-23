import socket


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
