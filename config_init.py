import socket
import python.api.data_utils.data_util as data_class


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
    finally:
        s.close()

    return ip

print(data_class.HOST_IP)
host_ip = get_host_ip()
data_class.host_ip = host_ip
print(data_class.HOST_IP)
