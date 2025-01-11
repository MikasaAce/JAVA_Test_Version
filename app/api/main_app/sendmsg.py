# -*- coding: utf-8 -*-

import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pymysql

class NotificationSystem:
    def __init__(self, email_config=None, webhook_url=None, db_config=None):
        """
        初始化通知系统
        :param email_config: 邮件配置
        :param webhook_url: 企业微信 Webhook URL
        :param db_config: 数据库配置
        """
        self.email_config = email_config
        self.webhook_url = webhook_url
        self.db_config = db_config

    def get_vulnerability_details(self):
        """
        从数据库中获取漏洞详情
        :return: 漏洞主题和消息内容
        """
        if not self.db_config:
            raise ValueError("数据库配置未提供。")

        try:
            # 连接数据库
            connection = pymysql.connect(
                host=self.db_config['host'],
                port=self.db_config['port'],
                user=self.db_config['user'],
                password=self.db_config['passwd'],
                database=self.db_config['database'],
                charset=self.db_config['charset']
            )

            with connection.cursor() as cursor:
                # 查询 itemdetail 表中的数据
                sql = "SELECT vul_id, severity, description FROM itemdetail LIMIT 1"  # 假设我们只取第一条记录
                cursor.execute(sql)
                result = cursor.fetchone()

                if result:
                    vul_id, severity, description = result
                    subject = f"漏洞告警：{vul_id}"
                    message = f"""
漏洞详情：
- 漏洞编号：{vul_id}
- 严重程度：{severity}
- 描述：{description}
"""
                    return subject, message
                else:
                    raise ValueError("数据库中未找到漏洞详情。")

        except Exception as e:
            print(f"数据库查询失败：{e}")
            raise
        finally:
            if connection:
                connection.close()

    def send_email(self, subject, message):
        """
        发送邮件
        :param subject: 邮件主题
        :param message: 邮件正文
        """
        if not self.email_config:
            raise ValueError("邮件配置未提供。")

        sender_email = self.email_config['sender_email']
        receiver_email = self.email_config['receiver_email']
        smtp_server = self.email_config['smtp_server']
        smtp_port = self.email_config['smtp_port']
        smtp_username = self.email_config['smtp_username']
        smtp_password = self.email_config['smtp_password']

        # 创建邮件对象
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        # 添加邮件正文
        msg.attach(MIMEText(message, 'plain'))

        try:
            # 连接 SMTP 服务器（使用 SSL）
            with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                server.login(smtp_username, smtp_password)  # 登录邮箱
                server.sendmail(sender_email, receiver_email, msg.as_string())  # 发送邮件
            print("邮件发送成功！")
        except Exception as e:
            print(f"邮件发送失败：{e}")

    def send_wechat_work_message(self, message, message_type="text"):
        """
        发送企业微信消息
        :param message: 消息内容
        :param message_type: 消息类型，支持 "text" 或 "markdown"
        """
        if not self.webhook_url:
            raise ValueError("企业微信 Webhook URL 未提供。")

        headers = {'Content-Type': 'application/json'}
        if message_type == "text":
            payload = {
                "msgtype": "text",
                "text": {
                    "content": message
                }
            }
        elif message_type == "markdown":
            payload = {
                "msgtype": "markdown",
                "markdown": {
                    "content": message
                }
            }
        else:
            raise ValueError("不支持的 message_type，请使用 'text' 或 'markdown'。")

        try:
            response = requests.post(self.webhook_url, json=payload, headers=headers)
            if response.status_code == 200:
                print("企业微信消息发送成功！")
            else:
                print(f"发送失败，状态码：{response.status_code}, 响应内容：{response.text}")
        except Exception as e:
            print(f"发送企业微信消息时发生错误：{e}")

    def notify(self, notify_type="all"):
        """
        发送通知
        :param notify_type: 通知类型，支持 "email"、"wechat" 或 "all"
        """
        subject, message = self.get_vulnerability_details()

        if notify_type == "email" or notify_type == "all":
            self.send_email(subject, message)
        if notify_type == "wechat" or notify_type == "all":
            self.send_wechat_work_message(message)

# 示例：配置邮件、企业微信和数据库
email_config = {
    'sender_email': '253480155@qq.com',  # 发件人邮箱
    'receiver_email': '1500861482@qq.com',  # 收件人邮箱
    'smtp_server': 'smtp.qq.com',  # QQ 邮箱 SMTP 服务器地址
    'smtp_port': 465,  # QQ 邮箱 SMTP 端口（SSL）
    'smtp_username': '253480155@qq.com',  # 发件人邮箱地址
    'smtp_password': 'pghjrkkphulmcaca'  # 授权码（非邮箱密码）
}

webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=490cb663-a167-40ee-b201-55aff6216dc9"

db_config = {
    "host": "0.0.0.0",
    "port": 3307,
    "database": "new_vul",
    "charset": "utf8",
    "user": "root",
    "passwd": "Li@123456"
}

# 初始化通知系统
notification_system = NotificationSystem(email_config=email_config, webhook_url=webhook_url, db_config=db_config)

# 发送通知
notification_system.notify(notify_type="all")