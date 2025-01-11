import pymysql
from app.api.config.config import *


# 把连接参数定义成字典
class Mysqldb():
    # 初始化方法
    def __init__(self):
        # 初始化方法中调用连接数据库的方法
        self.conn = self.get_conn()
        # 调用获取游标的方法
        self.cursor = self.get_cursor()

    # 连接数据库的方法
    def get_conn(self):
        # **config代表不定长参数
        conn = pymysql.connect(**config)
        return conn

    # 获取游标
    def get_cursor(self):
        cursor = self.conn.cursor()
        return cursor

    # 查询sql语句返回的所有数据，有参数
    def select_all(self, sql, parameters):
        self.conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
        self.cursor.execute(sql, parameters)
        return self.cursor.fetchall()

    # 查询sql语句返回的所有数据，没有参数
    def select_all_n(self, sql):
        self.conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
        self.cursor.execute(sql)
        return self.cursor.fetchall()

    # 查询sql语句返回的一条数据，有参数
    def select_one(self, sql, parameters):
        self.conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
        self.cursor.execute(sql, parameters)
        return self.cursor.fetchone()

    # 查询sql语句返回的几条数据，有参数
    def select_many(self, sql, parameters, num):
        self.conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
        self.cursor.execute(sql, parameters)
        return self.cursor.fetchmany(num)

    # 增删改除了SQL语句不一样其他都是一样的，都需要提交
    def commit_data(self, sql, parameters):
        try:
            self.conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
            # 执行语句
            flag = self.cursor.execute(sql, parameters)
            # 提交
            self.conn.commit()
            # print("提交成功")
            return flag
        except Exception as e:
            print("提交出错\n:", e)
            flag = False
            # 如果出错要回滚
            self.conn.rollback()
            return flag

    # 当对象被销毁时，游标要关闭,连接也要关闭
    # 创建时是先创建连接后创建游标，关闭时是先关闭游标后关闭连接
    def __del__(self):
        self.cursor.close()
        self.conn.close()
