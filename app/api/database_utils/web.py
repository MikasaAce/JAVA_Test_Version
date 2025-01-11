import base64
import json
import os

import chardet
import pymysql
import shutil
from Crypto.Cipher import AES
from django.http import HttpResponse, JsonResponse
from app.api.database_utils.mysql_util import config
from app.api.database_utils.export_pdf import Graphs
from datetime import datetime
import requests
# 本设置作用是将默认相对路径设为本文件夹路径
# 在未指定这三个参数的情况下，会默认搜索 “ templates ” 文件夹下的页面模板
# 默认搜索 “ static ” 文件夹的CSS JS等静态配置
# 直接修改template_folder参数，免去了修改HTML文件中各个相关文件的路径
from app.api.config import config as data_class
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from pip._internal import req

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)
file_save_path = data_class.file_save_path

key = '2023072320051500'


def aes_ECB_encrypt(data, key):
    """
    ECB模式的加密函数
    :param data: 明文字符串
    :param key: 16字节密钥字符串
    :return: 加密后的密文字符串
    """
    key = key.encode('utf-8')
    data = data.encode('utf-8')

    # 明文补位
    data_length = len(data)
    padding_length = 16 - (data_length % 16)
    data += bytes([padding_length]) * padding_length

    # 创建AES加密对象并加密
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    encrypted_data = cipher.encrypt(data)

    # 将加密结果转换为字符串并返回
    return base64.b64encode(encrypted_data).decode('utf-8')


def aes_ECB_decrypt(data, key):
    """
    ECB模式的解密函数
    :param data: 密文字符串
    :param key: 16字节密钥字符串
    :return: 解密后的明文字符串
    """
    key = key.encode('utf-8')
    encrypted_data = base64.b64decode(data.encode('utf-8'))

    # 创建AES解密对象并解密
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)

    # 去除补位并将解密结果转换为字符串并返回
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]
    return decrypted_data.decode('utf-8')


def login(request):
    """
    用户登录视图函数
    :param request: Django HttpRequest对象
    :return: Django HttpResponse对象
    """
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # 获取数据库中所有用户的账号和密码
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT account, password FROM count_pswd")
                users = cursor.fetchall()

                # 验证用户登录信息
        for user in users:
            if user[0] == username and aes_ECB_decrypt(user[1], key) == password:
                # 设置登录成功的cookie并返回
                response = HttpResponse(
                    json.dumps({'code': '200', 'msg': '登录成功'}, ensure_ascii=False)
                )
                # 设置cookie时间限制为24小时
                response.set_cookie(
                    'username', username, max_age=86400, path='/static/'
                )
                response['Access-Control-Allow-Origin'] = '*'
                return response

        # 登录失败时返回错误信息
        return HttpResponse(
            json.dumps({'code': '500', 'msg': '账号密码输入错误，请重新输入'}, ensure_ascii=False)
        )


def check(request):
    username = None
    #    password = None
    #    username = request.COOKIES.get('username')  # 获取名为'username'的Cookie的值
    #    print(username)
    if len(str(request.POST['username'])) != 0:
        username = request.POST['username']
    #    if len(str(request.POST['password'])) != 0:
    #        password = request.POST['password']
    if username is None:
        jsondata = {'isLogin': 'false1', 'code': '500'}
    else:
        sql = """select c.id as accountId,teamId,teamName,account,role,username from count_pswd c,team t where c.teamId = t.id and account = %s"""
        conn = pymysql.connect(**config)
        cursor = conn.cursor()
        conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
        cursor.execute(sql, username)
        data = cursor.fetchall()
        cursor.close()

        if len(data) == 0:
            jsondata = {'isLogin': 'false2', 'code': '500'}
        else:
            cursor2 = conn.cursor()
            sql2 = """select m.id as menuId,menuName from count_pswd c,role_menu r,menu m  where role = r.roleId and r.menuId = m.id and account = %s"""
            cursor2.execute(sql2, username)
            row_headers2 = [x[0] for x in cursor2.description]
            data2 = cursor2.fetchall()
            cursor2.close()
            conn.close()
            if len(data2) == 0:
                jsondata = {'isLogin': 'true', 'menu': '没有菜单，请为账号的角色分配菜单！', 'code': '200'}
            else:
                jsondata2 = []
                for result2 in data2:
                    jsondata2.append(dict(zip(row_headers2, result2)))
                article_info = {}
                jsondata = json.loads(json.dumps(article_info))
                jsondata['isLogin'] = 'true'
                jsondata['accountId'] = data[0][0]
                jsondata['teamId'] = data[0][1]
                jsondata['teamName'] = data[0][2]
                jsondata['account'] = data[0][3]
                jsondata['role'] = data[0][4]
                jsondata['username'] = data[0][5]
                jsondata['menu'] = jsondata2
                jsondata['code'] = '200'
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def delete_cookie(request):
    """
    删除用户 Cookie 的视图函数
    :param request: Django HttpRequest对象
    :return: Django HttpResponse对象
    """
    if request.method == 'POST':
        username = request.POST['username']  # 获取 POST 参数
        response = HttpResponse(
            json.dumps({'msg': '删除成功', 'code': '200'}, ensure_ascii=False)
        )
        response.delete_cookie(username)  # 删除名为 'username' 的 Cookie
        return response
    else:
        return HttpResponse(
            json.dumps({'msg': '请使用POST方法', 'code': '400'}, ensure_ascii=False),
            status=400
        )


def account_insert(request):
    """
    新增用户账号的视图函数
    :param request: Django HttpRequest对象
    :return: Django HttpResponse对象
    """
    if request.method == 'POST':
        teamId = request.POST['teamId']
        account = request.POST['account']
        password = aes_ECB_encrypt(request.POST['password'], key)
        createTime = request.POST['createTime']
        role = request.POST['role']
        username = request.POST['username']

        # 检查账号是否已经存在
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) AS counts FROM count_pswd WHERE account = %s", (account,))
                data = cursor.fetchall()

        if data[0][0] != 0:
            return HttpResponse(
                json.dumps({'msg': '账号已存在', 'msg-code': '500'}, ensure_ascii=False)
            )

        # 插入新的用户账号
        try:
            with pymysql.connect(**config) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO count_pswd (teamId, account, password, createTime, role, username) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (teamId, account, password, createTime, role, username)
                    )
                    conn.commit()
        except Exception as e:
            print("提交出错:", e)
            conn.rollback()
            return HttpResponse(
                json.dumps({'msg': '插入失败', 'msg-code': '500'}, ensure_ascii=False)
            )

        return HttpResponse(
            json.dumps({'msg': '插入成功', 'msg-code': '200'}, ensure_ascii=False)
        )
    else:
        return HttpResponse(
            json.dumps({'msg': '请使用POST方法', 'msg-code': '400'}, ensure_ascii=False),
            status=400
        )


def account_delete(request):
    """
    删除用户账号的视图函数
    :param request: Django HttpRequest对象
    :return: Django HttpResponse对象
    """
    if request.method == 'POST':
        id = request.POST['id']
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute("DELETE FROM count_pswd WHERE id = %s", (id,))
                    conn.commit()
                except Exception as e:
                    print("提交出错:", e)
                    conn.rollback()
                    return HttpResponse(
                        json.dumps({'msg': '删除失败', 'msg-code': '500'}, ensure_ascii=False)
                    )
        return HttpResponse(
            json.dumps({'msg': '删除成功', 'msg-code': '200'}, ensure_ascii=False)
        )
    else:
        return HttpResponse(
            json.dumps({'msg': '请使用POST方法', 'msg-code': '400'}, ensure_ascii=False),
            status=400
        )


def account_update(request):
    """
    更新用户账号的视图函数
    :param request: Django HttpRequest对象
    :return: Django HttpResponse对象
    """
    if request.method == 'POST':
        id = request.POST['id']
        username = request.POST['username']
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute("UPDATE count_pswd SET username = %s WHERE id = %s", (username, id))
                    conn.commit()
                except Exception as e:
                    print("提交出错:", e)
                    conn.rollback()
                    return HttpResponse(
                        json.dumps({'msg': '更新失败', 'msg-code': '500'}, ensure_ascii=False)
                    )
        return HttpResponse(
            json.dumps({'msg': '更新成功', 'msg-code': '200'}, ensure_ascii=False)
        )
    else:
        return HttpResponse(
            json.dumps({'msg': '请使用POST方法', 'msg-code': '400'}, ensure_ascii=False),
            status=400
        )


def account_update_pass(request):
    """
    更新用户密码的视图函数
    :param request: Django HttpRequest对象
    :return: Django HttpResponse对象
    """
    if request.method == 'POST':
        account = request.POST['account']
        old_password = request.POST['password']
        new_password = request.POST['password_n']

        # 加密密码
        old_password_encrypted = aes_ECB_encrypt(old_password, key)
        new_password_encrypted = aes_ECB_encrypt(new_password, key)

        # 检查旧密码是否正确
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) FROM count_pswd WHERE account = %s AND password = %s",
                    (account, old_password_encrypted)
                )
                data = cursor.fetchone()
                if data[0] != 1:
                    return HttpResponse(
                        json.dumps({'msg': '密码错误', 'msg-code': '500'}, ensure_ascii=False)
                    )

                # 更新密码
                try:
                    cursor.execute(
                        "UPDATE count_pswd SET password = %s WHERE account = %s",
                        (new_password_encrypted, account)
                    )
                    conn.commit()
                    return HttpResponse(
                        json.dumps({'msg': '更新成功', 'msg-code': '200'}, ensure_ascii=False)
                    )
                except Exception as e:
                    print("提交出错:", e)
                    conn.rollback()
                    return HttpResponse(
                        json.dumps({'msg': '更新失败', 'msg-code': '500'}, ensure_ascii=False)
                    )
    else:
        return HttpResponse(
            json.dumps({'msg': '请使用POST方法', 'msg-code': '400'}, ensure_ascii=False),
            status=400
        )


def account_getall(request):
    """
    获取所有用户账号的视图函数
    :param request: Django HttpRequest对象
    :return: Django HttpResponse对象
    """
    if request.method == 'POST':
        team_id = request.POST['teamId']
        page = int(request.POST['page'])
        rows = int(request.POST['rows'])
        account = request.POST['account']
        username = request.POST['username']

        start = (page - 1) * rows

        # 构建查询条件
        where_clause = ''
        if account:
            where_clause += f" AND account LIKE '%{account}%'"
        if username:
            where_clause += f" AND username LIKE '%{username}%'"

        # 获取总记录数
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) AS counts FROM count_pswd WHERE teamId = %s" + where_clause,
                    (team_id,)
                )
                data = cursor.fetchone()
                total_count = data[0]

        # 查询数据
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT c.id, t.teamName, account, c.createTime, role, username "
                    "FROM count_pswd c JOIN team t ON c.teamId = t.id "
                    "WHERE c.teamId = %s" + where_clause + " LIMIT %s, %s",
                    (team_id, start, rows)
                )
                data = cursor.fetchall()
                row_headers = [x[0] for x in cursor.description]

        # 构造返回结果
        if not data:
            return HttpResponse(
                json.dumps({'msg': '查询结果为空', 'msg-code': '200'}, ensure_ascii=False)
            )
        else:
            result = [dict(zip(row_headers, row)) for row in data]
            return HttpResponse(
                json.dumps({'count': total_count, 'data': result}, ensure_ascii=False)
            )
    else:
        return HttpResponse(
            json.dumps({'msg': '请使用POST方法', 'msg-code': '400'}, ensure_ascii=False),
            status=400
        )


def count_team(request):
    # 获取请求参数
    team_id = request.POST['teamId']
    page = int(request.POST['page'])
    rows = int(request.POST['rows'])
    username = request.POST['username']

    # 计算分页起始位置
    start = (page - 1) * rows

    # 构建 SQL 查询语句
    sql_filters = []
    if username:
        sql_filters.append("count_pswd.username LIKE '%{}%'".format(username))
    sql_where = "WHERE team.id = %s" % team_id
    if sql_filters:
        sql_where += " AND " + " AND ".join(sql_filters)

    sql_count = """
        SELECT COUNT(*) AS counts 
        FROM count_pswd 
        WHERE teamId = %s
    """ % team_id
    if sql_filters:
        sql_count += " AND " + " AND ".join(sql_filters)

    sql = """
        SELECT 
            count_pswd.username, 
            team.teamName,
            COUNT(itemdetail.id) AS itemNum,
            IFNULL(SUM(itemdetail.vulTotal), 0) AS vulNum,
            IFNULL(CAST(SUM(highNumber) AS SIGNED), 0) AS highNumber,
            IFNULL(CAST(SUM(mediumNumber) AS SIGNED), 0) AS mediumNumber,
            IFNULL(CAST(SUM(lowNumber) AS SIGNED), 0) AS lowNumber,
            GROUP_CONCAT(DISTINCT TOP5.vulType ORDER BY TOP5.vulNum DESC LIMIT 5) AS vulType
        FROM 
            (
                SELECT 
                    vul_group.id,
                    vul_group.username,
                    GROUP_CONCAT(DISTINCT vulType ORDER BY vulNum DESC) AS vulType
                FROM
                    (
                        SELECT 
                            count_pswd.id, 
                            count_pswd.username,
                            column1.vulnum,
                            column1.vultype
                        FROM 
                            count_pswd 
                        LEFT JOIN 
                            (
                                SELECT 
                                    count_pswd.id, 
                                    username, 
                                    COUNT(vultype) AS vulnum,
                                    vulType
                                FROM 
                                    count_pswd
                                LEFT JOIN itemdetail ON count_pswd.id = itemdetail.accountId
                                LEFT JOIN vuldetail ON itemdetail.id = vuldetail.itemId
                                LEFT JOIN vulfile ON vulfile.vulid = vuldetail.id
                                GROUP BY vulType
                                ORDER BY COUNT(vulType) DESC
                            ) AS column1 
                        ON count_pswd.id = column1.id
                    ) AS vul_group
                GROUP BY vul_group.id
            ) AS TOP5
        LEFT JOIN count_pswd ON TOP5.Id = count_pswd.id
        LEFT JOIN team ON count_pswd.teamId = team.id
        LEFT JOIN itemdetail ON TOP5.id = itemdetail.accountId
        LEFT JOIN vuldetail ON itemdetail.id = vuldetail.itemId
        {sql_where}
        GROUP BY count_pswd.id
        LIMIT %s, %s
    """.format(sql_where=sql_where)

    # 执行 SQL 查询并获取结果
    conn = pymysql.connect(**config)
    with conn.cursor() as cursor:
        cursor.execute(sql_count)
        counts = cursor.fetchone()[0]
        cursor.execute(sql, (start, rows))
        data = cursor.fetchall()

    # 组装返回数据
    result = {
        'counts': counts,
        'data': []
    }
    for row in data:
        item = {
            'username': row[0],
            'teamName': row[1],
            'itemNum': row[2],
            'vulNum': row[3],
            'highNumber': row[4],
            'mediumNumber': row[5],
            'lowNumber': row[6],
            'vulType': row[7]
        }
        result['data'].append(item)

    return HttpResponse(json.dumps(result, ensure_ascii=False))


def insert_Pol(req):
    """
    将用户选择的策略保存到数据库中

    Args:
        req (HttpRequest): Django 的 HTTP 请求对象

    Returns:
        HttpResponse: 保存成功或失败的 JSON 响应
    """
    account = req.POST["account"]
    policy = req.POST["policy"]

    sql = "UPDATE count_pswd SET data2=%s WHERE account = %s"

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, (policy, account))
                conn.commit()
        return HttpResponse(json.dumps({'msg': '保存成功', 'msg-code': '200'}))
    except Exception as e:
        print(f"提交出错\n: {e}")
        conn.rollback()
        return HttpResponse(json.dumps({'msg': '保存失败', 'msg-code': '500'}))


def get_Pol(req):
    """
    从数据库查询用户选择的检测策略

    Args:
        req (HttpRequest): Django 的 HTTP 请求对象

    Returns:
        HttpResponse: 包含用户策略或错误信息的 JSON 响应
    """
    # 从请求中获取账号信息
    account = req.POST["account"]

    # 构建查询数据库的 SQL 语句
    sql = "SELECT data2 FROM count_pswd WHERE account = %s"

    try:
        # 使用 with 语句管理数据库连接和游标
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 执行 SQL 查询并获取结果
                cursor.execute(sql, (account,))
                data = cursor.fetchone()

        # 构建响应 JSON 数据
        if data and data[0]:
            jsondata = {'policy': data[0]}
        else:
            jsondata = {'msg': '该用户未选择检测策略', 'msg-code': '500'}

        # 返回 JSON 响应
        return HttpResponse(json.dumps(jsondata, ensure_ascii=False))

    except Exception as e:
        # 打印出错信息
        print(f"查询出错\n: {e}")

        # 返回错误信息的 JSON 响应
        return HttpResponse(json.dumps({'msg': '查询失败', 'msg-code': '500'}), status=500)


def get_item_num(req):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    sql1 = """ select count(*) as item_count from itemdetail"""
    sql2 = """SELECT
                COUNT(*) AS task_count,
                SUM( code_size ) AS code_size,
                SUM( high_risk + med_risk + low_risk ) AS vul_count,
                SUM( CASE WHEN statues = '正在检测' THEN 1 ELSE 0 END ) AS testing_count,
                SUM( CASE WHEN statues = '检测完成' THEN 1 ELSE 0 END ) AS complete_count,
                SUM( CASE WHEN statues = '检测失败' THEN 1 ELSE 0 END ) AS fail_count 
            FROM
                vuldetail;"""

    cursor.execute(sql1)
    data1 = cursor.fetchall()
    cursor.execute(sql2)
    data2 = cursor.fetchall()
    result = data1[0] + data2[0]

    result = [str(res) for res in result]
    data = {'item_count': result[0] if result[0] != 'None' else 0,
            'task_count': result[1] if result[1] != 'None' else 0,
            'code_size': result[2] if result[2] != 'None' else 0,
            'vul_count': result[3] if result[3] != 'None' else 0,
            'testing_count': result[4] if result[4] != 'None' else 0,
            'complete_count': result[5] if result[5] != 'None' else 0,
            'fail_count': result[6] if result[6] != 'None' else 0
            }
    jsondata = {'data': data, 'code': '200'}

    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def TaskNum_Time(req):  # 接口4_1
    year = req.POST['year']
    conn = pymysql.connect(**config)  # 使用pymysql库建立与数据库的连接，config是一个包含数据库连接配置的字典
    cursor = conn.cursor()  # 创建游标对象，用于执行sql语句
    sql = """SELECT YEAR(startTime) AS year, MONTH(startTime) AS month, COUNT(*) AS task_count FROM vuldetail WHERE YEAR(startTime)=%s GROUP BY YEAR(startTime),MONTH(startTime) ORDER BY YEAR(startTime),MONTH(startTime)"""
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    cursor.execute(sql, (year,))  # 执行sql语句,传入年份
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()  # 获取执行sql语句获得的所有数据
    jsondata = []
    if len(data) == 0:
        jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
    else:
        for result in data:
            jsondata.append(dict(zip(row_headers, result)))
    cursor.close()  # 关闭游标对象
    conn.close()  # 关闭数据库连接
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def TaskNum_Time(request):
    """
    获取每月任务数量统计
    """
    try:
        year = request.POST['year']
    except KeyError:
        return HttpResponse(json.dumps({'msg': '请提供年份', 'msg-code': '400'}, ensure_ascii=False))

    with pymysql.connect(**config) as conn:
        with conn.cursor() as cursor:
            sql = """
                SELECT 
                    YEAR(startTime) AS year, 
                    MONTH(startTime) AS month, 
                    COUNT(*) AS task_count
                FROM vuldetail 
                WHERE YEAR(startTime) = %s
                GROUP BY YEAR(startTime), MONTH(startTime)
                ORDER BY YEAR(startTime), MONTH(startTime)
            """
            cursor.execute(sql, (year,))
            data = [dict(zip(('year', 'month', 'task_count'), row)) for row in cursor.fetchall()]

    if not data:
        return HttpResponse(json.dumps({'msg': '统计结果为空', 'msg-code': '200'}, ensure_ascii=False))
    else:
        return HttpResponse(json.dumps(data, ensure_ascii=False))


def LevelNum_Time(req):  # 接口4_2
    year = req.POST['year']
    conn = pymysql.connect(**config)  # 使用pymysql库建立与数据库的连接，config是一个包含数据库连接配置的字典
    cursor = conn.cursor()  # 创建游标对象，用于执行sql语句
    sql = """SELECT YEAR(startTime) AS year,SUM(high_risk) as high ,SUM(med_risk) as med,SUM(low_risk) as low FROM vuldetail """
    conditions = []
    if year:
        conditions.append("year(starttime) like '%%%s%%'" % year)

    if conditions:
        sql += " where " + " AND ".join(conditions)
    sql += "GROUP BY YEAR(startTime) "
    sql += "ORDER BY YEAR(startTime)"
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    cursor.execute(sql)  # 执行sql语句
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()  # 获取执行sql语句获得的所有数据
    jsondata = []
    if len(data) == 0:
        jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
    else:
        for result in data:
            jsondata.append(dict(zip(row_headers, result)))
    cursor.close()  # 关闭游标对象
    conn.close()  # 关闭数据库连接
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def get_all_vultype_files(request):
    """
    获取指定任务下所有漏洞类型及其对应的文件列表
    """
    try:
        task_id = request.POST['task_id']
    except KeyError:
        return HttpResponse(json.dumps({'msg': '请提供任务ID', 'msg-code': '400'}, ensure_ascii=False))

    with pymysql.connect(**config) as conn:
        with conn.cursor() as cursor:
            sql = """
                SELECT vultype, fileid, filename
                FROM vulfile
                WHERE taskId = %s
                ORDER BY vultype
            """
            cursor.execute(sql, (task_id,))
            data = cursor.fetchall()

    if not data:
        return HttpResponse(json.dumps({'msg': '统计结果为空', 'msg-code': '200'}, ensure_ascii=False))
    else:
        file_list = []
        current_vultype = None
        for vultype, fileid, filename in data:
            if vultype != current_vultype:
                if current_vultype is not None:
                    file_list.append({'name': current_vultype, 'files': files})
                current_vultype = vultype
                files = []
            files.append({'fileid': fileid, 'name': filename})
        if current_vultype is not None:
            file_list.append({'name': current_vultype, 'files': files})

        return HttpResponse(json.dumps({'fileList': file_list}, ensure_ascii=False))


def vulfile_update(task_id, file_id, repair_code, code_location):  # 修复后，修改 vulfile 表
    try:
        conn = pymysql.connect(**config)
        cursor = conn.cursor()
        conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
        print(task_id, file_id, repair_code, code_location)

        sql = """update vulfile set repair_code = %s, repair_status = '已修复',code_location = %s where taskid = %s and fileid = %s"""
        cursor.execute(sql, (repair_code, code_location, task_id, file_id))
        conn.commit()  # 提交事务

        cursor.close()
        conn.close()

        jsondata = {'msg': '修改成功', 'code': '200'}
    except Exception as e:
        jsondata = {'msg': '修改失败', 'code': '500', 'error': str(e)}

    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def read_file_content(file_path):
    # 检测文件编码格式
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
            result = chardet.detect(raw_data)
            encoding = result['encoding']
    except (OSError, IOError) as e:
        print(f"无法读取文件 {file_path}: {e}")
        return False
    # 计算代码总行数和文件大小
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            code = f.read()
        return code
    except UnicodeDecodeError as e:
        print(f"无法解码文件 {file_path}: {e}")
        return False
    except (OSError, IOError) as e:
        print(f"无法处理文件 {file_path}: {e}")
        return False

def generate_sequence(range_list):
    start, end = range_list
    return ", ".join(map(str, range(start, end + 1)))

def VulType_get(req):  # 接口6_2
    vul_id = req.POST['fileid']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    sql = """select * from vulfile where fileid = %s"""
    conn.ping(reconnect=True)
    cursor.execute(sql, (vul_id))
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()
    jsondata = []
    if len(data) == 0:
        jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
    else:
        for result in data:
            # 将查询结果转换为字典
            result_dict = dict(zip(row_headers, result))
            if "[" in result_dict['location'] and "]" in result_dict['location']:
                # 如果包含 "[" 和 "]"，执行 generate_sequence 函数
                result_dict['location'] = generate_sequence(json.loads(result_dict['location']))
            else:
                result_dict['location'] = f'"{result_dict["location"]}"'

            result_dict['code_location'] = result_dict['location']

            if 'filepath' in result_dict:
                file_path = result_dict['filepath']
                code = read_file_content(file_path)
                result_dict['source_code'] = code

            jsondata.append(result_dict)

    cursor.close()
    conn.close()
    return HttpResponse(json.dumps({'fileList': jsondata}, ensure_ascii=False))


def Task_Detail_1(req):  # 接口5_1
    task_id = req.POST['task_id']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    sql = """SELECT vuldetail.taskname,itemdetail.itemname,itemdetail.language,vuldetail.type,vuldetail.file_size,vuldetail.code_size,vuldetail.lasttime,vuldetail.review_status,itemdetail.source,vuldetail.file_num,itemdetail.creator,vuldetail.startTime,itemdetail.url
from itemdetail left join vuldetail on itemdetail.itemid = vuldetail.itemid where vuldetail.taskid = %s""" % (task_id)
    conn.ping(reconnect=True)
    cursor.execute(sql)
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()
    jsondata = []
    if len(data) == 0:
        jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
    else:
        for result in data:
            jsondata.append(dict(zip(row_headers, result)))
    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def Task_Detail_2(req):  # 接口5_2
    task_id = req.POST['task_id']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    sql = """select taskid,high_risk,med_risk,low_risk from vuldetail where taskid = %s""" % (task_id)
    conn.ping(reconnect=True)
    cursor.execute(sql)
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()
    jsondata = []
    if len(data) == 0:
        jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
    else:
        for result in data:
            jsondata.append(dict(zip(row_headers, result)))
    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def Task_Detail_3(req):  # 接口5_3
    task_id = req.POST['task_id']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    print(task_id)
    sql = """select vultype,count(*) as count from vulfile where taskid = %s GROUP BY vultype""" % (task_id)
    conn.ping(reconnect=True)
    cursor.execute(sql)
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()
    jsondata = []
    if len(data) == 0:
        jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
    else:
        for result in data:
            jsondata.append(dict(zip(row_headers, result)))
    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def Homepage_statistics(req):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    sql_queries = [
        "select year(createTime) as year,count(*) as item_sum from itemdetail GROUP BY year(createTime);",
        "select year(startTime) as year,count(*) as task_sum from vuldetail GROUP BY year(startTime);",
        "select year(startTime) as year,sum(code_size) as code_sum from vuldetail GROUP BY year(startTime);",
        "select year(vuldetail.startTime) as year,count(*) as vul_sum from vulfile left join vuldetail on vulfile.taskid = vuldetail.taskid GROUP BY year(vuldetail.startTime);"
    ]
    jsondata = {}
    filelists = ["filelist1", "filelist2", "filelist3", "filelist4"]
    for query, filelist in zip(sql_queries, filelists):
        conn.ping(reconnect=True)
        cursor.execute(query)
        row_headers = [x[0] for x in cursor.description]
        data = cursor.fetchall()

        if len(data) == 0:
            jsondata[filelist] = {'msg': '统计结果为空', 'msg-code': '200'}
        else:
            jsondata[filelist] = []
            for result in data:
                jsondata[filelist].append(dict(zip(row_headers, result)))
    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def file_detail(req):  # 接口7
    file_id = req.POST['file_id']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    sql = """SELECT
                cwelist.NAME,
                vulfile.repair_status,
                itemdetail.LANGUAGE,
                vulfile.risk_level,
                vulfile.filepath,
                vuldetail.startTime,
                cwelist.description,
                cwelist.example,
                cwelist.repairPlan 
            FROM
                vulfile
                LEFT JOIN vuldetail ON vulfile.taskId = vuldetail.taskid
                LEFT JOIN itemdetail ON vuldetail.itemid = itemdetail.itemid
                LEFT JOIN cwelist ON vulfile.vultype = cwelist.number 
            WHERE
                vulfile.fileid = %s"""
    conn.ping(reconnect=True)
    cursor.execute(sql, file_id)
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()
    jsondata = []
    if len(data) == 0:
        jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
    else:
        for result in data:
            jsondata.append(dict(zip(row_headers, result)))
    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def vul_statistics(req):  # 接口9
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    itemid = req.POST.get('itemid')
    vulname = req.POST['vulname']
    filename = req.POST['filename']
    risk_level = req.POST['risk_level']
    repair_status = req.POST['repair_status']
    starttime = req.POST['starttime']
    page = int(req.POST['page'])
    results_per_page = int(req.POST['rows'])

    # 计算分页的偏移量
    offset = (page - 1) * results_per_page

    # 查询总结果数量
    count_sql = """SELECT COUNT(*) 
                   from vulfile left join cwelist on vulfile.vultype = cwelist.number left join vuldetail on vulfile.taskid = vuldetail.taskid  """

    sql = """select cwelist.name,vulfile.filename,vulfile.risk_level,vulfile.repair_status,vulfile.remarks
             from vulfile left join cwelist on vulfile.vultype = cwelist.number left join vuldetail on vulfile.taskid = vuldetail.taskid"""

    conditions = []
    if itemid:
        conditions.append("vuldetail.itemid like '%%%s%%'" % itemid)

    if vulname:
        conditions.append("cwelist.name like '%%%s%%'" % vulname)

    if filename:
        conditions.append("vulfile.filename like '%%%s%%'" % filename)

    if risk_level:
        conditions.append("vulfile.risk_level like '%%%s%%'" % risk_level)

    if repair_status:
        conditions.append("vulfile.repair_status like '%%%s%%'" % repair_status)

    if starttime:
        conditions.append("vuldetail.starttime like '%%%s%%'" % starttime)

    if conditions:
        count_sql += " WHERE " + " AND ".join(conditions)

    if conditions:
        sql += " where " + " AND ".join(conditions)

    cursor.execute(count_sql)
    total_count = cursor.fetchone()[0]

    sql += " LIMIT %s, %s" % (offset, results_per_page)

    conn.ping(reconnect=True)
    cursor.execute(sql)
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()

    jsondata = {'count': total_count}
    if total_count == 0:
        jsondata['msg'] = '统计结果为空'
        jsondata['msg-code'] = '200'
    else:
        jsondata['data'] = []
        for result in data:
            jsondata['data'].append(dict(zip(row_headers, result)))

    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))

'''
def related_project_list(req): #自定义规则相关项目查找接口
    custom_rule = req.POST['custom_rule']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    sql = """SELECT
                itemname
             FROM
                itemdetail
             WHERE
                applied_rule = %s"""
    conn.ping(reconnect=True)
    cursor.execute(sql, custom_rule)
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()
    jsondata = []
    if len(data) == 0:
        jsondata = {'msg': '未找到对应项目', 'msg-code': '200'}
    else:
        for result in data:
            jsondata.append(dict(zip(row_headers, result)))
    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))
'''


def get_all_projects(): #获取所有项目接口
    sql_1 = "SELECT itemid FROM itemdetail"
    sql_2 = "SELECT itemname FROM itemdetail WHERE itemid = %s"
    sql_3 = "SELECT taskname FROM vuldetail WHERE itemId = %s"

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                conn.ping(reconnect=True)
                cursor.execute(sql_1)
                project_ids = cursor.fetchall()
                all_projects = []

                for project_id in project_ids:
                    project_id = project_id[0]
                    cursor.execute(sql_2, project_id)
                    project_name = cursor.fetchone()
                    project_name = project_name[0]

                    cursor.execute(sql_3, project_id)
                    task_names = cursor.fetchall()
                    task_list = []

                    for task_name in task_names:
                        task_name = task_name[0]
                        task_list.append(task_name)

                    all_projects.append({"project_name": project_name, "task_list": task_list})

                return JsonResponse({"code":200, "projects": all_projects})

    except Exception as e:
        print(f"Error:{e}")
        return JsonResponse({"error": "失败", "code": "500"})


def item_list(req):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    itemid = req.POST['itemid']
    itemname = req.POST['itemname']
    description = req.POST['description']
    language = req.POST['language']
    source = req.POST['source']
    createtime = req.POST['createtime']
    page = int(req.POST['page'])
    results_per_page = int(req.POST['rows'])

    # 计算分页的偏移量
    offset = (page - 1) * results_per_page

    # 查询总结果数量
    count_sql = """SELECT COUNT(*) 
                   FROM itemdetail  """
    conditions = []
    if itemid:
        conditions.append("itemdetail.itemid like '%%%s%%'" % itemid)

    if itemname:
        conditions.append("itemdetail.itemname like '%%%s%%'" % itemname)

    if description:
        conditions.append("itemdetail.description like '%%%s%%'" % description)

    if language:
        conditions.append("itemdetail.language like '%%%s%%'" % language)

    if source:
        conditions.append("itemdetail.source like '%%%s%%'" % source)

    if createtime:
        conditions.append("itemdetail.createtime like '%%%s%%'" % createtime)

    if conditions:
        count_sql += " WHERE " + " AND ".join(conditions)

    cursor.execute(count_sql)
    total_count = cursor.fetchone()[0]

    # 执行带分页参数的查询
    sql = """SELECT itemdetail.itemid,itemdetail.itemname,itemdetail.description,itemdetail.language,itemdetail.source,sum(vuldetail.high_risk) as high,sum(vuldetail.med_risk) as med,sum(vuldetail.low_risk) as low,itemdetail.createTime
             FROM itemdetail 
             LEFT JOIN vuldetail ON itemdetail.itemid = vuldetail.itemId """

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    sql += " GROUP BY itemdetail.itemid "
    sql += " ORDER BY itemdetail.createTime desc"
    sql += " LIMIT %s, %s" % (offset, results_per_page)

    conn.ping(reconnect=True)
    cursor.execute(sql)
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()

    jsondata = {'count': total_count}
    if total_count == 0:
        jsondata['msg'] = '统计结果为空'
        jsondata['msg-code'] = '200'
    else:
        jsondata['data'] = []
        for result in data:
            jsondata['data'].append(dict(zip(row_headers, result)))

    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def task_list(req):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    taskid = req.POST['taskid']
    taskname = req.POST['taskname']
    itemid = req.POST['itemid']
    itemname = req.POST['itemname']
    language = req.POST['language']
    type = req.POST['type']
    review_status = req.POST['review_status']
    source = req.POST['source']
    creator = req.POST['creator']
    starttime = req.POST['starttime']

    page = int(req.POST['page'])
    results_per_page = int(req.POST['rows'])

    # 计算分页的偏移量
    offset = (page - 1) * results_per_page

    # 查询总结果数量
    count_sql = """SELECT COUNT(*) 
                   FROM vuldetail LEFT JOIN itemdetail ON itemdetail.itemid = vuldetail.itemid """
    conditions = []
    if taskid:
        conditions.append("vuldetail.taskid like '%%%s%%'" % taskid)

    if taskname:
        conditions.append("vuldetail.taskname like '%%%s%%'" % taskname)

    if itemid:
        conditions.append("itemdetail.itemid like '%%%s%%'" % itemid)

    if itemname:
        conditions.append("itemdetail.itemname like '%%%s%%'" % itemname)

    if language:
        conditions.append("itemdetail.language like '%%%s%%'" % language)

    if type:
        conditions.append("vuldetail.type like '%%%s%%'" % type)

    if review_status:
        conditions.append("vuldetail.review_status like '%%%s%%'" % review_status)

    if source:
        conditions.append("itemdetail.source like '%%%s%%'" % source)

    if creator:
        conditions.append("itemdetail.creator like '%%%s%%'" % creator)

    if starttime:
        conditions.append("vuldetail.starttime like '%%%s%%'" % starttime)

    if conditions:
        count_sql += " WHERE " + " AND ".join(conditions)

    cursor.execute(count_sql)
    total_count = cursor.fetchone()[0]

    # 执行带分页参数的查询
    sql = """SELECT vuldetail.taskid,vuldetail.taskname,itemdetail.itemid,itemdetail.itemname,itemdetail.language,vuldetail.type,vuldetail.statues,vuldetail.file_size,vuldetail.code_size,vuldetail.lasttime,vuldetail.review_status,itemdetail.source,vuldetail.file_num,itemdetail.creator,vuldetail.startTime,itemdetail.url,vuldetail.high_risk,vuldetail.med_risk,vuldetail.low_risk
             FROM vuldetail 
             LEFT JOIN itemdetail ON itemdetail.itemid = vuldetail.itemid """

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    sql += " GROUP BY vuldetail.taskId "
    sql += " ORDER BY vuldetail.starttime desc"
    sql += " LIMIT %s, %s" % (offset, results_per_page)

    conn.ping(reconnect=True)
    cursor.execute(sql)
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()

    jsondata = {'count': total_count}
    if total_count == 0:
        jsondata['msg'] = '统计结果为空'
        jsondata['msg-code'] = '200'
    else:
        jsondata['data'] = []
        for result in data:
            jsondata['data'].append(dict(zip(row_headers, result)))

    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def get_id(column, table):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)

    sql = f"SELECT MAX(CAST({column} AS UNSIGNED)) FROM {table}"

    cursor.execute(sql)
    result = cursor.fetchone()
    max_id = result[0] if result[0] is not None else 0  # 如果查询结果为空，则将max_id设为0
    next_id = max_id + 1

    cursor.close()
    conn.close()

    return next_id


def itemdetail_insert(req):
    item_name = req.POST['item_name']
    url = req.POST['url']
    language = req.POST['language']
    source = req.POST['source']
    description = req.POST['description']
    creator_id = req.POST['creator_id']
    createTime = req.POST['createTime']
    creator = req.POST['creator']

    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    name_sql = """ select count(*) as count from itemdetail where itemname=%s """
    cursor.execute(name_sql, item_name)
    data1 = cursor.fetchall()[0][0]
    if data1 != 0:
        jsondata = {'msg': '项目名称已存在，请修改项目名之后新增', 'code': '500'}
    else:
        item_id = get_id('itemid', 'itemdetail')  # 生成项目id，获取表中itemid最大值，然后生成一个id+1的值
        folder_path = os.path.join(file_save_path, item_name)
        os.makedirs(folder_path)

        sql = """insert into itemdetail(itemid,itemname,url,language,source, description, creator_id, creator, createTime) values(%s,%s,%s,%s,%s,%s,%s,%s,%s) """

        conn = pymysql.connect(**config)
        cursor = conn.cursor()
        conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
        try:
            flag = cursor.execute(sql, [item_id, item_name, url, language, source, description, creator_id, creator,
                                        createTime])
            conn.commit()
        except Exception as e:
            flag = False
            print("提交出错\n:", e)
            # 如果出错要回滚
            conn.rollback()
        cursor.close()
        conn.close()
        if flag:
            jsondata = {'msg': '插入成功', 'code': '200'}
        else:
            jsondata = {'msg': '插入失败', 'code': '500'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def vuldetail_insert(task_id, item_id, task_name, type, high, mid, low, code_size, file_size, file_num, statues,
                     start_time, end_time, last_time, review_status, version=None):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接

    sql = """insert into vuldetail(taskId, itemId, taskname, type, high_risk, med_risk, low_risk, code_size, file_size, file_num, statues, startTime, endTime, lastTime, review_status, version) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) """

    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    try:
        flag = cursor.execute(sql, [task_id, item_id, task_name, type, high, mid, low, code_size, file_size, file_num,
                                    statues, start_time, end_time, last_time, review_status, version])
        conn.commit()
    except Exception as e:
        flag = False
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()
    cursor.close()
    conn.close()
    if flag:
        jsondata = {'msg': '插入成功', 'code': '200'}
    else:
        jsondata = {'msg': '插入失败', 'code': '500'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


# 创建全局数据库连接
conn = pymysql.connect(**config)
cursor = conn.cursor()

def vulfile_insert(task_id, file_id, combine_list):
    global conn, cursor

    sql = """insert into vulfile(taskId, fileId, filename, filepath, vultype, location, source_code, code_location, repair_code, risk_level, repair_status, is_question, Sink, Enclosing_Method, Source) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) """

    flag = True

    for i, data in enumerate(combine_list):
        file_id = file_id + 1
        file_name = data['filename']
        file_path = data['file_path']
        if data['vul_name']:
            vultype = data['vul_name']
        else:
            vultype = data['cwe_id']
        location = data['line_number']
        code = data['code']
        model = data['model']
        Sink = data.get('Sink', '')
        Enclosing_Method = data.get('Enclosing_Method', '')
        Source = data.get('Source', '')
        code_location = ','.join(map(str, data['new_line_number'])) if 'deepseek' in model else data['new_line_number']
        repair_code = data['repair_code']
        risk_level = data['risk_level']
        repair_status = data['repair_status']
        is_question = data['is_question']
        try:
            flag = cursor.execute(sql, [task_id, file_id, file_name, file_path, vultype, location, code, code_location,
                                        repair_code, risk_level, repair_status, is_question, Sink, Enclosing_Method,
                                        Source])
            conn.commit()
        except Exception as e:
            flag = False
            print("提交出错\n:", e)
            # 如果出错要回滚
            conn.rollback()
 
    if flag:
        jsondata = {'msg': '插入成功', 'code': '200'}
    else:
        jsondata = {'msg': '插入失败', 'code': '500'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def task_delete(req):  # 删除任务
    taskid = req.POST['taskid']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    sql = """DELETE vuldetail,vulfile FROM vuldetail left join vulfile on vuldetail.taskid = vulfile.taskid WHERE vuldetail.taskid = %s"""
    sql2 = """ select * from vuldetail where taskId = %s"""
    cursor.execute(sql2, taskid)
    task_data = cursor.fetchall()
    sql3 = """ select itemname from itemdetail where itemid = %s"""
    cursor.execute(sql3, task_data[0][2])
    itemname = cursor.fetchall()
    print(itemname)
    itemname = itemname[0][0]
    print(itemname)
    try:
        cursor.execute(sql, taskid)
        conn.commit()
        path = os.path.join(file_save_path, itemname, task_data[0][3])
        print(path)
        shutil.rmtree(path)
    except Exception as e:
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()
        jsondata = {'msg': '删除失败', 'code': '500'}
        return HttpResponse(json.dumps(jsondata, ensure_ascii=False))
    cursor.close()
    conn.close()
    jsondata = {'msg': '删除成功', 'code': '200'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def project_delete(req):  # 删除项目
    itemid = req.POST['itemid']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    sql2 = """ select count(*) from vuldetail where itemId = %s"""
    cursor.execute(sql2, itemid)
    data = cursor.fetchall()
    if data[0][0] != 0:
        jsondata = {'msg': '删除失败,请先删掉项目内的所有任务', 'code': '500'}
        return HttpResponse(json.dumps(jsondata, ensure_ascii=False))
    sql = """delete from itemdetail where itemid = %s """
    sql3 = """ select * from itemdetail where itemid = %s"""
    cursor.execute(sql3, itemid)
    item_data = cursor.fetchall()
    print(item_data)
    try:
        cursor.execute(sql, itemid)
        conn.commit()

        path = os.path.join(file_save_path, item_data[0][2])
        print(path)
        shutil.rmtree(path)
    except Exception as e:
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()
        jsondata = {'msg': '删除失败', 'code': '500'}
        return HttpResponse(json.dumps(jsondata, ensure_ascii=False))
    cursor.close()
    conn.close()
    jsondata = {'msg': '删除成功', 'code': '200'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def vuldetail_update(task_id, item_id, task_name, type, high, mid, low, code_size, file_size, file_num, statues,
                     start_time, end_time, last_time, review_status):
    sql = "UPDATE vuldetail SET taskId=%s, itemId=%s,taskname=%s, type=%s,high_risk=%s, med_risk=%s,low_risk=%s, code_size=%s,file_size=%s, file_num=%s,statues=%s, startTime=%s, endTime=%s, lastTime=%s, review_status=%s WHERE taskId = %s"

    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    try:
        cursor.execute(sql, (
            task_id, item_id, task_name, type, high, mid, low, code_size, file_size, file_num, statues, start_time,
            end_time, last_time, review_status, task_id))
        conn.commit()
        flag = True
    except Exception as e:
        flag = False
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()
    cursor.close()
    conn.close()
    if flag:
        return HttpResponse(json.dumps({'msg': '保存成功', 'msg-code': '200'}))
    else:
        return HttpResponse(json.dumps({'msg': '保存失败', 'msg-code': '500'}))


def project_statistics(req):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    sql_queries = [
        "SELECT count(*) as itemnum FROM itemdetail;",
        "SELECT count(*) as tasknum from vuldetail;",
        "SELECT count(*) as filenum from vuldetail left join vulfile on vuldetail.taskid = vulfile.taskid where vuldetail.statues like '检测完成';",
        "SELECT count(*) as detecting from vuldetail where statues like '正在检测';",
        "SELECT count(*) as detected from vuldetail where statues like '检测完成';",
        "SELECT count(*) as Detection_failed from vuldetail where statues like '检测失败';"
    ]
    jsondata = []
    for query in sql_queries:
        conn.ping(reconnect=True)
        cursor.execute(query)
        row_headers = [x[0] for x in cursor.description]
        data = cursor.fetchall()

        if len(data) == 0:
            jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
        else:
            for result in data:
                jsondata.append(dict(zip(row_headers, result)))
    cursor.close()
    conn.close()
    return JsonResponse(jsondata, safe=False)


def review_update(req):  # 更新审核状态
    taskid = req.POST['taskid']
    fileid = req.POST['fileid']
    is_question = req.POST.get('is_question')
    risk_level = req.POST.get('risk_level')
    is_fp = req.POST.get('is_fp')
    remarks = req.POST.get('remarks')
    data1 = req.POST.get('data1')  # 判断这个文件是否被审核，如果传1则表示已被审核

    # 处理 fileid 解析
    try:
        if isinstance(fileid, str) and not fileid.startswith('['):
            fileid = [int(id) for id in fileid.split(',')]
        else:
            fileid = json.loads(fileid)
    except json.JSONDecodeError as e:
        print("解析 fileid 失败:", e)
        jsondata = {'msg': 'fileid 格式无效', 'code': '500'}
        return HttpResponse(json.dumps(jsondata, ensure_ascii=False))

    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接

    try:
        for id in fileid:  # 确保 fileid 是一个可迭代对象
            # 查询当前记录的原始值和文件信息
            sql_select = 'SELECT risk_level, filename, filepath FROM vulfile WHERE taskid = %s AND fileid = %s'
            cursor.execute(sql_select, (taskid, id))
            result = cursor.fetchone()
            original_risk_level = result[0]  # 获取原始的 risk_level
            filename = result[1]            # 获取 filename
            filepath = result[2]            # 获取 filepath

            # 构建更新 SQL
            sql = """UPDATE vulfile SET """
            conditions = []
            if is_question:
                conditions.append("is_question = '%s' " % is_question)
            if is_fp:
                conditions.append("is_fp = '%s' " % is_fp)
            if risk_level:
                conditions.append("risk_level = '%s' " % risk_level)
            if remarks:
                conditions.append("remarks = '%s' " % remarks)
            if data1:
                conditions.append("data1 = '%s' " % data1)

            if conditions:
                sql += ', '.join(conditions)
                sql += ' WHERE taskid = %s AND fileid = %s'
                cursor.execute(sql, (taskid, id))
                conn.commit()

                # 记录日志（如果 risk_level 被修改）
                if risk_level and original_risk_level != risk_level:
                    log_sql = """
                    INSERT INTO audit_log (taskid, fileid, filename, filepath, old_value, new_value, remarks, update_time)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    log_data = (taskid, id, filename, filepath, original_risk_level, risk_level, remarks, datetime.now())
                    cursor.execute(log_sql, log_data)
                    conn.commit()

        # 查询数据并存储在列表中
        sql2 = 'SELECT data1 FROM vulfile WHERE vulfile.taskid = %s' % (taskid)
        cursor.execute(sql2)
        result = cursor.fetchall()
        data_list = [row[0] for row in result]

        # 判断列表中的值是否都为1
        if all(value == '1' for value in data_list):
            # 更新任务审核状态
            sql3 = 'UPDATE vuldetail SET review_status = "已审核" WHERE taskid = %s' % (taskid)
            cursor.execute(sql3)
            conn.commit()

    except Exception as e:
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()
        jsondata = {'msg': '修改失败', 'code': '500'}
        return HttpResponse(json.dumps(jsondata, ensure_ascii=False))
    cursor.close()
    conn.close()
    jsondata = {'msg': '修改成功', 'code': '200'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))
def query_audit_log(request):
    """
    查询 audit_log 表，支持分页和模糊查询，并与 vulfile 表进行连接
    返回 audit_log 表的全部内容以及 vulfile 表的 vultype 和 repair_status 字段
    """
    try:
        # 获取请求参数
        taskid = request.POST.get('taskid')
        fileid = request.POST.get('fileid')
        filename = request.POST.get('filename')
        filepath = request.POST.get('filepath')
        start_time = request.POST.get('start_time')
        end_time = request.POST.get('end_time')
        vultype = request.POST.get('vultype')  # 新增参数：漏洞类型
        repair_status = request.POST.get('repair_status')  # 新增参数：修复状态
        page = int(request.POST.get('page', 1))  # 默认第1页
        page_size = int(request.POST.get('page_size', 10))  # 默认每页10条

        # 连接数据库
        connection = None
        try:
            connection = pymysql.connect(**config)
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                # 构建查询 SQL
                sql = """
                    SELECT 
                        audit_log.*, 
                        vulfile.vultype, 
                        vulfile.repair_status 
                    FROM 
                        audit_log 
                    LEFT JOIN 
                        vulfile 
                    ON 
                        audit_log.taskid = vulfile.taskid 
                        AND audit_log.fileid = vulfile.fileid 
                    WHERE 
                        1=1
                """
                params = []

                # 根据参数动态添加查询条件（模糊查询）
                if taskid:
                    sql += " AND audit_log.taskid LIKE %s"
                    params.append(f"%{taskid}%")  # 使用 % 通配符实现模糊匹配
                if fileid:
                    sql += " AND audit_log.fileid LIKE %s"
                    params.append(f"%{fileid}%")
                if filename:
                    sql += " AND audit_log.filename LIKE %s"
                    params.append(f"%{filename}%")
                if filepath:
                    sql += " AND audit_log.filepath LIKE %s"
                    params.append(f"%{filepath}%")
                if start_time:
                    sql += " AND audit_log.update_time >= %s"
                    params.append(start_time)
                if end_time:
                    sql += " AND audit_log.update_time <= %s"
                    params.append(end_time)
                if vultype:  # 新增条件：漏洞类型
                    sql += " AND vulfile.vultype LIKE %s"
                    params.append(f"%{vultype}%")
                if repair_status:  # 新增条件：修复状态
                    sql += " AND vulfile.repair_status LIKE %s"
                    params.append(f"%{repair_status}%")

                # 添加分页条件
                sql += " LIMIT %s OFFSET %s"
                params.extend([page_size, (page - 1) * page_size])

                # 执行查询
                cursor.execute(sql, params)
                results = cursor.fetchall()

            # 返回查询结果
            return JsonResponse({'msg': '查询成功', 'msg-code': '200', 'data': results})

        except Exception as e:
            print(f"查询数据失败：{e}")
            return JsonResponse({'msg': f'查询数据失败：{e}', 'msg-code': '500'}, status=500)

        finally:
            if connection:
                connection.close()

    except Exception as e:
        return JsonResponse({'msg': f'查询时发生错误：{e}', 'msg-code': '500'}, status=500)


def negative_time_query(req):
    account = req.POST['account']
    start_time = req.POST['start_time']
    end_time = req.POST['end_time']

    sql = """select * from itemdetail, vuldetail,vulfile where creator_id = %s and itemdetail.itemid = vuldetail.itemId and vuldetail.taskId = vulfile.taskId and date(vuldetail.startTime) between %s and %s"""

    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    cursor.execute(sql, [account, start_time, end_time])
    data = cursor.fetchall()
    jsondata = {'data': data, 'code': '500'}

    cursor.close()
    conn.close()

    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def get_model_id(req):
    sql = """select * from model_list"""

    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)
    cursor.execute(sql)
    model = cursor.fetchall()

    jsondata = []
    if len(model) == 0:
        jsondata = {'msg': '查询结果为空', 'msg-code': '500'}
    else:
        for data in model:
            item = {
                'model_id': data[1],
                'model_name': data[2],
                'model_path': data[3],
                'model_train_start': data[4],
                'model_train_end': data[5],
                'cwe_id': data[6],
                'remarks': data[7]
            }
            jsondata.append(item)

    cursor.close()
    conn.close()

    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def positive_insert(positive_id, positive_name, folder_name, total_size, file_count, upload_time, upload_id):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接

    sql = """INSERT into positive_sample(positive_id,positive_name,url,size,file_num,upload_time,upload_id) VALUES(%s,%s,%s,%s,%s,%s,%s) """

    flag = True
    try:
        flag = cursor.execute(sql,
                              [positive_id, positive_name, folder_name, total_size, file_count, upload_time, upload_id])
        print("数据插入成功")
        conn.commit()
    except Exception as e:
        flag = False
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()

    cursor.close()
    conn.close()

    if flag:
        jsondata = {'msg': '插入成功', 'code': '200'}
    else:
        jsondata = {'msg': '插入失败', 'code': '500'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def negative_list(req):
    account = req.POST['account']
    starttime = req.POST['starttime']
    endtime = req.POST['endtime']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    sql = """
    SELECT fileId, filename, vultype
    FROM itemdetail, vuldetail, vulfile
    WHERE creator_id = %s
    AND itemdetail.itemid = vuldetail.itemId
    AND vuldetail.taskId = vulfile.taskId
    AND vuldetail.startTime BETWEEN %s AND %s
    ORDER BY vuldetail.startTime DESC
    """

    jsondata = []

    conn.ping(reconnect=True)
    cursor.execute(sql, (account, starttime, endtime))

    data = cursor.fetchall()

    if len(data) == 0:
        jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
    else:
        filename_dict = {}

        for result in data:
            fileId = result[0]
            filename = result[1]
            vultype = result[2]

            if filename not in filename_dict:
                filename_dict[filename] = {'fileId': fileId, 'vultypes': set([vultype])}
            else:
                filename_dict[filename]['vultypes'].add(vultype)

        for filename, file_data in filename_dict.items():
            fileId = file_data['fileId']
            vultypes = file_data['vultypes']
            vultypes_str = ','.join(vultypes)
            item = {
                'key': fileId,
                'label': f"{filename}({vultypes_str})"
            }
            jsondata.append(item)

    cursor.close()
    conn.close()
    return JsonResponse(jsondata, safe=False)


def positive_list(req):
    account = req.POST['account']
    starttime = req.POST['starttime']
    endtime = req.POST['endtime']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    sql = """ SELECT positive_id,positive_name FROM positive_sample WHERE upload_Time BETWEEN %s AND %s AND upload_id = %s ORDER BY upload_Time DESC; """
    jsondata = []

    conn.ping(reconnect=True)
    cursor.execute(sql, (starttime, endtime, account))
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()

    if len(data) == 0:
        jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
    else:
        positivename_dict = {}

        for result in data:
            positiveId = result[0]
            positivename = result[1]

            item = {
                'key': positiveId,
                'label': positivename
            }
            jsondata.append(item)

    cursor.close()
    conn.close()
    return JsonResponse(jsondata, safe=False)


def get_positive_path(positive_id):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    sql = """ SELECT * FROM positive_sample WHERE positive_id = %s """
    jsondata = []

    conn.ping(reconnect=True)
    for id in positive_id:
        cursor.execute(sql, id)
        data = cursor.fetchall()[0]
        jsondata.append(data[2])

    cursor.close()
    conn.close()
    return jsondata


def get_negtive_path(negtive_id):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    sql = """ SELECT filepath, vultype FROM vulfile WHERE fileId = %s """
    jsondata = []

    conn.ping(reconnect=True)
    for id in negtive_id:
        cursor.execute(sql, id)
        data = cursor.fetchall()[0]
        jsondata.append([data[0], data[1]])

    cursor.close()
    conn.close()
    return jsondata


def insert_model(model_id, model_name, model_path, model_train_start, model_train_end, cwe_id):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    # 检查模型名称是否存在
    sql_check = "SELECT model_name FROM model_list WHERE model_name LIKE %s"
    cursor.execute(sql_check, (model_name + '%',))
    existing_models = cursor.fetchall()

    # 获取最大的数字后缀
    max_suffix = 0
    for existing_model in existing_models:
        existing_name = existing_model[0]
        if existing_name.startswith(model_name):
            # 提取数字后缀
            suffix = existing_name[len(model_name):]
            if suffix.isdigit() and int(suffix) > max_suffix:
                max_suffix = int(suffix)

    # 构建带有数字后缀的模型名称
    model_name_with_suffix = model_name + str(max_suffix + 1)

    # 构建新的模型路径和文件名
    directory_part, filename_part = model_path.rsplit('/', 1)
    new_model_name = f"{model_name_with_suffix}.model"
    new_model_path = f"{directory_part}/{new_model_name}"

    # 重命名模型文件
    old_model_path = f"{directory_part}/{filename_part}"
    new_model_path = f"{directory_part}/{new_model_name}"
    os.rename(old_model_path, new_model_path)

    sql = """INSERT INTO model_list(model_id, model_name, model_path, model_train_start, model_train_end, cwe_id) VALUES (%s, %s, %s, %s, %s, %s)"""

    flag = True
    try:
        flag = cursor.execute(sql,
                              [model_id, model_name_with_suffix, new_model_path, model_train_start, model_train_end,
                               cwe_id])
        print("数据插入成功")
        conn.commit()
    except Exception as e:
        flag = False
        print("提交出错:\n", e)
        # 如果出错要回滚
        conn.rollback()

    cursor.close()
    conn.close()

    if flag:
        jsondata = {'msg': '插入成功', 'code': '200'}
    else:
        jsondata = {'msg': '插入失败', 'code': '500'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def delete_model(req):
    model_id = req.POST['model_id']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    sql = """delete from model_list where model_id=%s """

    flag = True
    try:
        flag = cursor.execute(sql, model_id)
        print("数据删除成功")
        conn.commit()
    except Exception as e:
        flag = False
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()

    cursor.close()
    conn.close()

    if flag:
        jsondata = {'msg': '删除成功', 'code': '200'}
    else:
        jsondata = {'msg': '删除失败', 'code': '500'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def update_model(req):
    model_id = req.POST['model_id']
    model_name = req.POST['model_name']
    model_remarks = req.POST['model_remarks']

    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    # 获取旧的模型路径
    sql_select_path = "SELECT model_path FROM model_list WHERE model_id = %s"
    cursor.execute(sql_select_path, model_id)
    old_model_path = cursor.fetchone()[0]

    # 构建新的模型路径和文件名
    directory_part, filename_part = old_model_path.rsplit('/', 1)
    new_model_name = f"{model_name}.model"
    new_model_path = f"{directory_part}/{new_model_name}"

    # 检查是否存在具有相同名称的记录
    sql_check = "SELECT model_name FROM model_list WHERE model_name = %s AND model_id != %s"
    cursor.execute(sql_check, (model_name, model_id))
    duplicate_record = cursor.fetchone()

    if duplicate_record:
        # 存在重名记录
        jsondata = {'msg': '存在重名记录，请修改模型名称', 'code': '400'}
    else:
        # 执行更新操作并重命名模型文件
        sql_update = "UPDATE model_list SET model_name = %s, model_path = %s, remarks = %s WHERE model_id = %s"
        try:
            cursor.execute(sql_update, (model_name, new_model_path, model_remarks, model_id))
            conn.commit()

            # 重命名模型文件
            os.rename(old_model_path, new_model_path)

            jsondata = {'msg': '更新成功', 'code': '200'}
        except Exception as e:
            conn.rollback()
            jsondata = {'msg': '更新失败', 'code': '500'}
            print("提交出错:", e)

    cursor.close()
    conn.close()

    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def get_repair_code(req):
    fileid = req.POST['fileid']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    sql = """ SELECT repair_code FROM vulfile WHERE fileId = %s """
    jsondata = []

    conn.ping(reconnect=True)
    cursor.execute(sql, fileid)
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()
    jsondata = []
    if len(data) == 0:
        jsondata = {'msg': '结果为空', 'msg-code': '200'}
    else:
        for result in data:
            jsondata.append(dict(zip(row_headers, result)))
    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def git_detail_insert(positive_id, positive_name, url, size, file_num, upload_time, upload_id):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    sql = """insert into positive_sample(positive_id,positive_name,url,size,file_num,upload_time,upload_id) values(%s,%s,%s,%s,%s,%s,%s)"""
    jsondata = []

    conn.ping(reconnect=True)
    try:
        flag = cursor.execute(sql, [positive_id, positive_name, url, size, file_num, upload_time, upload_id])
        # print("数据插入成功")
        conn.commit()
    except Exception as e:
        flag = False
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()

    cursor.close()
    conn.close()

    if flag:
        jsondata = {'msg': '插入成功', 'code': '200'}
    else:
        jsondata = {'msg': '插入失败', 'code': '500'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def negative_insert(fileid, filename, filepath, vultype, upload_time):
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接

    sql1 = """select level from cwelist where number = %s"""

    sql = """INSERT into vulfile(taskid,fileid,filename,filepath,vultype,repair_status,is_question,risk_level,data1) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) """

    cursor.execute(sql1, [vultype])
    level = cursor.fetchone()[0]
    repair_status = '未修复'
    taskid = 0
    is_question = '是问题'

    flag = True
    try:
        flag = cursor.execute(sql, [taskid, fileid, filename, filepath, vultype, repair_status, is_question, level,
                                    upload_time])
        # print("数据插入成功")
        conn.commit()
    except Exception as e:
        flag = False
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()

    cursor.close()
    conn.close()

    if flag:
        jsondata = {'msg': '插入成功', 'code': '200'}
    else:
        jsondata = {'msg': '插入失败', 'code': '500'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


# 更新修复反馈
def repair_update(req):
    fileId = req.POST['fileId']
    repair_feedback = req.POST['repair_feedback']
    sql = """update vulfile set repair_feedback=%s where fileid=%s """
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    try:
        flag = cursor.execute(sql, [repair_feedback, fileId])
        conn.commit()
    except Exception as e:
        flag = False
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()
    cursor.close()
    conn.close()
    if flag:
        jsondata = {'msg': '更新成功', 'msg-code': '200'}
    else:
        jsondata = {'msg': '更新失败', 'msg-code': '500'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def check_task_name(task_name, item_id):
    # 判断是否存在同名任务
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    name_sql = """ select count(*) as count from vuldetail where taskname=%s and itemid = %s"""
    cursor.execute(name_sql, (task_name, item_id))
    data = cursor.fetchall()[0][0]
    if data != 0:
        return True  # 存在重名
    else:
        return False  # 不存在重名


def export_pdf(request):  # 导出PDF
    taskId = request.POST['taskId']
    itemId = request.POST['itemId']
    # teamName = request.POST['teamName']
    itemName = request.POST['itemName']
    pdf_Time = request.POST['pdf_Time']  # 创建pdf的时间
    zipName = request.POST['zipName']
    vulFileNumber = request.POST['vulFileNumber']
    language = request.POST['language']
    detect_type = request.POST['type']
    # createTime = request.POST['createTime']
    startTime = request.POST['startTime']
    lastTime = request.POST['lastTime']
    vuls = request.POST['vuls']  # 检测文件的所有漏洞类型

    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    # 统计每种漏洞的个数
    # sql = """ select (@rownum:=@rownum+1) AS num,name,count(*) as count from vulfile,(SELECT @rownum:=0) r,cwelist  where taskId = %s and lower(vulType)=number group by vulType order by num """  #只展示漏洞知识库列表有的漏洞
    # sql = """ select (@rownum:=@rownum+1) AS num,IFNULL(name,vulType) as cweName,count(*) as count from (SELECT @rownum:=0) r,
    # vulfile left join cwelist on lower(vulType)=number where vulId = '%s'  group by vulType order by num"""  # 展示所有的漏洞
    sql = """select (@rownum:=@rownum+1) AS num,vulType as cweName,count(*) as count from (SELECT @rownum:=0) r,vulfile where taskId = %s group by vulType order by num"""
    cursor.execute(sql, taskId)
    vul_number = cursor.fetchall()
    sql2 = """ select vulType,count(*) as count from vulfile where taskId = %s and vulType!='' group by vulType order by count desc limit 5"""
    cursor.execute(sql2, taskId)
    header_five = cursor.fetchall()
    sql3 = """ select fileName,lower(vulType),location,source_code,repair_code,Sink,Enclosing_Method,Source from vulfile where taskId = %s order by vulType """
    cursor.execute(sql3, taskId)
    file_location = cursor.fetchall()
    sql4 = """ select lower(vulType),count(*) as count from vulfile where taskId = %s group by vulType order by vulType """
    cursor.execute(sql4, taskId)
    number = cursor.fetchall()
    sql5 = """ select version from vuldetail where taskId = %s"""
    cursor.execute(sql5, taskId)
    version = cursor.fetchall()
    version = version[0][0]
    sql6 = """ select vultype, risk_level from vulfile where taskId = %s"""
    cursor.execute(sql6, taskId)
    risk_level = cursor.fetchall()
    risk_level_dict = {row[0]: row[1] for row in risk_level}
    try:
        pdfName = Graphs.export_pdf(itemName, pdf_Time, zipName, vulFileNumber, language, detect_type,
                                    startTime, lastTime, vul_number, header_five, vuls, file_location, number, version, risk_level_dict)
        #        print(f"itemName: {itemName},\n\n pdf_Time: {pdf_Time},\n\n zipName: {zipName},\n\n vulFileNumber: {vulFileNumber},\n\n language: {language},\n\n detect_type: {detect_type},\n\n startTime: {startTime},\n\n lastTime: {lastTime},\n\n vul_number: {vul_number},\n\n header_five: {header_five},\n\n vuls: {vuls},\n\n file_location: {file_location},\n\n number: {number}")
        url = 'http://10.99.16.24:8088/static/Export_PDF/' + pdfName
        jsondata = {'{}'.format(pdfName): url, 'code': '200'}
        sql_insert = """ insert into export_file(export_name,url,createTime,vulId,fileType,data1,data2,data3,itemId) values(%s,%s,%s,%s,'pdf',null,null,null,%s) """
        cursor.execute(sql_insert, [pdfName, url, pdf_Time, taskId, itemId])  # 将数据加入到数据库
        conn.commit()
    except Exception as e:
        jsondata = {'msg': '导出失败', 'code': '500'}
        print(e)
    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def export_word(request):
    try:
        jsondata = {'msg': 'word导出成功', 'code': '200'}
    except Exception as e:
        jsondata = {'msg': '导出失败', 'code': '500'}
        print(e)
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def export_json(request):
    try:
        jsondata = {'msg': 'json导出成功', 'code': '200'}
    except Exception as e:
        jsondata = {'msg': '导出失败', 'code': '500'}
        print(e)
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def export_html(request):
    try:
        jsondata = {'msg': 'html导出成功', 'code': '200'}
    except Exception as e:
        jsondata = {'msg': '导出失败', 'code': '500'}
        print(e)
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def export_getall(request, ):
    vulId = request.POST['vulId']
    accountId = request.POST['accountId']
    itemName = request.POST['itemName']
    taskname = request.POST['taskname']
    file_startTime = request.POST['file_startTime']
    file_endTime = request.POST['file_endTime']
    fileType = request.POST['fileType']
    vul_startTime = request.POST['vul_startTime']
    vul_endTime = request.POST['vul_endTime']
    page = int(request.POST['page'])
    rows = int(request.POST['rows'])
    start = (page - 1) * rows

    str_1 = """"""
    str_2 = """"""
    str_3 = """"""
    str_4 = """"""
    str_5 = """"""
    str_6 = """"""
    str_7 = """"""
    if vulId:
        str_1 = """ and v.id='%s' """ % vulId
    if itemName:
        str_2 = """ and itemname like '%%%s%%' """ % itemName
    if taskname:
        str_3 = """ and  taskname like '%%%s%%' """ % taskname
    if file_startTime and file_endTime:
        str_4 = """ and e.createTime>'%s' and e.createTime<'%s' """ % (file_startTime, file_endTime)
    if fileType:
        str_5 = """ and fileType='%s' """ % fileType
    if vul_startTime and vul_endTime:
        str_6 = """ and startTime>'%s' and startTime<'%s' """ % (vul_startTime, vul_endTime)
    if accountId:
        str_7 = """ and creator_id='%s' """ % accountId
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    sql_str = """ select count(*) as count from export_file e,vuldetail v,itemdetail i where vulId=v.taskid and v.itemId=i.itemid """ + str_1 + str_2 + str_3 + str_4 + str_5 + str_6 + str_7
    cursor.execute(sql_str)
    counts = cursor.fetchall()[0][0]
    sql = """ select e.id as id,taskname,itemname,startTime,export_name,e.createTime,fileType,v.data1 as data1,e.url from export_file e,vuldetail v,itemdetail i where vulId=v.taskid and v.itemId=i.itemid""" + str_1 + str_2 + str_3 + str_4 + str_5 + str_6 + str_7 + """order by createtime DESC limit %s,%s""" % (
    start, rows)
    cursor.execute(sql)
    row_headers = [x[0] for x in cursor.description]
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    jsondata = []
    if len(data) == 0:
        jsondata = {'count': counts, 'data': ''}
    else:
        for result in data:
            jsondata.append(dict(zip(row_headers, result)))
        jsondata = {'count': counts, 'data': jsondata}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def export_delete(request):
    id = request.POST['id']
    export_name = request.POST['export_name']
    fileType = request.POST['fileType']
    if fileType == 'excel':
        location = '../../static/export/' + export_name
    else:
        location = '../../static/Export_PDF/' + export_name
    if os.path.isfile(location):  # 如果文件存在，删掉文件
        os.remove(location)
    else:
        jsondata = {'msg': '文件不存在，删除失败，请手动删除数据库数据', 'code': '500'}
        return HttpResponse(json.dumps(jsondata, ensure_ascii=False))
    sql = """delete from export_file where id = %s"""
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    conn.ping(reconnect=True)  # 每次连接之前，会检查当前连接是否已关闭，如果连接关闭则会重新进行连接
    try:
        flag = cursor.execute(sql, id)
        conn.commit()
    except Exception as e:
        flag = False
        print("提交出错\n:", e)
        # 如果出错要回滚
        conn.rollback()
    cursor.close()
    conn.close()
    if flag:
        jsondata = {'msg': '删除成功', 'code': '200'}
    else:
        jsondata = {'msg': '文件删除成功，数据删除失败', 'code': '500'}
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def get_vulname(cwe_id):
    # 根据cwe_id获取漏洞名
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                name_sql = """select name from cwelist where number = %s"""
                cursor.execute(name_sql, (cwe_id,))
                data = cursor.fetchall()
                if data:
                    return data[0][0]
                else:
                    return "Vulnerability name not found"
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}")
        return "Error occurred while fetching vulnerability name"


def get_level(cwe_id,  vul_name=None):
    # 根据cwe_id获取危险等级
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                if vul_name:
                    name_sql = """select level from subVulList where name_EN = %s"""
                    cursor.execute(name_sql, (vul_name,))
                else :
                    name_sql = """select level from cwelist where number = %s"""
                    cursor.execute(name_sql, (cwe_id,))
                data = cursor.fetchall()
                if data:
                    return data[0][0]
                else:
                    return "Vulnerability level not found"
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}")
    return "Error occurred while fetching vulnerability level"

def get_level_CN(vul_name):
    # 根据cwe_id获取危险等级
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                if vul_name:
                    name_sql = """select level from subVulList where name_CN = %s"""
                    cursor.execute(name_sql, (vul_name,))
                data = cursor.fetchall()
                if data:
                    return data[0][0]
                else:
                    return "Vulnerability level not found"
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}{vul_name}")
    return "Error occurred while fetching vulnerability level"
    
def update_pid(taskid, pid):
    # 向指定 taskid 的任务中插入进程 pid
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 检查 taskid 是否存在
                check_sql = "SELECT taskid FROM vuldetail WHERE taskid = %s"
                cursor.execute(check_sql, (taskid,))
                result = cursor.fetchone()

                if result is None:
                    print(f"Task ID {taskid} does not exist.")
                    return "Task ID does not exist"

                # 更新 pid
                update_sql = """UPDATE vuldetail SET pid = %s WHERE taskid = %s"""
                cursor.execute(update_sql, (pid, taskid))
                conn.commit()

                print(f"Successfully updated PID {pid} for Task ID {taskid}.")
                return "Success"

    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}")
        return "Error occurred while updating PID"


def get_taskid(task_name, item_id):
    # 根据task_name和项目id获取task_id
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                sql = "SELECT taskid FROM vuldetail WHERE taskname = %s and itemid = %s"
                cursor.execute(sql, (task_name, item_id))
                result = cursor.fetchone()

                if result is None:
                    return "Task ID does not exist"
                else:
                    return result[0]

    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}")
        return "Error occurred while getting taskid"


def get_pid(taskid):
    # 根据task_id和获取pid
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                sql = "SELECT pid FROM vuldetail WHERE taskid = %s"
                cursor.execute(sql, (taskid,))
                result = cursor.fetchone()

                if result is None:
                    return "PID does not exist"
                else:
                    return result[0]

    except Exception as e:
        print(f"Error: {e}")
        return "Error occurred while getting pid"


def update_status(taskid, status):
    # 根据task_id修改检测状态
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                sql = "update vuldetail set status = %s where taskid = %s"
                cursor.execute(sql, (status, taskid))
                conn.commit()
                print(f"检测状态已修改为：{status}")

    except Exception as e:
        print(f"Error: {e}")
        return "Error occurred while updating status"

def offer_subVul():
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                sql = "SELECT id, name_CN FROM subVulList"
                cursor.execute(sql)
                results = cursor.fetchall()  # 获取所有结果
                vulList = []
                for row in results:
                    vul = {'id':row[0],'name':row[1]}
                    vulList.append(vul)
                return JsonResponse({"code": "200", "vulList": vulList})
    except Exception as e:
        print(f"Error:{e}")
        return JsonResponse({"error":"查询失败", "code":"500"})
        
def create_policy(req):
    policy_name= req.POST['policy_name']
    vul_list = tuple(req.POST['vul_list'].split(','))

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 首先查看有没有这个策略名，没有的话就新建一个策略，有的话就不修改策略表
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                sql = "select id from subVulPolicies where name = %s"
                cursor.execute(sql, (policy_name,))
                policy_id_list = cursor.fetchone()
                if policy_id_list is None:
                    sql2 = "insert into subVulPolicies(name, timestamp) values(%s, %s)"
                    cursor.execute(sql2, (policy_name, timestamp))
                    conn.commit()

                    sql3 = "select id from subVulPolicies where name = %s"
                    cursor.execute(sql3, (policy_name,))
                    policy_id_list = cursor.fetchone()
                policy_id = policy_id_list[0]

                # 第二步，然后删除该策略当前的漏洞类型
                sql4 = "delete from subVulPolicySelected where policy_id = %s"
                cursor.execute(sql4, (policy_id,))
                # 第三步，针对该策略，把对应的漏洞类型存入漏洞类型选中表
                for vul_id in vul_list:
                    sql5 = "insert into subVulPolicySelected(policy_id, vul_id) values(%s, %s)"
                    cursor.execute(sql5, (policy_id, vul_id))

                conn.commit()
                return JsonResponse({"code": "200", "msg":"创建成功"})
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error:{e}")
        return JsonResponse({"error": "创建失败", "code": "500"})

#def search_policy(req):
#    policy_name = req.POST['policy_name']
#    sql1 = "select id from subVulPolicies where name = %s" # 获取policy_id
#    sql2 = "select vul_id from subVulPolicySelected where policy_id = %s" # 获取vul_id
#    sql3 = "select id, name_CN from subVulList where id = %s" # 获取vul_id对应的漏洞名称
#
#    try:
#        with pymysql.connect(**config) as conn:
#            with conn.cursor() as cursor:
#                cursor.execute(sql1, (policy_name,))
#                policy_id = cursor.fetchone()[0]
#
#                cursor.execute(sql2, (policy_id,))
#                vul_id_list = cursor.fetchall()
#                vul_id = []
#                for row in vul_id_list:
#                    vul_id.append(row[0])
#
#                results = []
#                for id in vul_id:
#                    cursor.execute(sql3, (id,))
#                    result = cursor.fetchone()
#                    results.append(result)
#
#                vulList = []
#                for row in results:
#                    vul = {'id': row[0], 'name': row[1]}
#                    vulList.append(vul)
#                return JsonResponse({"code": "200", "vulList": vulList})
#    except Exception as e:
#        print(f"Error:{e}")
#        return JsonResponse({"error": "查询失败", "code": "500"})

def get_all_policies(req):
    # 获取请求参数
    policy_name = req.POST.get('policy_name', '')  # 从 GET 请求中获取 policy_name 参数
    print(f"接收到的 policy_name: {policy_name}")  # 打印日志
    sql = "select name from subVulPolicies" # 获取所有的policy_name
    sql1 = "select id, timestamp,status from subVulPolicies where name = %s" # 根据policy_name获取policy_id和timestamp
    sql2 = "select vul_id from subVulPolicySelected where policy_id = %s" # 获取vul_id
    sql3 = "select id, name_CN from subVulList where id = %s" # 获取vul_id对应的漏洞名称

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 如果传入了 policy_name，则只查询该策略
                if policy_name:
                    cursor.execute(sql1, (policy_name,))
                    policy_info = cursor.fetchone()
                    policies = []
                    if not policy_info:
                        return JsonResponse({"code": "404", "msg": "策略未找到"})

                    # 确保查询结果包含 3 个字段
                    if len(policy_info) != 3:
                        return JsonResponse({"error": "查询结果字段数量不匹配", "code": "500"})

                    policy_id, timestamp, status = policy_info

                    cursor.execute(sql2, (policy_id,))
                    vul_id_list = cursor.fetchall()
                    vul_id = [row[0] for row in vul_id_list]

                    results = []
                    for id in vul_id:
                        cursor.execute(sql3, (id,))
                        result = cursor.fetchone()
                        if result:
                            results.append(result)

                    vulList = [{'id': row[0], 'name': row[1]} for row in results]
                    policies = [{
                        "policy_id": policy_id,
                        "timestamp": timestamp,
                        "status": status,
                        "policy_name": policy_name,
                        "vulList": vulList
                    }]
                else:
                    # 如果没有传入 policy_name，则查询所有策略
                    cursor.execute(sql)
                    names = cursor.fetchall()
                    policies = []

                    for policy_name in names:
                        policy_name = policy_name[0]
                        cursor.execute(sql1, (policy_name,))
                        policy_id, timestamp, status = cursor.fetchone()

                        cursor.execute(sql2, (policy_id,))
                        vul_id_list = cursor.fetchall()
                        vul_id = []
                        for row in vul_id_list:
                            vul_id.append(row[0])

                        results = []
                        for id in vul_id:
                            cursor.execute(sql3, (id,))
                            result = cursor.fetchone()
                            results.append(result)

                        vulList = []
                        for row in results:
                            vul = {'id': row[0], 'name': row[1]}
                            vulList.append(vul)

                        policies.append({"policy_id":policy_id, "timestamp":timestamp,"status":status,"policy_name":policy_name, "vulList":vulList})

                return JsonResponse({"code": "200", "policies": policies})
    except Exception as e:
        print(f"Error:{e}")
        return JsonResponse({"error": "查询失败", "code": "500"})


def delete_policy(req):
    policy_id = req.POST['policy_id']
    sql1 = "select * from subVulPolicies where id = %s" # 查看该策略是否存在，如果不存在则返回创建失败
    sql2 = "delete from subVulPolicySelected where policy_id = %s" # 然后删除该策略当前的漏洞类型
    sql3 = "delete from subVulPolicies where id = %s" # 删除该策略

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql1, (policy_id,))
                isExist = cursor.fetchone()
                if isExist is None:
                    return JsonResponse({"error": "不存在该策略，删除失败", "code": "500"})

                cursor.execute(sql2, (policy_id,))
                cursor.execute(sql3, (policy_id,))

                conn.commit()
                return JsonResponse({"code": "200", "msg": "删除成功"})
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error:{e}")
        return JsonResponse({"error": "删除失败", "code": "500"})

def update_policy(req):
    policy_id = req.POST['policy_id']
    vul_list = tuple(req.POST['vul_list'].split(','))
    sql1 = "select * from subVulPolicies where id = %s"  # 查看该策略是否存在，如果不存在则返回修改失败
    sql2 = "delete from subVulPolicySelected where policy_id = %s"  # 然后删除该策略当前的漏洞类型
    sql3 = "insert into subVulPolicySelected(policy_id, vul_id) values(%s, %s)"  # 更新该策略

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql1, (policy_id,))
                isExist = cursor.fetchone()
                if isExist is None:
                    return JsonResponse({"error": "不存在该策略，更新失败", "code": "500"})

                cursor.execute(sql2, (policy_id,))
                for vul_id in vul_list:
                    cursor.execute(sql3, (policy_id,vul_id))

                conn.commit()
                return JsonResponse({"code": "200", "msg": "更新成功"})
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error:{e}")
        return JsonResponse({"error": "更新失败", "code": "500"})

def get_rule_function_name():
    '''获取启用规则的函数名'''
    try:
        # 连接数据库
        conn = pymysql.connect(**config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)  # 使用字典游标
        conn.ping(reconnect=True)

        # 执行查询
        sql = """select svl.* from subVulPolicies svp left join subVulPolicySelected svps on svp.id = svps.policy_id left join subVulList svl on svps.vul_id = svl.id where svp.status = '1'"""
        cursor.execute(sql)
        data = cursor.fetchall()
        #print(data)

    except pymysql.Error as e:
        print(f"数据库错误: {e}")
        data = []
    finally:
        # 关闭连接
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return data

# def send_wechat_work_message(request):
#     """
#     发送企业微信消息
#     :param request: Django 请求对象，需包含 webhook_url 和 message
#     """
#     try:
#         # 从请求中获取 webhook_url 和 message
#         webhook_url = request.POST.get('webhook_url')
#         message = request.POST.get('message')
#
#         # 检查参数是否为空
#         if not webhook_url or not message:
#             return JsonResponse({'msg': 'webhook_url 和 message 不能为空', 'msg-code': '400'}, status=400)
#
#         # 固定使用 text 类型
#         message_type = "text"
#
#         headers = {'Content-Type': 'application/json'}
#         payload = {
#             "msgtype": message_type,
#             "text": {
#                 "content": message
#             }
#         }
#
#         # 发送请求
#         response = requests.post(webhook_url, json=payload, headers=headers)
#         if response.status_code == 200:
#             return JsonResponse({'msg': '企业微信消息发送成功', 'msg-code': '200'})
#         else:
#             return JsonResponse(
#                 {'msg': f'发送失败，状态码：{response.status_code}, 响应内容：{response.text}', 'msg-code': '500'},
#                 status=500)
#
#     except Exception as e:
#         return JsonResponse({'msg': f'发送企业微信消息时发生错误：{e}', 'msg-code': '500'}, status=500)

def save_to_db(sender, message):
    """
    将发送结果保存到数据库
    :param sender: 发送者（如 webhook_url 或 sender_email）
    :param message: 发送的消息内容
    """
    connection = None  # 初始化 connection 变量
    try:
        # 连接数据库
        connection = pymysql.connect(**config)
        with connection.cursor() as cursor:
            # 插入日志
            sql = """
                INSERT INTO alarm_logs (create_time, sender, message)
                VALUES (%s, %s, %s)
            """
            create_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # 使用 datetime 获取当前时间
            cursor.execute(sql, (create_time, sender, message))
        connection.commit()
    except Exception as e:
        print(f"保存日志到数据库失败：{e}")
    finally:
        if connection:
            connection.close()

def send_wechat_work_message(request):
    """
    发送企业微信消息
    """
    try:
        webhook_url = request.POST.get('webhook_url')
        message = request.POST.get('message')

        if not webhook_url or not message:
            return JsonResponse({'msg': 'webhook_url 和 message 不能为空', 'msg-code': '400'}, status=400)

        # 固定使用 text 类型
        message_type = "text"

        headers = {'Content-Type': 'application/json'}
        payload = {
            "msgtype": message_type,
            "text": {
                "content": message
            }
        }

        # 发送请求
        response = requests.post(webhook_url, json=payload, headers=headers)
        if response.status_code == 200:
            # 发送成功后保存日志
            save_to_db(webhook_url, message)
            return JsonResponse({'msg': '企业微信消息发送成功', 'msg-code': '200'})
        else:
            return JsonResponse(
                {'msg': f'发送失败，状态码：{response.status_code}, 响应内容：{response.text}', 'msg-code': '500'},
                status=500)

    except Exception as e:
        return JsonResponse({'msg': f'发送企业微信消息时发生错误：{e}', 'msg-code': '500'}, status=500)
def add_wechat_info(request):
    """
    向 wechat 表中添加 wechat_name 和 webhook_url 字段
    """
    try:
        wechat_name = request.POST.get('wechat_name')
        webhook_url = request.POST.get('webhook_url')

        if not wechat_name or not webhook_url:
            return JsonResponse({'msg': 'wechat_name 和 webhook_url 不能为空', 'msg-code': '400'}, status=400)

        connection = None  # 初始化 connection 变量
        try:
            # 连接数据库
            connection = pymysql.connect(**config)
            with connection.cursor() as cursor:
                # 插入数据
                sql = """
                    INSERT INTO wechat (wechat_name, webhook_url)
                    VALUES (%s, %s)
                """
                cursor.execute(sql, (wechat_name, webhook_url))
            connection.commit()
            return JsonResponse({'msg': '数据添加成功', 'msg-code': '200'})
        except Exception as e:
            print(f"保存数据到数据库失败：{e}")
            return JsonResponse({'msg': f'保存数据到数据库失败：{e}', 'msg-code': '500'}, status=500)
        finally:
            if connection:
                connection.close()
    except Exception as e:
        return JsonResponse({'msg': f'添加数据时发生错误：{e}', 'msg-code': '500'}, status=500)
def get_wechat_info(request):
    """
    查看 wechat 表中的数据，返回格式为每行一个 wechat_name 和 webhook_url
    """
    try:
        connection = None  # 初始化 connection 变量
        try:
            # 连接数据库
            connection = pymysql.connect(**config)
            with connection.cursor() as cursor:
                # 查询数据
                sql = """
                    SELECT wechat_name, webhook_url FROM wechat
                """
                cursor.execute(sql)
                result = cursor.fetchall()

                # 将查询结果格式化为每行一个字典
                data = [{"wechat_name": row[0], "webhook_url": row[1]} for row in result]

            return JsonResponse({'msg': '数据查询成功', 'data': data, 'msg-code': '200'})
        except Exception as e:
            print(f"查询数据失败：{e}")
            return JsonResponse({'msg': f'查询数据失败：{e}', 'msg-code': '500'}, status=500)
        finally:
            if connection:
                connection.close()
    except Exception as e:
        return JsonResponse({'msg': f'查询数据时发生错误：{e}', 'msg-code': '500'}, status=500)

def send_station_mail(request):
    """
    发送站内通知并保存日志到数据库
    """
    try:
        sender = request.POST.get('sender')  # 获取发送者（如 webhook_url 或 sender_email）
        message = request.POST.get('message')  # 获取消息内容

        if not sender or not message:
            return JsonResponse({'msg': 'sender 和 message 不能为空', 'msg-code': '400'}, status=400)

        # 将发送结果保存到数据库
        save_to_db(sender, message)

        return JsonResponse({'msg': '站内通知发送成功', 'msg-code': '200'})

    except Exception as e:
        # 发送失败后保存日志
        error_message = f"站内通知发送失败：{e}"
        save_to_db(sender, message)
        return JsonResponse({'msg': error_message, 'msg-code': '500'}, status=500)
def query_alarm_logs(request):
    """
    根据 sender 查询 alarm_logs 表中的 message 和 create_time
    """
    if request.method != 'POST':
        return JsonResponse({'msg': '仅支持 POST 请求', 'msg-code': '400'}, status=400)

    try:
        # 获取 POST 请求参数
        sender = request.POST.get('sender')  # 发送者

        if not sender:
            return JsonResponse({'msg': 'sender 不能为空', 'msg-code': '400'}, status=400)

        # 构建查询 SQL
        sql = """
            SELECT create_time, message
            FROM alarm_logs
            WHERE sender = %s
            ORDER BY create_time DESC
        """
        params = [sender]

        # 连接数据库并执行查询
        connection = None
        try:
            connection = pymysql.connect(**config)
            with connection.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(sql, params)
                logs = cursor.fetchall()  # 获取查询结果

            # 返回查询结果
            return JsonResponse({
                'msg': '查询成功',
                'msg-code': '200',
                'data': logs
            })

        except Exception as e:
            print(f"查询数据库失败：{e}")
            return JsonResponse({'msg': '查询失败', 'msg-code': '500'}, status=500)

        finally:
            if connection:
                connection.close()

    except Exception as e:
        # 捕获其他异常
        error_message = f"查询接口异常：{e}"
        return JsonResponse({'msg': error_message, 'msg-code': '500'}, status=500)
def send_email(request):
    """
    发送邮件
    """
    try:
        receiver_email = request.POST.get('receiver_email')
        message = request.POST.get('message')

        if not receiver_email or not message:
            return JsonResponse({'msg': 'receiver_email 和 message 不能为空', 'msg-code': '400'}, status=400)

        # 邮件配置
        email_config = {
            'sender_email': '253480155@qq.com',  # 发件人邮箱
            'smtp_server': 'smtp.qq.com',  # QQ 邮箱 SMTP 服务器地址
            'smtp_port': 465,  # QQ 邮箱 SMTP 端口（SSL）
            'smtp_username': '253480155@qq.com',  # 发件人邮箱地址
            'smtp_password': 'pghjrkkphulmcaca'  # 授权码（非邮箱密码）
        }

        subject = "漏洞告警通知"

        # 创建邮件对象
        msg = MIMEMultipart()
        msg['From'] = email_config['sender_email']
        msg['To'] = receiver_email
        msg['Subject'] = subject

        # 添加邮件正文
        msg.attach(MIMEText(message, 'plain'))

        # 连接 SMTP 服务器（使用 SSL）
        with smtplib.SMTP_SSL(email_config['smtp_server'], email_config['smtp_port']) as server:
            server.login(email_config['smtp_username'], email_config['smtp_password'])  # 登录邮箱
            server.sendmail(email_config['sender_email'], receiver_email, msg.as_string())  # 发送邮件

        # 发送成功后保存日志
        save_to_db(email_config['sender_email'], message)
        return JsonResponse({'msg': '邮件发送成功', 'msg-code': '200'})

    except Exception as e:
        # 发送失败后保存日志
        error_message = f"邮件发送失败：{e}"
        save_to_db(email_config['sender_email'], message)
        return JsonResponse({'msg': error_message, 'msg-code': '500'}, status=500)
def add_email_info(request):
    """
    向 email 表中插入 email_name 和 receiver_email 字段
    """
    try:
        email_name = request.POST.get('email_name')
        receiver_email = request.POST.get('receiver_email')

        if not email_name or not receiver_email:
            return JsonResponse({'msg': 'email_name 和 receiver_email 不能为空', 'msg-code': '400'}, status=400)

        connection = None  # 初始化 connection 变量
        try:
            # 连接数据库
            connection = pymysql.connect(**config)
            with connection.cursor() as cursor:
                # 插入数据
                sql = """
                    INSERT INTO email (email_name, receiver_email)
                    VALUES (%s, %s)
                """
                cursor.execute(sql, (email_name, receiver_email))
            connection.commit()
            return JsonResponse({'msg': '数据添加成功', 'msg-code': '200'})
        except Exception as e:
            print(f"保存数据到数据库失败：{e}")
            return JsonResponse({'msg': f'保存数据到数据库失败：{e}', 'msg-code': '500'}, status=500)
        finally:
            if connection:
                connection.close()
    except Exception as e:
        return JsonResponse({'msg': f'添加数据时发生错误：{e}', 'msg-code': '500'}, status=500)
def get_email_info(request):
    """
    查询 email 表中的数据，返回格式为每行一个 email_name 和 receiver_email
    """
    try:
        connection = None  # 初始化 connection 变量
        try:
            # 连接数据库
            connection = pymysql.connect(**config)
            with connection.cursor() as cursor:
                # 查询数据
                sql = """
                    SELECT email_name, receiver_email FROM email
                """
                cursor.execute(sql)
                result = cursor.fetchall()

                # 将查询结果格式化为每行一个字典
                data = [{"email_name": row[0], "receiver_email": row[1]} for row in result]

            return JsonResponse({'msg': '数据查询成功', 'data': data, 'msg-code': '200'})
        except Exception as e:
            print(f"查询数据失败：{e}")
            return JsonResponse({'msg': f'查询数据失败：{e}', 'msg-code': '500'}, status=500)
        finally:
            if connection:
                connection.close()
    except Exception as e:
        return JsonResponse({'msg': f'查询数据时发生错误：{e}', 'msg-code': '500'}, status=500)
def update_policyStatus(req):
    # 获取请求参数
    policy_id = req.POST.get('policy_id')
    if not policy_id:
        return JsonResponse({"error": "策略ID不能为空", "code": "400"})

    # 定义 SQL 语句
    sql_disable_all = "UPDATE subVulPolicies SET status = '0';"  # 禁用所有策略
    sql_enable_policy = "UPDATE subVulPolicies SET status = '1' WHERE id = %s;"  # 启用指定策略
    sql_check_policy = "SELECT id FROM subVulPolicies WHERE id = %s;"  # 检查策略是否存在

    try:
        # 连接数据库
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 检查策略是否存在
                cursor.execute(sql_check_policy, (policy_id,))
                if not cursor.fetchone():
                    return JsonResponse({"error": "不存在该策略，更新失败", "code": "404"})

                # 禁用所有策略
                cursor.execute(sql_disable_all)

                # 启用指定策略
                cursor.execute(sql_enable_policy, (policy_id,))

                # 提交事务
                conn.commit()

                return JsonResponse({"code": "200", "msg": "更新成功"})
    except pymysql.MySQLError as e:
        # 回滚事务并记录错误
        if 'conn' in locals() and conn:
            conn.rollback()
        print(f"数据库错误: {e}")
        return JsonResponse({"error": "数据库操作失败", "code": "500"})
    except Exception as e:
        # 捕获其他异常
        print(f"未知错误: {e}")
        return JsonResponse({"error": "更新失败", "code": "500"})

def get_clean_func(language, vul_name):
    # 获取清洁函数
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                sql = """select cf.func_name from clean_func cf left join subVulList svl on cf.vul_id = svl.id where svl.name_EN = %s and (language = %s or language = 'all') and status = '1'"""
                cursor.execute(sql, (vul_name,language,))
                data = cursor.fetchall()
                if data:
                    # 将查询结果转换为清洁函数名称列表
                    clean_funcs = [row[0] for row in data]
                    return clean_funcs
                else:
                    return []
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}")
    return "Error occurred while fetching clean function"

def get_custom_rules(language):
    # 获取自定义规则
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                sql = """select svl.name_EN,cr.func_name from custom_rules cr left join subVulList svl on cr.vul_id = svl.id where (language = %s or language = 'all') and status = '1' """
                cursor.execute(sql, (language,))
                data = cursor.fetchall()
                if data:
                    # 将查询结果转换为自定义规则名称列表
                    custom_rules = [{'name': row[0], 'pattern': row[1]} for row in data]
                    return custom_rules
                else:
                    return []
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}")
    return "Error occurred while fetching custom rules"

def select_clean_func(req):
    # 获取清洁函数
    try:
        id = req.POST.get('id')
        vul_name = req.POST.get('vul_name')
        language = req.POST.get('language')
        status = req.POST.get('status')
        page = int(req.POST.get('page'))
        rows = int(req.POST.get('rows'))
        sql = """SELECT cf.*, svl.name_CN FROM clean_func cf LEFT JOIN subVulList svl ON cf.vul_id = svl.id WHERE 1 = 1 """
        count_sql = """SELECT COUNT(*) as total FROM clean_func cf LEFT JOIN subVulList svl ON cf.vul_id = svl.id WHERE 1 = 1 """
        params = []  # 用于存储动态参数

        # 动态添加查询条件
        if id:
            sql += " AND cf.id = %s "
            count_sql += " AND cf.id = %s "
            params.append(id)
        if vul_name:
            sql += " AND svl.name_CN LIKE %s "
            count_sql += " AND svl.name_CN LIKE %s "
            params.append(f"%{vul_name}%")
        if language:
            sql += " AND cf.language = %s "
            count_sql += " AND cf.language = %s "
            params.append(language)
        if status:
            sql += " AND cf.status = %s "
            count_sql += " AND cf.status = %s "
            params.append(status)

        # 计算分页偏移量
        offset = (page - 1) * rows
        sql += "LIMIT %s,%s"  # 添加分页
        params.extend([offset, rows])  # 添加分页参数

        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 查询总行数
                cursor.execute(count_sql, params[:-2])  # 去掉分页参数
                total = cursor.fetchone()
                total = total[0] if total else 0

                # 查询分页数据
                cursor.execute(sql, params)
                row_headers = [x[0] for x in cursor.description]
                data = cursor.fetchall()

                # 构造返回数据
                jsondata = []
                if len(data) == 0:
                    jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
                else:
                    for result in data:
                        jsondata.append(dict(zip(row_headers, result)))

                # 添加分页信息
                pagination_info = {
                    'total': total,  # 总行数
                    'page': page,  # 当前页
                    'rows': rows,  # 每页行数
                }

                return HttpResponse(
                    json.dumps({'fileList': jsondata, 'pagination': pagination_info}, ensure_ascii=False),
                    content_type="application/json")
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}")
        return HttpResponse(json.dumps({'error': str(e)}), content_type="application/json", status=500)
    except Exception as e:
        print(f"Unexpected Error: {e}")
        return HttpResponse(json.dumps({'error': 'An unexpected error occurred'}), content_type="application/json",
                            status=500)


def insert_clean_func(req):
    """
    新增清洁函数

    Args:
        req (HttpRequest): Django 的 HTTP 请求对象

    Returns:
        HttpResponse: 保存成功或失败的 JSON 响应
    """
    language = req.POST["language"]
    name = req.POST["name"]
    vul_id = req.POST["vul_id"]
    func_name = req.POST["func_name"]
    notes = req.POST["notes"]
    status = req.POST["status"]

    sql = "insert into clean_func(language,name,vul_id,func_name,status,notes) values (%s,%s,%s,%s,%s,%s)"

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, (language, name, vul_id, func_name, status, notes))
                conn.commit()
        return HttpResponse(json.dumps({'msg': '新增成功', 'msg-code': '200'}))
    except Exception as e:
        print(f"提交出错\n: {e}")
        conn.rollback()
        return HttpResponse(json.dumps({'msg': '新增失败', 'msg-code': '500'}))


def delete_clean_func(req):
    """
    删除清洁函数

    Args:
        req (HttpRequest): Django 的 HTTP 请求对象

    Returns:
        HttpResponse: 保存成功或失败的 JSON 响应
    """
    id = req.POST["id"]

    sql = "delete from clean_func where id = %s"

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, (id,))
                conn.commit()
        return HttpResponse(json.dumps({'msg': '删除成功', 'msg-code': '200'}))
    except Exception as e:
        print(f"提交出错\n: {e}")
        conn.rollback()
        return HttpResponse(json.dumps({'msg': '删除失败', 'msg-code': '500'}))


def update_clean_func(req):
    """
    修改清洁函数（包括启用、禁用）

    Args:
        req (HttpRequest): Django 的 HTTP 请求对象

    Returns:
        HttpResponse: 保存成功或失败的 JSON 响应
    """
    id = req.POST["id"]
    language = req.POST["language"]
    name = req.POST["name"]
    vul_id = req.POST["vul_id"]
    func_name = req.POST["func_name"]
    notes = req.POST["notes"]
    status = req.POST["status"]

    sql = "update clean_func set "
    updates = []
    params = []

    if language:
        updates.append("language = %s")
        params.append(language)
    if name:
        updates.append("name = %s")
        params.append(name)
    if vul_id:
        updates.append("vul_id = %s")
        params.append(vul_id)
    if func_name:
        updates.append("func_name = %s")
        params.append(func_name)
    if notes:
        updates.append("notes = %s")
        params.append(notes)
    if status:
        updates.append("status = %s")
        params.append(status)

    # 如果没有提供任何更新字段，返回错误
    if not updates:
        return HttpResponse(json.dumps({'msg': '没有提供更新字段', 'msg-code': '400'}), status=400)

    sql += ", ".join(updates)
    sql += " WHERE id = %s"
    params.append(id)

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, params)
                conn.commit()
        return HttpResponse(json.dumps({'msg': '修改成功', 'msg-code': '200'}))
    except Exception as e:
        print(f"提交出错\n: {e}")
        conn.rollback()
        return HttpResponse(json.dumps({'msg': '修改失败', 'msg-code': '500'}))

def select_custom_rules(req):
    # 获取自定义规则
    try:
        id = req.POST.get('id')
        vul_name = req.POST.get('vul_name')
        language = req.POST.get('language')
        status = req.POST.get('status')
        page = int(req.POST.get('page'))
        rows = int(req.POST.get('rows'))
        sql = """SELECT cr.*, svl.name_CN FROM custom_rules cr LEFT JOIN subVulList svl ON cr.vul_id = svl.id WHERE 1 = 1 """
        count_sql = """SELECT COUNT(*) as total FROM custom_rules cr LEFT JOIN subVulList svl ON cr.vul_id = svl.id WHERE 1 = 1 """
        params = []  # 用于存储动态参数

        # 动态添加查询条件
        if id:
            sql += " AND cr.id = %s "
            count_sql += " AND cr.id = %s "
            params.append(id)
        if vul_name:
            sql += " AND svl.name_CN LIKE %s "
            count_sql += " AND svl.name_CN LIKE %s "
            params.append(f"%{vul_name}%")
        if language:
            sql += " AND cr.language = %s "
            count_sql += " AND cr.language = %s "
            params.append(language)
        if status:
            sql += " AND cr.status = %s "
            count_sql += " AND cr.status = %s "
            params.append(status)

        # 计算分页偏移量
        offset = (page - 1) * rows
        sql += "LIMIT %s,%s"  # 添加分页
        params.extend([offset, rows])  # 添加分页参数

        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 查询总行数
                cursor.execute(count_sql, params[:-2])  # 去掉分页参数
                total = cursor.fetchone()
                total = total[0] if total else 0

                # 查询分页数据
                cursor.execute(sql, params)
                row_headers = [x[0] for x in cursor.description]
                data = cursor.fetchall()

                # 构造返回数据
                jsondata = []
                if len(data) == 0:
                    jsondata = {'msg': '统计结果为空', 'msg-code': '200'}
                else:
                    for result in data:
                        jsondata.append(dict(zip(row_headers, result)))

                # 添加分页信息
                pagination_info = {
                    'total': total,  # 总行数
                    'page': page,  # 当前页
                    'rows': rows,  # 每页行数
                }

                return HttpResponse(
                    json.dumps({'fileList': jsondata, 'pagination': pagination_info}, ensure_ascii=False),
                    content_type="application/json")
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}")
        return HttpResponse(json.dumps({'error': str(e)}), content_type="application/json", status=500)
    except Exception as e:
        print(f"Unexpected Error: {e}")
        return HttpResponse(json.dumps({'error': 'An unexpected error occurred'}), content_type="application/json",
                            status=500)


def insert_custom_rules(req):
    """
    新增自定义规则

    Args:
        req (HttpRequest): Django 的 HTTP 请求对象

    Returns:
        HttpResponse: 保存成功或失败的 JSON 响应
    """
    language = req.POST["language"]
    name = req.POST["name"]
    vul_id = req.POST["vul_id"]
    func_name = req.POST["func_name"]
    notes = req.POST["notes"]
    status = req.POST["status"]

    sql = "insert into custom_rules(language,name,vul_id,func_name,status,notes) values (%s,%s,%s,%s,%s,%s)"

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, (language, name, vul_id, func_name, status, notes))
                conn.commit()
        return HttpResponse(json.dumps({'msg': '新增成功', 'msg-code': '200'}))
    except Exception as e:
        print(f"提交出错\n: {e}")
        conn.rollback()
        return HttpResponse(json.dumps({'msg': '新增失败', 'msg-code': '500'}))


def delete_custom_rules(req):
    """
    删除自定义规则

    Args:
        req (HttpRequest): Django 的 HTTP 请求对象

    Returns:
        HttpResponse: 保存成功或失败的 JSON 响应
    """
    id = req.POST["id"]

    sql = "delete from custom_rules where id = %s"

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, (id,))
                conn.commit()
        return HttpResponse(json.dumps({'msg': '删除成功', 'msg-code': '200'}))
    except Exception as e:
        print(f"提交出错\n: {e}")
        conn.rollback()
        return HttpResponse(json.dumps({'msg': '删除失败', 'msg-code': '500'}))


def update_custom_rules(req):
    """
    修改清洁函数（包括启用、禁用）

    Args:
        req (HttpRequest): Django 的 HTTP 请求对象

    Returns:
        HttpResponse: 保存成功或失败的 JSON 响应
    """
    id = req.POST["id"]
    language = req.POST["language"]
    name = req.POST["name"]
    vul_id = req.POST["vul_id"]
    func_name = req.POST["func_name"]
    notes = req.POST["notes"]
    status = req.POST["status"]

    sql = "update custom_rules set "
    updates = []
    params = []

    if language:
        updates.append("language = %s")
        params.append(language)
    if name:
        updates.append("name = %s")
        params.append(name)
    if vul_id:
        updates.append("vul_id = %s")
        params.append(vul_id)
    if func_name:
        updates.append("func_name = %s")
        params.append(func_name)
    if notes:
        updates.append("notes = %s")
        params.append(notes)
    if status:
        updates.append("status = %s")
        params.append(status)

    # 如果没有提供任何更新字段，返回错误
    if not updates:
        return HttpResponse(json.dumps({'msg': '没有提供更新字段', 'msg-code': '400'}), status=400)

    sql += ", ".join(updates)
    sql += " WHERE id = %s"
    params.append(id)

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, params)
                conn.commit()
        return HttpResponse(json.dumps({'msg': '修改成功', 'msg-code': '200'}))
    except Exception as e:
        print(f"提交出错\n: {e}")
        conn.rollback()
        return HttpResponse(json.dumps({'msg': '修改失败', 'msg-code': '500'}))

def index(req):
    method = req.POST["method"]
    if method == "login":
        return login(req)
    elif method == "check":
        return check(req)
    elif method == "project_delete":
        return project_delete(req)
    elif method == "account_insert":
        return account_insert(req)
    elif method == "account_delete":
        return account_delete(req)
    elif method == "account_update":
        return account_update(req)
    elif method == "account_update_pass":
        return account_update_pass(req)
    elif method == "account_getall":
        return account_getall(req)
    elif method == "count_team":
        return count_team(req)
    elif method == "insert_Pol":
        return insert_Pol(req)
    elif method == "get_Pol":
        return get_Pol(req)
    elif method == 'get_item_num':
        return get_item_num(req)
    elif method == 'TaskNum_Time':
        return TaskNum_Time(req)
    elif method == 'LevelNum_Time':
        return LevelNum_Time(req)
    elif method == 'get_all_vultype_files':
        return get_all_vultype_files(req)
    elif method == 'VulType_get':
        return VulType_get(req)
    elif method == 'Task_Detail_1':
        return Task_Detail_1(req)
    elif method == 'Task_Detail_2':
        return Task_Detail_2(req)
    elif method == 'Task_Detail_3':
        return Task_Detail_3(req)
    elif method == 'Homepage_statistics':
        return Homepage_statistics(req)
    elif method == 'file_detail':
        return file_detail(req)
    elif method == 'vul_statistics':
        return vul_statistics(req)
    elif method == 'item_list':
        return item_list(req)
    elif method == 'task_list':
        return task_list(req)
    elif method == 'itemdetail_insert':
        return itemdetail_insert(req)
    elif method == 'task_delete':
        return task_delete(req)
    elif method == 'project_statistics':
        return project_statistics(req)
    elif method == 'review_update':
        return review_update(req)
    elif method == 'negative_time_query':
        return negative_time_query(req)
    elif method == 'get_model_id':
        return get_model_id(req)
    elif method == 'negative_list':
        return negative_list(req)
    elif method == 'positive_list':
        return positive_list(req)
    elif method == 'delete_model':
        return delete_model(req)
    elif method == 'update_model':
        return update_model(req)
    elif method == 'get_repair_code':
        return get_repair_code(req)
    elif method == 'repair_update':
        return repair_update(req)
    elif method == 'export_pdf':
        return export_pdf(req)
    elif method == 'export_word':
        return export_word(req)
    elif method == 'export_json':
        return export_json(req)
    elif method == 'export_html':
        return export_html(req)
    elif method == 'export_getall':
        return export_getall(req)
    elif method == 'export_delete':
        return export_delete(req)
    elif method == 'offer_subVul':
        return offer_subVul()
    elif method == 'create_policy':
        return create_policy(req)
    elif method == 'get_all_policies':
        return get_all_policies(req)
    elif method == 'delete_policy':
        return delete_policy(req)
    elif method == 'update_policy':
        return update_policy(req)
    elif method == 'get_all_projects':
        return get_all_projects()
    elif method == 'send_email':
        return send_email(req)
    elif method == 'add_email_info':
        return add_email_info(req)
    elif method == 'get_email_info':
        return get_email_info(req)
    elif method == 'send_wechat_work_message':
        return send_wechat_work_message(req)
    elif method == 'add_wechat_info':
        return add_wechat_info(req)
    elif method == 'get_wechat_info':
        return get_wechat_info(req)
    elif method == 'update_policyStatus':
        return update_policyStatus(req)
    elif method == 'select_clean_func':
        return select_clean_func(req)
    elif method == 'insert_clean_func':
        return insert_clean_func(req)
    elif method == 'delete_clean_func':
        return delete_clean_func(req)
    elif method == 'update_clean_func':
        return update_clean_func(req)
    elif method == 'query_audit_log':
        return query_audit_log(req)
    elif method == 'send_station_mail':
        return send_station_mail(req)
    elif method == 'query_alarm_logs':
        return query_alarm_logs(req)
    elif method == 'select_custom_rules':
        return select_custom_rules(req)
    elif method == 'insert_custom_rules':
        return insert_custom_rules(req)
    elif method == 'delete_custom_rules':
        return delete_custom_rules(req)
    elif method == 'update_custom_rules':
        return update_custom_rules(req)
    else:
        return HttpResponse("method error! ")
