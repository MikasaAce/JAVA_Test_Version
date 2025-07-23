import json
import pymysql
from django.http import HttpResponse, JsonResponse
from app.api.database_utils.mysql_util import config

def get_knowledge_base(req):
    # 连接数据库,**config 是数据库连接的配置
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    # 获取参数，如果参数不存在则设置为空
    cwe_name = req.POST.get('name', '')  # 使用 get 方法，如果不存在则返回空字符串
    page = int(req.POST.get('page', 1))  # 默认值为 1
    results_per_page = int(req.POST.get('rows', 10))  # 默认值为 10

    # 计算分页的偏移量
    offset = (page - 1) * results_per_page

    # 查询总结果数量
    count_sql = """SELECT COUNT(*)  FROM subVulList"""
    conditions = []

    if cwe_name:
        conditions.append("subVulList.name_CN like '%%%s%%'" % cwe_name)

    if conditions:
        count_sql += " WHERE " + " AND ".join(conditions)

    cursor.execute(count_sql)
    total_count = cursor.fetchone()[0]

    sql = """ SELECT subVulList.id,subVulList.name_CN as name,subVulList.description,subVulList.level FROM subVulList """

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    sql += " LIMIT %s, %s" % (offset, results_per_page)

    # 检查数据库连接并执行查询
    conn.ping(reconnect=True)
    cursor.execute(sql)
    # 获取查询结果的列名
    row_headers = [x[0] for x in cursor.description]
    # 获取查询结果的所有行
    data = cursor.fetchall()

    jsondata = {'count': total_count}
    if total_count == 0:
        jsondata = {'msg': '结果为空', 'msg-code': '200'}
    else:
        jsondata['data'] = []
        for result in data:
            jsondata['data'].append(dict(zip(row_headers, result)))

    cursor.close()
    conn.close()
    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))

def insert_knowledge(req):
    """
    将用户新增的知识库保存到数据库中
    """
    cwe_name = req.POST["cwe_name"]
    cwe_description = req.POST["description"]
    cwe_level = req.POST["level"]

    # 参数校验，检查是否为空或格式是否正确
    if not all([cwe_name, cwe_description, cwe_level]):
        return HttpResponse(json.dumps({'msg': '信息未填写完整', 'msg-code': '400'}), content_type="application/json")

    sql = """
        INSERT INTO subVulList (name_CN, description, level) VALUES (%s, %s, %s)
    """

    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 检查 cwe_name 是否已存在
                check_sql = "SELECT name_CN FROM subVulList WHERE name_CN = %s"
                cursor.execute(check_sql, (cwe_name,))
                if cursor.fetchone():
                    return HttpResponse(json.dumps({'msg': '漏洞名称已存在', 'msg-code': '400'}),content_type="application/json")

                cursor.execute(sql, (cwe_name, cwe_description, cwe_level))
                conn.commit()  # 提交事务
        return HttpResponse(json.dumps({'msg': '保存成功', 'msg-code': '200'}), content_type="application/json")
    except Exception as e:
        print(f"提交出错\n: {e}")
        conn.rollback()
        return HttpResponse(json.dumps({'msg': '保存失败', 'msg-code': '500'}), content_type="application/json")

def update_knowledge(request):
    """
    更新,编辑
    """
    if request.method == 'POST':
        id = request.POST["id"]
        cwe_name = request.POST["cwe_name"]
        cwe_description = request.POST["description"]
        cwe_level = request.POST["level"]

        # 参数校验
        if not all([id,cwe_name, cwe_description, cwe_level]):
            return HttpResponse(
                json.dumps({'msg': '参数缺失', 'msg-code': '400'}, ensure_ascii=False),
                status=400
            )

        sql = """
            UPDATE subVulList 
            SET name_CN = %s, description = %s, level = %s 
            WHERE id = %s
        """
        try:
            with pymysql.connect(**config) as conn:
                with conn.cursor() as cursor:
                        cursor.execute(sql, (cwe_name, cwe_description, cwe_level,  id))
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

def delete_knowledge(request):
    """
    删除
    """
    if request.method == 'POST':
        id = request.POST['id']  # 获取 POST 参数

        if not id:  # 检查 cwe_id 是否为空
            return HttpResponse(
                json.dumps({'msg': 'id 不能为空', 'code': '400'}, ensure_ascii=False),
                status=400
            )
        try:
            conn = pymysql.connect(**config)
            cursor = conn.cursor()

            sql = """ DELETE FROM subVulList WHERE id = %s """
            cursor.execute(sql, (id,))

            # 检查是否删除了数据
            if cursor.rowcount == 0:  # 如果没有删除任何数据
                cursor.close()
                conn.close()
                return HttpResponse(
                    json.dumps({'msg': '未找到对应的记录', 'code': '404'}, ensure_ascii=False),
                    status=404
                )
            conn.commit()  # 提交事务
            cursor.close()
            conn.close()

            response = HttpResponse(
                json.dumps({'msg': '删除成功', 'code': '200'}, ensure_ascii=False)
            )

            return response
        except Exception as e:
            print(f"删除出错: {e}")
            if 'conn' in locals():  # 如果 conn 已定义
                conn.rollback()  # 回滚事务
                conn.close()
            return HttpResponse(
                json.dumps({'msg': '删除失败', 'code': '500'}, ensure_ascii=False),
                status=500
            )
    else:
        return HttpResponse(
            json.dumps({'msg': '无效的请求方法', 'code': '400'}, ensure_ascii=False),
            status=400
        )

def index(req):
    method = req.POST["method"]
    if method == "get_knowledge":
        return get_knowledge_base(req)
    elif method == "insert_knowledge":
        return insert_knowledge(req)
    elif method == "delete_knowledge":
        return delete_knowledge(req)
    elif method == "update_knowledge":
        return update_knowledge(req)
    else:
        return JsonResponse({"error": "Invalid method"}, status=400)
