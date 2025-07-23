from app.api.main_app.M_app import *

def get_result(task_id):
    # 连接数据库
    conn = pymysql.connect(**config)
    cursor = conn.cursor()

    # 执行 SQL 查询
    sql = "SELECT vultype FROM vulfile WHERE taskid = %s"
    cursor.execute(sql, (task_id,))

    # 提取查询结果
    rows = cursor.fetchall()  # 将结果保存到变量中

    data = [row[0] for row in rows]  # 提取元组中的第一个元素
    print(data)  # 打印处理后的列表
    print(type(data))
    # 关闭连接
    cursor.close()
    conn.close()

    return data


def vuldetail_update(task_id, item_id, task_name, **kwargs):
    # 必传参数检查
    if not all([task_id, item_id, task_name]):
        return HttpResponse(json.dumps({'msg': 'task_id, item_id 和 task_name 是必传参数', 'msg-code': '400'}))

    # 动态生成 SQL 语句
    sql = "UPDATE vuldetail SET "
    update_fields = []
    update_values = []

    # 遍历可选参数
    for key, value in kwargs.items():
        if value is not None:  # 只更新传入的参数
            update_fields.append(f"{key}=%s")
            update_values.append(value)

    # 如果没有需要更新的字段，直接返回
    if not update_fields:
        return HttpResponse(json.dumps({'msg': '没有需要更新的字段', 'msg-code': '400'}))

    # 拼接 SQL 语句
    sql += ", ".join(update_fields)
    sql += " WHERE taskId = %s"
    update_values.append(task_id)

    # 连接数据库并执行更新
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    try:
        cursor.execute(sql, update_values)
        conn.commit()
        flag = True
    except Exception as e:
        flag = False
        print("提交出错\n:", e)
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

    # 返回结果
    if flag:
        return HttpResponse(json.dumps({'msg': '保存成功', 'msg-code': '200'}))
    else:
        return HttpResponse(json.dumps({'msg': '保存失败', 'msg-code': '500'}))


def update_task(arg):
    """通过自定义规则进行检测"""
    item_id = arg['item_id']
    task_id = arg['task_id']
    task_name = arg['task_name']
    start_time = arg['start_time']
    current_status = arg['current_status']

    result = get_result(task_id)

    high_num = 0
    medium_num = 0
    low_num = 0
    for vul_name in result:
        vul_level = get_level_CN(vul_name)  # 根据漏洞名称获取漏洞危险等级

        if vul_level == '高危':
            high_num += 1
        elif vul_level == '中危':
            medium_num += 1
        elif vul_level == '低危':
            low_num += 1
        else:
            print(f'危险等级异常！{vul_name}')
            vul_level = '高危'
            high_num += 1

    end_time = get_current_time()
    start_time = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
    end_time = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
    last_time = end_time - start_time
    hours, remainder = divmod(last_time.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    last_time_str = f"{hours}时{minutes}分{seconds}秒"

    vulnerability_detail = vuldetail_update(
        task_id=task_id,
        item_id=item_id,
        task_name=task_name,
        high_risk=high_num,
        med_risk=medium_num,
        low_risk=low_num,
        code_size=None,
        file_size=None,
        file_num=None,
        statues=current_status,
        startTime=None,
        endTime=end_time,
        lastTime=last_time_str,
        review_status=None
    )

    if vulnerability_detail.status_code == 200:
        return JsonResponse({"msg": "漏洞信息页面数据插入成功", "code": "200"})
    else:
        return JsonResponse({"msg": "漏洞信息页面数据插入错误", "code": "500"})


