import json
import pymysql
from django.http import HttpResponse, JsonResponse
from app.api.database_utils.mysql_util import config
from app.api.database_utils.web import generate_sequence,read_file_content


def VulType_get(req):  # 接口6_2
    task_id = req.POST['taskid']
    conn = pymysql.connect(**config)
    cursor = conn.cursor()
    sql = """select * from vulfile where taskId = %s"""
    conn.ping(reconnect=True)
    cursor.execute(sql, (task_id))
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
            # else:
            #     result_dict['location'] = f'"{result_dict["location"]}"'

            result_dict['code_location'] = result_dict['location']

            if 'filepath' in result_dict:
                file_path = result_dict['filepath']
                code = read_file_content(file_path)
                result_dict['source_code'] = code

            jsondata.append(result_dict)

    cursor.close()
    conn.close()
    return HttpResponse(json.dumps({'fileList': jsondata}, ensure_ascii=False))

def index(req):
    method = req.POST["method"]
    if method == "get_ccnList":
        return VulType_get(req)