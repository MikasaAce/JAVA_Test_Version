import json
import os
import uuid
import subprocess
from pathlib import Path

import pymysql
from django.http import HttpResponse, JsonResponse
from app.api.ccn.process_lizard_xml import parse_lizard_xml, parse_single_lizard_xml
from app.api.database_utils.mysql_util import config, lizard_path

def calculate_ccn(orgin_arg):
    """
     计算ccn
    """

    conn = None  # 先初始化为 None，防止未定义
    task_id = orgin_arg.get('task_id')
    folder_path = orgin_arg.get('folder_path')

    # 参数校验
    if not all([task_id, folder_path]):
        return HttpResponse(
            json.dumps({'msg': 'Missing required parameters', 'code': '400'}, ensure_ascii=False), status=400)

    # 生成报告文件路径
    report_id = uuid.uuid4().hex
    # xml_path = REPORTS_DIR / f"{report_id}.xml"
    xml_path = Path(lizard_path) / f"{report_id}.xml"

    try:
        # 执行 lizard 命令
        cmd = f"lizard {folder_path} --xml -o {xml_path}"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300  # 5分钟超时
        )

        if result.returncode != 0:
            return HttpResponse(
                json.dumps({"error": f"Lizard execution failed: {result.stderr}"}), status=500)

        # 解析XML报告
        analysis_data = parse_lizard_xml(xml_path)

        # 存储到数据库
        sql = """
                    UPDATE vuldetail 
                    SET ccn = %s
                    where taskId = %s
                """
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:

                cursor.execute(sql, (analysis_data["global_avg_ccn"], task_id))
                conn.commit()  # 提交事务
        return HttpResponse(json.dumps({'msg': '保存成功', 'msg-code': '200'}), content_type="application/json")


    except Exception as e:
        print(f"提交出错\n: {e}")
        if conn:
            conn.rollback()
        return HttpResponse(json.dumps({'msg': '保存失败', 'msg-code': '500'}), content_type="application/json")


def calculate_file_ccn(task_id, file_id, test_result):
    """
     计算ccn
    """
    # 初始化 conn 防止 rollback 时报错
    conn = None
    
    folder_path = test_result[0]['file_path']
    folder_name = test_result[0]['filename']

    try:
        file_id = file_id + 1
        # 参数校验
        if not all([task_id, folder_path]):
            return HttpResponse(
                json.dumps({'msg': 'Missing required parameters', 'code': '400'}, ensure_ascii=False), status=400)
                
        # 生成报告文件路径
        report_id = uuid.uuid4().hex
        xml_path = Path(lizard_path) / f"{report_id}.xml"

    
        # 执行 lizard 命令
        cmd = f"lizard {Path(folder_path)} --xml -o {xml_path}"

        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300  # 5分钟超时
        )

        if result.returncode != 0:
            return HttpResponse(
                json.dumps({"error": f"Lizard 执行失败: {result.stderr}"}), status=500)

        # 解析XML报告
        analysis_data = parse_single_lizard_xml(xml_path)
#        print(f"cnn结果: {analysis_data}")
#        print(f"idddddddddddddddddddddddddddd: {task_id},{file_id}")


        # 提取需要的指标
        required_fields = ["avg_ccn", "max_ccn", "function_count", "avg_ncss"]
        for field in required_fields:
            if field not in analysis_data:
                raise ValueError(f"缺少必要字段: {field}")

        # 获取指标值
        avg_ccn = analysis_data["avg_ccn"]
        max_ccn = analysis_data["max_ccn"]
        function_count = analysis_data["function_count"]
        avg_ncss = analysis_data["avg_ncss"]


        # 存储到数据库
        sql = """
                    UPDATE vulfile 
                        SET avgCCN = %s,
                        max_ccn = %s,
                        function_count = %s,
                        avg_ncss = %s
                    WHERE taskId = %s AND fileId = %s
                """
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:

                cursor.execute(sql, (avg_ccn, max_ccn, function_count, avg_ncss, task_id, file_id ))
                conn.commit()  # 提交事务
        return HttpResponse(json.dumps({'msg': '保存成功', 'msg-code': '200'}), content_type="application/json")


    except Exception as e:
        print(f"提交出错\n: {e}")
        if conn:
            conn.rollback()
        return HttpResponse(json.dumps({'msg': '保存失败', 'msg-code': '500'}), content_type="application/json")



