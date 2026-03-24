from lxml import etree
from collections import defaultdict


def parse_lizard_xml(xml_path):
    """解析Lizard扫描一个文件夹后生成的XML报告"""
    tree = etree.parse(xml_path)
    root = tree.getroot()

    # 文件级统计
    file_stats = []
    total_functions = 0
    total_ncss = 0
    total_ccn = 0

    # 遍历所有文件条目
    for item in root.xpath("//measure[@type='File']/item"):
        filename = item.get("name")
        values = [e.text for e in item.findall("value")]

        file_data = {
            "filename": filename,
            "ncss": int(values[1]),
            "ccn": int(values[2]),
            "function_count": int(values[3])
        }
        file_stats.append(file_data)

        # 累计全局统计
        total_functions += file_data["function_count"]
        total_ncss += file_data["ncss"]
        total_ccn += file_data["ccn"]

    # 计算全局平均值
    global_avg_ncss = total_ncss / total_functions if total_functions else 0
    global_avg_ccn = total_ccn / total_functions if total_functions else 0

    # 输出全局统计
#    print("\n全局统计：")
#    print(f"总文件数：{file_count}")
#    print(f"总函数数：{total_functions}")
#    print(f"全局平均NCSS：{global_avg_ncss:.2f}")
#    print(f"全局平均CCN：{global_avg_ccn:.2f}")

    return {
        "file_stats": file_stats,
        "total_functions": total_functions,
        "global_avg_ncss": round(global_avg_ncss, 2),
        "global_avg_ccn": round(global_avg_ccn, 2)
    }
#
#    if __name__ == "__main__":
#        import sys
#        if len(sys.argv) != 2:
#            print("用法：python analyze_lizard.py [XML文件路径]")
#            sys.exit(1)
#    
#        analyze_lizard_report(sys.argv[1])


def parse_single_lizard_xml(xml_path):
    """解析单个文件的Lizard XML报告，提取函数统计信息"""
    tree = etree.parse(xml_path)
    root = tree.getroot()

    # 初始化结果字典
    result = {
        "function_count": 0,
        "avg_ncss": 0.0,
        "avg_ccn": 0.0,
        "max_ccn": 0
    }

    # 解析文件级别的函数总数（来自File measure的sum）
    file_measure = root.xpath("//measure[@type='File']")[0]
    if functions_sum := file_measure.xpath("./sum[@label='Functions']"):
        result["function_count"] = int(functions_sum[0].get("value"))

    # 解析函数级别的平均值（来自Function measure的average）
    func_measure = root.xpath("//measure[@type='Function']")[0]
    for avg in func_measure.xpath("./average"):
        label = avg.get("label")
        if label == "NCSS":
            result["avg_ncss"] = round(float(avg.get("value")), 1)
        elif label == "CCN":
            result["avg_ccn"] = round(float(avg.get("value")), 1)

    # 遍历所有函数条目找最大CCN
    max_ccn = 0
    for func_item in func_measure.xpath("./item"):
        # 第三个value对应CCN（根据labels顺序：Nr., NCSS, CCN）
        ccn = int(func_item.xpath("./value[3]/text()")[0])
        max_ccn = max(max_ccn, ccn)
    
    result["max_ccn"] = max_ccn

    return result

#if __name__ == "__main__":
#    stats = parse_single_lizard_xml("your_file.xml")
#    print(f"函数总数：{stats['function_count']}")
#    print(f"平均NCSS：{stats['avg_ncss']:.1f}")
#    print(f"平均CCN：{stats['avg_ccn']:.1f}")
#    print(f"最大CCN：{stats['max_ccn']}")
