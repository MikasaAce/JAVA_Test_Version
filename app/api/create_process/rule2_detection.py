from app.api.main_app.M_app import *
import xml.etree.ElementTree as ET
from app.api.ccn.processCCN import calculate_file_ccn
from collections import defaultdict
import os
import re


def get_level_EN_CN(vul_name):
    # 根据cwe_id获取危险等级
    # 注：这里其实是根据英文名获取中文名，注释有误
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                if vul_name:
                    name_sql = """select name_CN from subVulList where name_EN = %s"""
                    cursor.execute(name_sql, (vul_name,))
                data = cursor.fetchall()
                if data:
                    return data[0][0]
                else:
                    # print("未能查询到中文名的漏洞类型",vul_name)
                    return vul_name
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}{vul_name}")
    return "Error occurred while fetching vulnerability level"


def get_risk_level_EN(vul_name):
    # 根据英文名获取危险等级
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                if vul_name:
                    level_sql = """select level from subVulList where name_EN = %s"""
                    cursor.execute(level_sql, (vul_name,))
                data = cursor.fetchall()
                if data:
                    return data[0][0]
                else:
                    # print("未能查询到危险等级",vul_name)
                    return vul_name
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}{vul_name}")
    return "Error occurred while fetching vulnerability level"


def import_relation_insert(task_id, import_relations):
    """
    插入import关系到数据库
    """
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                sql = """INSERT INTO import_relation(taskId, source_file, imported_file) VALUES (%s, %s, %s)"""

                inserted_count = 0
                error_count = 0
                skipped_count = 0

                # 统计信息
                total_relations = sum(len(files) for files in import_relations.values())
                print(f"开始插入import关系，共发现 {len(import_relations)} 个源文件，{total_relations} 条关系")

                # 如果没有关系可插入，直接返回
                if total_relations == 0:
                    print("没有import关系需要插入")
                    jsondata = {'msg': '没有import关系需要插入', 'code': '200'}
                    return HttpResponse(json.dumps(jsondata, ensure_ascii=False))

                for source_file, imported_files in import_relations.items():
                    print(f"处理源文件: {source_file}")
                    
                    # 验证源文件数据
                    if not source_file or not task_id:
                        print(f"  跳过: 源文件或task_id为空")
                        skipped_count += len(imported_files)
                        continue
                        
                    for imported_file in imported_files:
                        # 验证导入文件数据
                        if not imported_file:
                            print(f"  跳过: 导入文件为空")
                            skipped_count += 1
                            continue
                            
                        try:
                            print(f"  准备插入: taskId={task_id}, 源文件={source_file}, 导入文件={imported_file}")
                            
                            # 执行插入
                            cursor.execute(sql, [task_id, source_file, imported_file])
                            inserted_count += 1
                            print(f"  插入成功")
                            
                        except pymysql.MySQLError as e:
                            error_count += 1
                            print(f"  插入失败 - 错误: {e}")
                            continue

                # 提交事务
                conn.commit()
                print(f"事务已提交，成功插入 {inserted_count} 条记录")

                # 验证插入结果
                if inserted_count > 0:
                    # 查询实际插入的记录数进行验证
                    verify_sql = "SELECT COUNT(*) FROM import_relation WHERE taskId = %s"
                    cursor.execute(verify_sql, [task_id])
                    actual_count = cursor.fetchone()[0]
                    print(f"验证: 数据库中实际存在 {actual_count} 条记录")

                print(f"import关系插入完成: 成功{inserted_count}条, 失败{error_count}条, 跳过{skipped_count}条")

                if error_count == 0 and skipped_count == 0:
                    jsondata = {'msg': f'import关系插入成功，共{inserted_count}条记录', 'code': '200'}
                else:
                    jsondata = {'msg': f'import关系插入完成: 成功{inserted_count}条, 失败{error_count}条, 跳过{skipped_count}条',
                                'code': '201'}

                return HttpResponse(json.dumps(jsondata, ensure_ascii=False))

    except pymysql.MySQLError as e:
        print(f"MySQL连接错误: {e}")
        jsondata = {'msg': '数据库连接失败', 'code': '500'}
        return HttpResponse(json.dumps(jsondata, ensure_ascii=False))


def import_relation_search(task_id, file_name):
    """
    根据文件名查找其被哪些文件import

    Args:
        task_id: 任务ID
        file_name: 要查找的文件名（可以是完整路径或单纯文件名）

    Returns:
        list: 包含该文件的完整文件路径列表
    """
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 方法1：如果file_name是完整路径，精确匹配
                sql1 = """
                SELECT DISTINCT source_file 
                FROM import_relation 
                WHERE taskId = %s AND imported_file = %s
                """
                cursor.execute(sql1, [task_id, file_name])
                results1 = cursor.fetchall()

                # 方法2：如果file_name只是文件名，进行模糊匹配
                sql2 = """
                SELECT DISTINCT source_file 
                FROM import_relation 
                WHERE taskId = %s AND imported_file LIKE %s
                """
                cursor.execute(sql2, [task_id, f'%{file_name}'])
                results2 = cursor.fetchall()

                # 合并结果并去重
                all_results = set()
                for row in results1 + results2:
                    all_results.add(row[0])  # 直接使用完整路径

                return list(all_results)

    except pymysql.MySQLError as e:
        print(f"查询import关系出错: {e}")
        return []


def extract_base_directory(file_path_list):
    """
    从文件路径列表中自动提取公共基目录
    """
    if not file_path_list:
        return None

    try:
        # 获取所有文件的公共路径前缀
        common_prefix = os.path.commonpath(file_path_list)
        return common_prefix
    except ValueError:
        # 如果路径在不同驱动器上，返回第一个文件的目录
        return os.path.dirname(file_path_list[0]) if file_path_list else None


def normalize_file_path(file_path):
    """
    标准化文件路径，确保使用绝对路径和一致的格式
    """
    if not file_path:
        return file_path
    
    # 转换为绝对路径
    abs_path = os.path.abspath(file_path)
    
    # 统一使用正斜杠
    normalized_path = abs_path.replace('\\', '/')
    
    return normalized_path


def build_ast_and_import_relations(file_path_list):
    """
    构建AST映射和import关系

    Args:
        file_path_list: Java文件路径列表

    Returns:
        tuple: (file_ast_map, import_relations)
    """
    # 自动提取基目录
    base_directory = extract_base_directory(file_path_list)
    print(f"自动提取的基目录: {base_directory}")

    # 构建所有Java文件的AST映射
    file_ast_map = {}
    import_relations = defaultdict(list)  # 记录每个文件导入的其他文件

    java_file_paths = [path for path in file_path_list if path.endswith('.java')]
    print(f"找到 {len(java_file_paths)} 个Java文件")

    # 预处理：构建文件名到完整路径的映射（使用标准化路径）
    file_name_to_paths = defaultdict(list)
    normalized_paths = {}  # 存储原始路径到标准化路径的映射
    
    for java_path in java_file_paths:
        normalized_path = normalize_file_path(java_path)
        normalized_paths[java_path] = normalized_path
        file_name = os.path.basename(java_path)
        file_name_to_paths[file_name].append(normalized_path)

    print("文件名映射:")
    for file_name, paths in file_name_to_paths.items():
        print(f"  {file_name}: {len(paths)} 个路径")

    for java_path in java_file_paths:
        normalized_java_path = normalized_paths[java_path]
        
        try:
            code = read_file(java_path)
            data = code['data']
            data_filter = filter_java_code(data)
            ast = javalang.parse.parse(data_filter)
            file_ast_map[normalized_java_path] = ast

            # 分析import语句
            imports = extract_imports(ast)
            print(f"文件 {os.path.basename(java_path)} 有 {len(imports)} 个import语句: {imports}")

            # 解析import关系
            for import_stmt in imports:
                print(f"  处理import: {import_stmt}")
                target_files = resolve_import_to_files(import_stmt, normalized_java_path, file_name_to_paths, base_directory)
                print(f"    解析为文件: {[os.path.basename(f) for f in target_files]}")
                
                for target_file in target_files:
                    if target_file != normalized_java_path:  # 避免自引用
                        import_relations[normalized_java_path].append(target_file)
                        print(f"    添加关系: {os.path.basename(normalized_java_path)} -> {os.path.basename(target_file)}")

        except Exception as e:
            print(f"构建AST映射失败 {java_path}: {str(e)}")
            continue

    print(f"最终构建了 {len(import_relations)} 个文件的import关系")
    return file_ast_map, import_relations


def extract_imports(ast):
    """
    从AST中提取所有import语句
    """
    imports = []
    for path, node in ast:
        if isinstance(node, javalang.tree.Import):
            imports.append(node.path)
    return imports


def resolve_import_to_files(import_path, source_file, file_name_to_paths, base_directory=None):
    """
    将import语句解析为对应的文件路径
    """
    import_parts = import_path.split('.')

    # 处理通配符import
    if import_path.endswith('.*'):
        package_path = import_path[:-2].replace('.', '/')
        matched_files = []
        for file_name, paths in file_name_to_paths.items():
            for file_path in paths:
                if is_package_match(file_path, package_path, base_directory):
                    matched_files.append(file_path)
        return matched_files

    # 标准类import
    class_name = import_parts[-1]
    package_path = '/'.join(import_parts[:-1]) if len(import_parts) > 1 else ''

    matched_files = []

    # 通过类名匹配 - 主要匹配逻辑
    possible_class_names = [
        f"{class_name}.java",  # 完整类文件名
        class_name,            # 仅类名
        f"{class_name}.java".lower(),  # 小写版本（Windows不区分大小写）
        class_name.lower()     # 小写类名
    ]

    for class_name_variant in possible_class_names:
        if class_name_variant in file_name_to_paths:
            for file_path in file_name_to_paths[class_name_variant]:
                if is_package_match(file_path, package_path, base_directory):
                    matched_files.append(file_path)

    # 相对路径解析 - 作为备选方案
    if not matched_files and base_directory:
        # 尝试将import路径转换为文件路径
        relative_path = import_path.replace('.', '/') + '.java'
        absolute_path = os.path.join(base_directory, relative_path)
        normalized_absolute_path = normalize_file_path(absolute_path)
        
        # 检查这个路径是否在文件列表中
        for paths in file_name_to_paths.values():
            for file_path in paths:
                if file_path == normalized_absolute_path:
                    matched_files.append(file_path)
                    break

    # 如果没有找到精确匹配，尝试模糊匹配
    if not matched_files:
        search_class_name = class_name.lower()
        for file_name, paths in file_name_to_paths.items():
            if search_class_name in file_name.lower():
                for file_path in paths:
                    if is_package_match(file_path, package_path, base_directory):
                        matched_files.append(file_path)

    return list(set(matched_files))


def is_package_match(file_path, package_path, base_directory=None):
    """
    检查文件是否属于指定的包
    """
    if not package_path:
        return True

    file_dir = os.path.dirname(file_path)

    if base_directory:
        try:
            # 计算相对于基目录的路径
            relative_path = os.path.relpath(file_dir, base_directory)
            relative_path = relative_path.replace('\\', '/')
            
            # 精确匹配包路径
            if relative_path == package_path:
                return True
            
            # 宽松匹配：检查包路径是否在相对路径的末尾
            if relative_path.endswith('/' + package_path):
                return True
                
        except ValueError:
            # 如果路径不在同一个驱动器上，回退到字符串匹配
            pass

    # 回退方案：直接检查路径是否包含包路径
    normalized_file_path = file_path.replace('\\', '/')
    return f"/{package_path}/" in normalized_file_path or normalized_file_path.endswith(f"/{package_path}")


def rule2_detection(arg, process_name, status, process_num):
    """通过自定义规则进行检测"""
    file_path_list = arg['file_path']
    item_id = arg.get('item_id', "")
    task_name = arg['task_name']
    language = arg['language']
    task_id = arg['task_id']

    try:
        print("该进程的文件数为：", len(file_path_list))

        # 从数据库加载规则
        rows = load_rules()

        # 动态加载规则函数
        rules_module = importlib.import_module("rules")
        rules = []
        for row in rows:
            function_name = row["function_name"]
            if hasattr(rules_module, function_name):
                rules.append(getattr(rules_module, function_name))

        # 构建所有Java文件的AST映射
        file_ast_map, import_relations = build_ast_and_import_relations(file_path_list)

        print("=== DEBUG: import_relations 内容 ===")
        print(f"import_relations 类型: {type(import_relations)}")
        print(f"import_relations 长度: {len(import_relations)}")
        
        # 详细打印 import_relations 内容并验证数据
        valid_relations = defaultdict(list)
        for source_file, imported_files in import_relations.items():
            print(f"源文件: {source_file} (有效: {bool(source_file)})")
            valid_imports = []
            for imported_file in imported_files:
                is_valid = bool(imported_file) and imported_file != source_file
                print(f"  导入文件: {imported_file} (有效: {is_valid})")
                if is_valid:
                    valid_imports.append(imported_file)
            
            if source_file and valid_imports:
                valid_relations[source_file] = valid_imports
        
        print(f"有效关系数量: {len(valid_relations)}")
        total_valid = sum(len(files) for files in valid_relations.values())
        print(f"有效关系条目: {total_valid}")
        print("=== DEBUG 结束 ===")

        # 使用验证后的数据
        if total_valid > 0:
            import_relation_insert(task_id, valid_relations)
        else:
            print("没有有效的import关系需要插入")

        for i, path in enumerate(file_path_list):
            # 跳过.jar文件
            if path.endswith('.jar'):
                print(f"跳过JAR文件: {path}")
                continue

            try:
                # 读取文件内容
                code = read_file(path)
                path = code['path']
                data = code['data']
                code_lines = data.splitlines()
            except Exception as e:
                print(f"读取文件 {path} 失败: {str(e)}")
                continue

            # 创建代码行的副本用于匹配，避免修改原始数据
            code_lines_for_matching = code_lines.copy()

            try:
                # 处理Java文件
                if path.endswith('.java'):
                    try:
                        data_filter = filter_java_code(data)
                        try:
                            ast = javalang.parse.parse(data_filter)
                            xml_list = ""
                        except javalang.parser.JavaSyntaxError as e:
                            print(f"Java语法错误 {path}: {str(e)}")
                            continue
                        except Exception as e:
                            print(f"解析Java AST失败 {path}: {str(e)}")
                            continue
                    except Exception as e:
                        print(f"过滤Java代码失败 {path}: {str(e)}")
                        continue

                # 处理JavaScript文件
                elif path.endswith('.js'):
                    try:
                        ast = esprima.parseScript(data, {"loc": True})
                    except esprima.Error as e:
                        print(f"解析JavaScript AST失败 {path}: {str(e)}")
                        continue
                    except Exception as e:
                        print(f"处理JavaScript文件失败 {path}: {str(e)}")
                        continue

                elif path.endswith('.xml'):
                    try:
                        ast = []
                        xml_list = path
                    except Exception as e:
                        print(f"处理XML文件失败 {path}: {str(e)}")
                        continue

                # 漏洞检测逻辑
                vulnerabilities = []
                for rule in rules:
                    try:
                        vulnerabilities.extend(rule(ast, code_lines, xml_list, path, file_path_list, file_ast_map))
                    except Exception as e:
                        print(f"执行规则 {rule.__name__} 失败 {path}: {str(e)}")
                        continue

                # 自定义规则检测
                try:
                    vuln_rules_list = get_custom_rules(language)
                    custom_result = detect_vulnerabilities_with_strings(vuln_rules_list, code_lines)
                    vulnerabilities.extend(custom_result)
                except Exception as e:
                    print(f"执行自定义规则检测失败 {path}: {str(e)}")
                    continue

                # 处理检测结果
                for result in vulnerabilities:
                    clean_func_info_list = get_clean_func(language, result['漏洞类型'], item_id, task_name)

                    # 检查整个文件中是否存在清洁函数模式
                    is_cleaned = False
                    vulnerability_name = result['漏洞类型']
                    line_number = result['爆发点行号'] if type(result['爆发点行号']) == int else 0

                    # 检查行号是否有效
                    if not (1 <= line_number <= len(code_lines_for_matching)):
                        continue

                    # 获取当前行的内容
                    line_content = code_lines_for_matching[line_number - 1]
                    # 如果该行已经被标记为已删除（None），则跳过
                    if line_content is None:
                        print(f"跳过已匹配的行 {line_number} 在文件 {path}")
                        continue

                    line_content = line_content.strip()

                    for func_info in clean_func_info_list:
                        # 构建要查找的模式：类名、清洁函数名、line_number对应行的内容、返回值
                        pattern_parts = []
                        if func_info['class']:
                            pattern_parts.append(re.escape(func_info['class']))
                        if func_info['func_name'] not in line_content:
                            pattern_parts.append(re.escape(func_info['func_name']))
                        pattern_parts.append(re.escape(line_content))

                        # 添加返回值
                        return_value = func_info['return_value'] if func_info['return_value'] else None
                        if return_value:
                            pattern_parts.append(re.escape(return_value))

                        # 检查代码中是否存在该模式
                        pattern = ".*".join(pattern_parts)  # 允许中间有其他内容
                        full_code = "\n".join([line for line in code_lines_for_matching if line is not None])

                        # 使用正则表达式检查模式是否存在于代码中
                        if re.search(pattern, full_code, re.DOTALL):
                            is_cleaned = True
                            # 标记该行内容为已匹配（设置为None）
                            code_lines_for_matching[line_number - 1] = None
                            print(f"清洁函数匹配成功，标记行 {line_number} 为已匹配")
                            break

                    if not is_cleaned:
                        if path.endswith('.xml'):
                            should_append = True
                        else:
                            should_append = True
                            defect_func_name = result.get('爆发点函数名', '')
                            if defect_func_name:
                                normalized_path = normalize_file_path(path)
                                importers = import_relation_search(task_id, normalized_path)
                                print(f"文件 {os.path.basename(path)} 被以下文件import: {[os.path.basename(f) for f in importers]}")

                                found_in_importer = False
                                for importer_path in importers:
                                    normalized_importer = normalize_file_path(importer_path)
                                    if any(normalized_importer == normalize_file_path(p) for p in file_path_list):
                                       try:
                                           importer_code = read_file(importer_path)
                                           importer_data = importer_code['data']
                                           if defect_func_name in importer_data:
                                               print(f"在调用文件 {os.path.basename(importer_path)} 中找到缺陷源函数名: {defect_func_name}")
                                               found_in_importer = True
                                               break
                                       except Exception as e:
                                           print(f"读取调用文件 {importer_path} 失败: {str(e)}")
                                           continue

                                 # 只有在有 importers 但都没找到函数名时才过滤掉
                                if importers and not found_in_importer:
                                    print(f"在所有调用文件中均未找到缺陷源函数名 {defect_func_name}，跳过该检测结果")
                                    should_append = False

                        # 根据检查结果决定是否添加检测结果
                        if should_append:
                            test_result = []
                            test_result_dtl = []
                            file_id = get_id('fileId', 'vulfile')
                            filename = os.path.basename(path)
                            sline_number = result['缺陷源'] if type(result['缺陷源']) == int else 0
                            vul_line_number = result['爆发点函数行号'] if type(result['爆发点函数行号']) == int else 0
                            vul_func_name = result['爆发点函数名'] if result['爆发点函数名'] else ''

                            Source_pre = code_lines[sline_number - 1] if 1 <= sline_number <= len(code_lines) else ''

                            Sink = code_lines[line_number - 1] if 1 <= line_number <= len(code_lines) else ''
                            Source = result['缺陷源内容'] if result['缺陷源内容'] else Source_pre
                            Enclosing_Method = code_lines[vul_line_number - 1] if 1 <= vul_line_number <= len(
                                code_lines) else ''

                            src_filename = result['缺陷源文件'] if result['缺陷源文件'] else ''

                            code_context = get_code_context(data, line_number, 15)

                            test_result.append({
                                'filename': filename,
                                'file_path': path,
                                'cwe_id': '',
                                'vul_name': get_level_EN_CN(vulnerability_name),
                                'code': code_context,
                                'line_number': line_number,
                                'risk_level': get_risk_level_EN(vulnerability_name),
                                'repair_code': '',
                                'new_line_number': '',
                                'repair_status': '未修复',
                                'is_question': '是问题',
                                'model': '',
                                'Sink': Sink,
                                'Enclosing_Method': Enclosing_Method,
                                'Source': Source,
                                'src_filename': src_filename
                            })

                            test_result_dtl.append({
                                'filename': filename,
                                'file_path': path,
                                'cwe_id': '',
                                'vul_name': get_level_EN_CN(vulnerability_name),
                                'code': code_context,
                                'line_number': line_number,
                                'src_line_number': sline_number,
                                'func_line_number': vul_line_number,
                                'risk_level': get_risk_level_EN(vulnerability_name),
                                'repair_code': '',
                                'new_line_number': '',
                                'repair_status': '未修复',
                                'is_question': '是问题',
                                'model': '',
                                'Sink': Sink,
                                'Enclosing_Method': Enclosing_Method,
                                'Source': Source,
                                'src_filename': src_filename
                            })

                            vulfile_insert(task_id, file_id, test_result_dtl)
                            calculate_file_ccn(task_id, file_id, test_result)
                        else:
                            print(f"跳过检测结果: 缺陷源函数名 {defect_func_name} 在所有调用文件中均未找到")
                    else:
                        print(f"漏洞已通过清洁函数过滤: {vulnerability_name}")

            except Exception as e:
                print(f"处理文件 {path} 时发生未知错误: {str(e)}")
                continue

        print(f"进程 {process_name}-{status} 已完成，共 {process_num} 个进程")
        return JsonResponse({"msg": "自定义规则扫描成功", "code": "200"})

    except Exception as e:
        print("全局错误发生:", str(e))
        return JsonResponse({"msg": "自定义规则扫描失败", "code": "500", "error": str(e)})