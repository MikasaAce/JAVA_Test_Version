import re
import pdfplumber
import subprocess
import os
import pandas as pd
import datetime

def run_fortify(target_folder_fortify, template, version):
    print(3333333)
    """在指定目录下运行fortify"""
    print("template:" + template)
    print("version:" + version)
    initial_path = os.getcwd()
    file_name_fortify_2 = os.path.basename(target_folder_fortify)
    memory_limit = "-Xmx100g"
    thread_count = 64

    """检查是否为C/C++代码,或其他检测命令不同的代码"""
    c_flag = 0
    cpp_flag = 0
    sql_flag = 0
    objc_flag = 0
    py_flag = 0
    files = os.listdir(target_folder_fortify)
    for code_file in files:
        if code_file.endswith('.c'):
            c_flag = 1
        if code_file.endswith('.cpp'):
            cpp_flag = 1
        """其他检测命令不同的代码标记"""
        if code_file.endswith('.sql'):
            sql_flag = 1
        if code_file.endswith('.m'):
            objc_flag = 1
        

    command_clean = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} --clean"
    command_build = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} -incremental ."
    command_scan = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} -scan -f {file_name_fortify_2}.fpr"
    command_report = f'BIRTReportGenerator -template "{template}" -format pdf -source "{file_name_fortify_2}.fpr" -output "{file_name_fortify_2}.pdf" --SecurityIssueDetails --version "{version}"'

    if c_flag == 1:
        command_clean = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} --clean"
        command_build = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} -incremental gcc -c {target_folder_fortify}/*.c"
        command_scan = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} -scan -f {file_name_fortify_2}.fpr"
        command_report = f'BIRTReportGenerator -template "{template}" -format pdf -source "{file_name_fortify_2}.fpr" -output "{file_name_fortify_2}.pdf" --SecurityIssueDetails --version "{version}"'

    if cpp_flag == 1:
        command_clean = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} --clean"
        command_build = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2}  -Dcom.fortify.sca.ThreadCount={thread_count} -incremental g++ -c {target_folder_fortify}/*.cpp"
        command_scan = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} -scan -f {file_name_fortify_2}.fpr"
        command_report = f'BIRTReportGenerator -template "{template}" -format pdf -source "{file_name_fortify_2}.fpr" -output "{file_name_fortify_2}.pdf" --SecurityIssueDetails --version "{version}"'

    '''SQL检测分Oracle数据库的PLSQL以及SQL Server和Azure SQL数据库的TSQL,这里build时有待区分'''
    if sql_flag == 1:
        command_clean = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} --clean"
        command_build = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} -incremental -Dcom.fortify.sca.fileextensions.sql=TSQL *.sql"
        command_scan = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} -scan -f {file_name_fortify_2}.fpr"
        command_report = f'BIRTReportGenerator -template "{template}" -format pdf -source "{file_name_fortify_2}.fpr" -output "{file_name_fortify_2}.pdf" --SecurityIssueDetails --version "{version}"'

    if objc_flag == 1:
        command_clean = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} --clean"
        command_build = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} clang -ObjC {target_folder_fortify}/*.m -Dcom.fortify.sca.ThreadCount={thread_count} -incremental ."
        command_scan = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} -scan -f {file_name_fortify_2}.fpr"
        command_report = f'BIRTReportGenerator -template "{template}" -format pdf -source "{file_name_fortify_2}.fpr" -output "{file_name_fortify_2}.pdf" --SecurityIssueDetails --version "{version}"'

    try:
        # 进入代码所在文件路径
        os.chdir(target_folder_fortify)
        # 清理项目构建
        print('正在清理项目构建')
        print("当前时间:", datetime.datetime.now())
        subprocess.run(command_clean, check=True, shell=True)
        # 构建项目
        print('正在构建项目')
        print("当前时间:", datetime.datetime.now())
        subprocess.run(command_build, check=True, shell=True)
        # 执行代码的扫描和分析，并在当前目录生成一个FPR文件
        print('正在执行扫描')
        print("当前时间:", datetime.datetime.now())
        subprocess.run(command_scan, check=True, shell=True)
        # 生成pdf报告
        print('正在生成报告')
        print("当前时间:", datetime.datetime.now())
        subprocess.run(command_report, check=True, shell=True)
        # 恢复初始路径
        os.chdir(initial_path)
        print("fortify运行成功，成功生成报告！")
    except subprocess.CalledProcessError as e:
        print("fortify运行失败：", e)


def run_custom_fortify(target_folder_fortify, template, version, custom_flag, custom_list, filter_flag, filter_list):
    """在指定目录下运行fortify, 启用自定义规则或过滤文件"""
    print("template:" + template)
    print("version:" + version)
    print("当前时间:", datetime.datetime.now())
    initial_path = os.getcwd()
    file_name_fortify_2 = os.path.basename(target_folder_fortify)
    memory_limit = "-Xmx100g"
    thread_count = 64
    cache_dir = "cache"
    custom_path = '/home/public/JAVA_gf/app/static/custom_rules'
    filter_path = '/home/public/JAVA_gf/app/static/filter/filter.txt'

    command_clean = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} --clean"
    command_build = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} -incremental ."
    command_scan = f"sourceanalyzer {memory_limit} -b {file_name_fortify_2} -Dcom.fortify.sca.ThreadCount={thread_count} -scan -f {file_name_fortify_2}.fpr"
    command_report = f'BIRTReportGenerator -template "{template}" -format pdf -source "{file_name_fortify_2}.fpr" -output "{file_name_fortify_2}.pdf" --SecurityIssueDetails --version "{version}"'

    if filter_flag == 1:
        filter_file = open(filter_path, mode='w')
        filter_file.write("#Filter for Category and Subcategory" + "\n")
        for issue in Not_Related_Issues:
            filter_file.write(issue + "\n")
        for issue in Issues:
            if issue not in filter_list:
                filter_file.write(issue + "\n")
        filter_file.close()
        command_scan =  command_scan + f" -filter {filter_path}"

    if custom_flag == 1:
        for custom_file in custom_list:
            command_scan = command_scan + f" -rules {custom_path+custom_file}"

    try:
        # 进入代码所在文件路径
        os.chdir(target_folder_fortify)
        print("当前时间:", datetime.datetime.now())
        # 清理项目构建
        print('正在清理项目构建')
        print("当前时间:", datetime.datetime.now())
        subprocess.run(command_clean, check=True, shell=True)
        # 构建项目
        print('正在构建项目')
        print("当前时间:", datetime.datetime.now())
        subprocess.run(command_build, check=True, shell=True)
        # 执行代码的扫描和分析，并在当前目录生成一个FPR文件
        print('正在执行扫描')
        print("当前时间:", datetime.datetime.now())
        subprocess.run(command_scan, check=True, shell=True)
        # 生成pdf报告
        print('正在生成报告')
        print("当前时间:", datetime.datetime.now())
        subprocess.run(command_report, check=True, shell=True)
        # 恢复初始路径
        os.chdir(initial_path)
        print("fortify运行成功，成功生成报告！")
    except subprocess.CalledProcessError as e:
        print("fortify运行失败：", e)


#   根据代码和行号定位
def extract_code_from_line(java_file, line_number):
    with open(java_file, 'r', encoding='utf-8') as file:
        lines = file.readlines()
        # print(line_number)
        if int(line_number) <= len(lines):
            start_line = max(0, int(line_number) - 15)
            end_line = min(len(lines), int(line_number) + 15)

            code_line = lines[start_line:end_line]
            new_line_number = int(line_number) - (start_line + 1)
            return ''.join(code_line), new_line_number
        else:
            return ''


#   将pdf中表格的内容提取出来，存到excel中
def extract_tables_to_excel(pdf_path):
    try:
        # 提取 PDF 中的表格
        with pdfplumber.open(pdf_path) as pdf:
            tables = []
            for page in pdf.pages:
                table = page.extract_tables()
                tables.extend(table)

        # 过滤掉列数不为3的表格
        filtered_tables = [table for table in tables if len(table[0]) == 3]

        # 如果没有符合条件的表格，则返回错误信息
        if not filtered_tables:
            print("没有找到列数为3的表格。")
            return None

        # 将表格数据转换为 DataFrame
        df_list = [pd.DataFrame(table) for table in filtered_tables]

        # 获取 PDF 文件的目录和文件名（不带后缀）
        pdf_dir, pdf_name = os.path.split(pdf_path)
        pdf_name_without_ext = os.path.splitext(pdf_name)[0]

        # 构建 Excel 文件的路径
        excel_path = os.path.join(pdf_dir, f'{pdf_name_without_ext}.xlsx')

        # 将 DataFrame 保存为 Excel 文件
        with pd.ExcelWriter(excel_path) as writer:
            for i, df in enumerate(df_list):
                df.to_excel(writer, sheet_name=f'Sheet{i + 1}', index=False)
        print("Excel转换成功！")
        return excel_path
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


########################################################################################################################
#   获取Fotify报告中的内容
########################################################################################################################
def location_fortify_2(target_folder_fortify, pdf_file_path):
    text = ""
    with pdfplumber.open(pdf_file_path) as pdf:
        for page in pdf.pages:
            text += page.extract_text()
    # 使用正则表达式从文本中提取 CWE ID、文件名和行号
    regex = r'CWE ID (\d+)(.*?)\[(\d+)\]'
    matches = re.findall(regex, text, re.DOTALL)
    file_list = []
    for match in matches:
        cwe_id, file_loc, _ = match
        lines = file_loc.strip().splitlines()
        flag = 0
        filename = ""
        for line in lines:
            # if "SCA" in line or "Enclosing Method:" in line or "Source" in line:
            #print(line)
            if "SCA" in line:
                filename = str(line).split(' Sink:')[0]
                pattern = r":[0-9]+"
                # 在文本中搜索匹配模式的字符串
                match = re.search(pattern, filename)
                if bool(match):
                    file_name = filename.strip().split(':')[0].strip()
                    line_number = filename.strip().split(':')[-1].strip()
                    file_list.append([file_name, cwe_id, line_number])
                    flag = 0
                else:
                    flag = 1
            elif flag == 1:
                if 'Enclosing Method:' in line and str(line).split('Enclosing Method:')[0].isspace():
                    file_name = filename.strip().split(':')[0].strip()
                    line_number = filename.strip().split(':')[-1].strip()
                    file_list.append([file_name, cwe_id, line_number])
                    flag = 0
                    filename = ""
                else:
                    filename += str(line).split('Enclosing Method:')[0]
                    pattern = r":[0-9]+"
                    # 在文本中搜索匹配模式的字符串
                    match = re.search(pattern, filename)
                    if bool(match):
                        file_name = filename.strip().split(':')[0].strip()
                        line_number = filename.strip().split(':')[-1].strip()
                        file_list.append([file_name, cwe_id, line_number])
                        flag = 0
                    else:
                        flag = 2
            elif flag == 2:
                if str(line).split('Source')[0].isspace():
                    file_name = filename.strip().split(':')[0].strip()
                    line_number = filename.strip().split(':')[-1].strip()
                    file_list.append([file_name, cwe_id, line_number])
                    flag = 0
                    filename = ""
                else:
                    file_name = filename.strip().split(':')[0].strip()
                    line_number = filename.strip().split(':')[-1].strip()
                    file_list.append([file_name, cwe_id, line_number])
                    flag = 0
                    filename = ""

    # print(file_list)
    file_info = []
    for file in file_list:
        file_name, cwe_id, line_number = file
        # print(file_name, line_number)
        for filename in os.listdir(target_folder_fortify):
            if file_name == filename and filename.endswith('.java'):
                java_file_path = os.path.join(target_folder_fortify, filename)
                code, new_line_number = extract_code_from_line(java_file_path, line_number)
                if code != '' and new_line_number != '':
                    file_detail = {'filename': file_name, 'cwe_id': 'CWE' + cwe_id, 'line_number': line_number,
                                   'code': code, 'new_line_number': new_line_number, 'model': 'model_R'}
                    if file_detail not in file_info:
                        file_info.append(file_detail)

    return file_info


def location_fortify(target_folder_fortify, pdf_file_path, template):
    try:
        # 读取Excel文件
        file_path = extract_tables_to_excel(pdf_file_path)
        xls = pd.ExcelFile(file_path)

        # 定义正则表达式匹配文件名和行号
        #pattern = re.compile(r'(?s)(.*\.java):(\d+)', re.DOTALL)
        pattern = re.compile(r'(?s)(.*\.(java|c|cpp|py|php|cs|go|js|sql|rb)):(\d+)', re.DOTALL)

        # 定义正则表达式匹配爆发点、爆发点函数、缺陷源
        sink_pattern = re.compile(r'Sink:\s*(.*?)\s*Enclosing Method:', re.DOTALL)
        enclosing_method_pattern = re.compile(r'Enclosing Method:\s*(.*?)\s*Source:', re.DOTALL)
        source_pattern = re.compile(r'Source:\s*(.*)', re.DOTALL)

        # 存储所有信息的列表
        results = []

        # 提取所有 vulnerability_type
        vulnerability_types = []

        # 遍历所有工作表
        for sheet_name in xls.sheet_names:
            # 读取当前工作表
            df = pd.read_excel(file_path, sheet_name=sheet_name, header=None)

            # 读取第二行第一列的内容，并提取第一行作为漏洞类型
            if df.shape[0] > 1:
                vulnerability_type = str(df.iloc[1, 0]).split('\n')[0]
                vulnerability_types.append(vulnerability_type)

        # 从 PDF 文件中提取所有 "CWE-数字" 组合
        with pdfplumber.open(pdf_file_path) as pdf:
            text = ""
            for page in pdf.pages:
                text += page.extract_text()

        if 'OWASP' in template:
            cwe_pattern = re.compile(r'A(\d+)')
        else:
            # cwe_pattern = re.compile(r'CWE-(\d+).*?CWE ID \d+', re.DOTALL)
            cwe_pattern = re.compile(r'CWE-(\d+)')
        cwe_matches = list(cwe_pattern.finditer(text))

        # 存储每个 vulnerability_type 对应的 CWE-数字
        vulnerability_cwe_map = {}

        for vulnerability_type in vulnerability_types:
            found = False
            for i, match in enumerate(cwe_matches):
                start_index = match.end()
                end_index = cwe_matches[i + 1].start() if i + 1 < len(cwe_matches) else None
                cwe_text = text[start_index:end_index]
                if 'Package:' in cwe_text:
                    vulnerability_cwe_map[vulnerability_type] = match.group(1)
                    found = True
                    break
            if not found:
                vulnerability_cwe_map[vulnerability_type] = None

        # 遍历所有工作表
        for sheet_name in xls.sheet_names:
            # 读取当前工作表
            df = pd.read_excel(file_path, sheet_name=sheet_name, header=None)

            if df.shape[0] > 1:
                # 读取第二行第一列的内容，并提取第一行作为漏洞类型
                vulnerability_type = str(df.iloc[1, 0]).split('\n')[0]

                # 获取对应的 CWE-数字
                cwe_id = vulnerability_cwe_map.get(vulnerability_type, None)

                # 如果 cwe_id 是两位数，则在前面加上一个 0
                if cwe_id and len(cwe_id) == 2:
                    cwe_id = '0' + cwe_id

                if 'OWASP' in template:
                    cwe_id = 'A' + cwe_id
                else:
                    cwe_id = 'CWE' + cwe_id

                # 遍历每一行
                for index, row in df.iterrows():
                    # 检查第一列的内容是否匹配正则表达式
                    match = pattern.search(str(row[0]))
                    if match:
                        # 提取文件名和行号
                        file_name = match.group(1)
                        line_number = match.group(3)

                        # 去掉文件名中的换行符
                        file_name = file_name.replace('\n', '')

                        # 读取第一列和第二列的内容
                        first_column_content = row[0]
                        second_column_content = row[1]

                        # 匹配第二列中的内容
                        sink_match = sink_pattern.search(str(second_column_content))
                        enclosing_method_match = enclosing_method_pattern.search(str(second_column_content))
                        source_match = source_pattern.search(str(second_column_content))

                        # 提取匹配的内容
                        sink_content = sink_match.group(1).replace('\n', '') if sink_match else None
                        enclosing_method_content = enclosing_method_match.group(1).replace('\n',
                                                                                           '') if enclosing_method_match else None
                        source_content = source_match.group(1).replace('\n', '') if source_match else None

                        java_file_path = os.path.join(target_folder_fortify, file_name)
                        code, new_line_number = extract_code_from_line(java_file_path, line_number)

                        # 将信息存储在字典中
                        result = {
                            "filename": file_name,
                            # "cwe_id": 'CWE'+cwe_id,
                            "cwe_id": cwe_id,
                            "vul_name": '',
                            "line_number": line_number,
                            "code": code,
                            'new_line_number': new_line_number,
                            "Sink": sink_content,
                            "Enclosing_Method": enclosing_method_content,
                            "Source": source_content,
                            'model': 'model_R'
                        }

                        # 将字典添加到列表中
                        results.append(result)



        return results
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def location_fortify_3(target_folder_fortify, pdf_file_path):
    text = ""
    with pdfplumber.open(pdf_file_path) as pdf:
        for page in pdf.pages:
            text += page.extract_text()

    # 使用正则表达式从文本中提取信息 , line 10 (Command Injection)
    regex =  r', line (\d+) \((.*?)\).*?Sink: (.*?)\nEnclosing Method: (.*?)\nFile: (.*?)\nTaint Flags'
    regex1 = r', line (\d+) \w*\n*\((.*?)\).*?Sink: (.*?)\nFile: (.*?)\nTaint Flags' # 第一 ruby和php的报告没有爆发函数，所以这里删掉了 Enclosing Method 匹配部分；第二 , line 10后面有可能会多一些垃圾内容，所以多加了一个\w*\n* 第三 File这里得到的不是文件名，而是文件路径，这个在后面处理了
    regex_filter = r'(, line)(.*?)(, line)'


    # 找到匹配的第一个位置
    pos = 0
    start_pos = []
    while pos < len(text):
        match = re.search(regex_filter, text[pos:], re.DOTALL)
        if match:  # 判断有没有', line***, line'的形式
            if 'Sink:' not in match.group():  # 判断***中有没有'Sink:'，没有才需要把初始地址加上去
                start_pos.append(pos + match.start())
            pos = pos + match.end() - 6
        else:
            break
    print(start_pos)

    # 进行过滤
    text_list = list(text)  # 将文本转换为列表，因为字符串是不可变的，使用列表修改更方便

    for start in start_pos:
        text_list[start:start + 6] = [''] * 6  # 替换从 start 开始的 6 个字符

    filtered_texts = ''.join(text_list)

    # 在剩余的字符串中，使用 regex 进行匹配
    matches =     re.findall(regex, filtered_texts, re.DOTALL)
    if not matches:
        matches1 = re.findall(regex1, filtered_texts, re.DOTALL) # ruby语言 php语言

    print(matches)
    print("---")

    file_list = []
    for match in matches:
        line_number, vul_name_rough, sink_content_dirty, enclosing_method_content_dirty, file_name_rough = match

        file_name = re.search(r'(.*\.(java|cpp|c|py|php|cs|go|js|sql|rb))',file_name_rough).group(1)
        vul_name = vul_name_rough.replace('Low\n','').replace('Medium\n','').replace('High\n','').replace('Critical\n','').replace('\n',' ')
        # Sink 和 Enclosing_Method 都要过滤一下才行    输入可能是xxx\n，需要的是\n前面的所有字符
        sink_content = sink_content_dirty.split('\n')[0]
        enclosing_method_content = enclosing_method_content_dirty.split('\n')[0]

        file_list.append([file_name, line_number, vul_name, sink_content, enclosing_method_content])

    if not matches:
        for match in matches1:
            line_number, vul_name_rough, sink_content_dirty, file_name_rough = match
            file_name = re.search(r'(.*\.(java|cpp|c|py|php|cs|go|js|sql|rb))', file_name_rough.split('/')[-1]).group(1)
            vul_name = vul_name_rough.replace('Low\n', '').replace('Medium\n', '').replace('High\n', '').replace(
                'Critical\n', '').replace('\n', ' ')
            # Sink 和 Enclosing_Method 都要过滤一下才行    输入可能是xxx\n，需要的是\n前面的所有字符
            sink_content = sink_content_dirty.split('\n')[0]
            file_list.append([file_name, line_number, vul_name, sink_content])

    print(file_list)

    file_info = []
    for file in file_list:
        if matches:
            file_name, line_number, vul_name, sink_content, enclosing_method_content = file
        else:
            file_name, line_number, vul_name, sink_content = file
        for filename in os.listdir(target_folder_fortify):
            if file_name == filename: #我把.java后缀检测去掉了，如果确实有特殊用处的一定需要这个的话改回来记得加上对其他语言的适配
                java_file_path = os.path.join(target_folder_fortify, filename)
                code, new_line_number = extract_code_from_line(java_file_path, line_number)
                if code != '' and new_line_number != '' and vul_name in Issues:
                    file_detail = {
                        'filename':file_name,
                        'cwe_id': '',
                        'vul_name':vul_name,
                        'line_number':line_number,
                        'code':code,
                        'new_line_number':new_line_number,
                        'Sink':sink_content,
                        'Enclosing_Method':enclosing_method_content if matches else None,
                        'Source':'',
                        'model':'model_R'
                    }
                    print(file_detail)
                    file_info.append(file_detail)

    return file_info


Issues = ["Cross-Site Scripting: Persistent", #跨站脚本：持久型
       "Log Forging", #日志伪造
       "Cross-Frame Scripting", #服务器端请求伪造
       "Denial of Service: Regular Expression", #拒绝服务：正则表达式
       "HTTP Response Splitting: Cookies", #HTTP响应拆分：Cookies
       "HTTP Response Splitting", #HTTP响应拆分
       "Path Manipulation", #路径操纵
       "Dynamic Code Evaluation: Unsafe YAML Deserialization", #动态解析代码：不安全的YAML反序列化
       "Dynamic Code Evaluation: Script Injection", #动态解析代码：脚本注入
       "Dynamic Code Evaluation: Unsafe JSON Deserialization", #动态解析代码：不安全的JSON反序列化
       "Dynamic Code Evaluation: Code Injection", #动态解析代码：代码注入
       "Dynamic Code Evaluation: Unsafe Deserialization", #动态解析代码：不安全的反序列化
       "Command Injection", #命令注入
       "SQL Injection", #SQL注入
       "Header Manipulation: SMTP", #SMTP标头操纵
       "Log Forging (debug)", #日志伪造(调试)
       "XSLT Injection", #XSLT 注入
       "Denial of Service: StringBuilder", #拒绝服务：StringBuilder
       "Denial of Service", #拒绝服务
       "XQuery Injection", #XQuery注入
       "Expression Language Injection: Spring", #表达式语言注入：Spring
       "XML Entity Expansion Injection", #XML实体扩展注入
       "Spring Beans Injection", #Spring Beans 注入
       "OGNL Expression Injection: Struts 2", #OGNL表达式注入：Struts 2
       "OGNL Expression Injection: Dynamic Method Invocation", #OGNL表达式注入：动态方法调用
       "OGNL Expression Injection: Double Evaluation", #OGNL表达式注入：双重计算
       "OGNL Expression Injection", #OGNL表达式注入
       "JSON Injection", #JSON注入
       "HTTP Parameter Pollution", #HTTP参数污染
       "Cookie Security: Cookie not Sent Over SSL", #Cookies安全：不通过SSL发送cookie
       "Cookie Security: HTTPOnly not Set", #Cookies安全：HTTPOnly没有设置
       "Bean Manipulation", #Bean操纵
       "Resource Injection", #资源注入
       "Mail Command Injection: POP3", #邮件命令注入：POP3
       "Mail Command Injection: SMTP", #邮件命令注入：SMTP
       "Mail Command Injection: IMAP", #邮件命令注入：IMAP
       "Setting Manipulation", #设置操纵
       "File Permission Manipulation", #文件权限操纵
       "Cross-Site Scripting: Reflected", #跨站脚本：反射型
       "Formula Injection", #公式注入
       "Access Control: LDAP", #访问控制：LDAP
       "LDAP Injection", #LDAP注入
       "XPath Injection", #XPath注入
       "Open Redirect", #Open重定向
       "XML External Entity Injection", #XML外部实体注入
       "Denial of Service: Format String", #拒绝服务：格式字符串
       "Server-Side Template Injection", #服务器端模板注入
       "Dangerous File Inclusion", #危险文件包含
       "Dynamic Code Evaluation: Code Manipulation", #动态解析代码：代码操作
       "Dynamic Code Evaluation: XMLDecoder Injection", #动态解析代码：XMLDecoder 注入
       "Dynamic Code Evaluation: Unsafe XStream Deserialization", #动态解析代码：不安全的XStream反序列化
       "Dynamic Code Evaluation: JNDI Reference Injection", #动态解析代码：JNDI引用注入
       "Password Management: Hardcoded Password", #密码管理：硬编码的密码
       "SQL Injection: PartiQL", #SQL注入：DynamoDB
       "SQL Injection: AWS", #SQL注入：AWS
       "SQL Injection: JDBC", #SQL注入：JDBC
       "SQL Injection: JPA", #SQL注入：JPA
       "SQL Injection: Turbine", #SQL注入：Turbine
       "SQL Injection: Hibernate", #SQL注入：Hibernate
       "SQL Injection: iBatis Data Map", #SQL注入：iBatis
       "SQL Injection: JDO", #SQL注入：JDO
       "SQL Injection: MyBatis Mapper", #SQL注入：MyBatis
       "SQL Injection: Persistence"  #SQL注入：持久型
       ]


Not_Related_Issues = [
       "Access Control"
       "Access Specifier Manipulation"
       "Android Bad Practices"
       "Code Correctness"
       "Cookie Security: Persistent Cookie"
       "Cross-Site Scripting: Poor Validation"
       "Dead Code"
       "Header Manipulation"
       "HTML5: Overly Permissive CORS Policy"
       "Insecure Randomness"
       "Insecure SSL"
       "J2EE Bad Practices"
       "JavaScript Hijacking"
       "Key Management: Empty Encryption Key"
       "LDAP Manipulation"
       "Missing Check against Null"
       "Missing Check for Null Parameter"
       "Missing XML Validation"
       "Null Dereference"
       "Object Model Violation"
       "Obsolete"
       "Often Misused"
       "Open Redirect"
       "Password Management: Empty Password"
       "Password Management: Password in Comment"
       "Poor Error Handling"
       "Poor Logging Practice"
       "Poor Style"
       "Portability Flaw"
       "Privacy Violation"
       "Privilege Management"
       "Process Control"
       "Race Condition"
       "Redundant Null Check"
       "Server-Side Request Forgery"
       "System Information Leak"
       "Trust Boundary Violation"
       "Unauthenticated Service"
       "Unchecked Return Value"
       "Unreleased Resource"
       "Unsafe JNI"
       "Unsafe Mobile Code"
       "Unsafe Reflection"
       "Weak Cryptographic Hash"
       "Weak Encryption"
       "Weak SecurityManager Check"
]