import os

from reportlab.pdfbase import pdfmetrics  # 注册字体
from reportlab.pdfbase.ttfonts import TTFont  # 字体类
from reportlab.platypus import Table, SimpleDocTemplate, Paragraph, Image, PageBreak  # 报告内容相关类
from reportlab.lib.pagesizes import letter  # 页面的标志尺寸(8.5*inch, 11*inch)
from reportlab.lib.styles import getSampleStyleSheet  # 文本样式
from reportlab.lib import colors  # 颜色模块
from reportlab.lib.colors import HexColor
from reportlab.graphics.charts.barcharts import VerticalBarChart  # 图表类
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.textlabels import Label
from reportlab.graphics.shapes import Drawing, String  # 绘图工具
from reportlab.lib.units import cm, mm  # 单位：cm
import pandas as pd
from reportlab.graphics.charts.piecharts import Pie

from app.api.config import config as data_class

# 获取py 文件所在目录
current_path = os.path.dirname(__file__)

# 把这个目录设置成工作目录
os.chdir(current_path)

# 注册字体(提前准备好字体文件, 如果同一个文件需要多种字体可以注册多个)
pdfmetrics.registerFont(TTFont('SimSun', 'font/simsun.ttf'))
pdfmetrics.registerFont(TTFont('SimSun-Bold', 'font/SimSun-Bold.ttf'))
csv_path = data_class.pdf_save_path


class Graphs:
    @staticmethod
    def escape_html_chars(text):
        # 替换 '<' 为 '&lt;'
        text = text.replace('<', '&lt;')
        # 替换 '>' 为 '&gt;'
        text = text.replace('>', '&gt;')
        return text

        # 绘制标题

    @staticmethod
    def draw_title_32(title: str):
        # 获取所有样式表
        style = getSampleStyleSheet()
        # 拿到标题样式
        ct = style['Heading1']
        # 单独设置样式相关属性
        #        ct.fontName = 'SimSun'  # 字体名
        ct.fontName = 'SimSun-Bold'
        ct.fontSize = 32  # 字体大小
        ct.leading = 50  # 行间距
        ct.textColor = colors.black  # 字体颜色
        ct.alignment = 1  # 居中
        # 创建标题对应的段落，并且返回
        return Paragraph(title, ct)

    @staticmethod
    def draw_title_28(title: str):
        # 获取所有样式表
        style = getSampleStyleSheet()
        # 拿到标题样式
        ct = style['Heading1']
        # 单独设置样式相关属性
        ct.fontName = 'SimSun'  # 字体名
        ct.fontSize = 28  # 字体大小
        ct.leading = 30  # 行间距
        ct.alignment = 1  # 居中
        ct.bold = True
        # 创建标题对应的段落，并且返回
        return Paragraph(title, ct)

    # 绘制小标题
    @staticmethod
    def draw_title_24(title: str):
        # 获取所有样式表
        style = getSampleStyleSheet()
        # 拿到标题样式
        ct = style['Normal']
        # 单独设置样式相关属性
        #        ct.fontName = 'SimSun'  # 字体名
        ct.fontName = 'SimSun-Bold'
        ct.fontSize = 24  # 字体大小
        ct.leading = 30  # 行间距
        ct.alignment = 1  # 居中
        # 创建标题对应的段落，并且返回
        return Paragraph(title, ct)

    # 绘制小标题
    @staticmethod
    def draw_title_20(title: str):
        # 获取所有样式表
        style = getSampleStyleSheet()
        # 拿到标题样式
        ct = style['Normal']
        # 单独设置样式相关属性
        #        ct.fontName = 'SimSun'  # 字体名
        ct.fontName = 'SimSun-Bold'
        ct.fontSize = 20  # 字体大小
        ct.leading = 30  # 行间距
        ct.alignment = 1  # 居中
        # 创建标题对应的段落，并且返回
        return Paragraph(title, ct)

    @staticmethod
    def draw_title_14(title: str):
        # 获取所有样式表
        style = getSampleStyleSheet()
        # 拿到标题样式
        ct = style['Normal']
        # 单独设置样式相关属性
        ct.fontName = 'SimSun'  # 字体名
        ct.fontSize = 14  # 字体大小
        ct.leading = 30  # 行间距
        ct.alignment = 1  # 居中
        # 创建标题对应的段落，并且返回
        return Paragraph(title, ct)

    # 靠左的标题
    def draw_left_16(title: str):
        # 获取所有样式表
        style = getSampleStyleSheet()
        # 拿到标题样式
        ct = style['Normal']
        # 单独设置样式相关属性
        #        ct.fontName = 'SimSun'  # 字体名
        ct.fontName = 'SimSun-Bold'
        ct.fontSize = 16  # 字体大小
        ct.leading = 30  # 行间距
        # 创建标题对应的段落，并且返回
        return Paragraph(title, ct)

    def draw_left_14(title: str):
        # 获取所有样式表
        style = getSampleStyleSheet()
        # 拿到标题样式
        ct = style['Normal']
        # 单独设置样式相关属性
        #        ct.fontName = 'SimSun'  # 字体名
        ct.fontName = 'SimSun-Bold'
        ct.fontSize = 14  # 字体大小
        ct.leading = 30  # 行间距
        # 创建标题对应的段落，并且返回
        return Paragraph(title, ct)

    def draw_left_12(title: str):
        # 获取所有样式表
        style = getSampleStyleSheet()
        # 拿到标题样式
        ct = style['Normal']
        # 单独设置样式相关属性
        ct.fontName = 'SimSun'  # 字体名
        ct.fontSize = 12  # 字体大小
        ct.leading = 30  # 行间距
        ct.firstLineIndent = 13
        ct.bold = 1
        # 创建标题对应的段落，并且返回
        return Paragraph(title, ct)

    def draw_left_12_bold(title: str):
        # 获取所有样式表
        style = getSampleStyleSheet()
        # 拿到标题样式
        ct = style['Normal']
        # 单独设置样式相关属性
        #        ct.fontName = 'SimSun'  # 字体名
        ct.fontName = 'SimSun-Bold'
        ct.fontSize = 12  # 字体大小
        ct.leading = 30  # 行间距
        ct.bold = 100  # 加粗
        # 创建标题对应的段落，并且返回
        return Paragraph(title, ct)

    # 绘制普通段落内容
    @staticmethod
    def draw_text_12(text: str):
        # 移除HTML标签（如果有的话）
        text = Graphs.escape_html_chars(text)

        # 获取所有样式表
        style = getSampleStyleSheet()
        # 获取普通样式
        ct = style['Normal']
        ct.fontName = 'SimSun'
        ct.fontSize = 12
        ct.bold = 1
        ct.wordWrap = 'CJK'  # 设置自动换行
        ct.alignment = 0  # 左对齐
        ct.firstLineIndent = 26  # 第一行开头空格
        ct.leading = 25
        return Paragraph(text, ct)

    # 绘制表格
    @staticmethod
    def draw_table(*args):
        # 列宽度
        col_width = 120
        row_high = 35
        style = [
            ('FONTNAME', (0, 0), (-1, -1), 'SimSun'),  # 字体
            ('FONTSIZE', (0, 0), (-1, -1), 14),  # 字体大小
            # ('FONTSIZE', (0, 1), (-1, -1), 12),  # 第二行到最后一行的字体大小
            ('BACKGROUND', (0, 0), (0, -1), '#d5dae6'),  # 设置第一列背景颜色
            # ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # 第一行水平居中
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  # 第二行到最后一行左右左对齐
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # 所有表格上下居中对齐
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.darkslategray),  # 设置表格内文字颜色
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),  # 设置表格框线为grey色，线宽为0.5

            # ('SPAN', (0, 1), (0, 2)),  # 合并第一列二三行
            # ('SPAN', (0, 3), (0, 4)),  # 合并第一列三四行
            # ('SPAN', (0, 5), (0, 6)),  # 合并第一列五六行
            # ('SPAN', (0, 7), (0, 8)),  # 合并第一列五六行
        ]
        # colWidths = (50 * mm, 50 * mm), rowHeights = (10 * mm, 250 * mm)
        table = Table(args, colWidths=(60 * mm, 90 * mm), rowHeights=row_high, style=style)
        return table

    # 绘制表格
    @staticmethod
    def draw_table_1(*args):
        # 列宽度
        col_width = 120
        row_high = 35
        style = [
            # (column_start,row_start),(column_end,row_end)
            ('FONTNAME', (0, 0), (-1, -1), 'SimSun'),  # 字体
            ('FONTSIZE', (0, 0), (-1, 0), 14),  # 第一行的字体大小
            ('FONTSIZE', (0, 1), (-1, -1), 12),  # 第二行到最后一行的字体大小
            ('BACKGROUND', (0, 0), (-1, 0), '#d5dae6'),  # 设置第一行背景颜色
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # 第一行水平居中
            # ('ALIGN', (0, 1), (-1, -1), 'LEFT'),  # 第二行到最后一行左右左对齐
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # 所有表格上下居中对齐
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.darkslategray),  # 设置表格内文字颜色
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),  # 设置表格框线为grey色，线宽为0.5
            # ('SPAN', (0, 1), (0, 2)),  # 合并第一列二三行
            # ('SPAN', (0, 3), (0, 4)),  # 合并第一列三四行
            # ('SPAN', (0, 5), (0, 6)),  # 合并第一列五六行
            # ('SPAN', (0, 7), (0, 8)),  # 合并第一列五六行
        ]
        table = Table(args, colWidths=(25 * mm, 120 * mm, 25 * mm), rowHeights=row_high, style=style)
        return table

    @staticmethod
    def draw_table_2(*args):
        # 列宽度
        col_width = 120
        row_high = 35
        style = [
            # (column_start,row_start),(column_end,row_end)
            ('FONTNAME', (0, 0), (-1, -1), 'SimSun'),  # 字体
            ('FONTSIZE', (0, 0), (-1, 0), 14),  # 第一行的字体大小
            ('FONTSIZE', (0, 1), (-1, -1), 12),  # 第二行到最后一行的字体大小
            ('BACKGROUND', (0, 0), (-1, 0), '#d5dae6'),  # 设置第一行背景颜色
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # 第一行水平居中
            # ('ALIGN', (0, 1), (-1, -1), 'LEFT'),  # 第二行到最后一行左右左对齐
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # 所有表格上下居中对齐
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.darkslategray),  # 设置表格内文字颜色
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),  # 设置表格框线为grey色，线宽为0.5
            # ('SPAN', (0, 1), (0, 2)),  # 合并第一列二三行
            # ('SPAN', (0, 3), (0, 4)),  # 合并第一列三四行
            # ('SPAN', (0, 5), (0, 6)),  # 合并第一列五六行
            # ('SPAN', (0, 7), (0, 8)),  # 合并第一列五六行
        ]
        table = Table(args, colWidths=(25 * mm, 120 * mm, 25 * mm, 25 * mm), rowHeights=row_high, style=style)
        return table

    # 创建图表
    @staticmethod
    def draw_bar(bar_info):
        # 1.把数据写在柱状图的顶端
        labels = bar_info[0]
        data = bar_info[1]

        drawing = Drawing(500, 250)
        bc = VerticalBarChart()
        bc.x = 45  # 整个图表的x坐标
        bc.y = 45  # 整个图表的y坐标
        bc.height = 300  # 图表的高度
        bc.width = 400  # 图表的宽度
        bc.data = [data]
        bc.strokeColor = colors.black  # 顶部和右边轴线的颜色
        bc.bars[0].fillColor = colors.lightblue
        bc.valueAxis.valueMin = 0  # 设置y坐标的最小值
        bc.valueAxis.valueMax = max(data) * 1.2  # 设置y坐标的最大值
        # bc.valueAxis.valueStep = _step  # 设置y坐标的步长
        bc.categoryAxis.labels.dx = 2
        bc.categoryAxis.labels.dy = -8
        bc.categoryAxis.labels.fontName = 'SimSun'
        bc.categoryAxis.labels.angle = 20
        bc.categoryAxis.categoryNames = labels

        # 添加数据标签并调整位置
        bc.barLabels.nudge = 10  # 将标签向上移动10个单位
        bc.barLabels.fontName = 'SimSun'
        bc.barLabels.fontSize = 10
        bc.barLabelFormat = '%s'
        bc.barLabels.dy = 0  # 调整垂直偏移量

        drawing.add(bc)
        return drawing

    # @staticmethod
    # def draw_bar(bar_data: list, ax: list, _max: int, _step: int):
    #     drawing = Drawing(500, 250)
    #     bc = VerticalBarChart()  #
    #     bc.x = 45  # 整个图表的x坐标
    #     bc.y = 45  # 整个图表的y坐标
    #     bc.height = 300  # 图表的高度
    #     bc.width = 400  # 图表的宽度
    #     bc.data = bar_data
    #     bc.strokeColor = colors.black  # 顶部和右边轴线的颜色
    #     bc.bars[0].fillColor = colors.lightblue
    #     bc.valueAxis.valueMin = 0  # 设置y坐标的最小值
    #     bc.valueAxis.valueMax = _max  # 设置y坐标的最大值
    #     bc.valueAxis.valueStep = _step  # 设置y坐标的步长
    #     bc.categoryAxis.labels.dx = 2
    #     bc.categoryAxis.labels.dy = -8
    #     bc.categoryAxis.labels.angle = 20
    #     bc.categoryAxis.categoryNames = ax
    #
    #     # 图示
    #     # leg = Legend()
    #     # leg.fontName = 'SimSun'
    #     # leg.alignment = 'right'
    #     # leg.boxAnchor = 'ne'
    #     # leg.x = 475  # 图例的x坐标
    #     # leg.y = 240
    #     # leg.dxTextSpace = 10
    #     # leg.columnMaximum = 3
    #     # # leg.colorNamePairs = items
    #     # drawing.add(leg)
    #     drawing.add(bc)
    #     return drawing

    @staticmethod
    def draw_pie(pie_info):
        labels = pie_info[0]
        data = pie_info[1]

        # 创建绘图对象
        drawing = Drawing(400, 200)

        # 创建饼图对象
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 200
        pie.height = 200

        # 设置饼图数据
        pie.data = data
        pie.labels = labels
        pie.slices.strokeWidth = 0.5
        pie.slices.fontName = 'SimSun'
        pie.slices[0].fillColor = HexColor('#ff7070')
        pie.slices[1].fillColor = HexColor('#eeb26c')
        pie.slices[2].fillColor = HexColor('#7ed3f4')

        # 添加标签和百分比
        pie.simpleLabels = 0
        pie.sideLabels = 1

        # 将饼图添加到绘图对象
        drawing.add(pie)
        return drawing

    # 绘制图片
    @staticmethod
    def draw_img(path):
        img = Image(path)  # 读取指定路径下的图片
        img.drawWidth = 5 * cm  # 设置图片的宽度
        img.drawHeight = 8 * cm  # 设置图片的高度
        return img

    # 绘制柱状图
    @staticmethod
    def drawbarchart(bar_data: list, ax: list):
        drawing = Drawing(400, 250)
        drawing.add(String(50, 180, "2021年销量柱状图", fontSize=16, fontName='SimSun', fillColor=colors.black))

        # drawing.add(Rect(320, 240, 5, 5, fillColor=colors.gray, strokeColor=colors.white))
        # drawing.add(String(326, 240, "张三", fontSize=5, fontName='SimSun', fillColor=colors.gray))
        # drawing.add(Rect(340, 240, 5, 5, fillColor=colors.green, strokeColor=colors.white))
        # drawing.add(String(346, 240, "李四", fontSize=5, fontName='微软雅黑', fillColor=colors.green))

        data = [
            (13, 5, 20, 22, 37, 45, 19, 4),
            # (14, 6, 21, 23, 38, 46, 20, 5),
        ]
        bc = VerticalBarChart()
        bc.x = 50
        bc.y = 50
        bc.height = 125
        bc.width = 300
        bc.data = bar_data
        bc.strokeColor = colors.gray
        bc.bars[0].fillColor = colors.gray
        # bc.bars[1].fillColor = colors.green
        bc.groupSpacing = 2  # 每组柱状图之间的间隔
        bc.barSpacing = 1  # 每个柱状图之间的间隔
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = 50
        bc.valueAxis.valueStep = 10
        bc.categoryAxis.labels.boxAnchor = 'ne'
        bc.categoryAxis.labels.dx = 8
        bc.categoryAxis.labels.dy = -2
        bc.categoryAxis.labels.angle = 30
        bc.categoryAxis.labels.setProperties({"fontName": "SimSun"})
        bc.categoryAxis.categoryNames = ax
        # ['1月', '2月', '3月','4月', '5月', '6月', '7月', '8月']
        drawing.add(bc)
        return drawing

    

    def export_pdf(itemName, pdf_Time, zipName, language, type_,startTime, lastTime, vul_number,
                   vuls, file_location, final_results, number, version, risk_level_dict, bar_info, pie_info, code_size, git_info):
        # 创建内容对应的空列表
        content = list()

        # 添加标题,第一页
        content.append(Graphs.draw_title_32('静态代码安全扫描系统报告'))
        content.append(Graphs.draw_title_24('项目报告'))
        content.append(Graphs.draw_title_32('<br/><br/><br/>'))
        content.append(Graphs.draw_title_20('项目名称：{}'.format(itemName)))
        content.append(Graphs.draw_title_32('<br/><br/><br/>'))
        # content.append(Graphs.draw_title_24('{}'.format(teamName)))
        content.append(Graphs.draw_title_32('<br/>'))
        content.append(Graphs.draw_title_20('报告生成时间：{}'.format(pdf_Time)))
        content.append(PageBreak())

        # 第二页，生成项目表格
        content.append(Graphs.draw_title_24('第一部分：漏洞扫描结果汇总'))
        content.append(Graphs.draw_title_32('<br/>'))
        content.append(Graphs.draw_left_16('1.项目基本情况'))
        content.append(Graphs.draw_title_32('<br/>'))
        # 添加表格
        locations = set()
        for file in file_location:
            locations.add(file[8])
        total = len(locations)
        data = [
            ('项目名称', '{}'.format(itemName)),
            ('检测文件名称', '{}'.format(zipName)),
            ('有漏洞文件数量', '{}'.format(total)),
            ('开发语言', '{}'.format(language)),
            ('扫描类型', '{}'.format(type_)),
            ('代码行数', '{}'.format(code_size)),
            ('检测开始时间', '{}'.format(startTime)),
            ('检测耗时', '{}'.format(lastTime))
        ]
        if git_info:
            data.extend([
                ('git仓库地址', f'{git_info[0] or ""}'),
                ('分支', f'{git_info[1] or "master"}'),
            ])
        content.append(Graphs.draw_table(*data))
        content.append(PageBreak())  # 添加分页符

        # 第三页，生成漏洞表格
        content.append(Graphs.draw_left_16('2.漏洞检测结果汇总'))
        content.append(Graphs.draw_title_32('<br/>'))
        content.append(Graphs.draw_left_14('2.1 检测结果汇总表'))
        content.append(Graphs.draw_title_14('漏洞检测结果详情统计'))
        # 添加漏洞的信息表格
        data = [('序号', '漏洞名称', '统计', '风险等级')]
        for i in range(0, len(vul_number)):
            nt = vul_number[i][0]
            nt = int(nt)
            vul_name = vul_number[i][1]
            data.append(('{}'.format(nt), '{}'.format(vul_number[i][1]), '{}'.format(vul_number[i][2]), '{}'.format(risk_level_dict[vul_name])))
        content.append(Graphs.draw_table_2(*data))
        content.append(PageBreak())

        # 第四页，生成图表
        content.append(Graphs.draw_left_14('2.2 漏洞类型统计图'))
        content.append(Graphs.draw_title_14('漏洞统计柱状图'))
        content.append(Graphs.draw_title_32('<br/><br/>'))
        content.append(Graphs.draw_bar(bar_info))
        content.append(PageBreak())

        content.append(Graphs.draw_title_14('漏洞等级分布饼图'))
        content.append(Graphs.draw_title_32('<br/><br/>'))
        content.append(Graphs.draw_pie(pie_info))
        content.append(PageBreak())
        # ax_data = []
        # b_data = []
        # data = []
        # Max = 5
        # for i in range(0, len(header_five)):
        #     ax_data.append(header_five[i][0])
        #     data.append(int(header_five[i][1]))
        # if len(data) != 0:
        #     Max = max(data) + 5
        # if Max <= 100:
        #     Step = 5
        # elif Max <= 200:
        #     Step = 10
        # elif Max <= 300:
        #     Step = 15
        # elif Max <= 400:
        #     Step = 20
        #     Max = max(data) + 10
        # elif Max <= 500:
        #     Step = 25
        #     Max = max(data) + 15
        # elif Max <= 700:
        #     Step = 30
        #     Max = max(data) + 15
        # elif Max <= 900:
        #     Step = 40
        #     Max = max(data) + 20
        # elif Max <= 1200:
        #     Step = 50
        #     Max = max(data) + 25
        # elif Max <= 1500:
        #     Step = 60
        #     Max = max(data) + 30
        # elif Max <= 2000:
        #     Step = 80
        #     Max = max(data) + 40
        # elif Max <= 3000:
        #     Step = 100
        #     Max = max(data) + 50
        # else:
        #     Step = 100
        #     Max = max(data) + 50
        # data = tuple(data)
        # b_data.append(data)
        # content.append(Graphs.draw_bar(b_data, ax_data, Max, Step))
        # content.append(PageBreak())

        # 第五页往后
        content.append(Graphs.draw_title_24('第二部分：漏洞扫描结果详情'))
        content.append(Graphs.draw_title_32('<br/>'))
        # fortify规则
        if version is not None:
            if version == 'Developer Workbook':
                j = 1
                vuls = vuls.split(',')
                for i, vul in enumerate(vuls):
                    vul = vul.strip()
                    level = risk_level_dict[vul]
                    Description = None
                    suggestion = None

                    content.append(Graphs.draw_left_16('{id} {cweName}'.format(id=j, cweName=vul)))
                    content.append(Graphs.draw_left_14('{id}.1 漏洞概述'.format(id=j)))
                    content.append(Graphs.draw_title_32('<br/>'))
                    # 添加漏洞的信息表格
                    data = [
                        ('漏洞编号', '漏洞名称', '风险等级'),
                        ('{}'.format(i + 1), '{}'.format(vul), '{}'.format(level))
                    ]
                    content.append(Graphs.draw_table_1(*data))
                    content.append(Graphs.draw_title_32('<br/>'))
                    content.append(Graphs.draw_left_14('{id}.2 漏洞详情'.format(id=j)))
                    num = 0
                    t = 1
                    for i2 in range(0, len(number)):
                        if vul.lower().replace(" ", "") == number[i2][0].replace(" ", ""):
                            for i3 in range(num, num + int(number[i2][1])):
                                content.append(Graphs.draw_left_12_bold('{id}）漏洞定位'.format(id=t)))
                                content.append(Graphs.draw_text_12(
                                    '{fileName}:{location}'.format(
                                        fileName=file_location[i3][0], location=file_location[i3][2]
                                    )
                                ))
                                if file_location[i3][2]:
                                    content.append(Graphs.draw_left_12('漏洞分析'))
                                    content.append(
                                        Graphs.draw_text_12('漏洞爆发点:{Sink}'.format(Sink=file_location[i3][5])))
                                    content.append(Graphs.draw_text_12(
                                        '爆发点函数:{Enclosing_Method}'.format(Enclosing_Method=file_location[i3][6])))
                                    content.append(
                                        Graphs.draw_text_12('缺陷源:{Source}'.format(Source=file_location[i3][7])))
                                if file_location[i3][3]:
                                    content.append(Graphs.draw_left_12('漏洞源代码'))
                                    content.append(
                                        Graphs.draw_text_12('{location}'.format(location=file_location[i3][3])))
                                if file_location[i3][4]:
                                    content.append(Graphs.draw_left_12('修复参考'))
                                    content.append(
                                        Graphs.draw_text_12('{location}'.format(location=file_location[i3][4])))
                                t += 1
                        num += int(number[i2][1])
                    if Description:
                        content.append(Graphs.draw_left_14('{id}.3 漏洞描述'.format(id=j)))
                        # 添加漏洞描述
                        content.append(Graphs.draw_text_12('{}'.format(Description)))
                    if suggestion:
                        content.append(Graphs.draw_left_14('{id}.4 修复建议'.format(id=j)))
                        # 添加修复建议
                        content.append(Graphs.draw_text_12('{}'.format(suggestion)))
                    j += 1
            elif 'OWASP' in version:
                if '2010' in version:
                    table = pd.read_csv(os.path.join(csv_path, "csv/OWASP_2010.csv"), encoding='gbk')
                elif '2013' in version:
                    table = pd.read_csv(os.path.join(csv_path, "csv/OWASP_2013.csv"), encoding='gbk')
                elif '2017' in version:
                    table = pd.read_csv(os.path.join(csv_path, "csv/OWASP_2017.csv"), encoding='gbk')
                vul_names = table['漏洞名称'].values.tolist()
                levels = table['漏洞等级'].values.tolist()
                Descriptions = table['漏洞描述'].values.tolist()
                suggestions = table['修复方案'].values.tolist()
                j = 1
                vuls = vuls.split(',')
                for vul in vuls:
                    id = 0
                    for i, _ in enumerate(vul_names):
                        if _ == vul:
                            id = i
                    vul_name = vul_names[id]
                    level = levels[id]
                    Description = Descriptions[id]
                    suggestion = suggestions[id]

                    content.append(Graphs.draw_left_16('{id} {cweName}'.format(id=j, cweName=vul_name)))
                    content.append(Graphs.draw_left_14('{id}.1 漏洞概述'.format(id=j)))
                    content.append(Graphs.draw_title_32('<br/>'))
                    # 添加漏洞的信息表格
                    data = [
                        ('漏洞编号', '漏洞名称', '风险等级'),
                        ('A{}'.format(id), '{}'.format(vul_name), '{}'.format(level))
                    ]
                    content.append(Graphs.draw_table_1(*data))
                    content.append(Graphs.draw_title_32('<br/>'))
                    content.append(Graphs.draw_left_14('{id}.2 漏洞详情'.format(id=j)))
                    num = 0
                    t = 1
                    for i2 in range(0, len(number)):
                        if vul.lower().replace(" ", "") == number[i2][0].replace(" ", ""):
                            for i3 in range(num, num + int(number[i2][1])):
                                content.append(Graphs.draw_left_12_bold('{id}）漏洞定位'.format(id=t)))
                                content.append(Graphs.draw_text_12(
                                    '{fileName}:{location}'.format(
                                        fileName=file_location[i3][0], location=file_location[i3][2]
                                    )
                                ))
                                if file_location[i3][2]:
                                    content.append(Graphs.draw_left_12('漏洞分析'))
                                    content.append(
                                        Graphs.draw_text_12('漏洞爆发点:{Sink}'.format(Sink=file_location[i3][5])))
                                    content.append(Graphs.draw_text_12(
                                        '爆发点函数:{Enclosing_Method}'.format(Enclosing_Method=file_location[i3][6])))
                                    content.append(
                                        Graphs.draw_text_12('缺陷源:{Source}'.format(Source=file_location[i3][7])))
                                if file_location[i3][3]:
                                    content.append(Graphs.draw_left_12('漏洞源代码'))
                                    content.append(
                                        Graphs.draw_text_12('{location}'.format(location=file_location[i3][3])))
                                if file_location[i3][4]:
                                    content.append(Graphs.draw_left_12('修复参考'))
                                    content.append(
                                        Graphs.draw_text_12('{location}'.format(location=file_location[i3][4])))
                                t += 1
                        num += int(number[i2][1])
                    if Description:
                        content.append(Graphs.draw_left_14('{id}.3 漏洞描述'.format(id=j)))
                        # 添加漏洞描述
                        content.append(Graphs.draw_text_12('{}'.format(Description)))
                    if suggestion:
                        content.append(Graphs.draw_left_14('{id}.4 修复建议'.format(id=j)))
                        # 添加修复建议
                        content.append(Graphs.draw_text_12('{}'.format(suggestion)))
                    j += 1
            elif 'CWE' in version:
                table = pd.read_csv(os.path.join(csv_path, "csv/漏洞知识库.csv"), encoding='gbk')
                ids = table['漏洞ID'].values.tolist()
                cweNames = table['漏洞名称'].values.tolist()
                levels = table['漏洞等级'].values.tolist()
                Descriptions = table['漏洞描述'].values.tolist()
                suggestions = table['修复方案'].values.tolist()
                j = 1
                vuls = vuls.split(',')
                for vul in vuls:
                    id = 0
                    for i, _ in enumerate(ids):
                        if _ == vul.lower().strip():
                            id = i
                    cweName = cweNames[id]
                    level = levels[id]
                    Description = Descriptions[id]
                    suggestion = suggestions[id]

                    content.append(Graphs.draw_left_16('{id} {cweName}'.format(id=j, cweName=cweName)))
                    content.append(Graphs.draw_left_14('{id}.1 漏洞概述'.format(id=j)))
                    content.append(Graphs.draw_title_32('<br/>'))
                    # 添加漏洞的信息表格
                    data = [
                        ('漏洞编号', '漏洞名称', '风险等级'),
                        ('{}'.format(vul), '{}'.format(cweName), '{}'.format(level))
                    ]
                    content.append(Graphs.draw_table_1(*data))
                    content.append(Graphs.draw_title_32('<br/>'))
                    content.append(Graphs.draw_left_14('{id}.2 漏洞详情'.format(id=j)))
                    num = 0
                    t = 1
                    for i2 in range(0, len(number)):
                        if vul.lower().replace(" ", "") == number[i2][0].replace(" ", ""):
                            for i3 in range(num, num + int(number[i2][1])):
                                if i3 == 161:
                                    jj = 1
                                content.append(Graphs.draw_left_12_bold('{id}）漏洞定位'.format(id=t)))
                                content.append(Graphs.draw_text_12(
                                    '{fileName}:{location}'.format(
                                        fileName=file_location[i3][0], location=file_location[i3][2]
                                    )
                                ))
                                if file_location[i3][2]:
                                    content.append(Graphs.draw_left_12('漏洞分析'))
                                    content.append(
                                        Graphs.draw_text_12('漏洞爆发点:{Sink}'.format(Sink=file_location[i3][5])))
                                    content.append(Graphs.draw_text_12(
                                        '爆发点函数:{Enclosing_Method}'.format(Enclosing_Method=file_location[i3][6])))
                                    content.append(
                                        Graphs.draw_text_12('缺陷源:{Source}'.format(Source=file_location[i3][7])))
                                if file_location[i3][3]:
                                    content.append(Graphs.draw_left_12('漏洞源代码'))
                                    content.append(
                                        Graphs.draw_text_12('{location}'.format(location=file_location[i3][3])))
                                if file_location[i3][4]:
                                    content.append(Graphs.draw_left_12('修复参考'))
                                    content.append(
                                        Graphs.draw_text_12('{location}'.format(location=file_location[i3][4])))
                                t += 1
                        num += int(number[i2][1])
                    if Description:
                        content.append(Graphs.draw_left_14('{id}.3 漏洞描述'.format(id=j)))
                        # 添加漏洞描述
                        content.append(Graphs.draw_text_12('{}'.format(Description)))
                    if suggestion:
                        content.append(Graphs.draw_left_14('{id}.4 修复建议'.format(id=j)))
                        # 添加修复建议
                        content.append(Graphs.draw_text_12('{}'.format(suggestion)))
                    j += 1
        # 抽象语法树规则、大模型
        else:
            # 这里直接根据grouped_results这个字段来构造整个导出报告
            for index, (vul_name, level, description, repairPlan, file_list) in enumerate(final_results, start=1):
                content.append(Graphs.draw_left_16('{id} {vul_name}'.format(id=index, vul_name=vul_name)))
                content.append(Graphs.draw_left_14('{id}.1 漏洞概述'.format(id=index)))
                content.append(Graphs.draw_title_32('<br/>'))
                # 添加漏洞的信息表格
                data = [
                    ('漏洞编号', '漏洞名称', '风险等级'),
                    ('{}'.format(index), '{}'.format(vul_name), '{}'.format(level))
                ]
                content.append(Graphs.draw_table_1(*data))
                content.append(Graphs.draw_title_32('<br/>'))
                content.append(Graphs.draw_left_14('{id}.2 漏洞详情'.format(id=index)))
                for file_index ,(fileName,vulType,location,source_code,repair_code,Sink,Enclosing_Method,Source,filepath) in enumerate(file_list, start=1):

                    content.append(Graphs.draw_left_12_bold('{id}）漏洞定位'.format(id=file_index)))
                    content.append(Graphs.draw_text_12(
                        '{filepath}:{location}'.format(
                            filepath=filepath, location=location
                        )
                    ))
                    if location:
                        content.append(Graphs.draw_left_12('漏洞分析'))
                        content.append(
                            Graphs.draw_text_12('漏洞爆发点:{Sink}'.format(Sink=Sink)))
                        content.append(Graphs.draw_text_12(
                            '爆发点函数:{Enclosing_Method}'.format(Enclosing_Method=Enclosing_Method)))
                        content.append(
                            Graphs.draw_text_12('缺陷源:{Source}'.format(Source=Source)))
                    if source_code:
                        content.append(Graphs.draw_left_12('漏洞源代码'))
                        content.append(
                            Graphs.draw_text_12('{source_code}'.format(source_code=source_code)))
                    if repair_code:
                        content.append(Graphs.draw_left_12('修复参考'))
                        content.append(
                            Graphs.draw_text_12('{repair_code}'.format(repair_code=repair_code)))
                if description:
                    content.append(Graphs.draw_left_14('{id}.3 漏洞描述'.format(id=index)))
                    # 添加漏洞描述
                    content.append(Graphs.draw_text_12('{}'.format(description)))
                if repairPlan:
                    content.append(Graphs.draw_left_14('{id}.4 修复建议'.format(id=index)))
                    # 添加修复建议
                    content.append(Graphs.draw_text_12('{}'.format(repairPlan)))
        # 生成pdf文件
        time = pdf_Time.replace(':', '')
        time = time.replace(' ', '')
        time = time.replace('-', '')
        doc = SimpleDocTemplate(
            os.path.join(csv_path, '{fileName}_{time}.pdf').format(fileName=itemName, time=time),
            pagesize=letter)
        doc.build(content)
        return ('{fileName}_{time}.pdf'.format(fileName=itemName, time=time))