import os

from reportlab.pdfbase import pdfmetrics  # 注册字体
from reportlab.pdfbase.ttfonts import TTFont  # 字体类
from reportlab.platypus import Table, SimpleDocTemplate, Paragraph, Image, PageBreak  # 报告内容相关类
from reportlab.lib.pagesizes import letter  # 页面的标志尺寸(8.5*inch, 11*inch)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # 文本样式
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.colors import black
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
pdfmetrics.registerFont(TTFont('HongDou-Bold', 'font/红豆宋体加粗字体.ttf'))
csv_path = data_class.pdf_save_path


class Graphs:
    """PDF文档样式工具类，提供各种标题和文本的格式化方法"""

    @staticmethod
    def escape_html_chars(text):
        """转义HTML特殊字符"""
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        return text

    @staticmethod
    def _create_paragraph(title, style_name, font_name, font_size, leading,
                          alignment=0, bold=False, first_line_indent=0, text_color=None,
                          word_wrap=None):
        """创建段落的通用方法"""
        style = getSampleStyleSheet()
        ct = style[style_name]

        ct.fontName = font_name
        ct.fontSize = font_size
        ct.leading = leading
        ct.alignment = alignment
        ct.bold = bold
        ct.firstLineIndent = first_line_indent

        if text_color:
            ct.textColor = text_color

        if word_wrap:
            ct.wordWrap = word_wrap

        return Paragraph(title, ct)

    # 居中标题方法
    @staticmethod
    def draw_title_32(title: str):
        """32号居中标题"""
        return Graphs._create_paragraph(
            title, 'Heading1', 'SimSun-Bold', 32, 50,
            alignment=1, text_color=colors.black
        )

    @staticmethod
    def draw_title_28(title: str):
        """28号居中标题"""
        return Graphs._create_paragraph(
            title, 'Heading1', 'SimSun', 28, 30,
            alignment=1, bold=True
        )

    @staticmethod
    def draw_title_24(title: str):
        """24号居中标题"""
        return Graphs._create_paragraph(
            title, 'Normal', 'SimSun-Bold', 24, 30,
            alignment=1
        )

    @staticmethod
    def draw_title_20(title: str):
        """20号居中标题"""
        return Graphs._create_paragraph(
            title, 'Normal', 'SimSun-Bold', 20, 30,
            alignment=1
        )

    @staticmethod
    def draw_title_14(title: str):
        """14号居中标题"""
        return Graphs._create_paragraph(
            title, 'Normal', 'SimSun', 14, 30,
            alignment=1
        )

    # 靠左标题方法
    @staticmethod
    def draw_left_16(title: str):
        """16号左对齐标题"""
        return Graphs._create_paragraph(
            title, 'Normal', 'SimSun-Bold', 16, 30
        )

    @staticmethod
    def draw_left_14(title: str):
        """14号左对齐标题"""
        return Graphs._create_paragraph(
            title, 'Normal', 'SimSun-Bold', 14, 30
        )

    @staticmethod
    def draw_left_12(title: str):
        """12号左对齐标题（首行缩进）"""
        return Graphs._create_paragraph(
            title, 'Normal', 'SimSun', 12, 30,
            first_line_indent=13, bold=True
        )

    @staticmethod
    def draw_left_12_bold(title: str):
        """12号左对齐加粗标题"""
        return Graphs._create_paragraph(
            title, 'Normal', 'SimSun-Bold', 12, 30,
            bold=True
        )

    # 普通段落内容
    @staticmethod
    def draw_text_12(text: str):
        """12号普通文本段落"""
        text = Graphs.escape_html_chars(text)

        return Graphs._create_paragraph(
            text, 'Normal', 'SimSun', 12, 25,
            alignment=0, bold=True, first_line_indent=26, word_wrap='CJK'
        )

    # 绘制表格
    @staticmethod
    def draw_table(data):
        """绘制表格

        Args:
            data: 二维数组数据，行数要么是10要么是8

        Returns:
            Table: 配置好的表格对象
        """
        # 页面配置
        page_width, _ = letter  # 612 × 792 points
        table_width = page_width - 160  # 左右各80边距

        # 创建段落样式
        styles = getSampleStyleSheet()
        normal_style = styles['Normal']
        normal_style.fontName = 'SimSun'
        normal_style.fontSize = 12
        normal_style.leading = 14  # 行高
        normal_style.alignment = 0  # 左对齐

        # 处理数据：将第二列和第四列转换为Paragraph
        processed_data = []
        for row in data:
            processed_row = []
            for i, cell in enumerate(row):
                # 第一列和第三列保持原样（索引0和2），其他列转换为Paragraph
                if i in [0, 2]:
                    processed_row.append(str(cell))
                else:
                    processed_row.append(Paragraph(str(cell), normal_style))
            processed_data.append(processed_row)

        # 表格样式配置
        row_height = 30
        base_style = [
            ('FONTNAME', (0, 0), (-1, -1), 'SimSun'),  # 字体
            ('FONTSIZE', (0, 0), (-1, -1), 12),  # 字体大小
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),  # 文字颜色

            # 第一列和第三列添加 灰色背景 和 粗体
            ('BACKGROUND', (0, 0), (0, 7), '#e6e6e6'),
            ('FONTNAME', (0, 0), (0, 7), 'HongDou-Bold'),
            ('BACKGROUND', (2, 0), (2, 7), '#e6e6e6'),
            ('FONTNAME', (2, 0), (2, 7), 'HongDou-Bold'),

            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  # 左对齐
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # 垂直居中

            ('GRID', (0, 0), (-1, -1), 0.5, '#3a3a3a'),  # 网格颜色
            ('BOX', (0, 0), (-1, -1), 2, colors.black),  # 边框颜色
            ('TOPPADDING', (0, 0), (-1, -1), 4),  # 上边距 8 points
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),  # 下边距 8 points
        ]

        # 动态样式配置
        style = base_style.copy()
        if len(processed_data) == 10:
            style.extend([
                # 第一列添加 灰色背景 和 粗体
                ('BACKGROUND', (0, 8), (0, 9), '#e6e6e6'),
                ('FONTNAME', (0, 8), (0, 9), 'HongDou-Bold'),
                ('SPAN', (1, 8), (3, 8)),  # 合并第9行的第2-4列
                ('SPAN', (1, 9), (3, 9))  # 合并第10行的第2-4列
            ])

        # 列宽配置
        width_ratios = [1.1, 2.5, 1.1, 1.7]
        total_ratio = sum(width_ratios)
        col_widths = [table_width * ratio / total_ratio for ratio in width_ratios]

        # 创建表格
        table = Table(
            processed_data,
            colWidths=col_widths,

            style=style
        )

        return table

    @staticmethod
    def draw_text_12_overview(data):
        styles = getSampleStyleSheet()

        text_style = ParagraphStyle(
            name='test_style',
            parent=styles['Normal'],
            fontName='SimSun',
            fontSize=13,
            leading=14,  # 行高
            textColor=black,
            alignment=TA_JUSTIFY,  # 两端对齐
            wordWrap='CJK',  # 支持中文换行
            leftIndent=0,  # 左缩进为0
            rightIndent=0,  # 右缩进为0
            firstLineIndent=24,  # 首行缩进为0
            spaceBefore=12,  # 段前间距为12
            spaceAfter=12,  # 段后间距为12
            borderPadding=0,  # 边框内边距为0
        )
        para = Paragraph(data, text_style)
        return para

    @staticmethod
    def draw_table_vul_level(data):
        """
        绘制漏洞等级表格

        Args:
            data: 表格数据，四行三列

        Returns:
            Table: 格式化后的表格对象

        Note:
            1. 第(1,2)-(3,2)单元格左对齐并转换为Paragraph
            2. 第一行加粗字体，灰色背景
            3. 整体水平居中，字体12号
        """
        # 创建段落样式
        styles = getSampleStyleSheet()
        normal_style = styles['Normal']
        normal_style.fontName = 'SimSun'
        normal_style.fontSize = 11
        normal_style.leading = 20  # 行高

        # 处理表格数据：将指定列转换为Paragraph
        processed_data = []
        for i, row in enumerate(data):
            processed_row = []
            for j, cell in enumerate(row):
                if i > 0 and j == 2:
                    processed_row.append(Paragraph(str(cell), normal_style))
                else:
                    processed_row.append(str(cell))
            processed_data.append(processed_row)

        # 定义表格样式
        table_styles = [
            # 全局样式
            ('FONTNAME', (0, 0), (-1, -1), 'SimSun'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # 整体水平居中
            ('ALIGN', (2, 1), (-1, -1), 'LEFT'),  # 右下角内容左对齐
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # 垂直居中
            ('LEADING', (0, 0), (-1, -1), 20),  # 行间距
            ('TOPPADDING', (0, 0), (-1, -1), 0),  # 上内边距
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),  # 下内边距

            # 表头样式
            ('BACKGROUND', (0, 0), (2, 0), '#e6e6e6'),  # 灰色背景
            ('FONTNAME', (0, 0), (2, 0), 'HongDou-Bold'),  # 加粗字体

            # 边框样式
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),  # 网格线
            ('BOX', (0, 0), (-1, -1), 2, colors.black),  # 外边框
        ]

        # 计算表格尺寸
        page_width, _ = letter  # 612 × 792 points
        table_width = page_width - 160  # 左右各80边距

        # 列宽配置
        width_ratios = [0.9, 1, 5.2]
        total_ratio = sum(width_ratios)
        col_widths = [table_width * ratio / total_ratio for ratio in width_ratios]

        # 行高配置
        row_ratios = [6, 15, 15, 15]
        total_row_ratio = sum(row_ratios)
        row_heights = [300 * ratio / total_row_ratio for ratio in row_ratios]

        # 创建表格
        table = Table(
            processed_data,
            colWidths=col_widths,
            rowHeights=row_heights,
            style=table_styles
        )

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
        cate_name = bar_info[0]
        data = bar_info[1]
        color_list = [
            HexColor('#ff6b6b'),
            HexColor('#ffa726'),
            HexColor('#42a5f5'),
            HexColor('#bdbdbd')
        ]

        drawing = Drawing(500, 250)
        bc = VerticalBarChart()

        # 图表基本设置
        bc.x = 45
        bc.y = 45
        bc.width = 400
        bc.height = 300
        bc.data = data
        bc.strokeColor = colors.black

        # 设置柱状图颜色
        for i in range(len(color_list)):
            bc.bars[i].fillColor = color_list[i]

        # 坐标轴设置
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = 1.2 * sum(item[0] for item in data)

        bc.categoryAxis.labels.dx = 2
        bc.categoryAxis.labels.dy = -8
        bc.categoryAxis.labels.fontName = 'SimSun'
        bc.categoryAxis.labels.angle = 20
        bc.categoryAxis.categoryNames = cate_name
        bc.categoryAxis.style = 'stacked'

        # 数据标签设置
        bc.barLabels.fontName = 'SimSun'
        bc.barLabels.fontSize = 10
        bc.barLabelFormat = '%s'

        for i in range(len(data)):
            for j in range(len(data[i])):
                if data[i][j] != 0:
                    label = bc.barLabels[(i, j)]
                    label.nudge = -(data[i][j] / 2) * 30
                    label.visible = True
                else:
                    bc.barLabels[(i, j)].visible = False

        # 图例设置
        legend = Legend()
        legend.fontName = 'SimSun'
        legend.alignment = 'right'
        legend.boxAnchor = 'ne'
        legend.x = 475
        legend.y = 300
        legend.dxTextSpace = 10
        risk_levels = ['高危', '中危', '低危', '无漏洞']
        legend.colorNamePairs = [
            (color, risk_levels[i])
            for i, color in enumerate(color_list)
        ]

        drawing.add(legend)
        drawing.add(bc)

        return drawing

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

    # 综合评分算法
    @staticmethod
    def calculate_comprehensive_score(high_risk, medium_risk, low_risk, total_lines):
        """
        综合评分算法
        :param high_risk: 高危缺陷数
        :param medium_risk: 中危缺陷数
        :param low_risk: 低危缺陷数
        :param total_lines: 代码总行数
        :param file_count: 文件数量
        :return: 综合评分(0-100)
        """

        # 1. 缺陷密度得分（30%权重）
        defect_density = (high_risk + medium_risk + low_risk) / total_lines * 1000
        density_score = max(0, 100 - defect_density * 20)

        # 2. 风险严重性得分（50%权重）
        risk_weighted = high_risk * 3 + medium_risk * 2 + low_risk * 1
        max_acceptable_risk = total_lines / 1000  # 每千行代码可接受风险基数
        risk_score = max(0, 100 - (risk_weighted / max(max_acceptable_risk, 1)) * 30)

        # 3. 缺陷分布得分（20%权重）
        # 检查是否多种类型缺陷并存
        risk_variety = len([x for x in [high_risk, medium_risk, low_risk] if x > 0])
        distribution_score = max(60, 100 - (risk_variety - 1) * 10) if risk_variety > 0 else 100

        # 综合计算
        final_score = (
                density_score * 0.3 +
                risk_score * 0.5 +
                distribution_score * 0.2
        )

        return round(max(0, min(100, final_score)), 1)

    # 风险评级算法
    @staticmethod
    def risk_rating(score, high_risk_count):
        """
        风险评级算法
        :param score: 综合评分
        :param high_risk_count: 高危缺陷数量
        :return: 风险等级
        """
        if score >= 90 and high_risk_count == 0:
            return "优秀"
        elif score >= 80 and high_risk_count <= 5:
            return "良好"
        elif score >= 70:
            return "中等"
        elif score >= 50:
            return "一般"
        elif score >= 30:
            return "中危"
        else:
            return "高危"

    def export_pdf(itemName, pdf_Time,  vuls, file_location, final_results, number, version, risk_level_dict, bar_info, pie_info, git_info, overview_info):
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
        if git_info[0]:
            overview_info.extend([
                ('git仓库地址', f'{git_info[0] or ""}'),
                ('分支', f'{git_info[1] or "master"}'),
            ])
        content.append(Graphs.draw_table(overview_info))

        high_vul = int(pie_info[1][0])
        med_vul = int(pie_info[1][1])
        low_vul = int(pie_info[1][2])
        code_lines = int(overview_info[3][3][:-1])
        score = Graphs.calculate_comprehensive_score(high_vul, med_vul, low_vul, code_lines)
        risk_rating = Graphs.risk_rating(score, high_vul)
        text = f'''本次对于 {itemName} 源代码工程的扫描测试，扫描了 {overview_info[2][1]} 个文件，其中 {code_lines} 行代码。本次检测语言为：{overview_info[1][1]}。共发现了 {overview_info[6][1]} 个缺陷，其中高危 {high_vul} 个，中危 {med_vul} 个，低危 {low_vul} 个。检测结果综合评分为 {score}，综合风险评级为 {risk_rating}。风险分布如下所示:'''
        content.append(Graphs.draw_text_12_overview(text))

        risk_data = [
            ['缺陷等级', '缺陷数量', '缺陷等级评定标准'],
            ['高危', f'{pie_info[1][0]}', '''1) 可直接导致严重的逻辑漏洞（如任意账户密码重置等），攻击者能够直接获取服务器权限或敏感数据；<br/>
        2) 可直接导致严重的信息泄露，如数据库连接字符串、密钥文件、大量用户敏感信息明文传输等。'''],
            ['中危', f'{pie_info[1][1]}', '''1) 可能间接导致安全风险，通常需要特定条件或用户交互才能利用；<br/>
        2) 可能导致一般性的信息泄露，如服务器版本信息、非关键路径下的文件路径泄露等。'''],
            ['低危', f'{pie_info[1][2]}', '''1) 属于代码质量或安全规范问题，短期内几乎无法被直接利用于攻击；<br/>
        2) 非常轻微的信息泄露，如普通的客户端错误信息回显。'''],
        ]
        content.append(Graphs.draw_table_vul_level(risk_data))

        # 生成漏洞表格
        content.append(Graphs.draw_left_16('2.漏洞检测结果汇总'))
        content.append(Graphs.draw_title_32('<br/>'))
        content.append(Graphs.draw_left_14('2.1 检测结果汇总表'))
        content.append(Graphs.draw_title_14('漏洞检测结果详情统计'))
        # 添加漏洞的信息表格
        # data = [('序号', '漏洞名称', '统计', '风险等级')]
        # for i in range(0, len(vul_number)):
        #     nt = vul_number[i][0]
        #     nt = int(nt)
        #     vul_name = vul_number[i][1]
        #     data.append(('{}'.format(nt), '{}'.format(vul_number[i][1]), '{}'.format(vul_number[i][2]), '{}'.format(risk_level_dict.get(vul_name,'高危'))))
        # content.append(Graphs.draw_table_2(*data))
        content.append(PageBreak())

        # 第四页，生成图表
        content.append(Graphs.draw_left_14('2.2 漏洞类型统计图'))
        content.append(Graphs.draw_title_14('漏洞统计柱状图'))
        content.append(Graphs.draw_title_32('<br/><br/>'))
        # content.append(Graphs.draw_bar(bar_info))
        content.append(PageBreak())

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

                                if file_location[i3][2]:
                                    content.append(Graphs.draw_left_12('漏洞分析'))
                                    content.append(
                                        Graphs.draw_text_12('缺陷路径:{fileName}:{location}'.format(
                                            fileName=file_location[i3][0], location=file_location[i3][2]
                                        )))
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
            for index, (vul_name, description, repairPlan, file_list) in enumerate(final_results, start=1):
                content.append(Graphs.draw_left_16('{id} {vul_name}'.format(id=index, vul_name=vul_name)))
                content.append(Graphs.draw_left_14('{id}.1 漏洞概述'.format(id=index)))
                content.append(Graphs.draw_title_32('<br/>'))
                # # 添加漏洞的信息表格
                # data = [
                #     ('漏洞编号', '漏洞名称', '风险等级'),
                #     ('{}'.format(index), '{}'.format(vul_name), '{}'.format(level))
                # ]
                # content.append(Graphs.draw_table_1(*data))
                content.append(Graphs.draw_title_32('<br/>'))
                content.append(Graphs.draw_left_14('{id}.2 漏洞详情'.format(id=index)))
                for file_index ,(fileName,vulType,location,source_code,repair_code,Sink,Enclosing_Method,Source,filepath,risk_level) in enumerate(file_list, start=1):

                    content.append(Graphs.draw_left_12_bold('{id}）漏洞定位'.format(id=file_index)))
                    if location:
                        content.append(Graphs.draw_left_12('漏洞分析'))
                        content.append(Graphs.draw_text_12(
                            '缺陷路径:{filepath}:{location}'.format(
                                filepath=filepath, location=location
                            )
                        ))
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