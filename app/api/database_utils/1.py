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
from reportlab.graphics import renderPM

pdfmetrics.registerFont(TTFont('SimSun', 'font/simsun.ttf'))
pdfmetrics.registerFont(TTFont('SimSun-Bold', 'font/SimSun-Bold.ttf'))

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
    bc.barLabelFormat = '%s'
    # 添加数据标签并调整位置
    bc.barLabels.nudge = 10  # 将标签向上移动10个单位
    bc.barLabels.fontName = 'SimSun'
    bc.barLabels.fontSize = 10
    bc.barLabelFormat = '%s'
    bc.barLabels.dy = 0  # 调整垂直偏移量



    drawing.add(bc)
    return drawing


# 极简测试数据
test_labels = ["A", "B", "C"]
test_data = [1, 2, 3]
test_bar_info = [test_labels, test_data]
drawing = draw_bar(test_bar_info)
content = list()
content.append(drawing)
doc = SimpleDocTemplate(
            './1.pdf',
            pagesize=letter)
doc.build(content)
