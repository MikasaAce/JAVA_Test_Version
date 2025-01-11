# 假设这是你的测试字符串
test_string = '漏洞爆发点:{Sink}\n爆发点函数:{Enclosing_Method}\n缺陷源:{Source}'.format(
    Sink='SinkValue',
    Enclosing_Method='EnclosingMethodValue',
    Source='SourceValue'
)

# 直接打印到控制台以检查换行符  
print(test_string)

# 如果你的 Graphs.draw_text_12 函数在这里，你可以尝试调用它并检查输出
# content.append(Graphs.draw_text_12(test_string))