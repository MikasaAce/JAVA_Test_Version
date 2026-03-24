FROM python:3.8.10 AS ai_detection
LABEL authors="ai_detection"

ADD . /ai_detection

# 设置工作目录
WORKDIR /ai_detection

# 安装系统依赖项
RUN apt-get update && \
    apt-get install -y vim && \
    pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/

# 暴露端口
EXPOSE 8089

# 添加启动脚本
COPY start.sh .
RUN chmod +x start.sh

# 设置 ENTRYPOINT 为启动脚本
ENTRYPOINT ["./start.sh"]