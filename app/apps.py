from django.apps import AppConfig
import threading
import os
import sys
from app.api.authorization.authorization import check
from app.api.Streaming_output.Streaming_output import run_vllm_server

class PythonConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "app"
    _vllm_started = False  # 类变量标记是否已初始化

    def ready(self):
        # 调用检查函数
        check()

#        # 关键1：通过环境变量判断是否为主进程（开发模式）
#        is_main_process = not os.environ.get("RUN_MAIN") and not os.environ.get("WERKZEUG_RUN_MAIN")
#        # 关键2：生产环境需额外判断（如通过 manage.py 参数）
#        if "runserver" in sys.argv:
#            is_main_process = True
#
#        # 仅在主进程且未初始化时启动
#        if is_main_process and not self._vllm_started:
#            self._start_vllm_server()
#            PythonConfig._vllm_started = True  # 标记为已启动

    def _start_vllm_server(self):
        

        """启动 vLLM 服务（线程安全）"""
        server_thread = threading.Thread(
            target=run_vllm_server,
            # kwargs={
            #     "model_path": "/home/public/model/DeepSeek-R1-Distill-Qwen-14B-unsloth-bnb-4bit",
            #     "served_model_name": "deepseek",
            #     "max_model_len": 16392,
            #     "dtype": "bfloat16",
            #     "tensor_parallel_size": 2,
            #     "cuda_devices": "0,1",
            #     "port": 8000
            # }
            kwargs={
                "model_path": "/home/public/model/deepseek-R1-qwen-14B",
                "served_model_name": "deepseek",
                "max_model_len": 16392,
                "dtype": "float16",
                "tensor_parallel_size": 2,
                "cuda_devices": "0,1",
                "port": 8000
            }
        )
        server_thread.daemon = True  # 守护线程随主进程退出
        server_thread.start()
        print("vLLM server started in background.")