import subprocess
import os

def run_vllm_server(
    model_path: str,
    served_model_name: str,
    max_model_len: int = 16392,
    dtype: str = "bfloat16",
    tensor_parallel_size: int = 2,
    cuda_devices: str = "0,1",
    port: int = 8000,
    host: str = "0.0.0.0"
):
    """
    通过命令行方式启动 vLLM OpenAI API 服务器

    参数说明：
    - model_path: 模型路径 (必须)
    - served_model_name: 服务暴露的模型名称
    - max_model_len: 最大上下文长度
    - dtype: 模型精度 (bfloat16/float16)
    - tensor_parallel_size: 张量并行度
    - cuda_devices: 使用的 GPU 设备 ID (e.g., "0,1")
    - port: 服务端口
    - host: 监听地址
    """
    # 设置 CUDA 可见设备
    os.environ["CUDA_VISIBLE_DEVICES"] = cuda_devices
    # 设置 网卡
    os.environ["NCCL_SOCKET_IFNAME"] = "enp7s0"

    # 构建命令行参数
    command = [
        "python", "-m", "vllm.entrypoints.openai.api_server",
        "--model", model_path,
        "--served-model-name", served_model_name,
        "--max-model-len", str(max_model_len),
        "--dtype", dtype,
        "--tensor-parallel-size", str(tensor_parallel_size),
        "--host", host,
        "--port", str(port),
        "--quantization", "bitsandbytes",
        "--load-format", "bitsandbytes",
    ]

    # 打印命令
    print("Running command:", " ".join(command))

    # 使用 subprocess 运行命令
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # 捕获输出
    stdout, stderr = process.communicate()

    # 打印输出
    if stdout:
        print("stdout:", stdout.decode())
    if stderr:
        print("stderr:", stderr.decode())

    # 检查返回值
    if process.returncode != 0:
        raise RuntimeError(f"Command failed with return code {process.returncode}")

# 使用示例
if __name__ == "__main__":
    run_vllm_server(
        model_path="/home/public/model/deepseek-R1-qwen-14B",
        served_model_name="deepseek",
        max_model_len=16392,
        dtype="bfloat16",
        tensor_parallel_size=2,
        cuda_devices="0,1",
        port=8000
    )