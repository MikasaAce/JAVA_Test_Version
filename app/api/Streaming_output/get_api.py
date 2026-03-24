# from vllm.engine.llm_engine import LLMEngine
# from vllm import SamplingParams
# from vllm.engine.llm_engine import LLMEngine
# from vllm import EngineArgs
#
# # 先通过 EngineArgs 配置参数
# engine_args = EngineArgs(
#     model="/home/public/model/deepseek-R1-qwen-14B",
#     tensor_parallel_size=2,
#     dtype="float16"
# )
# engine = LLMEngine.from_engine_args(engine_args)  # 正确调用方式
# # 内存中直接调用
# outputs = engine.generate(
#     prompts=["Hello world"],
#     sampling_params=SamplingParams(temperature=0)
# )










from openai import OpenAI

# Set OpenAI's API key and API base to use vLLM's API server.
openai_api_key = "EMPTY"
openai_api_base = "http://10.99.16.24:8000/v1"

client = OpenAI(
    api_key=openai_api_key,
    base_url=openai_api_base,
)

# 发起流式请求
chat_response = client.chat.completions.create(
    model="deepseek",  # 模型名称
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "西游记有哪些角色，这些有什么区别"},
    ],
    temperature=0.2,
    top_p=0.7,
    max_tokens=4096,
    stream=True,  # 启用流式输出
)

# 逐步处理流式响应
for chunk in chat_response:
    if chunk.choices[0].delta.content:  # 检查是否有新内容
        print(chunk.choices[0].delta.content, end="", flush=True)  # 逐步打印输出

# from gradio_client import Client
#
# client = Client("http://10.99.16.24:59997/deepseek/")
# result = client.predict(
# 		text="Hello!!",
# 		max_tokens=1024,
# 		temperature=1,
# 		lora_name="Hello!!",
# 		api_name="/complete"
# )
# print(result)