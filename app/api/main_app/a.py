import logging  
from django.http import HttpResponse  
from django.views.decorators.http import require_http_methods  
from datetime import datetime  

def ss():
    print("111")
    return HttpResponse("222", status=200)  

	
@require_http_methods(["POST"])  # 确保只接受 POST 请求  
def index(request):  
    method = request.POST["method"]
    if method == "ss":  
        return ss()
    else:  
        return HttpResponse("Invalid method", status=400)  