#import logging  
#from django.http import HttpResponse, JsonResponse
#from django.contrib.auth.decorators import login_required  
#from datetime import datetime
#  
## 获取Django的logger  
#logger = logging.getLogger("django")  
#
# 
#def log_user_access(request,status):  
#    # 获取登录用户信息   
#    username = request.POST['username']
#    login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#
##      空的话，记录传空
##	传1的话，登陆成功
##	传零的话登陆失败
#    # 写入日志  
#    logger.info("---------------------------------------------------------")
#    print(status)
#    if status is None:  
#        message = f"User {username} attempted login with empty status at {login_time}"  
#        logger.info(message)  
#    elif status == '1':  
#        message = f"User {username} logged in successfully at {login_time}"  
#        logger.info(message)  
#    elif status == '0':  
#        message = f"Failed login attempt by user {username} at {login_time}"  
#        logger.warning(message)  
#    else:  
#        message = f"Unknown login status for user {username} at {login_time}"  
#        logger.error(message)  
#  
#    return HttpResponse("Login information logged successfully!") 
#
#
#
#
#def index(req):
#    method = req.POST["method"]
#    status = req.POST["status"]
#    if method == "access_log":
#        return log_user_access(req,status)
#    else:
#        return HttpResponse("method error! ")

import logging  
from django.http import HttpResponse  
from django.views.decorators.http import require_http_methods  
from datetime import datetime  
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
  
# 获取Django的logger  
logger = logging.getLogger("django")  
  
def log_user_access(request, status):  
    try:  
        username = request.POST.get('username', 'Unknown User')  # 使用 get 方法避免 KeyError  
        login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  
  
        # 记录日志  
        if status == '':  
            message = f"User {username} attempted login with empty status at {login_time}"  
            logger.info(message)  
        elif status == '1':  
            message = f"User {username} logged in successfully at {login_time}"  
            logger.info(message)  
        elif status == '0':  
            message = f"Failed login attempt by user {username} at {login_time}"  
            logger.warning(message)  
        else:  
            message = f"Unknown login status for user {username} at {login_time}"  
            logger.error(message)  
  
        return HttpResponse("Login information logged successfully!")  
    except Exception as e:  
        logger.error(f"Error logging user access: {e}")  
        return HttpResponse("Error logging user access", status=500)  
  
@require_http_methods(["POST"])  # 确保只接受 POST 请求  
@permission_classes([IsAuthenticated])
def index(request):  
    method = request.POST.get("method", '')  
    status = request.POST.get("status", '')  
    
    if method == "access_log":  
        return log_user_access(request, status)  
    else:  
        return HttpResponse("Invalid method", status=400)  

  
