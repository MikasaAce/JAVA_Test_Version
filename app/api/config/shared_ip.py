from django.http import HttpResponse


def shared_ip(request):
    ip = request.get_host()
    return {'shared_ip': ip}