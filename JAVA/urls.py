from django.urls import path, include

from app import views

from app.api.database_utils import web,knowledgeBase
from app.api.main_app import M_app, a
from app.api.access_log import access_log
from app.api.muti_model_api import model_api
from app.api.default_model_api import default_model_api
from app.api.create_process import create_process

from oauth2_provider import urls as oauth2_urls
from django.contrib import admin
from oauth2_provider.decorators import protected_resource

urlpatterns = [
    path('', views.index, name='index'),
    path('login/', web.index, name='login'),
    path('create_process/', create_process.index, name='create_process'),
    path('default_model/', default_model_api.index, name='login'),
    path('Muti_transformer/', model_api.index, name='Muti_transformer'),
    path('knowledge/', knowledgeBase.index, name='knowledge'),
    path('access_log/', access_log.index, name='access_log'),
    path('Muti/', M_app.index, name='Muti'),
    path('rules/', a.index, name='rules'),
    path('celery-progress/', include('celery_progress.urls')),

    path("o/", include(oauth2_urls)),
    path('admin/', admin.site.urls),
]