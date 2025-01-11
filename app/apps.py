from django.apps import AppConfig
from app.api.authorization.authorization import check

class PythonConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "app"
    #check()
