
from django.urls import path
from . import views 

from .views import mainpage,successView, recview

app_name = "main"

urlpatterns = [

    # path("main",views.mainpage,name="main"),
    path("main/", mainpage, name="main"),
    path("success/", successView, name="success"),
    path("rec/", recview, name="rec")

]
