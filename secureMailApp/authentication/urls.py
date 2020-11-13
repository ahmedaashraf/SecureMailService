
from django.urls import path
from . import views 

app_name = "authentication"

urlpatterns = [
    path("",views.register,name="register"),
    path("logout", views.logout_request, name="logout"),
    path("login", views.login_request, name="login"),


]
