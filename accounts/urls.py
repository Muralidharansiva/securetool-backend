from django.urls import path
from .views import register, user_login

urlpatterns = [
    path("register/", register),
    path("login/", user_login),
]
