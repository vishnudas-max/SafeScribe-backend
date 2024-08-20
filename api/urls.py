
from django.contrib import admin
from django.urls import path
from user.views import GoogleLoginApi

urlpatterns = [
    path('auth/google/login/', GoogleLoginApi.as_view()),
]
