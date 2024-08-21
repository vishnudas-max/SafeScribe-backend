
from django.contrib import admin
from django.urls import path
from user.views import GoogleLoginApi,SaveAndGetPassword
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    path('auth/google/login/', GoogleLoginApi.as_view()),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('manage/password/',SaveAndGetPassword.as_view())
]
