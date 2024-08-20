
from rest_framework import serializers

from rest_framework_simplejwt.tokens import RefreshToken ,TokenError
from django.utils import timezone


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    # Add custom claims
    refresh['is_admin'] = user.is_superuser
    refresh['username'] = user.username


    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class AuthSerializer(serializers.Serializer):
    code = serializers.CharField(required=False)
    error = serializers.CharField(required=False)
