from django.conf import settings
from django.shortcuts import redirect
from django.core.exceptions import ValidationError
from urllib.parse import urlencode
from typing import Dict, Any
import requests
import jwt


GOOGLE_ACCESS_TOKEN_OBTAIN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo'


def google_get_access_token(code: str, redirect_uri: str) -> str:
    data = {
        'code': code,
        'client_id': settings.GOOGLE_OAUTH2_CLIENT_ID,
        'client_secret': settings.GOOGLE_OAUTH2_CLIENT_SECRET,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    print(data)
    response = requests.post(GOOGLE_ACCESS_TOKEN_OBTAIN_URL, data=data)
    print("Access Token Response Status:", response.status_code)
    print("Access Token Response Body:", response.text)
    if not response.ok:
         return {'status':False}
    access_token = response.json()['access_token']

    return access_token

def google_get_user_info(access_token: str) -> Dict[str, Any]:
    response = requests.get(
        GOOGLE_USER_INFO_URL,
        params={'access_token': access_token}
    )
    print(f"access token {access_token}")
    if not response.ok:
         return {'status':False}

    print(response.json())
    return response.json()



def get_user_data(validated_data):
    domain = settings.BASE_API_URL
    redirect_uri = f'{domain}api/auth/google/login/'
    print(redirect_uri)
    code = validated_data.get('code')
    error = validated_data.get('error')
    print(code)
    if error or not code:
        params = urlencode({'error': error})
        return {'status':False}
    
    access_token = google_get_access_token(code=code, redirect_uri=redirect_uri)
    print(access_token)
    user_data = google_get_user_info(access_token=access_token)
    
    profile_data = {
        'status':True,
        'email': user_data['email'],
        'first_name': user_data.get('given_name'),
        'last_name': user_data.get('family_name'),
    }
    return profile_data