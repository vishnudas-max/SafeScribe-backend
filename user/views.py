
from .services import get_user_data
from django.shortcuts import redirect
from django.conf import settings
from django.contrib.auth import login
from rest_framework.views import APIView
from .serializers import AuthSerializer,get_tokens_for_user,PasswordSerealizer
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework import status
import random,string
from django.contrib.auth.models import User
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions  import IsAuthenticated
from cryptography.fernet import Fernet
import base64
import logging
import traceback
from django.conf import settings

def encrypt(pas):
    try:
        pas = str(pas)
        key = settings.ENCRYPT_KEY.encode()  # Convert the key to bytes
        cipher_pass = Fernet(key)
        encrypted_pass = cipher_pass.encrypt(pas.encode('utf-8'))
        return encrypted_pass.decode('utf-8')
    except Exception as e:
        logging.getLogger("error_logger").error(traceback.format_exc())
        return None

def decrypt(pas):
    try:
        key = settings.ENCRYPT_KEY.encode()  # Convert the key to bytes
        cipher_pass = Fernet(key)
        decrypted_pass = cipher_pass.decrypt(pas.encode('utf-8')).decode('utf-8')
        return decrypted_pass
    except Exception as e:
        logging.getLogger("error_logger").error(traceback.format_exc())
        return None


# views that handle 'localhost://8000/api/auth/login/google/'
class GoogleLoginApi(APIView):
    def get(self, request, *args, **kwargs):
        print('here---')
        auth_serializer = AuthSerializer(data=request.GET)
        auth_serializer.is_valid(raise_exception=True)
        validated_data = auth_serializer.validated_data
        user_data = get_user_data(validated_data)
        if(user_data['status']==False):
            return redirect(settings.BASE_APP_URL)
        try:
            user = User.objects.get(email=user_data['email'])
            if(user.is_active == False):
                redirect_url = f"{settings.BASE_APP_URL}?message='This account in no longer accessible'"
                return redirect(redirect_url)
            tokens = get_tokens_for_user(user)
            redirect_url = f"{settings.BASE_APP_URL}?access={tokens['access']}&refresh={tokens['refresh']}"
            return redirect(redirect_url)
        except:
            first_name = user_data['first_name']
            last_name = user_data['last_name']
            base_username = f"{first_name}.{last_name}".lower()

            # Generate a unique username
            username = base_username
            while User.objects.filter(username=username).exists():
                unique_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
                username = f"{base_username}.{unique_suffix}"

            user = User.objects.create(
                first_name=first_name,
                last_name=last_name,
                email=user_data['email'],
                username=username 
            )
            tokens = get_tokens_for_user(user)
            redirect_url = f"{settings.BASE_APP_URL}?access={tokens['access']}&refresh={tokens['refresh']}"
            return redirect(redirect_url)
        
       
class SaveAndGetPassword(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes =[IsAuthenticated]

    def post(self, request):
        password = request.data.get('password')
        user = request.user.id
        data = request.data.copy()
        data['userID'] = user

        encrypted_password = encrypt(password)

        # Ensure to update the encrypted password in the data dictionary
        data['password'] = encrypted_password
        print(data)
        
        serializer = PasswordSerealizer(data=data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self,request):
        user = request.user
        allPassword = user.UserPasswords.all().order_by('-saved_date')
        serializer = PasswordSerealizer(allPassword,many =True)
        decrypted_data = []
        for password_data in serializer.data:
            decrypted_password = decrypt(password_data['password'])  # Decrypt the password field
            if decrypted_password:
                password_data['password'] = decrypted_password
            decrypted_data.append(password_data)
        
        return Response(decrypted_data, status=status.HTTP_200_OK)
