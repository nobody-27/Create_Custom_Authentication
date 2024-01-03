from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from app.models import User
import boto3
client = boto3.client('cognito-idp', )
from django.contrib.auth import authenticate, login
# Create your views here.

class Login(APIView):

    def get_token(self,username,password):
        pass
    def create_user(self,username,password):
        user.object.get_or_create(name=username, password=password)
        
    def create_cognito_user(self,user_obj:dict):
        username = user_obj.get('username')
        password = user_obj.get('password')

        user_attributes = [
                {'Name': 'email', 'Value': placeholder_email},
                {'Name': 'email_verified', 'Value': 'True'},
            ]

            response = cognito_client.admin_create_user(
                UserPoolId=user_pool_id,
                Username=username,
                TemporaryPassword=password,
                UserAttributes=user_attributes,
                ForceAliasCreation=False,
            )
        

        pass



    def get(self,request):
        user = request.GET.get('username')
        passw = request.GET.get('password')

        user = authenticate(username=user, password=passw)
        if not user is None:
            if user.cog_user:
                print("call token function")

            registered_user = self.create_cognito_user({'username':user,'password':passw})



        return Response({"message":"your are login"})


class Home(APIView):
    def get(self,request):
        return Response({"message":"done"})
    




