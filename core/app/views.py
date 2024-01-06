from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from app.models import User
import boto3
from botocore.exceptions import ClientError
from django.contrib.auth import authenticate, login
# Create your views here.
from django.conf import settings
from datetime import datetime, timedelta

cognito_region = settings.AWS_REGION
client_id = settings.COGNITO_APP_CLIENT_ID
user_pool_id = settings.COGNITO_USER_POOL_ID
cognito_client = boto3.client('cognito-idp', region_name=cognito_region)


class Login(APIView):

    def get_token(self,username,password):
        pass
        
    def create_cognito_user(self, username, password, user_instance):
        
        user_attributes = [
                {'Name': 'email', 'Value': username},
                {'Name': 'email_verified', 'Value': 'True'},
            ]
        try:
            response = cognito_client.admin_create_user(
                UserPoolId=user_pool_id,
                Username=username,
                TemporaryPassword=password,
                UserAttributes=user_attributes,
                ForceAliasCreation=False,
            )
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                user_instance.is_cognito = True
                user_instance.save()
                
        except cognito_client.exceptions.InvalidPasswordException as e:
            # return Response({'success': False, 'message': 'Invalid Password.'}) 
            print("Invalid_Password_Exception : ", e)     
        except ClientError as e:
            print("botocore_client_error : ", e)
            return False
        
    def get_user_auth(self, username, password,): 
           
        response = cognito_client.initiate_auth(
            ClientId=client_id,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )

        if 'ChallengeName' in response and response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
            # This code is essential for authenticating and validating users created by the owner.
            session = response['Session']
            staff_response = cognito_client.respond_to_auth_challenge(
                ClientId=client_id,
                ChallengeName='NEW_PASSWORD_REQUIRED',
                ChallengeResponses={
                    'USERNAME': username,
                    'NEW_PASSWORD': password
                }, Session=session)

            response = staff_response

        if 'AuthenticationResult' in response:
            access_token = response['AuthenticationResult']['AccessToken']
            refresh_token = response['AuthenticationResult']['RefreshToken']
            expires_in_seconds = response['AuthenticationResult'].get(
                'ExpiresIn')

            expiration_time = datetime.now() + timedelta(seconds=expires_in_seconds)

            

            data = {
                'expires_in': expiration_time.strftime('%Y-%m-%d %H:%M:%S'),
                # 'user_type': user_type,
                'access_token': access_token,
                'refresh_token': refresh_token
            }

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
    




