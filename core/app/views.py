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
from app.serializers import LoginSerializer

cognito_region = settings.AWS_REGION
client_id = settings.COGNITO_APP_CLIENT_ID
user_pool_id = settings.COGNITO_USER_POOL_ID
cognito_client = boto3.client('cognito-idp', region_name=cognito_region)


class Login(APIView):
    serializer_class = LoginSerializer

    def create_cognito_user(self, username, password, user_instance=None):
        print("run1")
        
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
                print("run2")
                return True
                
        except cognito_client.exceptions.InvalidPasswordException as e:
            print("run4")
            # return Response({'success': False, 'message': 'Invalid Password.'}) 
            print("Invalid_Password_Exception : ", e)     
        except ClientError as e:
            print("run5")
            print("botocore_client_error : ", e)
            return False
        
    def get_user_auth(self, username, password,): 
        
        try:   
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
                    'access_token': access_token,
                    'refresh_token': refresh_token
                }
                return data
        except cognito_client.exceptions.InvalidPasswordException as e:
            print("Invalid_Password_Exception : ", e)  
            return False
        except ClientError as e:
            print("botocore_client_error : ", e)
            return False

    def post(self, request):
        serilizer =  LoginSerializer(data=request.data)
        if serilizer.is_valid():
            username = serilizer.validated_data.get('username')
            password = serilizer.validated_data.get('password')
            
            data = self.get_user_auth(username, password)
            if data != False:
                return Response({'success': True, 'data': data})
            else:
                user = authenticate(username=username, password=password)
                if user is not None:
                    success = self.create_cognito_user(username, password)
                    if success == True:
                        data = self.get_user_auth(username, password)
                        if data != False:
                            return Response({'success': True, 'data': data})
                    else:
                        return Response({'success': False, 'message': 'Failed to create Cognito user.'})
                    
        return Response({'success': False,'message': 'User Not Found.'})


class Home(APIView):
    def get(self,request):
        return Response({"message":"done"})
    




