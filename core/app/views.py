from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response, JsonResponse
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

    def get_token(self, username, password):
        # You need to implement the logic to get the token here
        # For now, returning None as a placeholder
        return None

    def create_cognito_user(self, username, password, user_instance):
        # Replace 'user_pool_id' and 'client_id' with your actual Cognito User Pool ID and App Client ID
        user_pool_id = 'your_user_pool_id'
        client_id = 'your_client_id'

        user_attributes = [
            {'Name': 'email', 'Value': username},
            {'Name': 'email_verified', 'Value': 'True'},
        ]

        try:
            # Assume cognito_client is properly initialized somewhere in your code
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
                return True  # Indicate success

        except cognito_client.exceptions.InvalidPasswordException as e:
            print("Invalid_Password_Exception: ", e)
        except ClientError as e:
            print("botocore_client_error: ", e)

        return False  # Indicate failure

    def get_user_auth(self, username, password):
        # Replace 'client_id' with your actual App Client ID
        client_id = 'your_client_id'

        try:
            # Assume cognito_client is properly initialized somewhere in your code
            response = cognito_client.initiate_auth(
                ClientId=client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                }
            )

            # ... (rest of the existing code)

            return data  # Return the data dictionary on success

        except cognito_client.exceptions.InvalidPasswordException as e:
            print("Invalid_Password_Exception: ", e)
        except ClientError as e:
            print("botocore_client_error: ", e)

        return None  # Indicate failure

    def post(self, request):
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user_instance = User.objects.get(username=username, is_cognito=True)
        except User.DoesNotExist:
            user_instance = None

        if user_instance:
            data = self.get_user_auth(username, password)
        else:
            success = self.create_cognito_user(username, password, user_instance)
            if success:
                data = self.get_user_auth(username, password)
            else:
                return JsonResponse({'success': False, 'message': 'Failed to create Cognito user.'})

        return JsonResponse({'success': True, 'data': data})
    
    def get(self,request):
        user = request.GET.get('username')
        passw = request.GET.get('password')

        try:
            "run login congnito pass user name and pass"
            "return access token and refersh token"


            return Response({})
        except:
            """ run django login funtion """
            user = authenticate(username=user, password=passw)
            if not user is None:
                if user.cog_user:
                    print("call token function")
                registered_user = self.create_cognito_user({'username':user,'password':passw})

            return Response({"message":"user not exits"})



class Home(APIView):
    def get(self,request):
        return Response({"message":"done"})
    




