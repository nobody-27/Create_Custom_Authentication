from rest_framework.authentication import BaseAuthentication

class CognitoAuthentication(BaseAuthentication):
    def is_verify_cognito(self,token):
        pass

    def authenticate(self, request):
        username = request.GET.get('username')
        if username is None:
            return None
        
        