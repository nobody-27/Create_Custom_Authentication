from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from jose.backends.cryptography_backend import CryptographyBackend
from jose.constants import ALGORITHMS
import jose.jwt


User = get_user_model()

class CognitoAuthenticationBackend(BaseBackend):
    def authenticate(self, request, id_token=None):
        if not id_token:
            return None  # No ID token provided

        # Verify and decode the ID token using jose.jwt library
        try:
            claims = jose.jwt.decode(
                id_token,
                'YOUR_COGNITO_APP_CLIENT_SECRET',
                algorithms=ALGORITHMS.RS256,
                audience='YOUR_COGNITO_APP_CLIENT_ID'
            )

            # Get the sub (subject) claim from the ID token
            sub = claims.get('sub')

            # Find or create a Django user that corresponds to the Cognito user
            user, created = User.objects.get_or_create(username=sub)

            # You can associate additional user data here if needed
            # Example: user.profile = ... 
            return user

        except (jose.exceptions.JWTError, User.DoesNotExist):
            return None  # Authentication failed

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


# AUTHENTICATION_BACKENDS = [
#     # ...
#     'your_app.cognito_auth.CognitoAuthenticationBackend',
# ]