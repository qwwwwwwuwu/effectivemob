from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Session
from django.utils import timezone

class SessionAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]
        try:
            session = Session.objects.get(token=token)
            if not session.is_valid():
                raise AuthenticationFailed('Session expired')
            return (session.user, None)
        except Session.DoesNotExist:
            raise AuthenticationFailed('Invalid session token')