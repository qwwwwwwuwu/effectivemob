from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import authenticate
from .models import User, Role, Resource, Permission, RolePermission, Session
from .serializers import (
    UserSerializer, UserRegisterSerializer, UserUpdateSerializer,
    RoleSerializer, ResourceSerializer, PermissionSerializer,
    RolePermissionSerializer, SessionSerializer
)
import uuid
from rest_framework.permissions import AllowAny


class RegisterView(APIView):
    authentication_classes = []  # Отключаем проверку аутентификации
    permission_classes = [AllowAny]


    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user_role, _ = Role.objects.get_or_create(name='user')
            user.roles.add(user_role)
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):

    authentication_classes = []  # <- отключаем аутентификацию
    permission_classes = [AllowAny]  
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(request, username=email, password=password)
        if not user or not user.is_active:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # Create or update session
        session, created = Session.objects.update_or_create(
            user=user,
            defaults={'token': uuid.uuid4(), 'expires_at': timezone.now() + timedelta(days=7)}
        )

        return Response({
            'user': UserSerializer(user).data,
            'token': session.token,
            'expires_at': session.expires_at
        })

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        Session.objects.filter(user=request.user).delete()
        return Response({'message': 'Logged out successfully'})

class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def patch(self, request):
        serializer = UserUpdateSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        request.user.delete()
        Session.objects.filter(user=request.user).delete()
        return Response({'message': 'Account deleted successfully'})

class HasPermissionMixin:
    def has_permission(self, user, permission_name, resource_name):
        try:
            resource = Resource.objects.get(name=resource_name)
            permission = Permission.objects.get(name=permission_name)
            return RolePermission.objects.filter(
                role__users=user,
                permission=permission,
                resource=resource
            ).exists()
        except (Resource.DoesNotExist, Permission.DoesNotExist):
            return False

class RoleView(APIView, HasPermissionMixin):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if not self.has_permission(request.user, 'read', 'roles'):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)
        return Response(serializer.data)

    def post(self, request):
        if not self.has_permission(request.user, 'create', 'roles'):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserRoleView(APIView, HasPermissionMixin):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, user_id):
        if not self.has_permission(request.user, 'update', 'users'):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = User.objects.get(id=user_id)
            role_id = request.data.get('role_id')
            role = Role.objects.get(id=role_id)
            user.roles.add(role)
            return Response({'message': 'Role added successfully'})
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Role.DoesNotExist:
            return Response({'error': 'Role not found'}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, user_id, role_id):
        if not self.has_permission(request.user, 'update', 'users'):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = User.objects.get(id=user_id)
            role = Role.objects.get(id=role_id)
            user.roles.remove(role)
            return Response({'message': 'Role removed successfully'})
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Role.DoesNotExist:
            return Response({'error': 'Role not found'}, status=status.HTTP_404_NOT_FOUND)

class RolePermissionView(APIView, HasPermissionMixin):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, role_id):
        if not self.has_permission(request.user, 'update', 'roles'):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = RolePermissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(role_id=role_id)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, role_id, permission_id, resource_id):
        if not self.has_permission(request.user, 'update', 'roles'):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            role_permission = RolePermission.objects.get(
                role_id=role_id,
                permission_id=permission_id,
                resource_id=resource_id
            )
            role_permission.delete()
            return Response({'message': 'Permission removed successfully'})
        except RolePermission.DoesNotExist:
            return Response({'error': 'Permission not found'}, status=status.HTTP_404_NOT_FOUND)


class ProductView(APIView, HasPermissionMixin):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if not self.has_permission(request.user, 'read', 'products'):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        
        
        products = [
            {'id': 1, 'name': 'Product 1', 'price': 100},
            {'id': 2, 'name': 'Product 2', 'price': 200}
        ]
        return Response(products)

    def post(self, request):
        if not self.has_permission(request.user, 'create', 'products'):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        
        
        return Response({'id': 3, 'name': request.data.get('name'), 'price': request.data.get('price')}, 
                       status=status.HTTP_201_CREATED)