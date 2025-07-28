from django.contrib import admin
from django.urls import path
from accounts.views import (
    RegisterView, LoginView, LogoutView, ProfileView,
    RoleView, UserRoleView, RolePermissionView, ProductView
)
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny
from accounts.views import RegisterView 


urlpatterns = [
    path('api/auth/register/', permission_classes([AllowAny])(RegisterView.as_view())),
    path('admin/', admin.site.urls),
    path('api/auth/register/', RegisterView.as_view(), name='register'),
    path('api/auth/login/', LoginView.as_view(), name='login'),
    path('api/auth/logout/', LogoutView.as_view(), name='logout'),
    path('api/auth/profile/', ProfileView.as_view(), name='profile'),
    
    # Access control
    path('api/roles/', RoleView.as_view(), name='roles'),
    path('api/users/<int:user_id>/roles/', UserRoleView.as_view(), name='user-roles'),
    path('api/users/<int:user_id>/roles/<int:role_id>/', UserRoleView.as_view(), name='remove-user-role'),
    path('api/roles/<int:role_id>/permissions/', RolePermissionView.as_view(), name='role-permissions'),
    path('api/roles/<int:role_id>/permissions/<int:permission_id>/resources/<int:resource_id>/', 
         RolePermissionView.as_view(), name='remove-role-permission'),
    
    # Business mock
    path('api/products/', ProductView.as_view(), name='products'),
]