from rest_framework import serializers
from .models import User, Role, Resource, Permission, RolePermission, Session

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'is_active']
        extra_kwargs = {'password': {'write_only': True}}

class UserRegisterSerializer(serializers.ModelSerializer):
    password_confirmation = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'password_confirmation']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        if data['password'] != data['password_confirmation']:
            raise serializers.ValidationError("Passwords don't match")
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirmation')
        user = User.objects.create_user(**validated_data)
        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name']

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id', 'name', 'description']

class ResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Resource
        fields = ['id', 'name', 'description']

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'description']

class RolePermissionSerializer(serializers.ModelSerializer):
    role = RoleSerializer(read_only=True)
    permission = PermissionSerializer(read_only=True)
    resource = ResourceSerializer(read_only=True)
    role_id = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all(), write_only=True, source='role')
    permission_id = serializers.PrimaryKeyRelatedField(queryset=Permission.objects.all(), write_only=True, source='permission')
    resource_id = serializers.PrimaryKeyRelatedField(queryset=Resource.objects.all(), write_only=True, source='resource')

    class Meta:
        model = RolePermission
        fields = ['id', 'role', 'permission', 'resource', 'role_id', 'permission_id', 'resource_id']

class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Session
        fields = ['token', 'expires_at']