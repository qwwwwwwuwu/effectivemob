from django.db import migrations


def create_initial_data(apps, schema_editor):
    Role = apps.get_model('accounts', 'Role')
    Permission = apps.get_model('accounts', 'Permission')
    Resource = apps.get_model('accounts', 'Resource')
    RolePermission = apps.get_model('accounts', 'RolePermission')

    # Роли
    admin_role, _ = Role.objects.get_or_create(name='admin', defaults={'description': 'Administrator'})
    user_role, _ = Role.objects.get_or_create(name='user', defaults={'description': 'Regular user'})

    # Разрешения
    permission_names = ['read', 'create', 'update', 'delete']
    permissions = {}
    for perm_name in permission_names:
        perm, _ = Permission.objects.get_or_create(name=perm_name, defaults={'description': f'{perm_name} permission'})
        permissions[perm_name] = perm

    # Ресурсы
    resource_names = ['products', 'roles', 'users']
    resources = {}
    for res_name in resource_names:
        res, _ = Resource.objects.get_or_create(name=res_name, defaults={'description': f'{res_name} resource'})
        resources[res_name] = res

    # Назначение всех прав роли admin
    for perm in permissions.values():
        for res in resources.values():
            RolePermission.objects.get_or_create(
                role=admin_role,
                permission=perm,
                resource=res
            )


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_initial_data),
    ]
