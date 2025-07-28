# Система управления доступом (RBAC)

## Схема разграничения прав

### 1. Базовая архитектура
Система использует **Role-Based Access Control (RBAC)** с расширенными возможностями:

### 2. Основные сущности

#### Пользователь (User)
- Основная учетная запись
- Может иметь несколько ролей
- Поля: email, пароль, ФИО, активность

#### Роль (Role)
- Группирует набор разрешений
- Примеры: `admin`, `manager`, `user`
- Поля: название, описание

#### Ресурс (Resource)
- Объект системы для контроля доступа
- Примеры: `products`, `users`, `orders`
- Поля: название, описание

#### Разрешение (Permission)
- Действие над ресурсом
- Базовые CRUD-операции: `create`, `read`, `update`, `delete`
- Поля: название, описание

### 3. Связующая таблица
`RolePermission` - определяет какие роли имеют какие разрешения на какие ресурсы:
```python
class RolePermission(models.Model):
    role = models.ForeignKey(Role)
    permission = models.ForeignKey(Permission)
    resource = models.ForeignKey(Resource)
