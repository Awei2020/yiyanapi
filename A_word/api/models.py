from django.db import models

class Query(models.Model):
    id = models.AutoField(db_column='id',primary_key=True)
    text = models.CharField(db_column='text',null=False,max_length=999)
    likes = models.IntegerField(db_column='likes', default=0)
    class Mate:
        db_table = 'aword'
        ordering = ['id']
# 用户注册以及权限管理模块，主要有用户名，邮箱，密码，权限字段，其中权限字段为0表示普通用户，为1表示管理员
class User(models.Model):
    id = models.AutoField(db_column='id',primary_key=True)
    username = models.CharField(db_column='username',null=False,max_length=999)
    email = models.CharField(db_column='email',null=False,max_length=999)
    password = models.CharField(db_column='password',null=False,max_length=999)
    permission = models.IntegerField(db_column='permission', default=0)
    #添加token字段
    token = models.CharField(db_column='token',null=True,max_length=999)
    #添加token过期时间字段
    token_time = models.DateTimeField(db_column='token_time',null=True)
    class Mate:
        db_table = 'user'
        ordering = ['id']