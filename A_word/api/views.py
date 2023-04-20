import os
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import json
import random
from .models import Query, User
import hashlib
import time
import datetime
from django.forms.models import model_to_dict
import xlrd


# 修饰器，用于验证token，token有效才执行被修饰的函数
def check_token(func):
    def inner(request, *args, **kwargs):
        # 获取headers中的token
        if request.method == 'GET':
            token = request.META.get('HTTP_TOKEN')
            # 判断token是否存在
            if not token:
                return HttpResponse(json.dumps({'code': '403', 'msg': "token不存在"}, ensure_ascii=False))
            # 根据token查询用户信息
            user = User.objects.filter(token=token).first()
            # 判断用户是否存在
            if not user:
                return HttpResponse(json.dumps({'code': '403', 'msg': "用户不存在"}, ensure_ascii=False))
            # 判断token是否过期
            c_time = user.token_time
            now_time = datetime.datetime.now()
            if c_time < now_time:
                return HttpResponse(json.dumps({'code': '403', 'msg': "token过期"}, ensure_ascii=False))
        if request.method == 'POST':
            token = request.META.get('HTTP_TOKEN')
            # 判断token是否存在
            if not token:
                return HttpResponse(json.dumps({'code': '403', 'msg': "token不存在"}, ensure_ascii=False))
            # 根据token查询用户信息
            user = User.objects.filter(token=token).first()
            # 判断用户是否存在
            if not user:
                return HttpResponse(json.dumps({'code': '403', 'msg': "用户不存在"}, ensure_ascii=False))
            # 判断token是否过期
            c_time = user.token_time
            now_time = datetime.datetime.now()
            if c_time < now_time:
                return HttpResponse(json.dumps({'code': '403', 'msg': "token过期"}, ensure_ascii=False))
        # 验证通过，执行被修饰的函数
        return func(request, *args, **kwargs)

    return inner


def get_data(request):
    if request.method == 'POST':
        return HttpResponse(json.dumps({'code': '403', 'msg': "查询路径无权限post"}, ensure_ascii=False))
    # 获取数据库中所有的数据
    if request.method == 'GET':
        # 获取数据中所有id
        ids = Query.objects.values_list('id', flat=True)
        query_list = list(ids)
        num = len(query_list)
        ran = random.randint(0, num)
        data = Query.objects.filter(id=query_list[ran]).first()
        text = data.text
        likes = data.likes
        return HttpResponse(json.dumps({"code": 200, "msg": text, "likes": likes}, ensure_ascii=False))


# 用户注册，需要传入用户名，邮箱，密码，密码使用md5加密之后存入User表中
def register(request):
    if request.method == 'GET':
        return HttpResponse(json.dumps({'code': '403', 'msg': "注册路径无权限get"}, ensure_ascii=False))
    username = request.POST.get('username')
    email = request.POST.get('email')
    password = request.POST.get('password')
    if username == None or email == None or password == None:
        return HttpResponse(json.dumps({'code': '403', 'msg': "参数不完整"}, ensure_ascii=False))
    # md5加密密码
    md5 = hashlib.md5()
    md5.update(password.encode('utf-8'))
    password = md5.hexdigest()
    # 判断用户名是否已经存在
    if User.objects.filter(username=username).exists():
        return HttpResponse(json.dumps({'code': '403', 'msg': "用户名已存在"}, ensure_ascii=False))
    # 判断邮箱是否已经存在
    if User.objects.filter(email=email).exists():
        return HttpResponse(json.dumps({'code': '403', 'msg': "邮箱已存在"}, ensure_ascii=False))
    # 注册用户
    User.objects.create(username=username, email=email, password=password)
    return HttpResponse(json.dumps({'code': '200', 'msg': "注册成功"}, ensure_ascii=False))


# 用户登录，需要传入用户名，密码，密码使用md5加密之后与User表中的密码进行比对
def login(request):
    if request.method == 'GET':
        return HttpResponse(json.dumps({'code': '403', 'msg': "登录路径无权限get"}, ensure_ascii=False))
    username = request.POST.get('username')
    password = request.POST.get('password')
    if username == None or password == None:
        return HttpResponse(json.dumps({'code': '403', 'msg': "参数不完整"}, ensure_ascii=False))
    # md5加密密码
    md5 = hashlib.md5()
    md5.update(password.encode('utf-8'))
    password = md5.hexdigest()
    # 判断用户名是否存在
    if not User.objects.filter(username=username).exists():
        return HttpResponse(json.dumps({'code': '403', 'msg': "用户名不存在"}, ensure_ascii=False))
    # 判断密码是否正确
    if not User.objects.filter(username=username, password=password).exists():
        return HttpResponse(json.dumps({'code': '403', 'msg': "密码错误"}, ensure_ascii=False))
    # 登录成功，生成token
    token = username + password + str(time.time())
    md5 = hashlib.md5()
    md5.update(token.encode('utf-8'))
    token = md5.hexdigest()
    # 设置token过期时间
    token_time = datetime.datetime.now() + datetime.timedelta(days=7)
    # 更新token和token过期时间
    User.objects.filter(username=username).update(token=token, token_time=token_time)
    return HttpResponse(json.dumps({'code': '200', 'msg': "登录成功", 'token': token}, ensure_ascii=False))


# 用户注销，需要传入token
def logout(request):
    if request.method == 'GET':
        return HttpResponse(json.dumps({'code': '403', 'msg': "注销路径无权限get"}, ensure_ascii=False))
    token = request.POST.get('token')
    if token == None:
        return HttpResponse(json.dumps({'code': '403', 'msg': "参数不完整"}, ensure_ascii=False))
    # 判断token是否存在
    if not User.objects.filter(token=token).exists():
        return HttpResponse(json.dumps({'code': '403', 'msg': "token不存在"}, ensure_ascii=False))
    # 判断token是否过期
    if User.objects.filter(token=token).first().token_time < datetime.datetime.now():
        return HttpResponse(json.dumps({'code': '403', 'msg': "token已过期"}, ensure_ascii=False))
    # 注销用户
    User.objects.filter(token=token).update(token=None, token_time=None)
    return HttpResponse(json.dumps({'code': '200', 'msg': "注销成功"}, ensure_ascii=False))


# 判断用户是否为管理员

def is_admin(func):
    def inner(request, *args, **kwargs):
        if request.method == 'POST':
            token = request.META.get('HTTP_TOKEN')
            user = User.objects.filter(token=token).first()
            # 判断用户是否为管理员
            if user.permission == 0:
                return HttpResponse(json.dumps({'code': '403', 'msg': "用户不是管理员"}, ensure_ascii=False))
            # 验证通过，执行被修饰的函数
        if request.method == 'GET':
            token = request.META.get('HTTP_TOKEN')
            user = User.objects.filter(token=token).first()
            # 判断用户是否为管理员
            if user.permission == 0:
                return HttpResponse(json.dumps({'code': '403', 'msg': "用户不是管理员"}, ensure_ascii=False))
            # 验证通过，执行被修饰的函数
        return func(request, *args, **kwargs)

    return inner


# 管理员可调用此api，查看Query表中所有数据
@check_token
@is_admin
def get_all_data(request):
    data = Query.objects.all()
    data_list = []
    for i in data:
        json_data = model_to_dict(i)
        data_list.append(json_data)
    return HttpResponse(json.dumps({'code': '200', 'msg': "获取成功", 'data': data_list}, ensure_ascii=False))


# 用于接收用户上传的xls文件，需要传入token，并且验证有管理员权限
@check_token
@is_admin
def upload(request):
    if request.method == 'POST':
        file = request.FILES.get('xlsfile', None)
        if file == None:
            return HttpResponse(json.dumps({'code': '404', 'msg': "未发现文件"}, ensure_ascii=False))
        # 判断文件类型是否为xls
        print(file.name.split('.')[-1])
        if file.name.split('.')[-1] != 'xls':
            return HttpResponse(json.dumps({'code': '404', 'msg': "文件类型错误"}, ensure_ascii=False))
        # 保存文件
        file_path = os.getcwd() + '/api/file/' + file.name
        with open(file_path, 'wb') as f:
            for chunk in file.chunks():
                f.write(chunk)
        # 读取excel内容导入数据库
        data = xlrd.open_workbook(file_path)
        table = data.sheets()[0]
        nrows = table.nrows
        nclos = table.ncols
        # 判断的excel是否为空
        if nrows == 0 or nclos != 1:
            return HttpResponse(json.dumps({'code': '404', 'msg': "文件为空或格式不正确"}, ensure_ascii=False))
        for i in range(1, nrows):
            text = table.row_values(i)[0]
            # 判断是否有重复数据
            if Query.objects.filter(text=text).exists():
                continue
            Query.objects.create(text=text)
            print(text, '导入成功')
        return HttpResponse(json.dumps({'code': '200', 'msg': "导入文件成功"}, ensure_ascii=False))
    else:
        return HttpResponse(json.dumps({'code': '404', 'msg': "请求方式错误"}, ensure_ascii=False))
