from django.shortcuts import render
from django.http import HttpResponse
import json
import random
from .models import  Query,User
import hashlib
import time
import datetime

#修饰器，用于验证token，token有效才执行被修饰的函数
def check_token(func):
    def inner(request,*args,**kwargs):
        #获取token
        token = request.GET.get('token')
        #判断token是否存在
        if not token:
            return HttpResponse(json.dumps({'code':'403','msg':"token不存在"}, ensure_ascii=False))
        #根据token查询用户信息
        user = User.objects.filter(token=token).first()
        #判断用户是否存在
        if not user:
            return HttpResponse(json.dumps({'code':'403','msg':"用户不存在"}, ensure_ascii=False))
        #判断token是否过期
        c_time = user.token_time
        now_time = datetime.datetime.now()
        if (now_time-c_time).seconds > 3600:
            return HttpResponse(json.dumps({'code':'403','msg':"token过期"}, ensure_ascii=False))
        return func(request,*args,**kwargs)
    return inner
def get_data(request):
    if request.method == 'POST':
        return HttpResponse(json.dumps({'code':'403','msg':"查询路径无权限post"}, ensure_ascii=False))
    # 获取数据库中所有的数据
    full = Query.objects.all()
    num = full.count()
    ran = random.randint(0,num)
    text = full[ran].text
    likes = full[ran].likes
    return HttpResponse(json.dumps({"code":200, "msg":text, "likes":likes }, ensure_ascii=False))


# 用户注册，需要传入用户名，邮箱，密码，密码使用md5加密之后存入User表中
def register(request):
    if request.method == 'GET':
        return HttpResponse(json.dumps({'code':'403','msg':"注册路径无权限get"}, ensure_ascii=False))
    username = request.POST.get('username')
    email = request.POST.get('email')
    password = request.POST.get('password')
    if username == None or email == None or password == None:
        return HttpResponse(json.dumps({'code':'403','msg':"参数不完整"}, ensure_ascii=False))
    # md5加密密码
    md5 = hashlib.md5()
    md5.update(password.encode('utf-8'))
    password = md5.hexdigest()
    # 判断用户名是否已经存在
    if User.objects.filter(username=username).exists():
        return HttpResponse(json.dumps({'code':'403','msg':"用户名已存在"}, ensure_ascii=False))
    # 判断邮箱是否已经存在
    if User.objects.filter(email=email).exists():
        return HttpResponse(json.dumps({'code':'403','msg':"邮箱已存在"}, ensure_ascii=False))
    # 注册用户
    User.objects.create(username=username,email=email,password=password)
    return HttpResponse(json.dumps({'code':'200','msg':"注册成功"}, ensure_ascii=False))

# 用户登录，需要传入用户名，密码，密码使用md5加密之后与User表中的密码进行比对
def login(request):
    if request.method == 'GET':
        return HttpResponse(json.dumps({'code':'403','msg':"登录路径无权限get"}, ensure_ascii=False))
    username = request.POST.get('username')
    password = request.POST.get('password')
    if username == None or password == None:
        return HttpResponse(json.dumps({'code':'403','msg':"参数不完整"}, ensure_ascii=False))
    # md5加密密码
    md5 = hashlib.md5()
    md5.update(password.encode('utf-8'))
    password = md5.hexdigest()
    # 判断用户名是否存在
    if not User.objects.filter(username=username).exists():
        return HttpResponse(json.dumps({'code':'403','msg':"用户名不存在"}, ensure_ascii=False))
    # 判断密码是否正确
    if not User.objects.filter(username=username,password=password).exists():
        return HttpResponse(json.dumps({'code':'403','msg':"密码错误"}, ensure_ascii=False))
    #登录成功，生成token
    token = username + password
    md5 = hashlib.md5()
    md5.update(token.encode('utf-8'))
    token = md5.hexdigest()
    #设置token过期时间
    token_time = datetime.datetime.now() + datetime.timedelta(days=7)
    #更新token和token过期时间
    User.objects.filter(username=username).update(token=token,token_time=token_time)
    return HttpResponse(json.dumps({'code':'200','msg':"登录成功",'token':token}, ensure_ascii=False))

# 用户注销，需要传入token
def logout(request):
    if request.method == 'GET':
        return HttpResponse(json.dumps({'code':'403','msg':"注销路径无权限get"}, ensure_ascii=False))
    token = request.POST.get('token')
    if token == None:
        return HttpResponse(json.dumps({'code':'403','msg':"参数不完整"}, ensure_ascii=False))
    # 判断token是否存在
    if not User.objects.filter(token=token).exists():
        return HttpResponse(json.dumps({'code':'403','msg':"token不存在"}, ensure_ascii=False))
    # 判断token是否过期
    if User.objects.filter(token=token).first().token_time < datetime.datetime.now():
        return HttpResponse(json.dumps({'code':'403','msg':"token已过期"}, ensure_ascii=False))
    #注销用户
    User.objects.filter(token=token).update(token=None,token_time=None)
    return HttpResponse(json.dumps({'code':'200','msg':"注销成功"}, ensure_ascii=False))





