from django.shortcuts import render
from django.http import HttpResponse
import json
import random
from .models import  Query

def get_data(request):
    if request.method == 'POST':
        return HttpResponse(json.dumps({'code':'403','msg':"查询路径无权限post"}, ensure_ascii=False))
    full = Query.objects.all()
    num = full.count()
    ran = random.randint(0,num)
    text = full[ran].text
    likes = full[ran].likes
    return HttpResponse(json.dumps({"code":200, "msg":text, "likes":likes }, ensure_ascii=False))