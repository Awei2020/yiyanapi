from django.db import models

class Query(models.Model):
    id = models.AutoField(db_column='id',primary_key=True)
    text = models.CharField(db_column='text',null=False,max_length=999)
    likes = models.IntegerField(db_column='likes', default=0)
    class Mate:
        db_table = 'aword'
        ordering = ['id']