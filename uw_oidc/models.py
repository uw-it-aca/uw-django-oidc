from django.db import models


class PublicKey(models.Model):
    content = models.TextField(unique=True)
    added_date = models.DateTimeField(auto_now_add=True)
