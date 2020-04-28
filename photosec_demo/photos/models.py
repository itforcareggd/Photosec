from django.conf import settings
from django.db import models


class Photos(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,)
    title = models.CharField(max_length=200)
    photo = models.FileField(upload_to='uploads/')
    upload_date = models.DateField(auto_now_add=True, blank=True)

    def __str__(self):
        return self.title