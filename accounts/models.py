from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class OTP(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created = models.DateTimeField(auto_now_add=True)

class DailyScanLimit(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    count = models.IntegerField(default=0)
