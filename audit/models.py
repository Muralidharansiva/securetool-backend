from django.db import models

class ScanResult(models.Model):
    url = models.CharField(max_length=255)
    ip = models.CharField(max_length=100)
    open_ports = models.TextField(blank=True)
    risk_score = models.IntegerField()
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url
