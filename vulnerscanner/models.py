from django.db import models

# Create your models here.


class ScanData(models.Model):
    scan_num = models.IntegerField()
    domain = models.CharField(max_length=50)
    scan_progress = models.CharField(max_length=10)
    scan_status = models.CharField(max_length=15)
    total_urls = models.IntegerField()
    scan_time = models.DateTimeField(auto_now=True)

    # def __str__(self):

    #     return self.domain


class VulnerData(models.Model):
    scan_id = models.ForeignKey(ScanData, on_delete=models.CASCADE)
    urls = models.CharField(max_length=350)
    vul_name = models.CharField(max_length=500)
    risk = models.CharField(max_length=20)
    alert = models.CharField(max_length=400)
    decryption = models.CharField(max_length=2000)
    solution = models.CharField(max_length=3000)
    evidence = models.CharField(max_length=2000)
    other = models.TextField()


class ContextData(models.Model):
    context_name = models.CharField(max_length=50)
    con_number = models.IntegerField()
