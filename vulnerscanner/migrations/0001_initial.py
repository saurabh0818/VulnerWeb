# Generated by Django 3.1 on 2020-09-02 14:17

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ScanData',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scan_num', models.IntegerField()),
                ('domain', models.CharField(max_length=50)),
                ('scan_progress', models.CharField(max_length=10)),
                ('scan_status', models.CharField(max_length=15)),
                ('total_urls', models.IntegerField()),
                ('scan_time', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
