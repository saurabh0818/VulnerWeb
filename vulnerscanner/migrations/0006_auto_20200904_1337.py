# Generated by Django 3.1 on 2020-09-04 08:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vulnerscanner', '0005_auto_20200904_1303'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vulnerdata',
            name='other',
            field=models.CharField(max_length=6000),
        ),
    ]
