# Generated by Django 5.0.7 on 2025-01-31 17:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_v1', '0050_visitor_date_alter_visitor_time_slot'),
    ]

    operations = [
        migrations.AlterField(
            model_name='school',
            name='address',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='school',
            name='description',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='school',
            name='title',
            field=models.TextField(blank=True, null=True),
        ),
    ]
