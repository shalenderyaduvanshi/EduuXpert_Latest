# Generated by Django 5.0.7 on 2025-01-04 06:34

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_v1', '0021_alter_academicperformance_session_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='studentfee',
            name='academic_session',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='api_v1.academicsession'),
        ),
    ]
