# Generated by Django 5.0.7 on 2025-01-06 17:58

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_v1', '0027_helpsupport_branch_helpsupport_school_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='student',
            name='club',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='students', to='api_v1.club'),
        ),
    ]
