# Generated by Django 5.0.7 on 2025-01-20 03:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_v1', '0044_remove_discount_applicable_to_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='payment',
            name='payment_date',
            field=models.DateField(blank=True, null=True),
        ),
    ]
