# Generated by Django 5.0.7 on 2025-01-09 02:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_v1', '0031_alter_product_brand_alter_product_category_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='publish',
            field=models.BooleanField(default=False),
        ),
    ]
