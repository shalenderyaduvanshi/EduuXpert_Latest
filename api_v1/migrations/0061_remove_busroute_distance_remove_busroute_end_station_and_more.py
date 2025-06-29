# Generated by Django 5.0.7 on 2025-02-16 03:06

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_v1', '0060_busstation_vehicle_alter_busstation_lat_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='busroute',
            name='distance',
        ),
        migrations.RemoveField(
            model_name='busroute',
            name='end_station',
        ),
        migrations.RemoveField(
            model_name='busroute',
            name='start_station',
        ),
        migrations.AddField(
            model_name='busroute',
            name='vehicle',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='vehicle_bus_route', to='api_v1.vehicle'),
        ),
        migrations.AlterField(
            model_name='vehicle',
            name='routes',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='bus_route', to='api_v1.busroute'),
        ),
        migrations.CreateModel(
            name='RouteStop',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('active', models.BooleanField(default=True)),
                ('stop_order', models.PositiveIntegerField()),
                ('bus_station', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='route_stops', to='api_v1.busstation')),
                ('route', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='route_stops', to='api_v1.busroute')),
            ],
            options={
                'ordering': ['stop_order'],
            },
        ),
    ]
