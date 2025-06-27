from django.urls import path
from api_v1.consumers import *

websocket_urlpatterns = [
    # path(r'ws/distance-matrix/', DistanceMatrixConsumer.as_asgi()),
    path(r'api/ws/live_bus_location/<str:school_code>/',LiveBusLocationConsumer.as_asgi()),
]