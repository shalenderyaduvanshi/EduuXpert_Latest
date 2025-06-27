import json
import googlemaps
from channels.generic.websocket import AsyncWebsocketConsumer
from .models import *
from channels.layers import get_channel_layer
from channels.db import database_sync_to_async
from asgiref.sync import sync_to_async
from django.core.paginator import Paginator
from geopy.distance import geodesic 
import urllib.parse
from .serializers import *
from django.db import models
from django.utils import timezone


# Initialize Google Maps client
API_KEY = "AIzaSyDR0mOByPyNTaYWDSOYVHcws3KBatZ-vk0"
gmaps = googlemaps.Client(key=API_KEY)


class LiveBusLocationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.school_code = self.scope['url_route']['kwargs']['school_code']
        query_string = self.scope.get('query_string', b'').decode('utf-8')
        query_params = urllib.parse.parse_qs(query_string)
        self.username = query_params.get('username', [None])[0] or "unknown_user"
        self.vehicle_number = query_params.get('vehicle_number', [None])[0] or None
        self.room_group_name = f"bus_{self.school_code}"
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()
        await self.send_bus_list()
        print(self.vehicle_number)
        if self.vehicle_number:
            await self.send_engine_status('on')

    async def disconnect(self, close_code):
        # Leave the group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
        if self.vehicle_number:
            await self.send_engine_status('off')

    async def receive(self, text_data):
        data = json.loads(text_data)
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        vehicle_number = data.get('vehicle_number')
        speed = await self.calculate_speed(vehicle_number, latitude, longitude)

        if data.get('type') == "location_update":
            await self.update_vehicle_location(vehicle_number, latitude, longitude, speed)
            bus_list = await self.get_bus_update_locations(vehicle_number)
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'location_update',
                    'buses': bus_list,
                    'speed': speed,
                    'status': 'received',
                }
            )

    async def send_bus_list(self):
        bus_list = await self.get_all_bus_locations()
        await self.send(text_data=json.dumps({
            'type': 'bus_list',
            'buses': bus_list
        }))

    async def send_route_update(self):
        bus_list = await self.get_all_bus_locations()
        await self.send(text_data=json.dumps({
            'type': 'location_update',
            'buses': bus_list
        }))

    async def send_engine_status(self,engine_status):
        await self.update_engine_status(self.vehicle_number, engine_status)
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'engine_status',
                'engine_status': engine_status,
                'vehicle_number':self.vehicle_number
            }
        )
    async def engine_status(self, event):
        """Handler for engine_status messages."""
        engine_status = event.get('engine_status')
        vehicle_number = event.get('vehicle_number')

        # Send the engine status back to the WebSocket
        await self.send(text_data=json.dumps({
            'type': 'engine_status',
            'engine_status': engine_status,
            'vehicle_number': vehicle_number
        }))
    async def location_update(self, event):
        """Handler for location_update messages."""
        buses = event.get('buses')
        speed = event.get('speed')

        # Send the location update back to the WebSocket
        await self.send(text_data=json.dumps({
            'type': 'location_update',
            'buses': buses,
            'speed': speed
        }))

    @database_sync_to_async
    def update_engine_status(self, vehicle_number, engine_status):
        """Update the vehicle's engine status in the database."""
        vehicle = Vehicle.objects.get(vehicle_number=vehicle_number)
        vehicle.engine_status = engine_status  # Assuming engine_status field is added in the Vehicle model
        vehicle.speed= 0.0
        vehicle.save()
        

    @database_sync_to_async
    def update_vehicle_location(self, vehicle_number, latitude, longitude,speed):
        """Update the vehicle's location in the database."""
        vehicle = Vehicle.objects.get(vehicle_number=vehicle_number)
        vehicle.latitude = latitude
        vehicle.longitude = longitude
        vehicle.speed = speed
        vehicle.save()
    @database_sync_to_async
    def get_bus_update_locations(self, vehicle_number):
        bus = Vehicle.objects.filter(vehicle_number=vehicle_number).values(
            'id', 'vehicle_number', 'name',
            'latitude', 'longitude', 'speed', 'engine_status',
            'driver__username', 'driver__name', 'driver__mobile_no',
            'route_incharge__username', 'route_incharge__mobile_no', 'route_incharge__name',
            'updated_at'
        ).first()  # Use .first() to get the first matching record as a dictionary

        if not bus:
            return None  # Handle case when no bus is found with the provided vehicle_number
        try:
            bus_route = BusRoute.objects.get(vehicle__id=bus['id'])
        except BusRoute.DoesNotExist:
            return {"error": "Invalid BusRoute ID"}
        
        arrive_stops = RouteStop.objects.filter(
            route=bus_route, 
            type="arrive",
            bus_station__in=bus_route.arrive_stop_points.all()
        ).order_by('stop_order')

        return_stops = RouteStop.objects.filter(
            route=bus_route, 
            type="return",
            bus_station__in=bus_route.return_stop_points.all()
        ).order_by('stop_order')
        bus_location = (bus['latitude'], bus['longitude'])                 
        arrive_distances_and_times = self.calculate_distances_and_times(arrive_stops, bus_location, engine_status='on')
        return_distances_and_times = self.calculate_distances_and_times(return_stops, bus_location, engine_status='on')
        if arrive_stops.exists():
            arrive_source_location = (arrive_stops.first().bus_station.lat, arrive_stops.first().bus_station.lon)
            bus_distance_from_source, bus_time_from_source = self.get_distance_time(bus_location, arrive_source_location)
        else:
            bus_distance_from_source, bus_time_from_source = "0", "0"
        return {
           'vehicle_number': bus['vehicle_number'],
                'name': bus['name'],
                'latitude': bus['latitude'],
                'longitude': bus['longitude'],
                'speed': bus['speed'],
                'engine_status': bus['engine_status'],
                'place_name': self.get_place_name_sync(bus['latitude'], bus['longitude']) if bus['latitude'] and bus['longitude'] else "Unknown location",
                'updated_at': bus['updated_at'].isoformat() if bus['updated_at'] else None,
                'driver': {
                    'username': bus.get('driver__username'),
                    'mobile_no': bus.get('driver__mobile_no'),
                    'name': bus.get('driver__name'),
                } if bus.get('driver__username') else 'No driver',
                'route_incharge': {
                    'username': bus.get('route_incharge__username'),
                    'mobile_no': bus.get('route_incharge__mobile_no'),
                    'name': bus.get('route_incharge__name'),
                } if bus.get('route_incharge__username') else 'No route incharge',
                'distance': bus_distance_from_source,
                'time': bus_time_from_source,
                'arrive_stops': arrive_distances_and_times,
                'return_stops': return_distances_and_times
        }
    def get_distance_time(self,origins, destinations):
        result = gmaps.distance_matrix(origins, destinations, mode="driving")
        if result['rows'] and result['rows'][0]['elements']:
            element = result['rows'][0]['elements'][0]
            if element.get('status') == 'OK':
                return element['distance']['text'], element['duration']['text']
        return "N/A", "N/A"
    @database_sync_to_async
    def get_all_bus_locations(self):
        user = User.objects.get(username=self.username)
        school = user.school
        role = user.role.name
        role_filter = {"school": school, "active": True}
        if role == "driver":
            buses = Vehicle.objects.filter(driver=user, **role_filter)
        elif role != "school":
            buses = Vehicle.objects.filter(passenger_in=user, **role_filter)
        else:
            buses = Vehicle.objects.filter(**role_filter)
        buses =buses.filter(**role_filter).values(
        'id','vehicle_number', 'name',
        'latitude', 'longitude', 'speed', 'engine_status',
        'driver__username', 'driver__name', 'driver__mobile_no',
        'route_incharge__username', 'route_incharge__mobile_no', 'route_incharge__name',
        'updated_at',
        )
        
        result = []
        
        for bus in buses:
            try:
                bus_route = BusRoute.objects.get(vehicle__id=bus['id'])
            except BusRoute.DoesNotExist:
                return {"error": "Invalid BusRoute ID"}
            
            arrive_stops = RouteStop.objects.filter(
                route=bus_route, 
                type="arrive",
                bus_station__in=bus_route.arrive_stop_points.all()
            ).order_by('stop_order')

            return_stops = RouteStop.objects.filter(
                route=bus_route, 
                type="return",
                bus_station__in=bus_route.return_stop_points.all()
            ).order_by('stop_order')
            bus_location = (bus['latitude'], bus['longitude'])
            if bus['engine_status'] == 'off':
                arrive_distances_and_times = self.calculate_distances_and_times(arrive_stops, bus_location, engine_status='off')
                return_distances_and_times = self.calculate_distances_and_times(return_stops, bus_location, engine_status='off')
            else:                    
                arrive_distances_and_times = self.calculate_distances_and_times(arrive_stops, bus_location, engine_status='on')
                return_distances_and_times = self.calculate_distances_and_times(return_stops, bus_location, engine_status='on')
            if arrive_stops.exists():
                arrive_source_location = (arrive_stops.first().bus_station.lat, arrive_stops.first().bus_station.lon)
                bus_distance_from_source, bus_time_from_source = self.get_distance_time(bus_location, arrive_source_location)
            else:
                bus_distance_from_source, bus_time_from_source = "0", "0"
            # Add all information to the result
            result.append({
                'vehicle_number': bus['vehicle_number'],
                'name': bus['name'],
                'latitude': bus['latitude'],
                'longitude': bus['longitude'],
                'speed': bus['speed'],
                'engine_status': bus['engine_status'],
                'place_name': self.get_place_name_sync(bus['latitude'], bus['longitude']) if bus['latitude'] and bus['longitude'] else "Unknown location",
                'updated_at': bus['updated_at'].isoformat() if bus['updated_at'] else None,
                'driver': {
                    'username': bus.get('driver__username'),
                    'mobile_no': bus.get('driver__mobile_no'),
                    'name': bus.get('driver__name'),
                } if bus.get('driver__username') else 'No driver',
                'route_incharge': {
                    'username': bus.get('route_incharge__username'),
                    'mobile_no': bus.get('route_incharge__mobile_no'),
                    'name': bus.get('route_incharge__name'),
                } if bus.get('route_incharge__username') else 'No route incharge',
                'distance': bus_distance_from_source,
                'time': bus_time_from_source,
                'arrive_stops': arrive_distances_and_times,
                'return_stops': return_distances_and_times
            })
        
        return result
    def calculate_distances_and_times(self, stops, bus_location, engine_status='on'):
        distances_and_times = []

        for i in range(len(stops)):
            stop = stops[i]
            stop_location = (stop.bus_station.lat, stop.bus_station.lon)

            # Always calculate the fixed distance and time between consecutive stops
            if i == 0:
                distances_and_times.append({
                    "id": str(stop.bus_station.id),
                    "name": stop.bus_station.name,
                    "route_fair": stop.bus_station.route_fair,
                    "lat": stop.bus_station.lat,
                    "lon": stop.bus_station.lon,
                    "place_name": stop.bus_station.place_name,
                    "stop_order": stop.stop_order,
                    "fixed_distance": 0,  # Distance from source to itself is 0
                    "fixed_time": 0,  # Time from source to itself is 0
                    "bus_time": 0 if engine_status == 'off' else self.get_distance_time(bus_location, stop_location)[1],
                    "bus_distance": 0 if engine_status == 'off' else self.get_distance_time(bus_location, stop_location)[0],
                })
            else:
                # Calculate distance and time between current stop and the previous stop
                previous_stop_location = (stops[i - 1].bus_station.lat, stops[i - 1].bus_station.lon)
                fixed_distance, fixed_time = self.get_distance_time(previous_stop_location, stop_location)

                # Calculate distance and time from bus to the stop
                if engine_status == 'on':
                    bus_distance, bus_time = self.get_distance_time(bus_location, stop_location)
                else:
                    bus_distance, bus_time = 0, 0  # Set to 0 when engine is off

                distances_and_times.append({
                    "id": str(stop.bus_station.id),
                    "name": stop.bus_station.name,
                    "route_fair": stop.bus_station.route_fair,
                    "lat": stop.bus_station.lat,
                    "lon": stop.bus_station.lon,
                    "place_name": stop.bus_station.place_name,
                    "stop_order": stop.stop_order,
                    "fixed_distance": fixed_distance,  # Distance between stops
                    "fixed_time": fixed_time,  # Time between stops
                    "bus_time": bus_time,  # Time from the bus to the stop
                    "bus_distance": bus_distance  # Distance from the bus to the stop
                })

        return distances_and_times

    def calculate_distances_and_times(stops, bus_location):
        distances_and_times = []
        
        # Handle the case for the first stop (source)
        for i in range(len(stops)):
            stop = stops[i]
            stop_location = (stop.bus_station.lat, stop.bus_station.lon)
            
            # If this is the first stop, set distance to source as 0
            if i == 0:
                distances_and_times.append({
                    "id": str(stop.bus_station.id),
                    "name": stop.bus_station.name,
                    "route_fair": stop.bus_station.route_fair,
                    "lat": stop.bus_station.lat,
                    "lon": stop.bus_station.lon,
                    "place_name": stop.bus_station.place_name,
                    "stop_order": stop.stop_order,
                    "fixed_distance": 0, 
                     "fixed_time":0,
                    "bus_time": 0,
                    "bus_distance":0,
                })
            else:
                # Calculate distance and time between current stop and the previous stop
                previous_stop_location = (stops[i - 1].bus_station.lat, stops[i - 1].bus_station.lon)
                distance, time = self.get_distance_time(previous_stop_location, stop_location)
                distance_from_bus, time_from_bus = self.get_distance_time(bus_location, stop_location)
                
                distances_and_times.append({
                    "id": str(stop.bus_station.id),
                    "name": stop.bus_station.name,
                    "route_fair": stop.bus_station.route_fair,
                    "lat": stop.bus_station.lat,
                    "lon": stop.bus_station.lon,
                    "place_name": stop.bus_station.place_name,
                    "stop_order": stop.stop_order,
                    "fixed_distance": distance,
                    "bus_time": time_from_bus,
                    "bus_distance":distance_from_bus,
                    "fixed_time":time
                })
        
        return distances_and_times
    
    async def get_place_name(self, lat, lng):
        """Helper function to get human-readable place name from coordinates."""
        if lat is None or lng is None:
            return "Unknown location"
        result = gmaps.reverse_geocode((lat, lng))
        return result[0]["formatted_address"] if result else f"{lat},{lng}"

    def get_place_name_sync(self, lat, lng):
        """Synchronous helper function to get place name (used in the database fetch)."""
        if lat is None or lng is None:
            return "Unknown location"
        result = gmaps.reverse_geocode((lat, lng))
        return result[0]["formatted_address"] if result else f"{lat},{lng}"
    @database_sync_to_async
    def calculate_speed(self, vehicle_number, new_latitude, new_longitude):
        try:
            vehicle = Vehicle.objects.get(vehicle_number=vehicle_number)

            if vehicle.latitude is None or vehicle.longitude is None:
                return 0.0  

            origins = f"{vehicle.latitude},{vehicle.longitude}"
            destinations = f"{new_latitude},{new_longitude}"
            response = gmaps.distance_matrix(origins, destinations, mode="driving")
            distance_meters = response["rows"][0]["elements"][0]["distance"]["value"]
            duration_seconds = response["rows"][0]["elements"][0]["duration"]["value"]
            
            if duration_seconds <= 0:
                return 0.0  
            
            speed_km_per_hour = (distance_meters / 1000) / (duration_seconds / 3600)
            return round(speed_km_per_hour, 2)
        except (Vehicle.DoesNotExist, KeyError, IndexError, TypeError):
            return 0.0
        
    def get_bus_live_route_info(self, live_lat, live_lng, vehicle_id):
        """Fetch live route details for a bus."""
        required_fields = [live_lat, live_lng, vehicle_id]
        if not all(field in [live_lat, live_lng, vehicle_id] for field in required_fields):
           return {"error": "Missing required field"}
  
        try:
           live_lat = float(live_lat)
           live_lng = float(live_lng)
        except (ValueError, TypeError):
           return {"error": "Invalid latitude/longitude values"}
        try:
           bus_route = BusRoute.objects.get(vehicle__id=vehicle_id)
        except BusRoute.DoesNotExist:
           return {"error": "Invalid BusRoute ID"}
  
        # Calculate distance and time using Google Distance Matrix API
        def get_distance_time(origins, destinations):
           print(origins,destinations)
           result = gmaps.distance_matrix(origins, destinations, mode="driving")
           print(result)
           if result['rows'] and result['rows'][0]['elements']:
                 element = result['rows'][0]['elements'][0]
                 if element.get('status') == 'OK':
                    return element['distance']['text'], element['duration']['text']
           return "N/A", "N/A"
  
        # Extract locations from the bus route
        source_lat, source_lng = bus_route.start_station.lat, bus_route.start_station.lon
        destination_lat, destination_lng = bus_route.end_station.lat, bus_route.end_station.lon
        stop_points = bus_route.stop_points.all()
  
        # Calculate distance and time from live location to source and destination
        distance_to_source, time_to_source = get_distance_time((live_lat, live_lng), (source_lat, source_lng))
        distance_to_destination, time_to_destination = get_distance_time((live_lat, live_lng), (destination_lat, destination_lng))
  
        stops = []
        count = 0
        for stop in stop_points:
           count += 1
           distance, time = get_distance_time((live_lat, live_lng), (stop.lat, stop.lon))
           stops.append({
                 "id":f"{stop.id}",
                 "stop_number": count,
                 "name": stop.place_name,
                 "distance_from_live": distance,
                 "time_from_live": time
           })
  
        return {
            "id": f"{busroute_id}",
           "source": {
                 "stop_number": 0,
                 "id":f"{bus_route.start_station.id}",
                 "name": bus_route.start_station.place_name,
                 "distance_from_live": distance_to_source,
                 "time_from_live": time_to_source
           },
           "stops": stops,
           "destination": {
                  "id": f"{bus_route.end_station.id}",
                 "stop_number": count + 1,
                 "name": bus_route.end_station.place_name,
                 "distance_from_live": distance_to_destination,
                 "time_from_live": time_to_destination
           },
        }
    
    