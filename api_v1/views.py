# views.py
from rest_framework import generics, mixins
import uuid
from django.utils import timezone
from rest_framework.generics import *
from rest_framework.response import Response
from rest_framework import status,permissions
from django.contrib.auth import authenticate,logout  
from rest_framework.authtoken.models import Token
from .models import *
from .serializers import *
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.conf import settings
from rest_framework.pagination import PageNumberPagination
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView
from django.core.mail import send_mail,EmailMessage
import mimetypes
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from .helper import *
from django.db import transaction
from django.db import connection
from django.apps import apps
import re
from datetime import datetime,timedelta
from django.utils.timezone import now
from django.db.models import Sum, F, Count
from django.db.models import Q
from django.contrib.auth.signals import user_logged_in
from dateutil.relativedelta import relativedelta
from collections import defaultdict
from calendar import monthrange
from PIL import Image
from django.db.models.functions import ExtractDay, ExtractMonth
from pytesseract import pytesseract
import qrcode
from io import BytesIO
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from easyaudit.models import CRUDEvent
from django.core.files.base import ContentFile
from .utils import send_whatsapp_message,send_sms

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import pytz
import os
from google.auth.transport.requests import Request
import base64
import json
import requests
from decimal import Decimal
import googlemaps


gmaps = googlemaps.Client(key=settings.GOOGLE_API_KEY)


alert_perm_msg = "You do not have permission to access this resource. Please ensure you are logged in and have the required permissions."
class CustomPagination(PageNumberPagination):
    page_size = 10  # Default page size
    page_size_query_param = 'page_size'  # Allow user to pass `page_size` query param
    max_page_size = 100  # Limit the maximum page size to avoid excessive load

def generate_username(name, prefix=""):
    base_username = (prefix + name[:4].lower().replace(" ", "_")).strip()
    while True:
        username = base_username + str(uuid.uuid4().hex[:5])
        if not User.objects.filter(username=username).exists():
            return username

from django.core.mail import EmailMessage

def send_via_email(subject, message, email, attachment=None):
    email_message = EmailMessage(
        subject=subject,
        body=message,
        from_email=settings.EMAIL_HOST_USER,
        to=[email]
    )
    
    # If an attachment is provided, attach it to the email
    if attachment:
        content_type, _ = mimetypes.guess_type(attachment.name)
        if content_type is None:
            content_type = 'application/octet-stream'  # Default to binary if unknown

        email_message.attach(attachment.name, attachment.read(), content_type)

    email_message.send()

# ===================================report generate using sql query==========================
class ReportGenerateView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Permission check
        if not (request.user.is_superuser or (request.user.role and request.user.role.name == "school")):
            return Response({"message": "No permission to access"}, status=status.HTTP_403_FORBIDDEN)
        
        # Retrieve the query
        query = request.data.get('query')
        if not query:
            return Response({"message": "Query parameter is missing"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate SELECT statement
        if not self.is_select_query(query):
            return Response({"message": "Only SELECT queries are allowed."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Execute the query
            with connection.cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()
                columns = [col[0] for col in cursor.description]

            # Format the rows into a list of dictionaries
            result = []
            for row in rows:
                formatted_row = {}
                for column, value in zip(columns, row):
                    if self.is_valid_uuid(value):  # Check if the value is a UUID
                        value = str(uuid.UUID(value))  # Format UUID to include hyphens
                    formatted_row[column] = value
                result.append(formatted_row)

            return Response({"data": result}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def is_select_query(self, query):
        # Check if the query starts with SELECT
        return bool(re.match(r'^\s*SELECT', query, re.IGNORECASE))

    def is_valid_uuid(self, value):
        # Check if the value is a string
        if not isinstance(value, str):
            return False
        try:
            uuid.UUID(value)  # Attempt to convert to UUID
            return True
        except (ValueError, TypeError):
            return False

    def get(self, request, *args, **kwargs):
        if not (request.user.is_superuser or (request.user.role and request.user.role.name == "school")):
            return Response({"message": "No permission to access"}, status=status.HTTP_403_FORBIDDEN)
        
        # List all models in the app
        model_names = [model._meta.model_name for model in apps.get_models()]
        database_name = settings.DATABASES['default']['NAME']
        return Response({"table_names": model_names, "database_name": database_name}, status=status.HTTP_200_OK)
# ===========================================get filter list================================
class GetFilterListAPiView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        model_name = request.query_params.get('model')  # Default to empty JSON list if not provided
        fields_param = request.query_params.get('fields', '[]')  # Default to empty JSON list if not provided
        
        if not model_name:
            return Response({"error": "Model name is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not fields_param:
            return Response({"error": "Fields parameter is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            field_list = json.loads(fields_param) if isinstance(fields_param, str) else fields_param
        except json.JSONDecodeError:
            return Response({"error": "Invalid JSON format in 'fields' parameter."}, status=400)
        if not isinstance(field_list, list):
            return Response({"error": "'fields' must be a list of field names."}, status=400)
        return get_distinct_values(request,model_name,field_list)
#=========================================bulk import andsample==========================
class ImportBulkData(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        model_name = request.query_params.get('model')
        if not model_name:
            return Response({"message": "Model name is required."}, status=status.HTTP_400_BAD_REQUEST)
        school, error_response = check_permission_and_get_school(request, f"api_v1.add_{model_name}")
        if error_response:
            return error_response
        try:
            return generate_model_fields_excel(model_name, app_label='api_v1')
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        model_name = request.query_params.get('model')
        if not model_name:
            return Response({"message": "Model name is required."}, status=status.HTTP_400_BAD_REQUEST)
        school, error_response = check_permission_and_get_school(request, f"api_v1.add_{model_name}")
        if error_response:
            return error_response
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return Response({"message": "File is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            return import_bulk_data(model_name, uploaded_file)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
 # ===========================================bulk create================================
# class BulkUploadView(APIView):
#     permission_classes = [permissions.IsAuthenticated]

#     def post(self, request, *args, **kwargs):
#         if not (request.user.is_superuser or (request.user.role and request.user.role.name == "school")):
#             return Response({"message": "No permission to access"}, status=status.HTTP_403_FORBIDDEN)
#         data = request.data.get("data", [])
#         model_name = request.data.get("model_name", None)
#         if not data or not model_name:
#             return Response({"message": "Data and model name are required"}, status=status.HTTP_400_BAD_REQUEST)
#         try:
#             model = apps.get_model('api_v1', model_name) 
#             objects_to_create = [model(**item) for item in data]
#             with transaction.atomic():
#                 model.objects.bulk_create(objects_to_create)
#             return Response({"message": "Data imported successfully"}, status=status.HTTP_201_CREATED)
#         except LookupError:
#             return Response({"error": "Model not found"}, status=status.HTTP_404_NOT_FOUND)
#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
import json
import logging
logger = logging.getLogger(__name__)
class BulkUploadView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            # Parse JSON body
            body = json.loads(request.body)
            model_name = body.get("model_name")
            data = body.get("data")

            if not model_name or not data:
                return Response({"error": "Model name and data are required."}, status=status.HTTP_400_BAD_REQUEST)

            # Dynamically get the model
            try:
                model = apps.get_model(app_label="api_v1", model_name=model_name)
            except LookupError:
                return Response({"error": f"Model '{model_name}' not found."}, status=status.HTTP_400_BAD_REQUEST)

            upload_results = []

            # Process each record in the data
            for row_index, row in enumerate(data):
                try:
                    logger.debug(f"Processing row {row_index + 1}: {row}")
                    instance = model(**row)  # Dynamically create instance
                    instance.full_clean()  # Validate fields
                    instance.save()
                    upload_results.append({"row": row_index + 1, "success": True, "error": ""})
                except Exception as e:
                    logger.error(f"Error processing row {row_index + 1}: {e}")
                    upload_results.append({"row": row_index + 1, "success": False, "error": str(e)})

            logger.info(f"Upload results: {upload_results}")
            return Response(upload_results, status=status.HTTP_200_OK)

        except json.JSONDecodeError:
            logger.error("Invalid JSON format.")
            return Response({"error": "Invalid JSON format."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return Response({"error": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
# -------------==================---------------table name===========================================
class TableColumnsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request,*args, **kwargs):
        # Check user permissions
        if not (request.user.is_superuser or (request.user.role and request.user.role.name == "school")):
            return Response({"message": "No permission to access"}, status=status.HTTP_403_FORBIDDEN)
        table_name = request.query_params.get('table_name', None)
        if not table_name:
            return Response({"message": "Table Name is required"}, status=status.HTTP_400_BAD_REQUEST)

                # Construct the SQL query to get column names
        db_table_name = f"api_v1_{table_name}"  # Update this based on your naming convention

        try:
            with connection.cursor() as cursor:
                # Query to fetch column names
                cursor.execute(f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{db_table_name}'")
                columns = [row[0] for row in cursor.fetchall()]

            return Response({"columns": columns}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

###################################  USER API  ###########################################################
class UserAPI(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer
    pagination_class = CustomPagination

    def get_object(self):
        return self.request.user

    def get(self, request):
        user = self.get_object()
        role = request.query_params.get('role', None)
        school_id = request.query_params.get('school_id', None)
        
        if user.is_superuser or (user.role and user.role.name == "school"):
            try:
                role_instance = Role.objects.get(name=role)
            except Role.DoesNotExist:
                return Response({"message": "Role not Found"}, status=status.HTTP_400_BAD_REQUEST)
            if user.is_superuser:
                if role and school_id:
                    try:
                        uuid.UUID(school_id)
                    except ValueError:
                        return Response({"message": "Invalid UUID format for school"}, status=status.HTTP_400_BAD_REQUEST)
                    try:
                        school = School.objects.get(id=school_id)
                        users = User.objects.filter(role=role, school=school).order_by('-created_at')
                    except School.DoesNotExist:
                        return Response({"message": "School not found"}, status=status.HTTP_404_NOT_FOUND)
                elif school_id:
                    users = User.objects.filter(is_superuser=False, school__id=school_id).order_by('-created_at')
                elif role:
                    users = User.objects.filter(role=role_instance).order_by('-created_at')
                else:
                    users = User.objects.filter(is_superuser=False).order_by('-created_at')
                # message = "Hi, Admin, User retrieved successfully"
            
            if (user.role and user.role.name == "school"):
                # school = School.objects.get(id=user.school.id)
                users = User.objects.filter(role=role_instance,school=user.school.id).order_by('-created_at')
                # message = "User retrieved successfully"

            page = self.paginate_queryset(users)
            serializer = UserSerializer(page, many=True)
            response = self.get_paginated_response(serializer.data)
            return response  # Return directly the paginated response
        return Response({"message": "PermissionDenied"}, status=status.HTTP_401_UNAUTHORIZED)

    def delete(self, request, *args, **kwargs):
        user = self.get_object()
        if not (user.is_superuser or (user.role and user.role.name == "school")):
            return Response({"message": "You do not have permission to delete this user."}, status=status.HTTP_403_FORBIDDEN)
        
        user_id = kwargs.get('id')
        if not user_id:
            return Response({"message": "User ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"message": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        user.delete()
        return Response({"message": "User deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

    def post(self, request, *args, **kwargs):
        user = self.get_object()  # Assumes you have a method to get the current user
        role = request.query_params.get('role', None)
        username = request.data.get('username')
        password = request.data.get('password')

        # Check if the user has permission to create a user
        if not (user.is_superuser or (user.role and user.role.name == "school")):
            return Response({"message": "You do not have permission to create this user."}, status=status.HTTP_403_FORBIDDEN)

        # Check if username and password are provided
        if not username or not password:
            return Response({"message": "Username and password are required to create a user."}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the role exists
        try:
            role_instance = Role.objects.get(name=role)
        except Role.DoesNotExist:
            return Response({"message": "Role is missing!"}, status=status.HTTP_404_NOT_FOUND)

        # If the role is 'school', only superadmins can create schools
        if role == "school" and not user.is_superuser:
            return Response({"message": "Only superadmin can create a school!"}, status=status.HTTP_403_FORBIDDEN)

        # Handle the different roles for user creation
        if role == "school":
            serializer = SchoolSerializer(data=request.data)
        elif role == "student":
            serializer = StudentProfileSerializer(data=request.data)
        elif role == "teacher":
            bank_serializer = BankSerializer(data=request.data)
            if not bank_serializer.is_valid():
                return Response({"message": "Invalid bank data", "errors": bank_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

            createbank = bank_serializer.save()
            data = request.data.copy()
            data['bank'] = createbank.id  # Set the bank
            serializer = TeacherSerializer(data=data)
        elif role == "parent":
            serializer = ParentSerializer(data=request.data)
        else:
            return Response({"message": "Invalid role provided."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate the serializer
        if serializer.is_valid():
            created_user = serializer.save()

            # Create the User model associated with the profile
            user_data = {
                'username': username,
                'password': make_password(password),
                'role': role_instance,
            }

            if role == "school":
                user_data['school'] = created_user
            elif role == "student":
                user_data['student_profile'] = created_user
            elif role == "teacher":
                user_data['teacher_profile'] = created_user
            elif role == "parent":
                user_data['parent_profile'] = created_user

            user = User.objects.create(**user_data)
            user_serializer = UserSerializer(user)

            return Response({
                "message": f"{role} created successfully!",
                "data": {"profile": serializer.data, "user": user_serializer.data}
            }, status=status.HTTP_201_CREATED)

        # If serializer is invalid, return the errors
        error_messages = "; ".join([f"{key}: {', '.join(value)}" for key, value in serializer.errors.items()])
        return Response({"message": error_messages}, status=status.HTTP_400_BAD_REQUEST)

class SchoolDetailOnLogin(GenericAPIView):
    def get(self,request,*args, **kwargs):
        school_code = kwargs.get('school_code')
        if not school_code:
            return Response({"message": "School Code is required!"}, status=status.HTTP_400_BAD_REQUEST)
        school = School.objects.get(school_code = school_code)
        serializer = SchoolSerializer(school)
        return Response({
            "message": "Login Successfully!",
            "data":serializer.data
        },status=status.HTTP_200_OK)
    
###################################  LOGIN API  ###########################################################
class LoginAPI(GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = UserSerializer

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        # user_role = request.data.get('role')
        school_code = request.data.get('school_code')
        try:
            user = User.objects.filter(
                Q(username=username) | 
                Q(email=username) | 
                Q(mobile_no=username)
            ).distinct()

            if not user.exists():
                return Response({"message": "User with these credentials does not exist"}, status=status.HTTP_404_NOT_FOUND)

            user = user.first()

            # Check if the user belongs to the provided school_code
            if not hasattr(user, 'school'):  # Assuming school is linked to Profile
                return Response({"message": "User does not belong to any school."}, status=status.HTTP_400_BAD_REQUEST)

            # Validate that the user's school matches the provided school_code
            if user.school.school_code != school_code:
                return Response({"message": "User does not belong to the specified school."}, status=status.HTTP_401_UNAUTHORIZED)

        except User.DoesNotExist:
            return Response({"message": "User with these credentials does not exist"}, status=status.HTTP_404_NOT_FOUND)

             
        authenticated_user = authenticate(username=user.username, password=password)
        if authenticated_user is None:
            return Response({"message": "Invalid login credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        token, _ = Token.objects.get_or_create(user=authenticated_user)
        user_logged_in.send(sender=authenticated_user.__class__, request=request, user=authenticated_user)
        serializer = self.get_serializer(authenticated_user)
        return Response({
            "message": "Login Successfully!",
            "token": token.key,
            "data":serializer.data
        },status=status.HTTP_200_OK)
class UserDetailByTokenAPI(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserDetailTokenSerializer
    def get(self, request):
        serializer = self.get_serializer(request.user)
        return Response({
            "message": "User Detail Reterived Successfully!",
            "data":serializer.data
        },status=status.HTTP_200_OK)
class SchoolCodeValidateAPI(GenericAPIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        school_code = request.data.get('school_code')  # Get school code from the request body

        if not school_code:
            return Response({"error": "School code is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            school = School.objects.get(school_code=school_code)
            serializer = SchoolSerializer(school)
            return Response({"message":"SChool Code Validate Successfully","data":serializer.data}, status=status.HTTP_200_OK)
        except School.DoesNotExist:
            return Response({"message": "Invalid school code"}, status=status.HTTP_404_NOT_FOUND)
class UpdatePasswordView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request, *args, **kwargs):
        user_id = kwargs.get('id')  # Extract user ID from URL kwargs
        if not user_id:
            return Response({"message": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        new_password = request.data.get('password')
        if not new_password:
            return Response({"message": "Password is required"}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.plain_password = new_password 
        user.save()
        return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
###################################  LOGOUT API  ###########################################################
class LogoutAPI(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        try:
            request.user.auth_token.delete()
            logout(request)
        except AttributeError:
            pass
        return Response({"message": "Logged-Out Successfully"},status=status.HTTP_200_OK)
class CheckTokenAPI(GenericAPIView):
    permission_classes = [permissions.AllowAny]
    def post(self,request):
        token_key = self.request.data.get('token')
        if not token_key:
            return Response({'message': 'Token is missing'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = Token.objects.get(key=token_key)
        except Token.DoesNotExist:
            return Response({'message': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)
        if not token.user:
            return Response({'message': 'Token is not associated with any user.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'message': 'Token is valid.'}, status=status.HTTP_200_OK)
# ====================== create App and Appitem ===================
class AppApi(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AppSerializer

    def get_object(self):
        return self.request.user

    def post(self, request):
        user = self.get_object()
        if not user.is_superuser:
            return Response({"message": "Permission denied."}, status=status.HTTP_401_UNAUTHORIZED)
        app_name = request.data.get("app_name")
        app_icon = request.data.get("app_icon")
        item_names = request.data.get("app_item", [])
        
        if not app_name or not app_icon:
            return Response({'message': 'App name and icon are required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not isinstance(item_names, list):
            return Response({'message': 'app_item should be a list of names.'}, status=status.HTTP_400_BAD_REQUEST)
        
        app = App.objects.create(name=app_name, icon=app_icon)
        app_items = [AppItem(name=name, app=app) for name in item_names if name]
        AppItem.objects.bulk_create(app_items)
        return Response({'message': 'Hi, Admin, App and app items created successfully.'}, status=status.HTTP_201_CREATED)

    def get(self, request):
        user = self.get_object()
        if not user.is_superuser:
            return Response({"message":alert_perm_msg},status=status.HTTP_401_UNAUTHORIZED)
        try:
            app = App.objects.all()
        except App.DoesNotExist:
            return Response({'message': 'App is empty! '}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(app,many=True)
        return Response({'message': 'App reterived successfully! ',"data":serializer.data}, status=status.HTTP_200_OK)
    def delete(self, request,*args, **kwargs):
        user = self.get_object()
        if not user.is_superuser :
            return Response({"message":"You do not have permission to delete this App and Appitems."},status=status.HTTP_403_FORBIDDEN)
        app_id = kwargs.get('id')
        if not app_id:
            return Response({"message": "App ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            app = App.objects.get(id=app_id)
        except App.DoesNotExist:
            return Response({"message": "App not found."}, status=status.HTTP_404_NOT_FOUND)
        AppItem.objects.filter(app=app).delete()
        app.delete()
        return Response({"message": "Hi, admin, App and associated AppItems deleted successfully."},)
#    ==========================user app permission=================
class UserListView(APIView):
    def get(self, request):
        """
        Get the list of users based on role and school.
        """
        role = request.query_params.get("role")
        class_id = request.query_params.get("class_id")
        section_id = request.query_params.get("section_id")
        club_id = request.query_params.get('club_id', None)
        dormitory_id = request.query_params.get('dormitory_id', None)
        dormitoryroom_id = request.query_params.get('dormitoryroom_id', None)
        house_id = request.query_params.get('house_id', None)
        enroll_no = request.query_params.get('enroll_no', None)
        user = request.user
        school_id = request.query_params.get('school_id', None)
        if user.is_superuser and role != "school":
            if not school_id:
                return Response({"message": "School ID is required."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                school = School.objects.get(id=school_id)
            except School.DoesNotExist:
                return Response({"message": "Invalid school ID."}, status=status.HTTP_404_NOT_FOUND)
        if not user.is_superuser:
            school = user.school
        if not role:
            return Response({"error": "Role is required"}, status=status.HTTP_400_BAD_REQUEST)
        users = User.objects.all()
        if role.lower() == "school":
            users = users.filter(role__name="school")
            response_data = [
                {
                    "name": f"{user.username}/{user.school.name if user.school else ''}/{user.school.school_code if user.school else ''}",
                    "id": str(user.id)
                }
                for user in users
            ]
        elif role.lower() == "student":
            student_filter = {"role__name":"student","student_profile__isnull":False,"school":school}
            if class_id:
                student_filter['student_profile__school_class'] = class_id
            if section_id:
                student_filter['student_profile__section'] = section_id
            if club_id:
                student_filter['student_profile__club'] = club_id
            if dormitory_id:
                student_filter['student_profile__dormitory'] = dormitory_id
            if dormitoryroom_id:
                student_filter['student_profile__dormitoryroom'] = dormitoryroom_id
            if house_id:
                student_filter['student_profile__house'] = house_id
            if enroll_no:
                student_filter['student_profile__enroll_no'] = enroll_no
            
            users = users.filter(**student_filter)
            response_data = [
                {
                    "name": f"{user.username}/{user.student_profile.name if user.student_profile.name else ''}/{user.student_profile.school_class.name if user.student_profile else ''}/{user.student_profile.section.name if user.student_profile and user.student_profile.section else ''}",
                    "id": str(user.id),
                    "role": "student"
                }
                for user in users
            ]
        
        elif role.lower() == "teacher":
            users = users.filter(role__name="teacher",teacher_profile__isnull=False,school=school)
            response_data = [
                {
                    "name": f"{user.username}/{user.teacher_profile.name if user.teacher_profile.name else ''}/{user.teacher_profile.department.name if user.teacher_profile.department.name else ''}",
                    "id": str(user.id),
                    "role": "Teacher"
                }
                for user in users
            ]

        elif role.lower() == "parent":
            users = users.filter(role__name="parent",parent_profile__isnull=False,school=school)
            response_data = [
                {
                    "name": f"{user.username}/{user.parent_profile.name if user.parent_profile.name else ''}/{user.parent_profile.mobile_no if user.parent_profile else ''}",
                    "id": str(user.id),
                    "role": "Parent"
                }
                for user in users
            ]
        else:
            users = users.filter(role__name=role.lower(),school=school)
            response_data = [
                {
                    "name": f"{user.username}/{user.name if user.name else ''}/{user.mobile_no if user else ''}",
                    "id": str(user.id),
                    "role": role.lower()
                }
                for user in users
            ]
        
            

        return Response(response_data, status=status.HTTP_200_OK)
        
class SearchByUserList(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_user")
        if error_response:
            return error_response
        search = request.query_params.get('search', None)
        if not search:
            return Response(
                {"message": "Search is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        search = search.strip()
        users = User.objects.filter(school=school).filter(
            Q(name__icontains=search) |
            Q(username__icontains=search) |
            Q(mobile_no__icontains=search) |
            Q(email__icontains=search)
        )
        page = self.paginate_queryset(users)
        if page is not None:
            response_data = [
                {
                    "name": f"{user.username}/{user.name or ''}/{user.mobile_no or ''}",
                    "id": str(user.id),
                }
                for user in page
            ]
            return self.get_paginated_response(response_data)

        response_data = [
            {
                "name": f"{user.username}/{user.name or ''}/{user.mobile_no or ''}",
                "id": str(user.id),
            }
            for user in users
        ]
        return Response(response_data, status=status.HTTP_200_OK)


class AppPermissionApi(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def get_object(self):
        return self.request.user
    def post(self, request, *args, **kwargs):
        user = self.get_object()
        user_id = kwargs.get('id')
        app_and_appitem_id = kwargs.get('app_id')
        if user.is_superuser or user.type == "admin":
            try:
                perm_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({"message": "User Not Found!"}, status=status.HTTP_404_NOT_FOUND)
            try:
                app = App.objects.get(id=app_and_appitem_id)
                if AppPermissions.objects.filter(user=perm_user, app=app).exists():
                    AppPermissions.objects.get(user=perm_user, app=app).delete()
                    return Response({'message': 'App Permissions disable successfully!'}, status=status.HTTP_200_OK)
                else:
                    AppPermissions.objects.create(user=perm_user, app=app)
                    return Response({'message': 'App Permissions enable successfully!'}, status=status.HTTP_200_OK)
            
            except App.DoesNotExist:
                try:
                    appitem = AppItem.objects.get(id=app_and_appitem_id)
                    if AppListPermission.objects.filter(user=perm_user, appitem=appitem).exists():
                        AppListPermission.objects.get(user=perm_user, appitem=appitem).delete()
                        return Response({'message': 'App item Permissions disable successfully!'}, status=status.HTTP_200_OK)
                    else:
                        AppListPermission.objects.create(user=perm_user, appitem=appitem)
                        return Response({'message': 'App item Permissions enable successfully!'}, status=status.HTTP_200_OK)
                except AppItem.DoesNotExist:
                    return Response({"message": "App or AppItem Not Found!"}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"message": "Unauthorized!"}, status=status.HTTP_401_UNAUTHORIZED)

    def get(self, request,*args, **kwargs):
        user = self.get_object()
        user_id = kwargs.get('user_id')
        if user.is_superuser and not user_id:
            app = App.objects.all()
            serializers = AppSerializer(app,many=True)
            return Response({'message': 'Hi, Admin, Permissions retrieved successfully!', 'data':serializers.data}, status=status.HTTP_200_OK)
        if user_id:
            try:
                perm_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({"message": "User Not Found!"}, status=status.HTTP_404_NOT_FOUND)
            apps = AppPermissions.objects.filter(user=perm_user).values_list('app', flat=True)
            app_queryset = App.objects.filter(id__in=apps).order_by("order")
            app_serializer = AppPermissionSerializer(app_queryset, many=True, context={'user': perm_user})
            return Response({'message': 'Permissions retrieved successfully!', 'data':app_serializer.data}, status=status.HTTP_200_OK)
        else:
            search_filter={}
            role_filter={}
            school,error_response = check_permission_and_get_school(request,"api_v1.view_app")
            if error_response:
                return error_response
            if user.role:
                role_name = user.role.name
                if role_name == "school":
                    search_filter['user'] = user
                else:
                    user_curr = User.objects.filter(school = user.school,role__name = "school").first() 
                    search_filter['user'] = user_curr
                    role_filter["role__contains"] = user.role.name
            apps = AppPermissions.objects.filter(**search_filter).values_list('app', flat=True)
            app_queryset = App.objects.filter(id__in=apps,**role_filter).order_by("order")
            app_serializer = AppPermissionSerializer(app_queryset, many=True, context={'user': user})
            return Response({'message': 'Permissions retrieved successfully!', 'data':app_serializer.data}, status=status.HTTP_200_OK)
class AppSidebarItemApi(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request,*args, **kwargs):
        user = request.user
        if user.role.name == "school":
            apps = AppPermissions.objects.filter(user=user,show_in_sidebar=True).order_by("order")
            app_item = AppListPermission.objects.filter(user=user,show_in_sidebar=True).order_by("order")
            app_serializer = AppPermissionSidebarSerializer(apps, many=True,)
            app_item_serializer = AppListPermissionSerializer(app_item, many=True,)
            return Response({'message': 'Permissions retrieved successfully!', 'data':{"app":app_serializer.data,"app_item":app_item_serializer.data}}, status=status.HTTP_200_OK)
        else:
            user_role = user.role.name
            if user_role == "student":
                user_profile = user.student_profile.school
            elif  user_role == "teacher":
                user_profile = user.teacher_profile.school
            elif  user_role == "parents":
                user_profile = user.parent_profile.school
            if not user_profile:
                return Response({"message": "User profile not found!"}, status=status.HTTP_404_NOT_FOUND)

        # Get users that belong to the same school
            try:
                prm_user = User.objects.get(school=user_profile)
                # prm_user = User.objects.filter(school =)
            except User.DoesNotExist:
                return Response({"message": "User Not Found!"}, status=status.HTTP_404_NOT_FOUND)

            apps = AppPermissions.objects.filter(user=prm_user).values_list('app', flat=True)
            app_queryset = App.objects.filter(id__in=apps,role__contains=[user_role]).order_by("order")
            app_serializer = AppPermissionRoleSerializer(app_queryset, many=True, context={'user': prm_user})
            return Response({'message': 'Permissions retrieved successfully!', 'data':app_serializer.data}, status=status.HTTP_200_OK)
#==============================================permissions list ======================================
class PermissionListView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_user_permissions(self, user):
        """Fetch user permissions including group and individual permissions."""
        group_permissions = (
            user.role.group.permissions.all()
            if user.role and user.role.group
            else []
        )
        user_permissions = user.user_permissions.all()
        return group_permissions | user_permissions

    def is_school_user_allowed(self, user_id, request_user):
        """Check if a school user is allowed to view or modify another user's permissions."""
        return user_id and user_id != request_user.id and request_user.school != request_user.school

    def get(self, request, *args, **kwargs):
        

        user_id = request.query_params.get("user_id")
        role_id = request.query_params.get("role_id")
        role_all = request.query_params.get("role_all")
        role = getattr(request.user, 'role', None)
        is_admin = request.user.is_superuser
        is_school = role and role.name.lower() == "school"

        # Fetch permissions based on role_id
        if role_id:
            try:
                target_role = Role.objects.get(id=role_id)
                if is_school and target_role.school != request.user.school:
                    return Response(
                        {"detail": "You are not authorized to view permissions for this role."},
                        status=status.HTTP_403_FORBIDDEN,
                    )
                all_permissions = target_role.group.permissions.all() if target_role.group else []
            except Role.DoesNotExist:
                return Response(
                    {"error": "Invalid role ID."},
                    status=status.HTTP_404_NOT_FOUND,
                )
        elif role_all:
            all_roles = Role.objects.filter(school=request.user.school)
            roles_permissions = []
            for role in all_roles:
                if is_school and role.school != request.user.school:
                    continue  # Skip roles that the user is not authorized to view
                permissions = role.group.permissions.all() if role.group else []
                
                # Group permissions by model
                grouped_permissions = {}
                for permission in permissions:
                    model_name = permission.content_type.model  # Get the model name
                    if model_name not in grouped_permissions:
                        grouped_permissions[model_name] = []  # Initialize list for the model
                    grouped_permissions[model_name].append({
                        "id": permission.id,
                        "name": permission.name,
                        "codename": permission.codename,
                    })
                
                roles_permissions.append({
                    "role_id": role.id,
                    "role_name": role.name,
                    "permissions": grouped_permissions,  # Use the grouped permissions
                })
            return Response(
                {"roles_permissions": roles_permissions},
                status=status.HTTP_200_OK,
            )
        elif is_admin:
            all_permissions = Permission.objects.all() if not user_id else self.get_user_permissions(User.objects.get(id=user_id))
        elif is_school:
            if user_id and self.is_school_user_allowed(int(user_id), request.user):
                return Response(
                    {"detail": "You are not authorized to view or modify other users' permissions."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            user = request.user if not user_id else User.objects.get(id=user_id)
            all_permissions = self.get_user_permissions(user)
        else:
            if user_id and int(user_id) != request.user.id:
                return Response(
                    {"detail": "You are not authorized to view other users' permissions."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            all_permissions = self.get_user_permissions(request.user)

        # Group permissions by model
        grouped_permissions = {}
        for permission in all_permissions:
            model_name = permission.content_type.model
            if model_name not in grouped_permissions:
                grouped_permissions[model_name] = []
            grouped_permissions[model_name].append(
                {"id": permission.id, "name": permission.name, "codename": permission.codename}
            )

        return Response(grouped_permissions, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_cart")
        if error_response:
            return error_response

        role = getattr(request.user, 'role', None)
        is_admin = request.user.is_superuser
        is_school = role and role.name.lower() == "school"

        if not is_admin and not is_school:
            return Response(
                {"detail": "You are not authorized to modify permissions."},
                status=status.HTTP_403_FORBIDDEN,
            )

        role_id = request.data.get("role_id")
        user_id = request.data.get("user_id")
        permission_ids = request.data.get("permissions", [])

        # Validate permissions
        permissions_qs = Permission.objects.filter(id__in=permission_ids)
        if not permissions_qs.exists():
            return Response(
                {"error": "No valid permissions found."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if role_id:
            # Assign permissions to a role
            try:
                role = Role.objects.get(id=role_id)
            except Role.DoesNotExist:
                return Response(
                    {"error": "Invalid role ID."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            if not role.group:
                return Response(
                    {"error": "Role does not have an associated group."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            group = role.group
            for permission in permissions_qs:
                if group.permissions.filter(id=permission.id).exists():
                    group.permissions.remove(permission)
                else:
                    group.permissions.add(permission)

            group.save()
            return Response(
                {"message": "Permissions updated for the role successfully."},
                status=status.HTTP_200_OK,
            )

        elif user_id:
            # Assign permissions to a user
            try:
                user = User.objects.get(id=user_id)
                if is_school and user.school != request.user.school:
                    return Response(
                        {"detail": "You are not authorized to modify other users' permission."},
                        status=status.HTTP_403_FORBIDDEN,
                    )
            except User.DoesNotExist:
                return Response(
                    {"error": "Invalid user ID."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            group_permissions = user.role.group.permissions.all() if user.role and user.role.group else []

            for permission in permissions_qs:
                if permission not in group_permissions and not user.user_permissions.filter(id=permission.id).exists():
                    user.user_permissions.add(permission)
                elif user.user_permissions.filter(id=permission.id).exists():
                    user.user_permissions.remove(permission)

            user.save()
            return Response(
                {"message": "Permissions toggled for the user successfully."},
                status=status.HTTP_200_OK,
            )

        return Response(
            {"error": "Either role_id or user_id must be provided."},
            status=status.HTTP_400_BAD_REQUEST,
        )
# ===========================================user permission==========================================

class UserPermissionsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    serializer_class = UserWithPermissionsSerializer

    def post(self, request, pk=None, *args, **kwargs):
        """
        Add permissions to a specific user (identified by pk).
        """
        if not request.user.is_authenticated:
            return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = UserPermissionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        permission_ids = request.data.get('ids' or [])

        if pk:
            try:
                user = User.objects.get(pk=pk)

                for perm_id in permission_ids:
                    try:
                        permission = Permission.objects.get(id=perm_id)
                        if user.user_permissions.filter(id=perm_id).exists():
                            # If the user already has this permission, remove it
                            user.user_permissions.remove(permission)
                        else:
                            # If the user does not have this permission, add it
                            user.user_permissions.add(permission)
                    except Permission.DoesNotExist:
                        return Response({"error": f"Permission '{perm_id}' does not exist."}, status=status.HTTP_400_BAD_REQUEST)

                user.save()
                return Response({"message": "User permissions updated successfully."}, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error": "User ID is required to update permissions."}, status=status.HTTP_400_BAD_REQUEST)


    def get(self, request, pk=None, *args, **kwargs):
        """
        Retrieve all users with permissions or a specific user's permissions.
        """
        if pk:
            try:
                user = User.objects.get(pk=pk)
                if not user.user_permissions.exists():
                    return Response({"message": "User has no additional permissions."}, status=status.HTTP_200_OK)
                
                serializer = self.serializer_class(user)
            except User.DoesNotExist:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            users_with_permissions = User.objects.filter(user_permissions__isnull=False).distinct()
            serializer = self.serializer_class(users_with_permissions, many=True)
            
        return Response(serializer.data, status=status.HTTP_200_OK)


    def delete(self, request, pk=None, *args, **kwargs):
        """
        Remove all permissions from a specific user.
        """
        if not request.user.is_authenticated:
            return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

        if pk:
            try:
                user = User.objects.get(pk=pk)
                user.user_permissions.clear()  
                return Response({"message": "All additional permissions removed successfully."}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error": "User ID is required to delete permissions."}, status=status.HTTP_400_BAD_REQUEST)


###################################  ROLE API  ###########################################################
class RoleAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = RoleSerializer
    pagination_class = CustomPagination 

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_role")
        if error_response:
            return error_response

        subject_filters = {'school': school}
        get_model = Role.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_role")
        if error_response:
            return error_response

        data = request.data
        data['school'] = school.id

        # Check for duplicate role name
        if Role.objects.filter(name=data.get('name'), school=school).exists():
            return Response(
                {"message": f"A role with the name '{data.get('name')}' already exists in this school."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Use transaction to ensure role and group are created atomically
        with transaction.atomic():
            serializer = self.serializer_class(data=data)
            if serializer.is_valid():
                role = serializer.save()

                # Use school_code as prefix for the group name
                group_name = f"{school.school_code}_{data.get('name')}"
                group, created = Group.objects.get_or_create(name=group_name)
                role.group = group  # Set the group's one-to-one relationship with role
                role.save()

                return Response({"message": "Role created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_role")
        if error_response:
            return error_response

        model_id = request.data.get('id', None)
        try:
            put_model = Role.objects.get(id=model_id)
        except Role.DoesNotExist:
            return Response({"message": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

        if put_model.name.lower() in {"admin", "school", "teacher", "student", "parent","vendor"}:
            return Response({"message": "This role cannot be updated."}, status=status.HTTP_403_FORBIDDEN)

        if put_model.school != school:
            return Response({"message": "You can only update roles for your own school."}, status=status.HTTP_403_FORBIDDEN)

        # Check for duplicate role name (excluding current role being updated)
        if Role.objects.filter(name=request.data.get('name'), school=school).exclude(id=put_model.id).exists():
            return Response(
                {"message": f"A role with the name '{request.data.get('name')}' already exists in this school."},
                status=status.HTTP_400_BAD_REQUEST
            )   

        # Use transaction to ensure role and group are updated atomically
        with transaction.atomic():
            serializer = self.serializer_class(put_model, data=request.data, partial=True)
            if serializer.is_valid():
                updated_role = serializer.save()

                # Use school_code as prefix for the group name
                group_name = f"{school.school_code}_{request.data.get('name')}"
                group, created = Group.objects.get_or_create(name=group_name)
                updated_role.group = group  # Ensure the role's group is set
                updated_role.save()

                return Response({"message": "Role updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_role")
        if error_response:
            return error_response

        role_ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not role_ids:
            return Response({"message": "Role list is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Use transaction to ensure role and group are deleted atomically
        with transaction.atomic():
            for role_id in role_ids:
                try:
                    delete_model = Role.objects.get(id=role_id)
                except Role.DoesNotExist:
                    return Response({"message": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

                if delete_model.name.lower() in {"admin", "school", "teacher", "student", "parent","vendor"}:
                    return Response({"message": f"Role '{delete_model.name}' cannot be deleted."}, status=status.HTTP_403_FORBIDDEN)

                if delete_model.school != school:
                    return Response({"message": "You can only delete roles for your own school."}, status=status.HTTP_403_FORBIDDEN)

                # Delete the group related to this role (if it exists)
                if delete_model.group:
                    delete_model.group.delete()

                # Delete the role
                delete_model.delete()

        return Response({"message": "Roles deleted successfully."}, status=status.HTTP_200_OK)
class RoleListAPIView(GenericAPIView):
    serializer_class = RolelistSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_role")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subject_filters['active']=True
        list_model = Role.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(list_model, many=True)
        return  Response({"message": "Role List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
    
 
 ############################  Teacher ###############################################
class TeacherAPIView(GenericAPIView):
    serializer_class = TeacherSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def post(self, request):
        user = request.user
        username = request.data.get('username')
        password = request.data.get('password')
        # Check user permissions
        if not (user.is_superuser or (user.role and user.role.name == "school")):
            return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
        if not username or not password:
            return Response({"message": "Username and password are required to create a user."}, status=status.HTTP_400_BAD_REQUEST)
        # Get school ID from query params
        school_id = request.query_params.get('school_id', None)

        # Determine the school based on user role
        if user.role and user.role.name == "school":
            school = user.school  # Automatically assign the user's school
            if school_id and school.id != school_id:
                return Response({"message": "You can only create classes for your own school."}, status=status.HTTP_403_FORBIDDEN)
        else:
            if not school_id:
                return Response({"message": "School is required."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                school = School.objects.get(id=school_id)
            except School.DoesNotExist:
                return Response({"message": "Invalid School"}, status=status.HTTP_404_NOT_FOUND)
        
        # Create the bank record first
        bank_serializer = BankSerializer(data=request.data)
        if bank_serializer.is_valid():
            createbank = bank_serializer.save()
        else:
            return Response({"message": "Invalid bank data", "errors": bank_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        # Prepare data for the teacher serializer
        data = request.data.copy()
        data['school'] = school.id  # Set the school
        data['bank'] = createbank.id

        serializer = self.serializer_class(data=data)
        role_instance = Role.objects.get(name="teacher")

        # Validate the serializer
        if serializer.is_valid():
            created_user = serializer.save()
            user = User.objects.create(username=username, password=make_password(password), teacher_profile=created_user, role=role_instance)
            user_serializer = UserSerializer(user)

            return Response({
                "message": "Teacher created successfully!",
                "data": {
                    "profile": serializer.data,
                    "user": user_serializer.data
                }
            }, status=status.HTTP_201_CREATED)

        # If serializer is invalid, return the errors
        error_messages = "; ".join([f"{key}: {', '.join(value)}" for key, value in serializer.errors.items()])
        return Response({"message": error_messages}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        user = request.user
        if user.is_superuser or (user.role and user.role.name == "school"):
            class_id = request.data.get('id', None)
            try:
                school_class = SchoolClass.objects.get(id=class_id)
            except SchoolClass.DoesNotExist:
                return Response({"message": "Class not found"}, status=status.HTTP_404_NOT_FOUND)
            if user.role and user.role.name == "school":
                if school_class.school != user.school:
                    return Response({"message": "You can only update classes for your own school."}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.serializer_class(school_class, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "School class updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
    def delete(self, request, *args, **kwargs):
        user = request.user
        class_ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not class_ids:
            return Response({"message": "Class list is required"}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_superuser or (user.role and user.role.name == "school"):
            for class_id in class_ids:
                try:
                    session = SchoolClass.objects.get(id=class_id)
                except SchoolClass.DoesNotExist:
                    return Response({"message": "Class not found"}, status=status.HTTP_404_NOT_FOUND)
                if (user.role and user.role.name == "school") and session.school != user.school:
                    return Response({"message": "You can only delete Class for your own school."}, status=status.HTTP_403_FORBIDDEN)
                session.delete()

            return Response({"message": "Class deleted successfully"}, status=status.HTTP_200_OK)

        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)   
############################  School Class ###############################################
class SchoolClassAPIView(GenericAPIView):
    serializer_class = SchoolClassSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_schoolclass")
        if error_response:
            return error_response
        if request.query_params.get('Export'):
            return generate_model_fields_excel('User', app_label='api_v1')
        school_classes = SchoolClass.objects.filter(school=school).order_by('-created_at')
        if request.query_params.get('filter_fields'):
            filter_dict = request.query_params.get('filter_fields', '{}')
            try:
                filter_dict = json.loads(filter_dict)
            except json.JSONDecodeError:
                return Response({"error": "Invalid JSON format in 'filter_fields' parameter."}, status=status.HTTP_400_BAD_REQUEST)
            filtered_queryset = filter_model_data(school_classes, filter_dict)
            if isinstance(filtered_queryset, dict) and 'error' in filtered_queryset:
                return Response(filtered_queryset, status=status.HTTP_400_BAD_REQUEST)
            school_classes = filtered_queryset
        page = self.paginate_queryset(school_classes)
        if page is not None:
            serializer = SchoolClassGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = SchoolClassGetSerializer(school_classes, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_schoolclass")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id 
        class_name = data.get('name')
        series = data.get('series')
        exists, conflict_response = check_if_exists(SchoolClass, name=class_name,school=school)
        if conflict_response:
            return conflict_response
        if series:
            exists, conflict_response = check_if_exists(SchoolClass, series=series,school=school)
            if conflict_response:
                return conflict_response
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Class created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_schoolclass")
        if error_response:
            return error_response
        class_id = request.data.get('id', None)
        try:
            school_class = SchoolClass.objects.get(id=class_id)
        except SchoolClass.DoesNotExist:
            return Response({"message": "Class not found"}, status=status.HTTP_404_NOT_FOUND)
        if school_class.school != school:
            return Response({"message": "You can only update class for your own school."}, status=status.HTTP_403_FORBIDDEN)
        class_name = request.data.get('name')
        series = request.data.get('series')

        if class_name and class_name != school_class.name:
            exists, conflict_response = check_if_exists(SchoolClass, name=class_name, school=school)
            if conflict_response:
                return conflict_response
        if series and series != school_class.series:
            exists, conflict_response = check_if_exists(SchoolClass, series=series,school=school)
            if conflict_response:
                return conflict_response
        serializer = self.serializer_class(school_class, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "School class updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_schoolclass")
        if error_response:
            return error_response
        class_ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not class_ids:
            return Response({"message": "Class list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for class_id in class_ids:
            try:
                delete_model = SchoolClass.objects.get(id=class_id)
            except SchoolClass.DoesNotExist:
                return Response({"message": "Class not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update class for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Class deleted successfully"}, status=status.HTTP_200_OK)

# =========================================school list api========================================
class SchoolListAPIView(GenericAPIView):
    serializer_class = SchoolListSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        if user.is_superuser:
            school = School.objects.all().order_by('-created_at')
            serializer = self.serializer_class(school, many=True)
            return  Response({"message": "School List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)  
#   ============================get class list=============================
class SchoolClassListAPIView(GenericAPIView):
    serializer_class = SchoolClassListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_schoolclass")
        if error_response:
            return error_response
        filters = {'school': school}
        filters['active']=True
        school_classes = SchoolClass.objects.filter(**filters).order_by('-created_at')
        serializer = self.serializer_class(school_classes, many=True)
        return  Response({"message": "Class List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
 

###################################  Section  API  ###########################################################
class SectionAPIView(GenericAPIView):
    serializer_class = SectionSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_section")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        class_id = request.query_params.get('class_id', None)
        if class_id:
            sh_class = get_object_or_404(SchoolClass, id=class_id)
            subject_filters['school_class'] = sh_class
        sections = Section.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(sections)
        serializer = SectionGetSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_schoolclass")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id 
        section_name = data.get('name')
        section_class = data.get('school_class')
        exists, conflict_response = check_if_exists(Section, name=section_name,school_class=section_class,school=school)
        if conflict_response:
            return conflict_response
        data = request.data.copy()
        data['school'] = school.id  # Set the school
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Section created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_section")
        if error_response:
            return error_response
        section_id = request.data.get('id', None)
        try:
            section = Section.objects.get(id=section_id)
        except Section.DoesNotExist:
            return Response({"message": "section not found"}, status=status.HTTP_404_NOT_FOUND)
        section_name = request.data.get('name')
        section_class = request.data.get('school_class')
        if section_name and section_class and section_name != section.name and section_class != section.school_class:
            exists, conflict_response = check_if_exists(Section, name=section_name,school_class=section_class,school=school)
            if conflict_response:
                return conflict_response
        if section.school != school:
            return Response({"message": "You can only update section for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(section, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Section updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_section")
        if error_response:
            return error_response
        section_ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not section_ids:
            return Response({"message": "Section list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for section_id in section_ids:
            try:
                section = Section.objects.get(id=section_id)
            except Section.DoesNotExist:
                return Response({"message": "Section not found"}, status=status.HTTP_404_NOT_FOUND)
            if section.school != school:
                return Response({"message": "You can only update Section for your own school."}, status=status.HTTP_403_FORBIDDEN)
            section.delete()
        return Response({"message": "Section deleted successfully"}, status=status.HTTP_200_OK)
  #   ============================get section list=============================
class SectionListAPIView(GenericAPIView):
    serializer_class = SectionListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_section")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subject_filters['active']=True
        class_id = request.query_params.get('class_id', None)
        if not class_id:
            return Response({"message": "Class is required"}, status=status.HTTP_400_BAD_REQUEST)
        subject_filters['school_class__id'] = class_id
        sections = Section.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(sections, many=True)
        return Response({"message": "Section list retrieved successfully", "data": serializer.data}, status=status.HTTP_200_OK)
# =====================================================AcademicSession api===================================
class AcademicSessionAPIView(GenericAPIView):
    serializer_class = AcademicSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        user = request.user
        if user.is_superuser or (user.role and user.role.name == "school"):
            school_id = request.query_params.get('school_id', None)
            if user.role and user.role.name == "school":
                if school_id and user.school.school_id != school_id:
                    return Response({"message": "You can only access your own school data."}, status=status.HTTP_403_FORBIDDEN)
                school = user.school  
            else:
                if not school_id:
                    return Response({"message": "School is required"}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    school = School.objects.get(id=school_id)
                except School.DoesNotExist:
                    return Response({"message": "Invalid school_code"}, status=status.HTTP_404_NOT_FOUND)
            school_classes = AcademicSession.objects.filter(school=school).order_by('-created_at')
            page = self.paginate_queryset(school_classes)
            serializer = self.serializer_class(page, many=True)
            response = self.get_paginated_response(serializer.data)
            return response
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
    def post(self, request):
        user = request.user
        if user.is_superuser or (user.role and user.role.name == "school"):
            school_id = request.query_params.get('school_id', None)
            if user.role and user.role.name == "school":
                if school_id and user.school.school_id != school_id:
                    return Response({"message": "You can only create classes for your own school."}, status=status.HTTP_403_FORBIDDEN)
                school = user.school  # Automatically assign the user's school
            else:
                if not school_id:
                    return Response({"message": "school is required"}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    school = School.objects.get(id=school_id)
                except School.DoesNotExist:
                    return Response({"message": "Invalid School"}, status=status.HTTP_404_NOT_FOUND)
            data = request.data.copy()
            data['school'] = school.id  # Set the school
            serializer = self.serializer_class(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Academic Session created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Permission Denied"}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        user = request.user
        if user.is_superuser or (user.role and user.role.name == "school"):
            session_id = request.data.get('id', None)
            try:
                session = AcademicSession.objects.get(id=session_id)
            except AcademicSession.DoesNotExist:
                return Response({"message": "Session not found"}, status=status.HTTP_404_NOT_FOUND)
            if user.role and user.role.name == "school":
                if session.school != user.school:
                    return Response({"message": "You can only update session for your own school."}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.serializer_class(session, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Session updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
    def delete(self, request, *args, **kwargs):
        user = request.user
        session_ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not session_ids:
            return Response({"message": "Session list is required"}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_superuser or (user.role and user.role.name == "school"):
            for session_id in session_ids:
                try:
                    session = AcademicSession.objects.get(id=session_id)
                except AcademicSession.DoesNotExist:
                    return Response({"message": "Session not found"}, status=status.HTTP_404_NOT_FOUND)
                if (user.role and user.role.name == "school") and session.school != user.school:
                    return Response({"message": "You can only delete Session for your own school."}, status=status.HTTP_403_FORBIDDEN)
                session.delete()

            return Response({"message": "Session deleted successfully"}, status=status.HTTP_200_OK)

        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
class AcedemicSessionListAPIView(GenericAPIView):
    serializer_class = AcademicSessionListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_academicsession")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        ac_session = AcademicSession.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(ac_session, many=True)
        return  Response({"message": "Session List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  




######################################  House API  ##########################################################
class HouseAPIView(GenericAPIView):
    serializer_class = HouseSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_house")
        if error_response:
            return error_response
        house = House.objects.filter(school=school).order_by('-created_at')
        page = self.paginate_queryset(house)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(house, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_house")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id  # Set the school
        class_name = data.get('name')
        house_code = data.get('house_code')
        exists, conflict_response = check_if_exists(House, name=class_name,school=school)
        if conflict_response:
            return conflict_response
        if house_code:
            exists, conflict_response = check_if_exists(House, house_code=house_code,school=school)
            if conflict_response:
                return conflict_response
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "House created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_house")
        if error_response:
            return error_response
        house_id = request.data.get('id', None)
        try:
            house = House.objects.get(id=house_id)
        except House.DoesNotExist:
            return Response({"message": "House not found"}, status=status.HTTP_404_NOT_FOUND)
        class_name = request.data.get('name')
        house_code = request.data.get('house_code')
        if class_name and class_name != house.name:
            exists, conflict_response = check_if_exists(House, name=class_name, school=school)
            if conflict_response:
                return conflict_response
        if house_code and house_code != house.house_code:
            exists, conflict_response = check_if_exists(House, house_code=house_code,school=school)
            if conflict_response:
                return conflict_response
        
        if house.school != school:
            return Response({"message": "You can only update house for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(house, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "School house updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_house")
        if error_response:
            return error_response
        house_ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not house_ids:
            return Response({"message": "House list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for class_id in house_ids:
            try:
                house = House.objects.get(id=class_id)
            except House.DoesNotExist:
                return Response({"message": "House not found"}, status=status.HTTP_404_NOT_FOUND)
            if house.school != school:
                return Response({"message": "You can only update House for your own school."}, status=status.HTTP_403_FORBIDDEN)
            house.delete()
        return Response({"message": "House deleted successfully"}, status=status.HTTP_200_OK)
class HouseListAPIView(GenericAPIView):
    serializer_class = HouseListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_house")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subject_filters['active']=True
        house = House.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(house, many=True)
        return  Response({"message": "House List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  

############################  Department  ###############################################
class DepartmentAPIView(GenericAPIView):
    serializer_class = DepartmentSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        user = request.user
        if user.is_superuser or (user.role and user.role.name == "school"):
            school_id = request.query_params.get('school_id', None)
            if user.role and user.role.name == "school":
                if school_id and user.school.school_id != school_id:
                    return Response({"message": "You can only access your own school data."}, status=status.HTTP_403_FORBIDDEN)
                school = user.school  
            else:
                if not school_id:
                    return Response({"message": "School is required"}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    school = School.objects.get(id=school_id)
                except School.DoesNotExist:
                    return Response({"message": "Invalid school_code"}, status=status.HTTP_404_NOT_FOUND)
            department = Department.objects.filter(school=school).order_by('-created_at')
            page = self.paginate_queryset(department)
            serializer = self.serializer_class(page, many=True)
            response = self.get_paginated_response(serializer.data)
            return response
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
    def post(self, request):
        user = request.user
        if user.is_superuser or (user.role and user.role.name == "school"):
            school_id = request.query_params.get('school_id', None)
            if user.role and user.role.name == "school":
                if school_id and user.school.id != school_id:
                    return Response({"message": "You can only create department for your own school."}, status=status.HTTP_403_FORBIDDEN)
                school = user.school  # Automatically assign the user's school
            else:
                if not school_id:
                    return Response({"message": "school is required"}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    school = School.objects.get(id=school_id)
                except School.DoesNotExist:
                    return Response({"message": "Invalid School"}, status=status.HTTP_404_NOT_FOUND)
            data = request.data.copy()
            data['school'] = school.id  # Set the school
            serializer = self.serializer_class(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Department created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Permission Denied"}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        user = request.user
        if user.is_superuser or (user.role and user.role.name == "school"):
            department_id = request.data.get('id', None)
            try:
                department = Department.objects.get(id=department_id)
            except Department.DoesNotExist:
                return Response({"message": "Department not found"}, status=status.HTTP_404_NOT_FOUND)
            if user.role and user.role.name == "school":
                if department.school != user.school:
                    return Response({"message": "You can only update department for your own school."}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.serializer_class(department, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Department updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
    def delete(self, request, *args, **kwargs):
        user = request.user
        department_id = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not department_id:
            return Response({"message": "Class list is required"}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_superuser or (user.role and user.role.name == "school"):
            for department_id in department_id:
                try:
                    department = Department.objects.get(id=department_id)
                except Department.DoesNotExist:
                    return Response({"message": "Class not found"}, status=status.HTTP_404_NOT_FOUND)
                if (user.role and user.role.name == "school") and department.school != user.school:
                    return Response({"message": "You can only delete department for your own school."}, status=status.HTTP_403_FORBIDDEN)
                department.delete()

            return Response({"message": "Department deleted successfully"}, status=status.HTTP_200_OK)

        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
class DepartmentListAPIView(GenericAPIView):
    serializer_class = DepartmentListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        user = request.user
        if user.is_superuser or (user.role and user.role.name == "school"):
            school_id = request.query_params.get('school_id', None)
            if user.role and user.role.name == "school":
                if school_id and user.school.school_id != school_id:
                    return Response({"message": "You can only access your own school data."}, status=status.HTTP_403_FORBIDDEN)
                school = user.school  
            else:
                if not school_id:
                    return Response({"message": "School is required"}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    school = School.objects.get(id=school_id)
                except School.DoesNotExist:
                    return Response({"message": "Invalid school_code"}, status=status.HTTP_404_NOT_FOUND)
            department = Department.objects.filter(school=school).order_by('-created_at')
            serializer = self.serializer_class(department, many=True)
            return  Response({"message": "Department List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)  


###################################  Designation  API  ###########################################################
class DesignationAPIView(GenericAPIView):
    serializer_class = DesignationSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get_school_and_class(self, request):
        user = request.user
        school_id = request.query_params.get('school_id', None)
        department_id = request.query_params.get('department_id', None)
        
        if  not department_id:
            return None, None, Response({"message": "Despartment are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if user.role and user.role.name == "school":
            if school_id and user.school.id != int(school_id):
                return None, None, Response({"message": "You can only access your own school data."}, status=status.HTTP_403_FORBIDDEN)
            return user.school, department_id, None  # Automatically assign the user's school
        if  not school_id:
            return None, None, Response({"message": "School are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            school = School.objects.get(id=school_id)
        except School.DoesNotExist:
            return None, None, Response({"message": "Invalid School"}, status=status.HTTP_404_NOT_FOUND)
        try:
            department = Department.objects.get(id=department_id)
        except Department.DoesNotExist:
            return Response({"message": "Invalid Department"}, 
                            status=status.HTTP_404_NOT_FOUND)
        return school, department, None
    def get(self, request):
        school, department, error_response = self.get_school_and_class(request)
        if error_response:
            return error_response
        sections = Designation.objects.filter(school=school,department=department).order_by('-created_at')
        page = self.paginate_queryset(sections)
        serializer = DesignationGetSerializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    def post(self, request):
        user = request.user
        if user.is_superuser or (user.role and user.role.name == "school"):
            school_id = request.query_params.get('school_id', None)
            department_id = request.data.get('department_id', None)
            try:
                uuid.UUID(str(department_id)) 
            except ValueError:
                return Response({"message": "Invalid Department ID."}, status=status.HTTP_401_UNAUTHORIZED)
            if user.role and user.role.name == "school":
                if school_id and user.school.id != school_id:
                    return Response({"message": "You can only create designation for your own school."}, status=status.HTTP_403_FORBIDDEN)
                school = user.school  # Automatically assign the user's school
            else:
                if not school_id and not department_id:
                    return Response({"message": "school and Despartment is required"}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    school = School.objects.get(id=school_id)
                except School.DoesNotExist:
                    return Response({"message": "Invalid School"}, 
                                    status=status.HTTP_404_NOT_FOUND)
            try:
                department = Department.objects.get(id=department_id)
            except Department.DoesNotExist:
                return Response({"message": "Invalid Department"}, 
                                status=status.HTTP_404_NOT_FOUND)
            data = request.data.copy()
            data['school'] = school.id 
            data['department'] = department.id
            serializer = self.serializer_class(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Designation created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Permission Denied"}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        user = request.user
        if user.is_superuser or (user.role and user.role.name == "school"):
            section_id = request.data.get('id', None)
            try:
                designation = Designation.objects.get(id=section_id)
            except Designation.DoesNotExist:
                return Response({"message": "Designation not found"}, status=status.HTTP_404_NOT_FOUND)
            if user.role and user.role.name == "school":
                if designation.school != user.school:
                    return Response({"message": "You can only update designation for your own school."}, status=status.HTTP_403_FORBIDDEN)
            serializer = self.serializer_class(designation, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Designation updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        user = request.user
        designation_ids = request.data.get('ids', []) 
        if not designation_ids:
            return Response({"message": "designation list is required"}, status=status.HTTP_400_BAD_REQUEST)
        if user.is_superuser or (user.role and user.role.name == "school"):
            for designation_id in designation_ids:
                try:
                    designation = Designation.objects.get(id=designation_id)
                except Designation.DoesNotExist:
                    return Response({"message": "Designation not found"}, status=status.HTTP_404_NOT_FOUND)
                if (user.role and user.role.name == "school") and designation.school != user.school:
                    return Response({"message": "You can only delete designation for your own school."}, status=status.HTTP_403_FORBIDDEN)
                designation.delete()
            return Response({"message": "Designation deleted successfully"}, status=status.HTTP_200_OK)
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)

class DesignationListAPIView(GenericAPIView):
    serializer_class = DesignationListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        user = request.user
        if user.is_superuser or user.role:
            school_id = request.query_params.get('school_id', None)
            department_id = request.query_params.get('department_id', None)
            if user.role:
                if school_id and user.school.school_id != school_id:
                    return Response({"message": "You can only access your own school data."}, status=status.HTTP_403_FORBIDDEN)
                school = user.school 
                try:
                    uuid.UUID(str(department_id)) 
                except ValueError:
                    return Response({"message": "Invalid department_id."}, status=status.HTTP_401_UNAUTHORIZED) 
            else:
                if not school_id and not department_id:
                    return Response({"message": "school and department is required"}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    school = School.objects.get(id=school_id)
                except School.DoesNotExist:
                    return Response({"message": "Invalid School"}, status=status.HTTP_404_NOT_FOUND)
            try:
                department = Department.objects.get(id=department_id)
            except Department.DoesNotExist:
                return Response({"message": "Invalid Department"}, 
                                status=status.HTTP_404_NOT_FOUND)
            designations = Designation.objects.filter(school=school,department=department).order_by('-created_at')
            serializer = self.serializer_class(designations, many=True)
            return  Response({"message": "Designations List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
        return Response({"message": "Permission Denied"}, status=status.HTTP_403_FORBIDDEN)
    


# =========================================subject============================================
class SubjectAPIView(GenericAPIView):
    serializer_class = SubjectSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        class_id = request.query_params.get('class_id', None)
        school,error_response = check_permission_and_get_school(request,"api_v1.view_subject")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        if class_id:
            sh_class = get_object_or_404(SchoolClass, id=class_id)
            subject_filters['school_class'] = sh_class
        subjects = Subject.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(subjects)
        if page is not None:
            serializer = SubjectGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = SubjectGetSerializer(subjects, many=True)
        return Response(serializer.data)

    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_subject")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id  # Set the school
        subject_code = data.get('subject_code')
        if subject_code:
            exists, conflict_response = check_if_exists(Subject, subject_code=subject_code,school=school)
            if conflict_response:
                return conflict_response
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Subject created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_subject")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = Subject.objects.get(id=model_id)
        except Subject.DoesNotExist:
            return Response({"message": "Subject not found"}, status=status.HTTP_404_NOT_FOUND)
        class_name = request.data.get('name')
        subject_code = request.data.get('subject_code')

        if class_name and class_name != put_model.name:
            exists, conflict_response = check_if_exists(Subject, name=class_name, school=school)
            if conflict_response:
                return conflict_response
        if subject_code and subject_code != put_model.subject_code:
            exists, conflict_response = check_if_exists(Subject, series=series,school=school)
            if conflict_response:
                return conflict_response
        if put_model.school != school:
            return Response({"message": "You can only update Subject for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Subject updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_subject")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Subject list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = Subject.objects.get(id=id)
            except Subject.DoesNotExist:
                return Response({"message": "Subject not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Subject for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Subject deleted successfully"}, status=status.HTTP_200_OK)
class SubjectListAPIView(GenericAPIView):
    serializer_class = SubjectListSerializer
    def get(self, request):
        class_id = request.query_params.get('class_id', None)
        school,error_response = check_permission_and_get_school(request,"api_v1.view_subject")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subject_filters["active"]=True
        if not class_id:
            return Response({"message":"Class is required"}, status=status.HTTP_404_NOT_FOUND)

        sh_class = get_object_or_404(SchoolClass, id=class_id)
        subject_filters['school_class'] = sh_class
        subjects = Subject.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(subjects, many=True)
        return  Response({"message": "Subject List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
    

# ==============================leave=======================================
class LeaveAPIView(GenericAPIView):
    serializer_class = LeaveSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
  
    def get(self, request):
        user = request.user
        subject_filters={}
        if user.is_superuser or user.role and user.role.name == "school":
            school,error_response = check_permission_and_get_school(request,"api_v1.view_leaves")
            if error_response:
                return error_response
            subject_filters['school'] = school
            user_id = request.query_params.get('user_id', None)
            if user_id:
                user_get = get_object_or_404(User, id=user_id)
                subject_filters['sender'] = user_get
        else:
            subject_filters['sender'] = request.user 
        leave_type = request.query_params.get('type', None)
        if leave_type:
            subject_filters['type'] = leave_type          
        subjects = Leaves.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(subjects)
        if page is not None:
            serializer = LeaveGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = LeaveGetSerializer(subjects, many=True)
        return Response(serializer.data)

    def post(self, request):
        data = request.data.copy()
        school,error_response = check_permission_and_get_school(request,"api_v1.add_leaves")
        if error_response:
            return error_response
        data['school'] = school.id 
        data['sender'] = request.user.id
        data['reciever'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Leave Apply successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        user = request.user
        school, error_response = check_permission_and_get_school(request, "api_v1.change_leaves")
        if error_response:
            return error_response
        leave_id = request.data.get('id', None)
        if not leave_id:
            return Response({"message": "Leave ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            leave = Leaves.objects.get(id=leave_id)
        except Leaves.DoesNotExist:
            return Response({"message": "Leave not found"}, status=status.HTTP_404_NOT_FOUND)
        if leave.school != school:
            return Response({"message": "You can only update leaves for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(leave, data=request.data, partial=True)
        if serializer.is_valid():
            status_up = request.data.get('status', None)
            remark = request.data.get('remark', None)
            if status_up is not None:
                serializer.status = status_up
                serializer.status_updated_by = user
                serializer.status_updated_dateandtime = timezone.now()
            if remark is not None:
                serializer.remark = remark
            serializer.save()
            return Response({"message": "Leave status updated successfully", "data": self.serializer_class(leave).data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        user = request.user
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_leaves")
        if error_response:
            return error_response
        leaves_ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not leaves_ids:
            return Response({"message": "Leave list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for leave_id in leaves_ids:
            try:
                subject = Leaves.objects.get(id=leave_id)
            except Leaves.DoesNotExist:
                return Response({"message": "Leave not found"}, status=status.HTTP_404_NOT_FOUND)
            if (user.role and user.role.name == "school") and subject.school != school:
                return Response({"message": "You can only delete Leaves for your own school."}, status=status.HTTP_403_FORBIDDEN)
            subject.delete()
        return Response({"message": "Leaves deleted successfully"}, status=status.HTTP_200_OK)

# ======================================noticeboard========================
class NoticeBoardAPIView(GenericAPIView):
    serializer_class = NoticeBoardSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_noticeboard")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        noticeboard = NoticeBoard.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(noticeboard)
        serializer = self.serializer_class(page, many=True)
        response = self.get_paginated_response(serializer.data)
        return response
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_noticeboard")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            notice_board_instance = serializer.save()  # Save the instance
            subject = f"New Notice: {notice_board_instance.title}"
            message = notice_board_instance.message
            users = User.objects.filter(school=school)
            recipient_emails = [user.email for user in users if user.email]  # Collect emails, ensuring they're not None
            for recipient_email in recipient_emails:
                if notice_board_instance.attach:
                    send_via_email(subject, message, recipient_email, notice_board_instance.attach)
                else:
                    send_via_email(subject, message, recipient_email)
            return Response({"message": "Noticeboard created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_noticeboard")
        if error_response:
            return error_response
        notice_id = request.data.get('id', None)
        try:
            notice_board = NoticeBoard.objects.get(id=notice_id)
        except NoticeBoard.DoesNotExist:
            return Response({"message": "NoticeBoard not found"}, status=status.HTTP_404_NOT_FOUND)
        if notice_board.school != school:
            return Response({"message": "You can only update Noticeboard for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(notice_board, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "NoticeBoard updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_noticeboard")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Noticeboard list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = NoticeBoard.objects.get(id=id)
            except NoticeBoard.DoesNotExist:
                return Response({"message": "Noticeboard not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Noticeboard for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Noticeboard deleted successfully"}, status=status.HTTP_200_OK)

# ======================================Syllabus========================
class SyllabusAPIView(GenericAPIView):
    serializer_class = SyllabusSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def check_admin_and_school(self, request):
        user = request.user
        school_id = request.query_params.get('school_id', None)
        if user.is_superuser:
            if not school_id:
                return None, Response({"message": "School ID is required"}, status=status.HTTP_400_BAD_REQUEST)
            try:
                school = School.objects.get(id=school_id)
            except School.DoesNotExist:
                 return None,  Response({"message": "Invalid school ID"}, status=status.HTTP_404_NOT_FOUND)
        elif user.role and user.role.name == "school":
            school = user.school
        else: 
            return None, Response({"message": "You do not have permission to access this data."}, status=status.HTTP_403_FORBIDDEN)

        return school,None
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_syllabus")
        if error_response:
            return error_response
        subject_id = request.query_params.get('subject_id', None)
        if subject_id:
            subject = get_object_or_404(Subject, id=subject_id)
            syllabus = Syllabus.objects.filter(subject=subject).order_by('-created_at')
        else:
            syllabus = Syllabus.objects.filter(school=school).order_by('-created_at')
        page = self.paginate_queryset(syllabus)
        serializer = SyllabusGetSerializer(page, many=True)
        response = self.get_paginated_response(serializer.data)
        return response
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_syllabus")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()  # Save the instance
            return Response({"message": "Syllabus created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_syllabus")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = Syllabus.objects.get(id=model_id)
        except Syllabus.DoesNotExist:
            return Response({"message": "Syllabus not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Syllabus for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Syllabus updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_syllabus")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Syllabus list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = Syllabus.objects.get(id=id)
            except Syllabus.DoesNotExist:
                return Response({"message": "Syllabus not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Syllabus for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Syllabus deleted successfully"}, status=status.HTTP_200_OK)

# ======================================student enquiry===========================
class StudentEnquiryAPIView(GenericAPIView):
    serializer_class = StudentEnquirySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_studentenquiry")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        enquiry_no = request.query_params.get('enquiry_no', None)
        if enquiry_no:
            subject_filters['enquiry_no__contain'] = enquiry_no
        get_model = StudentEnquiry.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = StudentEnquiryGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = StudentEnquiryGetSerializer(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_studentenquiry")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        if "name" in data:
            data["enquiry_no"] = generate_username(data["name"], prefix="Enq_")
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Student Enquiry Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_studentenquiry")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = StudentEnquiry.objects.get(id=model_id)
        except StudentEnquiry.DoesNotExist:
            return Response({"message": "Student Enquiry not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Student Enquiry for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Student Enquiry updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_studentenquiry")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Student Enquiry list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = StudentEnquiry.objects.get(id=id)
            except StudentEnquiry.DoesNotExist:
                return Response({"message": "Student Enquiry not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Student Enquiry for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Student Enquiry deleted successfully"}, status=status.HTTP_200_OK)
class StudentEnquiryListAPIView(GenericAPIView):
    serializer_class = StudentEnquiryListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_studentenquiry")
        if error_response:
            return error_response
        subject_filters = {'school': school,'status': "Closed"}
        enquiry_no = request.query_params.get('enquiry_no', None)
        if enquiry_no:
            subject_filters['enquiry_no'] = enquiry_no
        list_model = StudentEnquiry.objects.filter(**subject_filters).order_by('-created_at')
        response_data = [
            {    
                "name": f"{res.name}/{res.enquiry_no}",  # Concatenate values
                "id": str(res.id)  # Convert UUID to string if needed
            }
            for res in list_model
        ]
        return  Response({"message": "Student Enquiry List retrieved successfully","data":response_data}, status=status.HTTP_200_OK)  
class StudentEnquiryByIdAPIView(GenericAPIView):
    serializer_class = StudentEnquiryGetSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_studentenquiry")
        if error_response:
            return error_response
        res_id = request.query_params.get('id', None)
        if not res_id:
            return Response({'message': "Id is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            role_instance = StudentEnquiry.objects.get(id=res_id)
        except StudentEnquiry.DoesNotExist:
            return Response({"message": "Student Enquiry not Found"}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(role_instance)
        return Response(serializer.data)
        
class ExamListAPIView(GenericAPIView):
    serializer_class = ExamSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_exam")
        if error_response:
            return error_response
        search_filter = {'school': school}
        search_filter['active'] = True
        list_model = Exam.objects.filter(**search_filter).order_by('-created_at')
        response_data = [
            {    
                "school_class":str(exam.school_class.id),
                "section":str(exam.section.id),
                "name": f"{exam.examtype.name}/{exam.mode}/{exam.center}/{exam.school_class.name}/{exam.section.name}",  # Concatenate values
                "id": str(exam.id)  # Convert UUID to string if needed
            }
            for exam in list_model
        ]

        return Response({"message": "Exam List retrieved successfully", "data": response_data}, status=status.HTTP_200_OK)
# ====================================================student===========================================
class StudentNewAPIView(GenericAPIView):
    serializer_class = StudentSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_student")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        club_id = request.query_params.get('club_id', None)
        class_id = request.query_params.get('class_id', None)
        session_id = request.query_params.get('session_id', None)
        section_id = request.query_params.get('section_id', None)
        dormitory_id = request.query_params.get('dormitory_id', None)
        category = request.query_params.get('category', None)
        dormitoryroom_id = request.query_params.get('dormitoryroom_id', None)
        house_id = request.query_params.get('house_id', None)
        student_category_id = request.query_params.get('student_category_id', None)
        enroll_no = request.query_params.get('enroll_no', None)
        if club_id:
            club = get_object_or_404(Club, id=club_id)
            subject_filters['club'] = club
        if class_id:
            sh_class = get_object_or_404(SchoolClass, id=class_id)
            subject_filters['school_class'] = sh_class
        if session_id:
            session = get_object_or_404(AcademicSession, id=session_id)
            subject_filters['session'] = session
        if section_id:
            section = get_object_or_404(Section, id=section_id)
            subject_filters['section'] = section
        if dormitory_id:
            dormitory = get_object_or_404(Dormitory, id=dormitory_id)
            subject_filters['dormitory'] = dormitory
        if dormitoryroom_id:
            dormitoryroom = get_object_or_404(DormitoryRoom, id=dormitoryroom_id)
            subject_filters['dormitoryroom'] = dormitoryroom
        if house_id:
            house = get_object_or_404(House, id=house_id)
            subject_filters['house'] = house
        if student_category_id:
            student_category = get_object_or_404(Student_Category, id=student_category_id)
            subject_filters['student_category'] = student_category
        if enroll_no:
            subject_filters['enroll_no'] = enroll_no
        if category:
            subject_filters['category'] = category
        # try:
        #     role_instance = Role.objects.get(name='student')
        # except Role.DoesNotExist:
        #     return Response({"message": "Role not Found"}, status=status.HTTP_400_BAD_REQUEST)
        # subject_filters = {'role': role_instance}
        students = Student.objects.filter(**subject_filters)
        get_model = User.objects.filter(student_profile__in=students).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = StudentGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = StudentGetSerializer(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_student")
        if error_response:
            return error_response
        role_student, role_created = Role.objects.get_or_create(
            name='student',
            school=school,
            defaults={'description': 'Role for students in the school'}
        )
        data = request.data.copy()
        data['school'] = school.id
        data['is_active'] = True 
        if "name" in data:
            data["username"] = generate_username(data["name"], prefix="ST-")
        with transaction.atomic():
            student_serializer = self.serializer_class(data=data)
            if student_serializer.is_valid():
                student_instance = student_serializer.save()
            else:
                return Response(student_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            user_data = {
                'username': data.get("username"),
                'password': data.get("date_of_birth",0000),
                'mobile_no': data.get("mobile_no"),
                'email': data.get("email"),
                'name': data.get("name"),
                'school': school.id,
                'branch': data.get("branch_id"),
                'role': role_student.id,
                'student_profile': student_instance.id
            }
            user_serializer = UserStudentSerializer(data=user_data)
            if user_serializer.is_valid():
                user_instance = user_serializer.save()
                group_name = f"{school.school_code}_{role_student.name}"
                group, created = Group.objects.get_or_create(name=group_name)
                user_instance.groups.add(group)
                if role_created:
                  role_student.group = group  # Set the group's one-to-one relationship with role
                  role_student.save()
                if not QRCode.objects.filter(name=user_instance.id).exists():
                    qr_data = {"id":str(user_instance.id),"name":user_instance.name if user_instance.name else "" }
                    create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school)
            else:
                return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Student created successfully", "data": student_serializer.data}, status=status.HTTP_201_CREATED)

    def put(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_student")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            user_instance = User.objects.get(id=model_id, school=school)
            student_instance = user_instance.student_profile
        except User.DoesNotExist:
            return Response({"message": "Student not found"}, status=status.HTTP_404_NOT_FOUND)

        with transaction.atomic():
            student_serializer = StudentSerializer(student_instance, data=request.data, partial=True)
            if student_serializer.is_valid():
                student_serializer.save()
            else:
                return Response(student_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            user_data = {}
            if 'mobile_no' in request.data:
                user_data['mobile_no'] = request.data.get('mobile_no')
            if 'name' in request.data:
                user_data['name'] = request.data.get('name')
            if 'email' in request.data:
                user_data['email'] = request.data.get('email')
            if user_data:  # Only update if there's data to update
                user_serializer = UserStudentSerializer(user_instance, data=user_data, partial=True)
                if user_serializer.is_valid():
                    user_instance = user_serializer.save()
                    if not QRCode.objects.filter(name=user_instance.id).exists():
                        qr_data = {"id":str(user_instance.id),"name":user_instance.name if user_instance.name else "" }
                        create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school)
                else:
                    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Student updated successfully"}, status=status.HTTP_200_OK)
    def patch(self, request):
        # Check permission and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.change_student")
        if error_response:
            return error_response
        user_ids = request.data.get('ids', [])
        update_data = request.data.get('update_data', {})
        if not user_ids:
            return Response({"message": "User ID list is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not update_data:
            return Response({"message": "Update data is required"}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            users = User.objects.filter(id__in=user_ids, school=school)
            if not users.exists():
                return Response({"message": "No users found for the given IDs"}, status=status.HTTP_404_NOT_FOUND)
            for user in users:
                if user.student_profile:
                    student = user.student_profile
                    for key, value in update_data.items():
                        if hasattr(student, key):  # Ensure key is a valid field of Student
                            setattr(student, key, value)
                    student.save()  # Save the updated student record
                if 'password' in update_data:
                    new_password = update_data['password']
                    user.plain_password=new_password
                    user.password = make_password(new_password)  # Hash the password before saving
                    user.save()
        return Response({"message": "Students updated successfully"}, status=status.HTTP_200_OK)
    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_student")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Student ID list is required"}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            for student_id in ids:
                try:
                    user_instance = User.objects.get(id=student_id)
                    student_instance = user_instance.student_profile
                except User.DoesNotExist:
                    return Response({"message": f"Student with ID {student_id} not found"}, status=status.HTTP_404_NOT_FOUND)
                # Verify if the student belongs to the current school
                if user_instance.school != school:
                    return Response({"message": "You can only delete students from your own school."}, status=status.HTTP_403_FORBIDDEN)
                # Delete both the student and user instance
                student_instance.delete()
                user_instance.delete()
        return Response({"message": "Student and User deleted successfully"}, status=status.HTTP_200_OK)
class StudentListNewAPIView(GenericAPIView):
    serializer_class = StudentListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_dormitory")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        class_id = request.query_params.get('class_id', None)
        if not class_id:
            return Response({"message": "Class is required"}, status=status.HTTP_400_BAD_REQUEST)
        subject_filters['school_class__id'] = class_id
        section_id = request.query_params.get('section_id', None)
        if section_id:
            subject_filters['section__id'] = section_id
        list_model = Student.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(list_model, many=True)
        return  Response({"message": "Student List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
class StudentBulkNewAPIView(GenericAPIView):
    serializer_class = StudentSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_student")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        club_id = request.query_params.get('club_id', None)
        class_id = request.query_params.get('class_id', None)
        session_id = request.query_params.get('session_id', None)
        section_id = request.query_params.get('section_id', None)
        dormitory_id = request.query_params.get('dormitory_id', None)
        category = request.query_params.get('category', None)
        dormitoryroom_id = request.query_params.get('dormitoryroom_id', None)
        house_id = request.query_params.get('house_id', None)
        student_category_id = request.query_params.get('student_category_id', None)
        enroll_no = request.query_params.get('enroll_no', None)
        search = request.query_params.get('search', None)
        if not any([
            club_id, class_id, session_id, section_id,
            dormitory_id, category, dormitoryroom_id,
            house_id, student_category_id, enroll_no,search
        ]):
            return Response(
                {"error": "At least one filter parameter is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if club_id:
            club = get_object_or_404(Club, id=club_id)
            subject_filters['club'] = club
        if class_id:
            sh_class = get_object_or_404(SchoolClass, id=class_id)
            subject_filters['school_class'] = sh_class
        if session_id:
            session = get_object_or_404(AcademicSession, id=session_id)
            subject_filters['session'] = session
        if section_id:
            section = get_object_or_404(Section, id=section_id)
            subject_filters['section'] = section
        if dormitory_id:
            dormitory = get_object_or_404(Dormitory, id=dormitory_id)
            subject_filters['dormitory'] = dormitory
        if dormitoryroom_id:
            dormitoryroom = get_object_or_404(DormitoryRoom, id=dormitoryroom_id)
            subject_filters['dormitoryroom'] = dormitoryroom
        if house_id:
            house = get_object_or_404(House, id=house_id)
            subject_filters['house'] = house
        if student_category_id:
            student_category = get_object_or_404(Student_Category, id=student_category_id)
            subject_filters['student_category'] = student_category
        if enroll_no:
            subject_filters['enroll_no'] = enroll_no
        if category:
            subject_filters['category'] = category
        students = Student.objects.filter(**subject_filters)
        if search:
            students = students.filter(
                Q(name__icontains=search) |
                Q(date_of_birth__icontains=search) |
                Q(age__icontains=search) |
                Q(religion__icontains=search) |
                Q(city__icontains=search) |
                Q(mobile_no__icontains=search) |
                Q(enroll_no__icontains=search) |
                Q(card_number__icontains=search) |
                Q(category__icontains=search) |
                Q(guardian_name__icontains=search) |
                Q(guardian_relation__icontains=search) |
                Q(guardian_occupation__icontains=search) |
                Q(father_name__icontains=search) |
                Q(father_occupation__icontains=search) |
                Q(mother_name__icontains=search) |
                Q(mother_occupation__icontains=search) |
                Q(guardian_phone__icontains=search) |
                Q(mother_phone__icontains=search) |
                Q(father_phone__icontains=search)
            )
        get_model = User.objects.filter(student_profile__in=students).order_by('-created_at')
        serializer = StudentGetSerializer(get_model, many=True)
        return Response(serializer.data)
# =========================================================school api=======================================
class SchoolNewAPIView(GenericAPIView):
    serializer_class = SchoolSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        if not request.user.is_superuser:
            return Response({"message": "Only for EduuXpert team. Please contact to EduuXpert team!"}, status=status.HTTP_400_BAD_REQUEST)
        school = School.objects.all()
        get_model = User.objects.filter(school__in=school,role__name="school").order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = SchoolGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = SchoolGetSerializer(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        if not request.user.is_superuser:
            return Response({"message": "Only for EduuXpert team. Please contact to EduuXpert team!"}, status=status.HTTP_400_BAD_REQUEST)
        role_student, role_created = Role.objects.get_or_create(
            name='school',
            defaults={'description': 'Role for schools in the system'}
        )
        data = request.data.copy()
        data['active'] = True
        if "name" in data:
            data["username"] = generate_username(data["name"], prefix="SH-")
        with transaction.atomic():
            school_serializer = self.serializer_class(data=data)
            if school_serializer.is_valid():
                school_instance = school_serializer.save()
            else:
                return Response(school_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            user_data = {
                'username': data.get("username"),
                'password': data.get("school_code",0000),
                'mobile_no': data.get("mobile_no"),
                'email': data.get("email"),
                'name': data.get("name"),
                'school': school_instance.id,
                'branch': data.get("branch_id"),
                'role': role_student.id,
            }
            if 'logo' in request.FILES:
                user_data['image'] = request.FILES['logo']
            user_serializer = UserSchoolSerializer(data=user_data)
            if user_serializer.is_valid():
                user_instance = user_serializer.save()
                group_name = f"{school_instance.school_code}_{role_student.name}"
                group, created = Group.objects.get_or_create(name=group_name)
                user_instance.groups.add(group)
                if role_created:
                    role_student.group = group  # Set the group's one-to-one relationship with role
                    role_student.save()
                if not QRCode.objects.filter(name=user_instance.id).exists():
                    qr_data = {"id":str(user_instance.id),"name":user_instance.name}
                    create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school_instance)
            else:
                return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "School created successfully", "data": school_serializer.data}, status=status.HTTP_200_OK)

    def put(self, request):
        if not request.user.is_superuser:
            return Response({"message": "Only for EduuXpert team. Please contact to EduuXpert team!"}, status=status.HTTP_400_BAD_REQUEST)
        model_id = request.data.get('id', None)
        try:
            user_instance = User.objects.get(id=model_id)
            school_instance = user_instance.school
        except User.DoesNotExist:
            return Response({"message": "School not found"}, status=status.HTTP_404_NOT_FOUND)

        with transaction.atomic():
            student_serializer = SchoolSerializer(school_instance, data=request.data, partial=True)
            if student_serializer.is_valid():
                student_serializer.save()
            else:
                return Response(student_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            user_data = {}
            if 'mobile_no' in request.data:
                user_data['mobile_no'] = request.data.get('mobile_no')
            if 'email' in request.data:
                user_data['email'] = request.data.get('email')
            if 'name' in request.data:
                user_data['name'] = request.data.get('name')
            if 'logo' in request.FILES:
                user_data['image'] = request.FILES['logo']
            if user_data:  # Only update if there's data to update
                user_serializer = UserSchoolSerializer(user_instance, data=user_data, partial=True)
                if user_serializer.is_valid():
                    user_detail = user_serializer.save()
                    if not QRCode.objects.filter(name=user_detail.id).exists():
                        qr_data = {"id":str(user_detail.id),"name":user_detail.name}
                        create_qrcode_url(self, qr_data, user_detail.id, user_detail.role.name,school_instance)
                    
                else:
                    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "School updated successfully"}, status=status.HTTP_200_OK)
    def patch(self, request):
        if request.user.role.name != "school":
            return Response({"message": "Only for School"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user_instance = request.user
            school_instance = user_instance.school
        except User.DoesNotExist:
            return Response({"message": "School not found"}, status=status.HTTP_404_NOT_FOUND)

        with transaction.atomic():
            student_serializer = SchoolSerializer(school_instance, data=request.data, partial=True)
            if student_serializer.is_valid():
                student_serializer.save()
            else:
                return Response(student_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            user_data = {}
            if 'mobile_no' in request.data:
                user_data['mobile_no'] = request.data.get('mobile_no')
            if 'email' in request.data:
                user_data['email'] = request.data.get('email')
            if 'name' in request.data:
                user_data['name'] = request.data.get('name')
            if 'logo' in request.FILES:
                user_data['image'] = request.FILES['logo']
            if user_data:  # Only update if there's data to update
                user_serializer = UserSchoolSerializer(user_instance, data=user_data, partial=True)
                if user_serializer.is_valid():
                    user_serializer.save()
                else:
                    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "School updated successfully"}, status=status.HTTP_200_OK)
    def delete(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            return Response({"message": "Only for EduuXpert team. Please contact to EduuXpert team!"}, status=status.HTTP_400_BAD_REQUEST)
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Student ID list is required"}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            for student_id in ids:
                try:
                    user_instance = User.objects.get(id=student_id)
                    school_instance = user_instance.school
                except User.DoesNotExist:
                    return Response({"message": f"School with ID {student_id} not found"}, status=status.HTTP_404_NOT_FOUND)
                school_instance.delete()
                user_instance.delete()
        return Response({"message": "School and User deleted successfully"}, status=status.HTTP_200_OK)
# =========================================Parents============================================

class ParentAPIView(GenericAPIView):
    serializer_class = ParentSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_parent")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        student_id = request.query_params.get('student_id', None)
        if student_id:
            student = get_object_or_404(Student, id=student_id)
            parent_ids = student.parents.values_list('id', flat=True)
            subject_filters['parent_profile__id__in'] = parent_ids
        try:
            role_instance = Role.objects.get(name='parent',school=school)
        except Role.DoesNotExist:
            return Response({"message": "Role not Found"}, status=status.HTTP_400_BAD_REQUEST)
        subject_filters = {'role': role_instance}

        get_model = User.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = ParentGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = ParentGetSerializer(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        # Check for permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.add_parent")
        if error_response:
            return error_response
        role_parent, role_created = Role.objects.get_or_create(
            name='parent',
            school=school,
            defaults={'description': 'Role for Parent in the school'}
        )
        data = request.data.copy()
        data['school'] = school.id
        data['is_active'] = True
        if "name" in data:
            data["username"] = generate_username(data["name"], prefix="P-")
        with transaction.atomic():
            parent_serializer = ParentSerializer(data=data)
            if parent_serializer.is_valid():
                parent_instance = parent_serializer.save()
            else:
                return Response(parent_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            user_data = {
                'username': data.get("username"),
                'password': data.get("date_of_birth",0000),
                'mobile_no': data.get("mobile_no"),
                'email': data.get("email"),
                'name': data.get("name"),
                'school': school.id,
                'branch': data.get("branch_id"),
                'role': role_parent.id,
                'parent_profile': parent_instance.id
            }

            user_serializer = UserParentSerializer(data=user_data)
            if user_serializer.is_valid():
                user_instance = user_serializer.save()
                if not QRCode.objects.filter(name=user_instance.id).exists():
                    qr_data = {"id":str(user_instance.id),"name":user_instance.name if user_instance.name else "" }
                    create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school)
                try:
                    group_name = f"{school.school_code}_{role_parent.name}"
                    group, created = Group.objects.get_or_create(name=group_name)
                    user_instance.groups.add(group)
                    if role_created:
                        role_parent.group = group  # Set the group's one-to-one relationship with role
                        role_parent.save()
                except Group.DoesNotExist:
                    return Response({"message": "Group does not exist"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Parent created successfully", "data": parent_serializer.data}, status=status.HTTP_200_OK)

    def put(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_parent")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        if not model_id:
            return Response({"message": "Parent ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user_instance = User.objects.get(id=model_id, school=school)
            parent_instance = user_instance.parent_profile  # Assuming reverse relation from Student to User
        except User.DoesNotExist:
            return Response({"message": "Parent not found"}, status=status.HTTP_404_NOT_FOUND)
        with transaction.atomic():
            parent_serializer = ParentSerializer(parent_instance, data=request.data, partial=True)
            if parent_serializer.is_valid():
                parent_serializer.save()
            else:
                return Response(parent_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            user_data = {}
            if 'mobile_no' in request.data:
                user_data['mobile_no'] = request.data.get('mobile_no')
            if 'name' in request.data:
                user_data['name'] = request.data.get('name')
            if 'email' in request.data:
                user_data['email'] = request.data.get('email')
            if user_data:
                user_serializer = UserParentSerializer(user_instance, data=user_data, partial=True)
                if user_serializer.is_valid():
                    user_instance = user_serializer.save()
                    if not QRCode.objects.filter(name=user_instance.id).exists():
                        qr_data = {"id":str(user_instance.id),"name":user_instance.name if user_instance.name else "" }
                        create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school)
                else:
                    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Parent updated successfully"}, status=status.HTTP_200_OK)


    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_parent")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Parent ID list is required"}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            for parent_id in ids:
                try:
                    user_instance = User.objects.get(id=parent_id)
                    parent_instance = user_instance.parent_profile
                except User.DoesNotExist:
                    return Response({"message": f"Parent with ID {parent_id} not found"}, status=status.HTTP_404_NOT_FOUND)
                # Verify if the student belongs to the current school
                if user_instance.school != school:
                    return Response({"message": "You can only delete parent from your own school."}, status=status.HTTP_403_FORBIDDEN)
                # Delete both the student and user instance
                parent_instance.delete()
                user_instance.delete()
        return Response({"message": "Parent deleted successfully"}, status=status.HTTP_200_OK)
class ParentListAPIView(GenericAPIView):
    serializer_class = StudentListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_parent")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        student_id = request.query_params.get('student_id', None)
        # if not student_id:
        #     return Response({"message": "Student ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        if student_id:
            student = get_object_or_404(Student, id=student_id)
            parent_ids = student.parents.values_list('id', flat=True)
            subject_filters['id__in'] = parent_ids
        # try:
        #     student = Student.objects.get(id=student_id, school=school)
        #     parent_ids = student.parents.values_list('id', flat=True)
        # except Student.DoesNotExist:
        #     return Response({"message": "Student not found"}, status=status.HTTP_404_NOT_FOUND)
        list_model = Parent.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(list_model, many=True)
        return Response({"message": "Parent List retrieved successfully", "data": serializer.data}, status=status.HTTP_200_OK)
# ==================================teacher==================================================
class TeacherNewAPIView(GenericAPIView):
    serializer_class = TeacherSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_teacher")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        department_id = request.query_params.get('department_id', None)
        if department_id:
            department = get_object_or_404(Department, id=department_id)
            subject_filters['department'] = department
        try:
            role_instance = Role.objects.get(name='teacher',school=school)
        except Role.DoesNotExist:
            return Response({"message": "Role not Found"}, status=status.HTTP_400_BAD_REQUEST)
        subject_filters = {'role': role_instance}

        get_model = User.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = TeacherGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = TeacherGetSerializer(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_parent")
        if error_response:
            return error_response
        role_teacher, role_created = Role.objects.get_or_create(
            name='teacher',
            school=school,
            defaults={'description': 'Role for Teacher in the school'}
        )
        data = request.data.copy()
        data['school'] = school.id
        data['is_active'] = True 
        if "name" in data:
            data["username"] = generate_username(data["name"], prefix="T-")
        with transaction.atomic():
            teacher_serializer = self.serializer_class(data=data)
            if teacher_serializer.is_valid():
                teacher_instance = teacher_serializer.save()
            else:
                return Response(teacher_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            user_data = {
                'username': data.get("username"),
                'password': data.get("date_of_birth",0000),
                'mobile_no': data.get("mobile_no"),
                'email': data.get("email"),
                'name': data.get("name"),
                'school': school.id,
                'branch': data.get("branch_id"),
                'role': role_teacher.id,
                'teacher_profile': teacher_instance.id
            }
            user_serializer = UserTeacherSerializer(data=user_data)
            if user_serializer.is_valid():
                user_instance = user_serializer.save()
                group_name = f"{school.school_code}_{role_teacher.name}"
                group, created = Group.objects.get_or_create(name=group_name)
                user_instance.groups.add(group)
                if role_created:
                    role_teacher.group = group  # Set the group's one-to-one relationship with role
                    role_teacher.save()
                if not QRCode.objects.filter(name=user_instance.id).exists():
                    qr_data = {"id":str(user_instance.id),"name":user_instance.name if user_instance.name else "" }
                    create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school)
            else:
                return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Teacher created successfully", "data": teacher_serializer.data}, status=status.HTTP_200_OK)

    def put(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_teacher")
        if error_response:
            return error_response

        model_id = request.data.get('id', None)
        if not model_id:
            return Response({"message": "Teacher ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_instance = User.objects.get(id=model_id, school=school)
            teacher_instance = user_instance.teacher_profile
        except User.DoesNotExist:
            return Response({"message": "Teacher not found"}, status=status.HTTP_404_NOT_FOUND)

        with transaction.atomic():
            teacher_serializer = TeacherSerializer(teacher_instance, data=request.data, partial=True)
            if teacher_serializer.is_valid():
                teacher_serializer.save()
            else:
                return Response(teacher_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            user_data = {}
            if 'mobile_no' in request.data:
                user_data['mobile_no'] = request.data.get('mobile_no')
            if 'name' in request.data:
                user_data['name'] = request.data.get('name')
            if 'email' in request.data:
                user_data['email'] = request.data.get('email')
            if user_data:
                user_serializer = UserTeacherSerializer(user_instance, data=user_data, partial=True)
                if user_serializer.is_valid():
                    user_instance = user_serializer.save()
                    if not QRCode.objects.filter(name=user_instance.id).exists():
                        qr_data = {"id":str(user_instance.id),"name":user_instance.name if user_instance.name else "" }
                        create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school)
                else:
                    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Teacher updated successfully"}, status=status.HTTP_200_OK)


    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_teacher")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Teacher ID list is required"}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            for user_id in ids:
                try:
                    user_instance = User.objects.get(id=user_id)
                    teacher_instance = user_instance.teacher_profile
                except User.DoesNotExist:
                    return Response({"message": f"Teacher with ID {user_id} not found"}, status=status.HTTP_404_NOT_FOUND)
                # Verify if the student belongs to the current school
                if user_instance.school != school:
                    return Response({"message": "You can only delete Teacher from your own school."}, status=status.HTTP_403_FORBIDDEN)
                # Delete both the student and user instance
                teacher_instance.delete()
                user_instance.delete()
        return Response({"message": "Teacher deleted successfully"}, status=status.HTTP_200_OK)
class TeacherListAPIView(GenericAPIView):
    serializer_class = TeacherListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_teacher")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        department_id = request.query_params.get('department_id', None)
        if department_id:
            department = get_object_or_404(Department, id=department_id)
            subject_filters['department'] = department
        list_model = Teacher.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(list_model, many=True)
        return Response({"message": "Teacher List retrieved successfully", "data": serializer.data}, status=status.HTTP_200_OK)


# =========================================Student Category============================================
class StudentCategoryAPIView(GenericAPIView):
    serializer_class = Student_CategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_student_category")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subjects = Student_Category.objects.filter(**subject_filters).order_by('-created_at')
        if request.query_params.get('filter_fields'):
            filter_dict = request.query_params.get('filter_fields', '{}')
            try:
                filter_dict = json.loads(filter_dict)
            except json.JSONDecodeError:
                return Response({"error": "Invalid JSON format in 'filter_fields' parameter."}, status=status.HTTP_400_BAD_REQUEST)
            filtered_queryset = filter_model_data(subjects, filter_dict)
            if isinstance(filtered_queryset, dict) and 'error' in filtered_queryset:
                return Response(filtered_queryset, status=status.HTTP_400_BAD_REQUEST)
            subjects = filtered_queryset
        page = self.paginate_queryset(subjects)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(subjects, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_student_category")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        class_name = data.get('name')
        exists, conflict_response = check_if_exists(Student_Category, name=class_name,school=school)
        if conflict_response:
            return conflict_response
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Student Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_student_category")
        if error_response:
            return error_response
        studentcat_id = request.data.get('id', None)
        try:
            student_category = Student_Category.objects.get(id=studentcat_id)
        except Student_Category.DoesNotExist:
            return Response({"message": "Student Category not found"}, status=status.HTTP_404_NOT_FOUND)
        class_name = request.data.get('name')
        if class_name and class_name != student_category.name:
            exists, conflict_response = check_if_exists(Student_Category, name=class_name, school=school)
            if conflict_response:
                return conflict_response
        if student_category.school != school:
            return Response({"message": "You can only update Student Category for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(student_category, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Student Category updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_student_category")
        if error_response:
            return error_response
        subject_ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not subject_ids:
            return Response({"message": "Subject list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for subject_id in subject_ids:
            try:
                student_category = Student_Category.objects.get(id=subject_id)
            except Student_Category.DoesNotExist:
                return Response({"message": "student category not found"}, status=status.HTTP_404_NOT_FOUND)
            if student_category.school != school:
                return Response({"message": "You can only update Student Category for your own school."}, status=status.HTTP_403_FORBIDDEN)
            student_category.delete()
        return Response({"message": "Subject deleted successfully"}, status=status.HTTP_200_OK)
class StudentCategoryListAPIView(GenericAPIView):
    serializer_class = SubjectListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_student_category")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subject_filters['active'] = True
        subjects = Student_Category.objects.filter(**subject_filters).order_by('-created_at')
        serializer = Student_CategorylistSerializer(subjects, many=True)
        return  Response({"message": "Subject List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
    
# =========================================Club============================================
class ClubAPIView(GenericAPIView):
    serializer_class = ClubSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_club")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        club = Club.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(club)
        if page is not None:
            serializer = ClubGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = ClubGetSerializer(club, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_club")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id
        class_name = data.get('name')
        exists, conflict_response = check_if_exists(Club, name=class_name,school=school)
        if conflict_response:
            return conflict_response 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Club Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_club")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            club = Club.objects.get(id=model_id)
        except club.DoesNotExist:
            return Response({"message": "Club not found"}, status=status.HTTP_404_NOT_FOUND)
        class_name = request.data.get('name')
        if class_name and class_name != club.name:
            exists, conflict_response = check_if_exists(Club, name=class_name, school=school)
            if conflict_response:
                return conflict_response
        if club.school != school:
            return Response({"message": "You can only update Club for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(club, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Club updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_club")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Club list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = Club.objects.get(id=id)
            except Club.DoesNotExist:
                return Response({"message": "Club not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Club for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Club deleted successfully"}, status=status.HTTP_200_OK)
class ClubListAPIView(GenericAPIView):
    serializer_class = ClublistSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_club")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subject_filters['active'] = True
        subjects = Club.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(subjects, many=True)
        return  Response({"message": "Club List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
    

# ======================================feedback============================

class FeedbackAPIView(GenericAPIView):
    serializer_class = FeedbackSerializer
    permission_classes = [permissions.IsAuthenticated]
        
    def get(self, request, *args, **kwargs):
        user = request.user
        feedback_filters = {}
        school,error_response = check_permission_and_get_school(request,"api_v1.view_feedback")
        if error_response:
            return error_response
        feedback_filters['school'] = school
        # Helper function to get an object or return a response
        def get_object_or_response(model, id, error_message):
            obj = get_object_or_404(model, id=id)
            if not obj:
                return Response({"message": error_message}, status=status.HTTP_404_NOT_FOUND)
            return obj

        # Apply filters based on request parameters
        student_id = request.query_params.get('student_id')
        if student_id:
            feedback_filters['students__in'] = get_object_or_response(Student, student_id, "Invalid student ID")

        class_id = request.query_params.get('class_id')
        if class_id:
            feedback_filters['school_class'] = get_object_or_response(SchoolClass, class_id, "Invalid class ID")
        section_id = request.query_params.get('section_id')
        if section_id:
            feedback_filters['section'] = get_object_or_response(Section, section_id, "Invalid class ID")
       
        if user.role:
            role_name = user.role.name
            if role_name == "student":
                feedback_filters['students__in'] = [user.student_profile]
            elif role_name == "parent":
                students = Student.objects.filter(parents__in=[user.parent_profile])
                if not students.exists():
                    return Response({"message": "No students found for this parent."}, status=status.HTTP_404_NOT_FOUND)
                feedback_filters['students__in'] = students.values_list('id', flat=True)
        else:
            return Response({"message": "You do not have permission to access this data."}, status=status.HTTP_403_FORBIDDEN)

        # Filter feedback and apply pagination
        feedbacks = Feedback.objects.filter(**feedback_filters).order_by('created_at')
        page = self.paginate_queryset(feedbacks)
        serializer = FeedbackGetSerializer(page, many=True, context={'request': request})
        return self.get_paginated_response(serializer.data)


    def post(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_feedback")
        if error_response:
            return error_response
        data = request.data
        data['school']=school.id
        data['sender'] = request.user.id  # Set sender to the current user (teacher)
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Feedback created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        feedback_id = request.data.get('id', None)
        try:
            feedback = Feedback.objects.get(id=feedback_id)
        except Feedback.DoesNotExist:
            return Response({"message": "Feedback not found"}, status=status.HTTP_404_NOT_FOUND)
        if feedback.school != request.user.school:
            return Response({"message": "You can only delete Feedback for your own school."}, status=status.HTTP_403_FORBIDDEN)

        # Check if the user is allowed to update the feedback
        if feedback.sender != request.user and (request.user.is_superuser or request.user.role and request.user.role.name == "school"):
            return Response({"message": "You can only update your own feedback."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(feedback, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Feedback updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        feedback_ids = request.data.get('ids', [])
        if not feedback_ids:
            return Response({"message": "Feedback list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for feedback_id in feedback_ids:
            try:
                feedback = Feedback.objects.get(id=feedback_id)
            except Feedback.DoesNotExist:
                return Response({"message": "Feedback not found"}, status=status.HTTP_404_NOT_FOUND)
            if feedback.school != request.user.school:
                return Response({"message": "You can only delete Feedback for your own school."}, status=status.HTTP_403_FORBIDDEN)

            # Check if the user is allowed to delete the feedback
            if feedback.sender != request.user and (request.user.is_superuser or request.user.role and request.user.role.name == "school"):
                return Response({"message": "You can only delete your own feedback."}, status=status.HTTP_403_FORBIDDEN)

            feedback.delete()

        return Response({"message": "Feedback deleted successfully"}, status=status.HTTP_200_OK)


# ===========================Group Permision and User Permission=====================================
class GroupPermissionAPIView(GenericAPIView):
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = Group.objects.all()

    def get(self, request, pk=None, *args, **kwargs):
        """Handle GET requests - list all groups or retrieve a specific group"""
        if pk:
            try:
                group = Group.objects.get(pk=pk)
                serializer = self.serializer_class(group)
                return Response(serializer.data)
            except Group.DoesNotExist:
                return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            groups = Group.objects.all()
            serializer = self.serializer_class(groups, many=True)
            return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """Handle POST requests - create a new group"""
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            group = Group.objects.create(name=serializer.validated_data['name'])
            permissions_data = serializer.validated_data.get('permissions', [])
            group.permissions.set(permissions_data)
            group.save()
            return Response(self.serializer_class(group).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk=None, *args, **kwargs):
        """Handle PUT requests - update a group"""
        try:
            group = Group.objects.get(pk=pk)
            serializer = self.serializer_class(group, data=request.data, partial=True)
            if serializer.is_valid():
                permissions_data = serializer.validated_data.get('permissions', [])
                group.permissions.set(permissions_data)
                group.name = serializer.validated_data.get('name', group.name)
                group.save()
                return Response(self.serializer_class(group).data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Group.DoesNotExist:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, pk=None, *args, **kwargs):
        """Handle DELETE requests - delete a group"""
        try:
            group = Group.objects.get(pk=pk)
            group.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Group.DoesNotExist:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

class TokenPermissionAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        model_name = request.data.get('model_name')
        user = request.user
        permissions_dict = self.get_user_permissions(user, model_name)
        return Response(permissions_dict, status=status.HTTP_200_OK)
    def get_user_permissions(self, user, model_name):
        permissions = {
            'add': False,
            'update': False,
            'delete': False,
            'show': False
        }
        try:
            content_type = ContentType.objects.get(model=model_name.lower())
        except ContentType.DoesNotExist:
            return permissions  # Return default permissions if the model does not exist
        permissions['add'] = user.has_perm(f'{content_type.app_label}.add_{content_type.model}')
        permissions['update'] = user.has_perm(f'{content_type.app_label}.change_{content_type.model}')
        permissions['delete'] = user.has_perm(f'{content_type.app_label}.delete_{content_type.model}')
        permissions['show'] = user.has_perm(f'{content_type.app_label}.view_{content_type.model}')
        return permissions
# ==============================================timetable============================================
class TimetableAPIView(GenericAPIView):
    serializer_class = TimetableSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        school, error_response = check_permission_and_get_school(request, "api_v1.view_timetable")
        if error_response:
            return error_response

        filters = {'school': school}

        # Teacher should only see their own timetable
        if user.role and user.role.name == "teacher":
            filters['teacher__user'] = user

        # Student can only see their class & section timetable
        elif user.role and user.role.name == "student":
            if user.student_profile and user.student_profile.school_class and user.student_profile.section:
                filters['school_class'] = user.student_profile.school_class
                filters['section'] = user.student_profile.section
            else:
                return Response({"message": "Student class and section information is missing."},
                                status=status.HTTP_400_BAD_REQUEST)

        # School (admin or superadmin) can filter by class, section, and teacher
        else:
            class_id = request.query_params.get('class_id')
            if class_id:
                filters['school_class'] = get_object_or_404(SchoolClass, id=class_id)
            section_id = request.query_params.get('section_id')
            if section_id:
                filters['section'] = get_object_or_404(Section, id=section_id)
            teacher_id = request.query_params.get('teacher_id')
            if teacher_id:
                filters['teacher'] = get_object_or_404(Teacher, id=teacher_id)

        selected_day = request.query_params.get('day', None)

        # Fetch all unique_name values from the TimePeriods model
        unique_names = TimePeriods.objects.filter(school=school).values_list('unique_name', flat=True).distinct()

        response_data = {}

        # Iterate over each unique_name to fetch periods and timetable data
        for unique_name in unique_names:
            # Fetch periods for the current unique_name
            time_periods = TimePeriods.objects.filter(school=school, unique_name=unique_name).order_by('start_time')
            period_data = [{
                "id": period.id,
                "unique_name": period.unique_name,
                "name": period.name,
                "start_time": period.start_time,
                "end_time": period.end_time,
            } for period in time_periods]

            # Fetch timetable entries for the current unique_name
            timetable_entries = Timetable.objects.filter(**filters, period__unique_name=unique_name).select_related(
                'period').order_by('day', 'period__start_time')

            if selected_day:
                timetable_entries = timetable_entries.filter(day=selected_day)

            # Group timetable entries by day and period
            grouped_results = defaultdict(lambda: defaultdict(list))
            for entry in timetable_entries:
                serialized_entry = TimetableGetSerializer(entry).data
                serialized_entry.update({
                    "class_name": entry.school_class.name,
                    "section_name": entry.section.name,
                    "subject_name": entry.subject.name,
                    "teacher_name": entry.teacher.name,
                })
                grouped_results[entry.day][entry.period.id].append(serialized_entry)

            # Group by days and include periods with their corresponding timetable entries
            for day in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]:
                daily_data = grouped_results.get(day, {})
                # Add periods data alongside the timetable data
                day_periods = []
                for period in period_data:
                    period_id = period["id"]
                    period_info = {
                        "id": period["id"],
                        "unique_name": period["unique_name"],
                        "name": period["name"],
                        "start_time": period["start_time"],
                        "end_time": period["end_time"],
                        "timetable": daily_data.get(period_id, [])
                    }
                    day_periods.append(period_info)
                if day not in response_data:
                    response_data[day] = {}
                response_data[day][unique_name] = {
                    "periods": day_periods
                }

        return Response({"results": response_data, "count": timetable_entries.count()},
                        status=status.HTTP_200_OK)


    def post(self, request):
        user = request.user
        school, error_response = check_permission_and_get_school(request, "api_v1.add_timetable")
        if error_response:
            return error_response

        data = request.data
        data['school'] = school.id

        # Assign teacher if role is teacher
        if user.role and user.role.name == "teacher":
            data['teacher'] = user.id

        # Validate input
        try:
            school_class = get_object_or_404(SchoolClass, id=data['school_class'], school=school)
            section = get_object_or_404(Section, id=data['section'], school=school)
            subject = get_object_or_404(Subject, id=data['subject'], school=school)
            period = get_object_or_404(TimePeriods, id=data['period'], school=school)
            if user.role and user.role.name == "teacher" and subject.teacher.user != user:
                raise ValueError("You are not assigned to this subject.")
        except:
            return Response({"message": "Invalid class, section, subject, or period."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Ensure no duplicate period entries for the same class and teacher
        if Timetable.objects.filter(school=school, day=data['day'], period=period, teacher=subject.teacher).exists():
            return Response({"message": "This teacher is already assigned to another class at this period."},
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Timetable created successfully", "data": serializer.data},
                            status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        user = request.user
        school, error_response = check_permission_and_get_school(request, "api_v1.change_timetable")
        if error_response:
            return error_response

        timetable_id = request.data.get('id')
        try:
            timetable_entry = Timetable.objects.get(id=timetable_id, school=school)
            if user.role and user.role.name == "teacher" and timetable_entry.teacher.user != user:
                return Response({"message": "You don't have permission to update this timetable entry."},
                                status=status.HTTP_403_FORBIDDEN)
        except Timetable.DoesNotExist:
            return Response({"message": "Timetable entry not found."}, status=status.HTTP_404_NOT_FOUND)

        data = request.data
        period = get_object_or_404(TimePeriods, id=data['period'],
                                   school=school) if 'period' in data else timetable_entry.period

        # Ensure no duplicate period entries
        if Timetable.objects.filter(school=school, day=data.get('day', timetable_entry.day), period=period,
                                    teacher=timetable_entry.teacher).exclude(id=timetable_id).exists():
            return Response({"message": "This teacher is already assigned to another class at this period."},
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = self.serializer_class(timetable_entry, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Timetable updated successfully", "data": serializer.data},
                            status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        user = request.user
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_timetable")
        if error_response:
            return error_response

        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Timetable list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for id in ids:
            try:
                delete_model = Timetable.objects.get(id=id, school=school)
                if user.role and user.role.name == "teacher" and delete_model.teacher.user != user:
                    return Response({"message": "You can only delete your own timetable entries."},
                                    status=status.HTTP_403_FORBIDDEN)
                delete_model.delete()
            except Timetable.DoesNotExist:
                return Response({"message": f"Timetable entry with id {id} not found."},
                                status=status.HTTP_404_NOT_FOUND)

        return Response({"message": "Timetable deleted successfully"}, status=status.HTTP_200_OK)



class TimePeriodAPIView(GenericAPIView):
    serializer_class = TimePeriodSerializer  # Assuming you have created a TimePeriodSerializer for the model
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_timeperiod")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        get_model = TimePeriods.objects.filter(**subject_filters).order_by('-start_time')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = TimePeriodGetSerializer(page, many=True)  # Assuming TimePeriodGetSerializer is created
            return self.get_paginated_response(serializer.data)
        serializer = TimePeriodGetSerializer(get_model, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_timeperiod")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Time Period Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_timeperiod")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = TimePeriods.objects.get(id=model_id)
        except TimePeriods.DoesNotExist:
            return Response({"message": "Time Period not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Time Periods for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Time Period updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_timeperiod")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Time Period list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = TimePeriods.objects.get(id=id)
            except TimePeriods.DoesNotExist:
                return Response({"message": "Time Period not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only delete Time Periods for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Time Periods deleted successfully"}, status=status.HTTP_200_OK)  
# =========================================Hostel Room============================================
class HostelRoomAPIView(GenericAPIView):
    serializer_class = HostelRoomSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_hostelroom")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        get_model = HostelRoom.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_hostelroom")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Hostel Room Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_hostelroom")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = HostelRoom.objects.get(id=model_id)
        except HostelRoom.DoesNotExist:
            return Response({"message": "HostelRoom not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update HostelRoom for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "HostelRoom updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_hostelroom")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "HostelRoom list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = HostelRoom.objects.get(id=id)
            except HostelRoom.DoesNotExist:
                return Response({"message": "Club not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update HostelRoom for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "HostelRoom deleted successfully"}, status=status.HTTP_200_OK)
class HostelRoomListAPIView(GenericAPIView):
    serializer_class = HostelRoomlistSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_hostelroom")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        list_model = HostelRoom.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(list_model, many=True)
        return  Response({"message": "HostelRoom List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
# =========================================Hostel Category============================================
class HostelCategoryAPIView(GenericAPIView):
    serializer_class = HostelCategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_hostelcategory")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        get_model = HostelCategory.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_hostelcategory")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Hostel Category Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_hostelcategory")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = HostelCategory.objects.get(id=model_id)
        except HostelCategory.DoesNotExist:
            return Response({"message": "Hostel Category not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Hostel Category for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Hostel Category updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_hostelcategory")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Hostel Category list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = HostelCategory.objects.get(id=id)
            except HostelCategory.DoesNotExist:
                return Response({"message": "Hostel Category not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Hostel Category for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Hostel Category deleted successfully"}, status=status.HTTP_200_OK)
class HostelCategoryListAPIView(GenericAPIView):
    serializer_class = HostelCategorylistSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_hostelcategory")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        list_model = HostelCategory.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(list_model, many=True)
        return  Response({"message": "Hostel Category List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
    
# =========================================Dormitory==========================================
class DormitoryAPIView(GenericAPIView):
    serializer_class = DormitorySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_dormitory")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        get_model = Dormitory.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = DormitoryGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = DormitoryGetSerializer(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_dormitory")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Dormitory Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_dormitory")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = Dormitory.objects.get(id=model_id)
        except Dormitory.DoesNotExist:
            return Response({"message": "Dormitory not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Dormitory for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Dormitory updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_dormitory")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Dormitory list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = Dormitory.objects.get(id=id)
            except Dormitory.DoesNotExist:
                return Response({"message": "Dormitory not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Dormitory for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Dormitory deleted successfully"}, status=status.HTTP_200_OK)
class DormitoryListAPIView(GenericAPIView):
    serializer_class = DormitoryListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_dormitory")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        list_model = Dormitory.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(list_model, many=True)
        return  Response({"message": "Dormitory List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
    
# =========================================Dormitory Room==========================================
class DormitoryRoomAPIView(GenericAPIView):
    serializer_class = DormitoryRoomSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_dormitoryroom")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        dormitory_id = request.query_params.get('dormitory_id', None)
        if dormitory_id:
            dormitory = get_object_or_404(Dormitory, id=dormitory_id)
            subject_filters['dormitory'] = dormitory
        get_model = DormitoryRoom.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = DormitoryRoomGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = DormitoryRoomGetSerializer(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_dormitoryroom")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "DormitoryRoom Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_dormitoryroom")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = DormitoryRoom.objects.get(id=model_id)
        except DormitoryRoom.DoesNotExist:
            return Response({"message": "DormitoryRoom not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update DormitoryRoom for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "DormitoryRoom updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_dormitoryroom")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "DormitoryRoom list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = DormitoryRoom.objects.get(id=id)
            except DormitoryRoom.DoesNotExist:
                return Response({"message": "DormitoryRoom not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update DormitoryRoom for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "DormitoryRoom deleted successfully"}, status=status.HTTP_200_OK)
class DormitoryRoomListAPIView(GenericAPIView):
    serializer_class = DormitoryRoomListSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_dormitoryroom")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        dormitory_id = request.query_params.get('dormitory_id', None)
        if dormitory_id:
            dormitory = get_object_or_404(Dormitory, id=dormitory_id)
            subject_filters['dormitory'] = dormitory
        list_model = DormitoryRoom.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(list_model, many=True)
        return  Response({"message": "DormitoryRoom List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
###################### CALENDAR ###############################################

class CalendarAPIView(GenericAPIView):
    serializer_class = EventSerializer
    permission_classes = [permissions.IsAuthenticated]

    # GET API to retrieve events by month and year
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_event")
        if error_response:
            return error_response
        search_filter={"school":school}
        month = request.query_params.get('month')
        year = request.query_params.get('year')

        if month or year:
            try:
                month = int(month)
                year = int(year)
                search_filter['date__year']=year
                search_filter['date__month']=month
                if not (1 <= month <= 12):
                    return Response({"message": "Invalid month. It should be between 1 and 12."}, status=status.HTTP_400_BAD_REQUEST)
            except ValueError:
                return Response({"message": "Invalid month or year format"}, status=status.HTTP_400_BAD_REQUEST)
        events = Event.objects.filter(**search_filter).order_by('date')
        # if not events.exists():
        #     return Response({"message": "No events found for the given month and year."}, status=status.HTTP_404_NOT_FOUND)

        page = self.paginate_queryset(events)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(events, many=True)
        return Response(serializer.data)

    # POST API to create a new event
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_event")
        if error_response:
            return error_response
        data = request.data
        data["school"] = school.id
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Event created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"message": "Event creation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    # PUT API to update an existing event by its ID
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_event")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = Event.objects.get(id=model_id)
        except Event.DoesNotExist:
            return Response({"message": "Event not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Event for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Event updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    # DELETE API to delete an existing event by its ID
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_event")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Event list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = Event.objects.get(id=id)
            except Event.DoesNotExist:
                return Response({"message": "Event not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Event for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Event deleted successfully"}, status=status.HTTP_200_OK)  
# =============================================exam========================================================

class ExamTypeAPIView(GenericAPIView):
    serializer_class = ExamTypeSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_examtype")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        get_model = ExamType.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_examtype")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Exam Type Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_exam")
        if error_response:
            return error_response

        model_id = request.data.get('id')
        try:
            exam = Exam.objects.get(id=model_id, school=school)
        except Exam.DoesNotExist:
            return Response({"message": "Exam not found"}, status=status.HTTP_404_NOT_FOUND)

        data = request.data
        examsubject_data = data.pop('examsubject', [])

        serializer = self.serializer_class(exam, data=data, partial=True)
        if serializer.is_valid():
            with transaction.atomic():
                serializer.save()
                existing_subjects = {subj.id: subj for subj in exam.examsubject_set.all()}
                for subj_data in examsubject_data:
                    subj_id = subj_data.get("id")
                    if subj_id and subj_id in existing_subjects:
                        subj_instance = existing_subjects.pop(subj_id)
                        ExamSubjectSerializer().update(subj_instance, subj_data)
                    else:
                        ExamSubject.objects.create(exam=exam, **subj_data)

                # Delete subjects not in the request
                for subj in existing_subjects.values():
                    subj.delete()

            return Response(
                {"message": "Exam updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_examtype")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Exam Type list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = ExamType.objects.get(id=id)
            except ExamType.DoesNotExist:
                return Response({"message": "Exam Type not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Exam Type for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Exam Type deleted successfully"}, status=status.HTTP_200_OK)
class ExamTypeListAPIView(GenericAPIView):
    serializer_class = ExamTypeSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_examtype")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subject_filters['active']=True
        list_model = ExamType.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(list_model, many=True)
        return  Response({"message": "Exam Type List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
    
# =============================================grade scale========================================================

class GradeScaleAPIView(GenericAPIView):
    serializer_class = GradingScaleSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_gradingscale")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        get_model = GradingScale.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_gradingscale")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Grade Scale Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_gradingscale")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = GradingScale.objects.get(id=model_id)
        except GradingScale.DoesNotExist:
            return Response({"message": "Grade Scale not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Grade Scale for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Grade Scale updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_gradingscale")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Grade Scale list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = GradingScale.objects.get(id=id)
            except GradingScale.DoesNotExist:
                return Response({"message": "Grade Scale not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Grade Scale for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Grade Scale deleted successfully"}, status=status.HTTP_200_OK)
class GradeScaleListAPIView(GenericAPIView):
    serializer_class = GradingScaleSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_gradingscale")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subject_filters['active']=True
        list_model = GradingScale.objects.filter(**subject_filters).order_by('-created_at')
        serializer = self.serializer_class(list_model, many=True)
        return  Response({"message": "Grade Scale List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  

# =============================================exam========================================================

class ExamAPIView(GenericAPIView):
    serializer_class = ExamSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_exam")
        if error_response:
            return error_response

        search_filter = {'school': school}
        exam_id = request.query_params.get('exam_id')
        if exam_id:
            exam = get_object_or_404(Exam, id=exam_id, **search_filter)
            return Response(
                {"message": "Exam retrieved successfully", "data": ExamGetSerializer(exam).data},
                status=status.HTTP_200_OK
            )

        date = request.query_params.get('date')
        class_id = request.query_params.get('class_id')
        section_id = request.query_params.get('section_id')
        if date:
            search_filter["date"] = date
        if class_id:
            sh_class = get_object_or_404(SchoolClass, id=class_id, school=school)
            search_filter["school_class"] = sh_class
        if section_id:
            section = get_object_or_404(Section, id=section_id, school=school)
            search_filter["section"] = section

        exams = Exam.objects.filter(**search_filter).order_by('-created_at')
        page = self.paginate_queryset(exams)
        if page is not None:
            serializer = ExamGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = ExamGetSerializer(exams, many=True)
        return Response({"data": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_exam")
        if error_response:
            return error_response

        data = request.data
        data['school'] = school.id  # Ensure school is set in the data

        exam_subjects = data.pop('exam_subjects', [])  # Handle nested subjects
        serializer = self.serializer_class(data=data)

        if serializer.is_valid():
            with transaction.atomic():
                exam = serializer.save()
                for subject_data in exam_subjects:
                    subject_data['exam'] = exam.id
                    subject_serializer = ExamSubjectSerializer(data=subject_data)
                    if subject_serializer.is_valid():
                        subject_serializer.save()
                    else:
                        return Response(subject_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            return Response({"message": "Exam created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        # Check permission and get school
        school, error_response = check_permission_and_get_school(request, "api_v1.change_exam")
        if error_response:
            return error_response
    
        # Get the exam ID
        exam_id = request.data.get('id')
        try:
            exam = Exam.objects.get(id=exam_id, school=school)
        except Exam.DoesNotExist:
            return Response({"message": "Exam not found"}, status=status.HTTP_404_NOT_FOUND)
    
        # Extract data from request
        data = request.data
        exam_subjects = data.pop('exam_subjects', None)  # Default to None if 'exam_subjects' is not present
    
        # Update exam details
        serializer = self.serializer_class(exam, data=data, partial=True)
        if serializer.is_valid():
            with transaction.atomic():
                serializer.save()
    
                # Update Exam Subjects only if provided
                if exam_subjects is not None:
                    # Get existing subjects
                    existing_subjects = {subject.id: subject for subject in exam.examsubject_set.all()}
    
                    # Iterate over the passed exam_subjects to update or create them
                    for subject_data in exam_subjects:
                        subject_id = subject_data.get("id")
                        if subject_id and subject_id in existing_subjects:
                            # Update existing subject
                            subject_instance = existing_subjects.pop(subject_id)
                            ExamSubjectSerializer().update(subject_instance, subject_data)
                        else:
                            # Create new subject
                            ExamSubject.objects.create(exam=exam, **subject_data)
    
                    # Delete remaining subjects not sent in the request
                    for subject in existing_subjects.values():
                        subject.delete()
    
            # Return success response
            return Response({"message": "Exam updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        # Return error if validation fails
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_exam")
        if error_response:
            return error_response

        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Exam list is required"}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            for exam_id in ids:
                try:
                    exam = Exam.objects.get(id=exam_id, school=school)
                    exam.delete()
                except Exam.DoesNotExist:
                    return Response({"message": f"Exam with id {exam_id} not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"message": "Exam(s) deleted successfully"}, status=status.HTTP_200_OK)
class ExamListAPIView(GenericAPIView):
    serializer_class = ExamSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_exam")
        if error_response:
            return error_response
        search_filter = {'school': school}
        search_filter['active'] = True
        list_model = Exam.objects.filter(**search_filter).order_by('-created_at')
        response_data = [
            {    
                "school_class":str(exam.school_class.id),
                "section":str(exam.section.id),
                "name": f"{exam.examtype.name}/{exam.mode}/{exam.center}/{exam.school_class.name}/{exam.section.name}",  # Concatenate values
                "id": str(exam.id)  # Convert UUID to string if needed
            }
            for exam in list_model
        ]

        return Response({"message": "Exam List retrieved successfully", "data": response_data}, status=status.HTTP_200_OK)
# ========================================================Admit Card=============================================================
class AdmitCardAPIView(GenericAPIView):
    serializer_class = AdmitCardSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        user = request.user
        school, error_response = check_permission_and_get_school(request, "api_v1.view_admitcard")
        if error_response:
            return error_response
        search_filter = {'school': school}
        date = request.query_params.get('date')
        class_id = request.query_params.get('class_id')
        section_id = request.query_params.get('section_id')
        student_id = request.query_params.get('student_id')
        if date:
            search_filter["exam__date"] = date
        if class_id:
            sh_class = get_object_or_404(SchoolClass, id=class_id)
            search_filter["exam__school_class"] = sh_class
        if section_id:
            section = get_object_or_404(Section, id=section_id)
            search_filter["exam__section"] = section
        if student_id:
            student = get_object_or_404(Student, id=student_id)
            search_filter["student"] = student
        role_name = user.role.name
        if role_name == "student":
           search_filter['student'] = user.student_profile
        elif role_name == "parent":
            students = Student.objects.filter(parents__in=[user.parent_profile])
            if not students.exists():
                return Response({"message": "No students found for this parent."}, status=status.HTTP_404_NOT_FOUND)
            search_filter['student__in'] = students.values_list('id', flat=True)
        # Filter by school
        admitcards = AdmitCard.objects.filter(**search_filter).order_by('-created_at')
        page = self.paginate_queryset(admitcards)
        if page is not None:
            serializer = AdmitCardGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer =AdmitCardGetSerializer(admitcards, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_admitcard")
        if error_response:
            return error_response
        
        student_ids = request.data.get('student', [])
        exam_id = request.data.get('exam', None)

        if not student_ids or not exam_id:
            return Response({"message": "Both student IDs and exam ID are required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            exam_subjects = ExamSubject.objects.filter(exam_id=exam_id)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        if not exam_subjects.exists():
            return Response({"message": "No subjects found for the given exam ID"}, status=status.HTTP_404_NOT_FOUND)
        admit_cards = []
        for student_id in student_ids:
            try:
                # Create admit card for each student
                admit_card = AdmitCard(student_id=student_id, exam_id=exam_id, school=school)
                admit_card.save()
                admit_card.exam_subjects.set(exam_subjects)  # Associate exam subjects
                admit_cards.append(admit_card)
            except Exception as e:
                return Response({"message": f"Failed to create admit card for student ID {student_id}: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Serialize and return the created admit cards
        serializer = self.serializer_class(admit_cards, many=True)
        return Response({"message": "Admit Cards created successfully", "data": serializer.data}, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_admitcard")
        if error_response:
            return error_response
        
        model_id = request.data.get('id', None)
        try:
            admit_card = AdmitCard.objects.get(id=model_id)
        except AdmitCard.DoesNotExist:
            return Response({"message": "Admit Card not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if admit_card.school != school:
            return Response({"message": "You can only update Admit Cards for your own school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(admit_card, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Admit Card updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_admitcard")
        if error_response:
            return error_response
        
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Admit Card list is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        for id in ids:
            try:
                admit_card = AdmitCard.objects.get(id=id)
            except AdmitCard.DoesNotExist:
                return Response({"message": "Admit Card not found"}, status=status.HTTP_404_NOT_FOUND)
            
            if admit_card.school != school:
                return Response({"message": "You can only delete Admit Cards for your own school."}, status=status.HTTP_403_FORBIDDEN)
            
            admit_card.delete()
        
        return Response({"message": "Admit Card(s) deleted successfully"}, status=status.HTTP_200_OK)
# ========================================================Result=============================================================
class ResultAPIView(GenericAPIView):
    serializer_class = ResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        user = request.user
        school, error_response = check_permission_and_get_school(request, "api_v1.view_admitcard")
        if error_response:
            return error_response
        search_filter = {'school': school}
        exam_filter ={'school': school}
        date = request.query_params.get('date')
        class_id = request.query_params.get('class_id')
        section_id = request.query_params.get('section_id')
        student_id = request.query_params.get('student_id')
        if date:
            exam_filter["date"] = date
        if class_id:
            sh_class = get_object_or_404(SchoolClass, id=class_id)
            exam_filter["school_class"] = sh_class
        if section_id:
            section = get_object_or_404(Section, id=section_id)
            exam_filter["section"] = section
        if student_id:
            student = get_object_or_404(Student, id=student_id)
            search_filter["student"] = student
        role_name = user.role.name
        if role_name == "student":
           search_filter['student'] = user.student_profile
        elif role_name == "parent":
            students = Student.objects.filter(parents__in=[user.parent_profile])
            if not students.exists():
                return Response({"message": "No students found for this parent."}, status=status.HTTP_404_NOT_FOUND)
            search_filter['student__in'] = students.values_list('id', flat=True)
        try:
            results_data = []
            exams = Exam.objects.filter(**exam_filter)  # or any other filtering criteria

            for exam in exams:
                exam_subjects = ExamSubject.objects.filter(exam=exam)
                if exam_subjects.exists():  # Only apply if there are subjects
                    search_filter["exam_subject__in"] = exam_subjects  # Use __in to filter by exam subjects
                    results = Result.objects.filter(**search_filter)

                    # Prepare the response structure
                    results_data.append({
                        "exam": ExamResultSerializer(exam).data,
                        "student":StudentResultSerializer(results[0].student).data,
                        "results": ResultGetSerializer(results, many=True).data
                    })

            paginator = self.pagination_class()
            paginated_data = paginator.paginate_queryset(results_data, request)
            return paginator.get_paginated_response(paginated_data)

        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_result")
        if error_response:
            return error_response

        student_id = request.data.get('student')  # Expecting a single student ID
        exam_data = request.data.get('exam_data', [])

        if not student_id or not exam_data:
            return Response({"message": "Both student ID and exam data are required"}, status=status.HTTP_400_BAD_REQUEST)

        results = []
        for subject in exam_data:
            exam_subject_id = subject.get('exam_subject')
            marks_obtained = subject.get('marks_obtained')
            grade = subject.get('grade')

            try:
                # Check if the exam subject exists
                exam_subject = ExamSubject.objects.get(id=exam_subject_id)

                # Prepare a Result instance for the student and subject
                result = Result(
                    student_id=student_id,
                    exam_subject=exam_subject,
                    marks_obtained=float(marks_obtained),  # Convert marks to float
                    grade=grade,
                    grading_scale=None,  # Assign appropriate grading scale if available
                    school=school
                )
                results.append(result)

            except ExamSubject.DoesNotExist:
                return Response({"message": f"Exam subject with ID {exam_subject_id} does not exist."}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"message": f"Failed to create result for student ID {student_id}: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Use bulk_create to save all results at once
        if results:
            Result.objects.bulk_create(results)

        # Serialize and return the created results
        serializer = ResultSerializer(results, many=True)
        return Response({"message": "Results created successfully", "data": serializer.data}, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_result")
        if error_response:
            return error_response

        student_id = request.data.get('student')  # Expecting a single student ID
        exam_data = request.data.get('exam_data', [])

        if not student_id or not exam_data:
            return Response({"message": "Both student ID and exam data are required"}, status=status.HTTP_400_BAD_REQUEST)

        updated_results = []
        for subject in exam_data:
            exam_subject_id = subject.get('exam_subject')
            marks_obtained = subject.get('marks_obtained')
            grade = subject.get('grade')

            try:
                # Check if the exam subject exists
                exam_subject = ExamSubject.objects.get(id=exam_subject_id)

                # Get the existing result for the student and exam subject
                result = get_object_or_404(Result, student_id=student_id, exam_subject=exam_subject, school=school)
                
                # Update the result fields
                result.marks_obtained = float(marks_obtained)  # Convert marks to float
                result.grade = grade

                updated_results.append(result)

            except ExamSubject.DoesNotExist:
                return Response({"message": f"Exam subject with ID {exam_subject_id} does not exist."}, status=status.HTTP_404_NOT_FOUND)
            except Result.DoesNotExist:
                return Response({"message": f"Result for student ID {student_id} with exam subject ID {exam_subject_id} does not exist."}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"message": f"Failed to update result for student ID {student_id}: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Use bulk_update to save all updated results at once
        if updated_results:
            Result.objects.bulk_update(updated_results, ['marks_obtained', 'grade'])

        # Serialize and return the updated results
        serializer = ResultSerializer(updated_results, many=True)
        return Response({"message": "Results updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_admitcard")
        if error_response:
            return error_response
        
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Admit Card list is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        for id in ids:
            try:
                delete_mdl = Result.objects.get(id=id)
            except Result.DoesNotExist:
                return Response({"message": "Admit Card not found"}, status=status.HTTP_404_NOT_FOUND)
            
            if delete_mdl.school != school:
                return Response({"message": "You can only delete Admit Cards for your own school."}, status=status.HTTP_403_FORBIDDEN)
            
            delete_mdl.delete()
        
        return Response({"message": "Results deleted successfully"}, status=status.HTTP_200_OK)
# =========================================Payroll==========================================
class PayrollAPIView(GenericAPIView):
    serializer_class = PayrollSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_payroll")
        if error_response:
            return error_response
        search_filter = {'school': school}
        date = request.query_params.get('date')
        month = request.query_params.get('month')
        user_id = request.query_params.get('user')
        if date:
            search_filter["payment_date"] = date
        if month:
            search_filter["month"] = month
        if Teacher.objects.filter(id=user_id).exists():  # Correct the spelling from 'exist' to 'exists'
            try:
                user_curr = User.objects.get(teacher_profile__id=user_id)
                search_filter["user"] = user_curr.id  # Set the user ID instead of the User object itself
            except User.DoesNotExist:
                return Response({"message": "User associated with this teacher does not exist."}, status=status.HTTP_404_NOT_FOUND)
        get_model = Payroll.objects.filter(**search_filter).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = PayrollGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = PayrollGetSerializer(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_payroll")
        if error_response:
            return error_response
        user_id = request.data.get("user")
        data = request.data.copy()  # Use copy to avoid modifying the original request data
        data['school'] = school.id 
        if Teacher.objects.filter(id=user_id).exists():  # Correct the spelling from 'exist' to 'exists'
            try:
                user_curr = User.objects.get(teacher_profile__id=user_id)
                data["user"] = user_curr.id  # Set the user ID instead of the User object itself
            except User.DoesNotExist:
                return Response({"message": "User associated with this teacher does not exist."}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Payroll Created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_payroll")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = Payroll.objects.get(id=model_id)
        except Payroll.DoesNotExist:
            return Response({"message": "Payroll not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Payroll for your own school."}, status=status.HTTP_403_FORBIDDEN)
        user_id = request.data.get("user")
        data = request.data.copy()
        if Teacher.objects.filter(id=user_id).exists():  # Correct the spelling from 'exist' to 'exists'
            try:
                user_curr = User.objects.get(teacher_profile__id=user_id)
                data["user"] = user_curr.id  # Set the user ID instead of the User object itself
            except User.DoesNotExist:
                return Response({"message": "User associated with this teacher does not exist."}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(put_model, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Payroll updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_payroll")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Payroll list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = Payroll.objects.get(id=id)
            except Payroll.DoesNotExist:
                return Response({"message": "Payroll not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Payroll for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Payroll deleted successfully"}, status=status.HTTP_200_OK)
class PayrollUserSalaryAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_payroll")
        if error_response:
            return error_response
        user_id = request.query_params.get('id')
        if not user_id:
            return Response({"message": "User is required."}, status=status.HTTP_404_NOT_FOUND)

        data={}
        if Teacher.objects.filter(id=user_id).exists():  # Correct the spelling from 'exist' to 'exists'
            try:
                user_curr = Teacher.objects.get(id=user_id)
                data["salary"]=user_curr.joining_salary
            except Teacher.DoesNotExist:
                return Response({"message": "Teacher does not exist."}, status=status.HTTP_404_NOT_FOUND)
        
        return Response({"message": "Salary fetch successfully","data":data}, status=status.HTTP_200_OK)



# ========================================================fees category=============================================================
class FeeCategoryAPIView(GenericAPIView):
    serializer_class = FeeCategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_feecategory")
        if error_response:
            return error_response
        get_model = FeeCategory.objects.filter(school=school).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_feecategory")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Fee Category Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_feecategory")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = FeeCategory.objects.get(id=model_id)
        except FeeCategory.DoesNotExist:
            return Response({"message": "Fee Category not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Fee Category for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Fee Category updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_feecategory")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Fee Category list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = FeeCategory.objects.get(id=id)
            except FeeCategory.DoesNotExist:
                return Response({"message": "Fee Category not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Fee Category for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Fee Category deleted successfully"}, status=status.HTTP_200_OK)
class FeeCategoryListAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_feecategory")
        if error_response:
            return error_response
        category_names = FeeCategory.objects.filter(
            school=school,active = True
        ).order_by('-created_at')
        serializer = FeeCategorySerializer(category_names, many=True)
        return Response({
            "message": "Fee Category List retrieved successfully",
           "data": serializer.data
        }, status=status.HTTP_200_OK)  
#===========================================================terms ================================================
class FeeTermAPIView(GenericAPIView):
    serializer_class = FeeTermSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_feeterm")
        if error_response:
            return error_response
        get_model = FeeTerm.objects.filter(school=school).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_feeterm")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Fee term Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_feeterm")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = FeeTerm.objects.get(id=model_id)
        except FeeTerm.DoesNotExist:
            return Response({"message": "Fee term not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Fee term for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Fee term updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_feecategory")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Fee term list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = FeeTerm.objects.get(id=id)
            except FeeTerm.DoesNotExist:
                return Response({"message": "Fee terms not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Fee terms for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Fee terms deleted successfully"}, status=status.HTTP_200_OK)
class FeeTermListAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_feeterm")
        if error_response:
            return error_response
        category_names = FeeTerm.objects.filter(
            school=school,active = True
        ).order_by('-created_at').values_list('name', flat=True)
        return Response({
            "message": "Fee term List retrieved successfully",
           "data": list(category_names)
        }, status=status.HTTP_200_OK)  
# =====================================================================feee Notes================================

class FeeNotesAPIView(GenericAPIView):
    serializer_class = FeeNoteSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    # GET: List all FeeStructures for the specific school
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_feenote")
        if error_response:
            return error_response
        fee_structures = FeeNote.objects.filter(school=school).order_by('-created_at')
        page = self.paginate_queryset(fee_structures)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(fee_structures, many=True)
        return Response(serializer.data)

    # POST: Create a new FeeStructure
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_feenote")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id  # Assign the school from the request
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Fee Notes created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # PUT: Update an existing FeeStructure
    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_feenote")
        if error_response:
            return error_response

        model_id = request.data.get('id', None)
        try:
            fee_structure = FeeNote.objects.get(id=model_id)
        except FeeNote.DoesNotExist:
            return Response({"message": "Fee Note not found"}, status=status.HTTP_404_NOT_FOUND)

        if fee_structure.school != school:
            return Response({"message": "You can only update Fee Note for your own school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(fee_structure, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Fee Note updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # DELETE: Delete one or multiple FeeStructures
    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_feenote")
        if error_response:
            return error_response

        ids = request.data.get('ids', [])  # Expecting a list of IDs from the request body
        if not ids:
            return Response({"message": "Fee Note list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for id in ids:
            try:
                fee_structure = FeeNote.objects.get(id=id)
            except FeeNote.DoesNotExist:
                return Response({"message": f"Fee Note with id {id} not found"}, status=status.HTTP_404_NOT_FOUND)

            if fee_structure.school != school:
                return Response({"message": "You can only delete Fee Note for your own school."}, status=status.HTTP_403_FORBIDDEN)

            fee_structure.delete()

        return Response({"message": "Fee Note deleted successfully"}, status=status.HTTP_200_OK)
 
# =====================================================================feee structure================================

class FeeStructureAPIView(GenericAPIView):
    serializer_class = FeeStructureSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    # GET: List all FeeStructures for the specific school
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_feestructure")
        if error_response:
            return error_response

        filters = {'school': school}
        feecategory_id = request.query_params.get('feecategory_id', None)
        student_id = request.query_params.get('student_id', None)
        if  feecategory_id:
            feecategory = get_object_or_404(FeeCategory, id=feecategory_id)
            filters["fee_category"] = feecategory
        if student_id:
            student = Student.objects.get(id=student_id, school=school)  # Ensure the school matches
            filters["class_assigned"] = student.school_class  # Assuming school_class exists in the Student model
            filters["session"] = student.session
        fee_structures = FeeStructure.objects.filter(**filters).order_by('-created_at')
        # Paginate queryset
        page = self.paginate_queryset(fee_structures)
        if page is not None:
            serializer = FeeStructureGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = FeeStructureGetSerializer(fee_structures, many=True)
        return Response(serializer.data)

    # POST: Create a new FeeStructure
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_feestructure")
        if error_response:
            return error_response
        
        data = request.data
        data['school'] = school.id  # Assign the school from the request
        serializer = self.serializer_class(data=data)
        
        if serializer.is_valid():
            # Save the initial fee structure
            fee_structure = serializer.save()

            # Automatically create additional FeeStructures based on the term
            term = fee_structure.term
            base_amount = fee_structure.amount

            # Define the other terms to create and calculate the amount
            related_terms = []
            if term.lower() == "monthly":
                related_terms = [("Yearly", base_amount * 12), ("Quarterly", base_amount * 3)]
            elif term.lower() == "yearly":
                related_terms = [("Monthly", base_amount / 12), ("Quarterly", base_amount / 4)]
            elif term.lower() == "quarterly":
                related_terms = [("Monthly", base_amount / 3), ("Yearly", base_amount * 4)]

            for related_term, calculated_amount in related_terms:
                # Check if a FeeStructure with the same fee_category, class_assigned, and school already exists for this term
                if not FeeStructure.objects.filter(
                    fee_category=fee_structure.fee_category,
                    class_assigned=fee_structure.class_assigned,
                    term=related_term,
                    session=fee_structure.session,
                    school=fee_structure.school,
                    branch=fee_structure.branch
                ).exists():
                    # Create the new FeeStructure with the related term and calculated amount
                    FeeStructure.objects.create(
                        fee_category=fee_structure.fee_category,
                        class_assigned=fee_structure.class_assigned,
                        term=related_term,
                        amount=calculated_amount, 
                        session=fee_structure.session,
                        late_fee=fee_structure.late_fee,  # Adjust as necessary
                        effective_from=fee_structure.effective_from,
                        effective_until=fee_structure.effective_until,
                        school=fee_structure.school,
                        branch=fee_structure.branch,
                    )

            return Response({"message": "Fee Structure created successfully, along with related terms", "data": serializer.data}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    # PUT: Update an existing FeeStructure
    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_feestructure")
        if error_response:
            return error_response

        model_id = request.data.get('id', None)
        try:
            fee_structure = FeeStructure.objects.get(id=model_id)
        except FeeStructure.DoesNotExist:
            return Response({"message": "Fee Structure not found"}, status=status.HTTP_404_NOT_FOUND)

        if fee_structure.school != school:
            return Response({"message": "You can only update Fee Structure for your own school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(fee_structure, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Fee Structure updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # DELETE: Delete one or multiple FeeStructures
    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_feestructure")
        if error_response:
            return error_response

        ids = request.data.get('ids', [])  # Expecting a list of IDs from the request body
        if not ids:
            return Response({"message": "Fee Structure list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for id in ids:
            try:
                fee_structure = FeeStructure.objects.get(id=id)
            except FeeStructure.DoesNotExist:
                return Response({"message": f"Fee Structure with id {id} not found"}, status=status.HTTP_404_NOT_FOUND)

            if fee_structure.school != school:
                return Response({"message": "You can only delete Fee Structure for your own school."}, status=status.HTTP_403_FORBIDDEN)

            fee_structure.delete()

        return Response({"message": "Fee Structure deleted successfully"}, status=status.HTTP_200_OK)
class FeeStructureListAPIView(GenericAPIView):
    serializer_class = FeeStructureSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_feecategory")
        if error_response:
            return error_response
        filters = {'school': school}
        class_id = request.query_params.get('class_id', None)
        feecategory_id = request.query_params.get('feecategory_id', None)
        if  feecategory_id:
            feecategory = get_object_or_404(FeeCategory, id=feecategory_id)
            filters["fee_category"] = feecategory
        if class_id:
            sh_class = get_object_or_404(SchoolClass, id=class_id)
            filters["class_assigned"] = sh_class
        list_model = FeeStructure.objects.filter(**filters).order_by('-created_at')
        # serializer = self.serializer_class(list_model, many=True)
        response_data = [
                    {    
                        "name": f"{feecat.fee_category.name}/{feecat.term}/{feecat.class_assigned.name}/{feecat.amount}",  # Concatenate values
                        "id": str(feecat.id)  # Convert UUID to string if needed
                    }
                    for feecat in list_model
        ]
        return Response({
            "message": "Fee Structure List retrieved successfully",
            "data": response_data
        }, status=status.HTTP_200_OK)  


class StudentFeeAPIView(generics.GenericAPIView):
    serializer_class = StudentFeeSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination  # Use your custom pagination class

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_studentfee")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        student_id = request.query_params.get('student_id', None)
        session_id = request.query_params.get('session_id', None)
        if  student_id:
            student = get_object_or_404(Student, id=student_id)
            subject_filters["student"] = student
            if session_id:
                subject_filters["academic_session"] = session_id
            else:
                subject_filters["academic_session"] = student.session
        
        get_model = StudentFee.objects.filter(**subject_filters).prefetch_related('discounts').order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer =StudentFeegetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer =StudentFeegetSerializer(get_model, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_studentfee")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Student Fee created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_studentfee")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = StudentFee.objects.get(id=model_id)
        except StudentFee.DoesNotExist:
            return Response({"message": "Student Fee not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Student Fee for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Student Fee updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_studentfee")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Student Fee list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = StudentFee.objects.get(id=id)
            except StudentFee.DoesNotExist:
                return Response({"message": "Student Fee not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only delete Student Fee for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Student Fee deleted successfully"}, status=status.HTTP_200_OK)
class StudentFeeListAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_feecategory")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        student_id = request.query_params.get('student_id', None)
        session_id = request.query_params.get('session_id', None)
        if request.user.role and request.user.role.name == "student":
            subject_filters["student"] = request.user.student_profile
    
            # Set the session based on the student's current session or the provided session_id
            if session_id:
                session = get_object_or_404(AcademicSession, id=session_id)
                subject_filters["academic_session"] = session
            else:
                subject_filters["academic_session"] = request.user.student_profile.session
    
        else:
            if student_id:
                student = get_object_or_404(Student, id=student_id)
                subject_filters["student"] = student
    
                if session_id:
                    session = get_object_or_404(AcademicSession, id=session_id)
                    subject_filters["academic_session"] = session
                else:
                    subject_filters["academic_session"] = student.session
            else:
                return Response({
                    "error": "Student ID is required for non-student users."
                }, status=status.HTTP_400_BAD_REQUEST)

        list_model = StudentFee.objects.filter(**subject_filters).order_by('-created_at')
        serializer =StudentFeegetforlistSerializer(list_model, many=True)
        return Response({
            "message": "Student Fee List retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
         

#===================================================student fee assign =============================================
class AssignStudentFeeView(APIView):
    def get(self, request, student_id, *args, **kwargs):
        """
        Get FeeStructure filtered by the student's class and session, 
        along with the student's fee record and total amount.
        """
        # Check permission and get school
        school, error_response = check_permission_and_get_school(request, "api_v1.add_studentfee")
        if error_response:
            return error_response

        try:
            # Fetch the student instance
            student = Student.objects.get(id=student_id, school=school)  # Ensure the school matches
            class_assigned = student.school_class  # Assuming school_class exists in the Student model
            session = student.session.id

            # Filter fee structures based on class and session
            fee_structures = FeeStructure.objects.filter(
                class_assigned=class_assigned,
                session=session
            )

            # Retrieve the student's fee records
            student_fees = StudentFee.objects.filter(student=student, fee_structure__in=fee_structures)

            # Calculate the total amount for the student
            total_amount = sum(student_fee.total_amount for student_fee in student_fees)

            # Prepare the response data by combining the FeeStructure and StudentFee data
            fee_data = []
            for student_fee in student_fees:
                fee_data.append({
                    "fee_structure": FeeStructureSerializer(student_fee.fee_structure).data,
                    "amount": student_fee.total_amount
                })

            return Response(
                {
                    "student": {
                        "id": student.id,
                        "name": student.name,
                        "class_assigned": class_assigned,
                        "session": session
                    },
                    "fee_data": fee_data,
                    "total_amount": total_amount
                },
                status=status.HTTP_200_OK
            )

        except Student.DoesNotExist:
            return Response({"error": "Student not found"}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_studentfee")
        if error_response:
            return error_response
        data = request.data
        student_id = data.get('student_id')
        fee_structure_ids = data.get('fee_structure_ids', [])

        if not fee_structure_ids:
            return Response(
                {"error": "No fee structures provided"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Fetch the student instance
            student = Student.objects.get(id=student_id, school=school)  # Ensure the school matches
            # Process the provided fee structure IDs
            for fee_structure_id in fee_structure_ids:
                try:
                    fee_structure = FeeStructure.objects.get(id=fee_structure_id)

                    # Create or update StudentFee for the student
                    if not StudentFee.objects.filter(student=student, fee_structure__fee_category=fee_structure.fee_category).exists():
                    # Create StudentFee if it does not already exist
                        student_fee = StudentFee.objects.create(
                            student=student,
                            fee_structure=fee_structure,
                            total_amount=fee_structure.amount,
                            academic_session=student.session,
                            school=student.school,
                            branch=student.branch,
                        )
                    else:
                        # If the fee structure is already assigned, you can skip or handle accordingly
                        continue
                except FeeStructure.DoesNotExist:
                    return Response(
                        {"error": f"Fee structure with ID {fee_structure_id} not found"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

            return Response(
                {
                    "message": "Fee structures assigned successfully",
                },
                status=status.HTTP_200_OK,
            )

        except Student.DoesNotExist:
            return Response({"error": "Student not found"}, status=status.HTTP_404_NOT_FOUND)

class PaymentAPIView(GenericAPIView):
    serializer_class = PaymentSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_payment")
        if error_response:
            return error_response

        payment_filters = {'student_fee__student__school': school}
        payments = Payment.objects.filter(**payment_filters).order_by('-payment_date')

        page = self.paginate_queryset(payments)
        if page is not None:
            serializer = PaymentGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PaymentGetSerializer(payments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_payment")
        if error_response:
            return error_response

        data = request.data
        student_fee = StudentFee.objects.get(id=data['student_fee'])

        # Ensure the student fee is linked to the correct school
        if student_fee.student.school != school:
            return Response({"message": "You can only add payment for students in your school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Payment recorded successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_payment")
        if error_response:
            return error_response

        payment_id = request.data.get('id')
        try:
            payment = Payment.objects.get(id=payment_id)
        except Payment.DoesNotExist:
            return Response({"message": "Payment not found"}, status=status.HTTP_404_NOT_FOUND)

        # Ensure the payment is linked to the correct school
        if payment.student_fee.student.school != school:
            return Response({"message": "You can only update payments for your own school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(payment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Payment updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_payment")
        if error_response:
            return error_response

        payment_ids = request.data.get('ids', [])
        if not payment_ids:
            return Response({"message": "Payment ID list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for payment_id in payment_ids:
            try:
                payment = Payment.objects.get(id=payment_id)
            except Payment.DoesNotExist:
                return Response({"message": "Payment not found"}, status=status.HTTP_404_NOT_FOUND)

            # Ensure the payment is linked to the correct school
            if payment.student_fee.student.school != school:
                return Response({"message": "You can only delete payments for your own school."}, status=status.HTTP_403_FORBIDDEN)

            payment.delete()

        return Response({"message": "Payments deleted successfully"}, status=status.HTTP_200_OK)

#===================================================Assign  Dsicount on fee=============================================
class AssignFeeDiscountAPIView(APIView):
    def post(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_feediscount")
        if error_response:
            return error_response
        studentfee_id = request.data.get('studentfee_id')
        discount_id = request.data.get('discount_id')
        discount_amount = request.data.get('discount_amount')
        discount_type = request.data.get('discount_type', 'flat')  # Default to 'flat' if not provided
        valid_until = request.data.get('valid_until')
        
        # Check if both studentfee_id and discount_id are provided
        if not studentfee_id or not discount_id:
            return Response({"error": "studentfee_id and discount_id are required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            student_fee = StudentFee.objects.get(id=studentfee_id)
            discount = Discount.objects.get(id=discount_id)
        except StudentFee.DoesNotExist:
            return Response({"error": "StudentFee with the given id does not exist"}, status=status.HTTP_404_NOT_FOUND)
        except Discount.DoesNotExist:
            return Response({"error": "Discount with the given id does not exist"}, status=status.HTTP_404_NOT_FOUND)

        # Create the FeeDiscount object
        fee_discount = FeeDiscount(
            student=student_fee.student,
            fee=student_fee,
            discount_name=discount,
            discount_amount=discount_amount,
            discount_type=discount_type,
            valid_until=valid_until,
            school=student_fee.school,
            branch=student_fee.branch
        )

        fee_discount.save()
        return Response({
            "message": "Discount assigned successfully",
            "data": FeeDiscountSerializer(fee_discount).data
        }, status=status.HTTP_200_OK)
    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_feediscount")
        if error_response:
            return error_response

        ids = request.data.get('ids', [])  # Expecting a list of IDs from the request body
        if not ids:
            return Response({"message": "Discount list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for id in ids:
            try:
                fee_structure = FeeDiscount.objects.get(id=id)
            except FeeStructure.DoesNotExist:
                return Response({"message": f"Discount with id {id} not found"}, status=status.HTTP_404_NOT_FOUND)

            if fee_structure.school != school:
                return Response({"message": "You can only delete Fee Note for your own school."}, status=status.HTTP_403_FORBIDDEN)

            fee_structure.delete()

        return Response({"message": "Discount deleted successfully"}, status=status.HTTP_200_OK)

class DiscountAPIView(GenericAPIView):
    serializer_class = DiscountSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_discount")
        if error_response:
            return error_response

        discount_filters = {'school': school}
        discounts = Discount.objects.filter(**discount_filters).order_by('-created_at')

        page = self.paginate_queryset(discounts)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.serializer_class(discounts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_discount")
        if error_response:
            return error_response

        data = request.data
        data['school'] = school.id  # Assign the school from the request
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Discount created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_discount")
        if error_response:
            return error_response

        model_id = request.data.get('id', None)
        try:
            fee_structure = Discount.objects.get(id=model_id)
        except FeeStructure.DoesNotExist:
            return Response({"message": "Discount not found"}, status=status.HTTP_404_NOT_FOUND)

        if fee_structure.school != school:
            return Response({"message": "You can only update Fee Note for your own school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(fee_structure, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Discount updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # DELETE: Delete one or multiple FeeStructures
    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_discount")
        if error_response:
            return error_response

        ids = request.data.get('ids', [])  # Expecting a list of IDs from the request body
        if not ids:
            return Response({"message": "Discount list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for id in ids:
            try:
                fee_structure = Discount.objects.get(id=id)
            except FeeStructure.DoesNotExist:
                return Response({"message": f"Discount with id {id} not found"}, status=status.HTTP_404_NOT_FOUND)

            if fee_structure.school != school:
                return Response({"message": "You can only delete Fee Note for your own school."}, status=status.HTTP_403_FORBIDDEN)

            fee_structure.delete()

        return Response({"message": "Discount deleted successfully"}, status=status.HTTP_200_OK)
class DiscountListAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_discount")
        if error_response:
            return error_response
        category_data = Discount.objects.filter(
            school=school, active=True
        ).order_by('-created_at').values_list('id', 'name')  # Fetch both 'id' and 'name'
        
        # Convert the list of tuples into a list of dictionaries
        category_names = [{"id": category[0], "name": category[1]} for category in category_data]
        
        return Response({
            "message": "Fee term List retrieved successfully",
            "data": category_names
        }, status=status.HTTP_200_OK) 

class FeeReceiptAPIView(GenericAPIView):
    serializer_class = FeeReceiptSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_feereceipt")
        if error_response:
            return error_response

        # Filter fee receipts by school using the related student fee
        receipt_filters = {'student_fee__student__school': school}
        fee_receipts = FeeReceipt.objects.filter(**receipt_filters).order_by('-receipt_date')

        page = self.paginate_queryset(fee_receipts)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.serializer_class(fee_receipts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_feereceipt")
        if error_response:
            return error_response

        data = request.data
        student_fee = StudentFee.objects.get(id=data['student_fee'])

        # Ensure the student fee is linked to the correct school
        if student_fee.student.school != school:
            return Response({"message": "You can only add fee receipt for students in your school."}, status=status.HTTP_403_FORBIDDEN)

        # Check if the payment is valid and matches the student fee
        payment = Payment.objects.get(id=data['payment'])
        if payment.student_fee != student_fee:
            return Response({"message": "The payment does not match the student fee."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Fee receipt created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_feereceipt")
        if error_response:
            return error_response

        receipt_id = request.data.get('id')
        try:
            fee_receipt = FeeReceipt.objects.get(id=receipt_id)
        except FeeReceipt.DoesNotExist:
            return Response({"message": "Fee receipt not found"}, status=status.HTTP_404_NOT_FOUND)

        # Ensure the fee receipt is linked to the correct school
        if fee_receipt.student_fee.student.school != school:
            return Response({"message": "You can only update fee receipts for your own school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(fee_receipt, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Fee receipt updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_feereceipt")
        if error_response:
            return error_response

        receipt_ids = request.data.get('ids', [])
        if not receipt_ids:
            return Response({"message": "Fee receipt ID list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for receipt_id in receipt_ids:
            try:
                fee_receipt = FeeReceipt.objects.get(id=receipt_id)
            except FeeReceipt.DoesNotExist:
                return Response({"message": "Fee receipt not found"}, status=status.HTTP_404_NOT_FOUND)

            # Ensure the fee receipt is linked to the correct school
            if fee_receipt.student_fee.student.school != school:
                return Response({"message": "You can only delete fee receipts for your own school."}, status=status.HTTP_403_FORBIDDEN)

            fee_receipt.delete()

        return Response({"message": "Fee receipt(s) deleted successfully"}, status=status.HTTP_200_OK)

# ==========================dashboard============================
class DashboardAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        # Check permissions and retrieve school instance
        school, error_response = check_permission_and_get_school(request, "api_v1.view_student")
        school, error_response = check_permission_and_get_school(request, "api_v1.view_teacher")
        if error_response:
            return error_response

        # Fetch counts for active and inactive students based on school
        student_male_active_count = Student.objects.filter(gender='male', school=school, is_active=True).count()
        student_female_active_count = Student.objects.filter(gender='female', school=school, is_active=True).count()
        student_male_inactive_count = Student.objects.filter(gender='male', school=school, is_active=False).count()
        student_female_inactive_count = Student.objects.filter(gender='female', school=school, is_active=False).count()

        # Fetch counts for active and inactive teachers based on school
        teacher_male_active_count = Teacher.objects.filter(gender='male', school=school, is_active=True).count()
        teacher_female_active_count = Teacher.objects.filter(gender='female', school=school, is_active=True).count()
        teacher_male_inactive_count = Teacher.objects.filter(gender='male', school=school, is_active=False).count()
        teacher_female_inactive_count = Teacher.objects.filter(gender='female', school=school, is_active=False).count()

        # Total counts
        total_students = student_male_active_count + student_female_active_count + student_male_inactive_count + student_female_inactive_count
        total_teachers = teacher_male_active_count + teacher_female_active_count + teacher_male_inactive_count + teacher_female_inactive_count

        # Get current month for earnings and dues calculations
        current_month_start = now().replace(day=1)
        current_month_end = current_month_start + timedelta(days=30)

        # Calculate total earnings (paid fees) and dues for the current month
        # total_earnings = Payment.objects.filter(
        #     student_fee__school=school,
        #     payment_date__range=[current_month_start, current_month_end]
        # ).aggregate(total_paid=Sum('amount_paid'))['total_paid'] or 0

        # total_dues = StudentFee.objects.filter(
        #     school=school,
        #     created_at__range=[current_month_start, current_month_end],
        #     is_paid=False
        # ).aggregate(total_due=Sum(F('total_amount') - F('paid_amount')))['total_due'] or 0

        # Prepare response data
        data = {
            "student": {
                "male": {"active": student_male_active_count, "inactive": student_male_inactive_count},
                "female": {"active": student_female_active_count, "inactive": student_female_inactive_count}
            },
            "teacher": {
                "male": {"active": teacher_male_active_count, "inactive": teacher_male_inactive_count},
                "female": {"active": teacher_female_active_count, "inactive": teacher_female_inactive_count}
            },
            "total_students": total_students,
            "total_teachers": total_teachers,
            # "total_earnings": total_earnings,
            # "total_dues": total_dues
        }
        return Response({"data":data}, status=status.HTTP_200_OK)
class DashboardCalendarAPIView(GenericAPIView):
    serializer_class = EventSerializer
    permission_classes = [permissions.IsAuthenticated]

    # GET API to retrieve events by month and year
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_event")
        if error_response:
            return error_response
        
        # Retrieve month and year from query parameters
        month = request.query_params.get('month')
        year = request.query_params.get('year')

        # Check if both month and year are provided
        if month is None or year is None:
            return Response({"message": "Month and Year are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            month = int(month)
            year = int(year)

            # Validate month range
            if not (1 <= month <= 12):
                return Response({"message": "Invalid month. It should be between 1 and 12."}, status=status.HTTP_400_BAD_REQUEST)

            # Build search filter for events
            search_filter = {"school": school, 'date__year': year, 'date__month': month}

        except ValueError:
            return Response({"message": "Invalid month or year format"}, status=status.HTTP_400_BAD_REQUEST)

        events = Event.objects.filter(**search_filter).order_by('date')

        # If no events found
        if not events.exists():
            return Response({"message": "No events found for the given month and year."}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(events, many=True)
        return Response(serializer.data)

# =======================================attendance======================================
class AttendanceAPIView(GenericAPIView):
    serializer_class = AttendanceSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        # Check user permissions and retrieve school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_attendance")
        if error_response:
            return error_response

        search_filter = {"school": school}
        date = request.query_params.get('date')
        class_id = request.query_params.get('class_id')
        section_id = request.query_params.get('section_id')
        student_id = request.query_params.get('student_id')

        if not class_id and not date:
            return Response({"message": "class_id or date is required"}, status=status.HTTP_400_BAD_REQUEST)

        if date:
            search_filter["date"] = date
        if class_id:
            sh_class = get_object_or_404(SchoolClass, id=class_id)
            search_filter["school_class"] = sh_class
        if section_id:
            section = get_object_or_404(Section, id=section_id)
            search_filter["section"] = section
        if student_id:
            student = get_object_or_404(Student, id=student_id)
            search_filter["student"] = student
        
        attendance_records = Attendance.objects.filter(**search_filter).order_by('-date')
        if not attendance_records.exists():
            return Response({"message": "No attendance records found for the given parameters."}, status=status.HTTP_404_NOT_FOUND)
        
        page = self.paginate_queryset(attendance_records)
        if page is not None:
            serializer = AttendanceGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = AttendanceGetSerializer(attendance_records, many=True)
        return Response({
            "message": "Attendance records retrieved successfully.",
            "data": serializer.data,
            "count": attendance_records.count()  # Include count in the response
            }, status=status.HTTP_200_OK)
        

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_attendance")
        if error_response:
            return error_response

        data = request.data
        student_ids = data.get('students', [])
        school_class_id = data.get('school_class')
        section_id = data.get('section')
        status_att = data.get('status')
        generator = request.user.id
        attendance_date = data.get('date', date.today())  # Use today's date if not provided

        # Validate input
        if not school_class_id or not student_ids:
            return Response({"message": "school_class and student_ids are required"}, status=status.HTTP_400_BAD_REQUEST)
        if status_att not in ['Present', 'Absent']:
            return Response({"message": "Invalid status. Only 'Present' or 'Absent' allowed."}, status=status.HTTP_400_BAD_REQUEST)

        # Filter students in the specified class and section
        students_in_class_section = Student.objects.filter(school_class=school_class_id, school=school)
        if section_id:
            students_in_class_section = students_in_class_section.filter(section=section_id)

        # Separate the students to update based on student_ids and others
        target_students = students_in_class_section.filter(id__in=student_ids)
        other_students = students_in_class_section.exclude(id__in=student_ids)

        created_records = []

        # Update attendance for specified student_ids with provided status_att
        for student in target_students:
            existing_attendance = Attendance.objects.filter(student=student, date=attendance_date).first()
            attendance_data = {
                'student': student.id,
                'status': status_att,
                'school': school.id,
                'date': attendance_date,
                'school_class': school_class_id,
                'section': section_id,
                'generator': generator,
                'branch': data.get('branch')
            }
            if existing_attendance:
                serializer = self.serializer_class(existing_attendance, data=attendance_data, partial=True)
            else:
                serializer = self.serializer_class(data=attendance_data)

            if serializer.is_valid():
                serializer.save()
                created_records.append(serializer.data)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Update attendance for other students in the class and section with the opposite status
        opposite_status = 'Absent' if status_att == 'Present' else 'Present'
        for student in other_students:
            existing_attendance = Attendance.objects.filter(student=student, date=attendance_date).first()
            attendance_data = {
                'student': student.id,
                'status': opposite_status,
                'school': school.id,
                'date': attendance_date,
                'school_class': school_class_id,
                'section': section_id,
                'generator': generator,
                'branch': data.get('branch')
            }
            if existing_attendance:
                serializer = self.serializer_class(existing_attendance, data=attendance_data, partial=True)
            else:
                serializer = self.serializer_class(data=attendance_data)

            if serializer.is_valid():
                serializer.save()
                created_records.append(serializer.data)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "message": "Attendance records created/updated successfully",
            "created_records": created_records
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_attendance")
        if error_response:
            return error_response
        attendance_id = request.data.get('id')
        attendance = get_object_or_404(Attendance, id=attendance_id)
        if attendance.school != school:
            return Response({"message": "You can only update attendance records for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(attendance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Attendance record updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_attendance")
        if error_response:
            return error_response
        attendance_ids = request.data.get('ids', [])
        if not attendance_ids:
            return Response({"message": "A list of attendance IDs is required."}, status=status.HTTP_400_BAD_REQUEST)
        for attendance_id in attendance_ids:
            try:
                attendance = Attendance.objects.get(id=attendance_id)
                if attendance.school != school:
                    return Response({"message": "You can only delete attendance records for your own school."}, status=status.HTTP_403_FORBIDDEN)
                attendance.delete()
            except Attendance.DoesNotExist:
                return Response({"message": f"Attendance record with ID {attendance_id} not found."}, status=status.HTTP_404_NOT_FOUND)

        return Response({"message": "Attendance records deleted successfully"}, status=status.HTTP_200_OK)
# =====================================promotion========================
class PromotionStudentAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_student")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        class_id = request.query_params.get('class_id', None)
        session_id = request.query_params.get('session_id', None)
        section_id = request.query_params.get('section_id', None)
        if not class_id and not session_id and not section_id:
            return Response({"message": "Class ,Section and Session not Found"}, status=status.HTTP_400_BAD_REQUEST)
        sh_class = get_object_or_404(SchoolClass, id=class_id)
        subject_filters['school_class'] = sh_class
        session = get_object_or_404(AcademicSession, id=session_id)
        subject_filters['session'] = session
        section = get_object_or_404(Section, id=section_id)
        subject_filters['section'] = section
        get_model = Student.objects.filter(**subject_filters).order_by('-created_at')
        serializer = StudentResultSerializer(get_model, many=True)
        return Response(serializer.data)
class PromotionHistoryAPIView(GenericAPIView):
    serializer_class = PromotionHistorySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_promotionhistory")
        if error_response:
            return error_response
        promotion_history = PromotionHistory.objects.filter(school=school).order_by('-promotion_date')
        page = self.paginate_queryset(promotion_history)
        if page is not None:
            serializer = PromotionHistoryGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = PromotionHistoryGetSerializer(promotion_history, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_promotionhistory")
        if error_response:
            return error_response

        data = request.data
        students = data.get('students', [])
        from_class = data.get('from_school_class')
        from_section = data.get('from_section')
        from_session = data.get('from_session')
        to_class = data.get('to_school_class')
        to_section = data.get('to_section')
        to_session = data.get('to_session')
        remarks = data.get('remarks', "")
        approved_by = request.user

        # List to hold PromotionHistory instances
        promotion_records = []
        for student_id in students:
            promotion_record = PromotionHistory(
                student_id=student_id,
                from_class_id=from_class,
                from_section_id=from_section,
                session_id=from_session,
                to_class_id=to_class,
                to_section_id=to_section,
                approved_by = approved_by,
                remarks=remarks,
                school=school,
                branch= None
            )
            promotion_records.append(promotion_record)
            # Update student's current class and section
            Student.objects.filter(id=student_id).update(
                school_class_id=to_class,
                section_id=to_section,
                session = to_session
            )
        # Use bulk_create to save all records at once
        PromotionHistory.objects.bulk_create(promotion_records)

        return Response(
            {"message": "Promotion history created successfully for all students"},
            status=status.HTTP_201_CREATED
        )

    def put(self, request, *args, **kwargs):
            # Step 1: Retrieve school and check permissions
        school, error_response = check_permission_and_get_school(request, "api_v1.change_promotionhistory")
        if error_response:
            return error_response
        
        # Step 2: Retrieve PromotionHistory object by ID and school
        model_id = request.data.get('id', None)
        try:
            promotion_history = PromotionHistory.objects.get(id=model_id, school=school)
        except PromotionHistory.DoesNotExist:
            return Response({"message": "PromotionHistory not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Step 3: Extract data from request
        student_id = request.data.get('students', promotion_history.student_id)
        from_class = request.data.get('from_school_class', promotion_history.from_class_id)
        from_section = request.data.get('from_section', promotion_history.from_section_id)
        from_session = request.data.get('from_session', promotion_history.session_id)
        to_class = request.data.get('to_school_class', promotion_history.to_class_id)
        to_section = request.data.get('to_section', promotion_history.to_section_id)
        to_session = request.data.get('to_session', promotion_history.session_id)
        remarks = request.data.get('remarks', promotion_history.remarks)
        approved_by = request.user

        # Step 4: Update PromotionHistory object
        promotion_history.student_id = student_id
        promotion_history.from_class_id = from_class
        promotion_history.from_section_id = from_section
        promotion_history.session_id = from_session
        promotion_history.to_class_id = to_class
        promotion_history.to_section_id = to_section
        promotion_history.session_id = to_session
        promotion_history.remarks = remarks
        promotion_history.approved_by = approved_by
        promotion_history.save()

        # Step 5: Update the associated Student record's class, section, and session
        Student.objects.filter(id=student_id).update(
            school_class_id=to_class,
            section_id=to_section,
            session_id=to_session
        )

        # Step 6: Serialize the updated PromotionHistory object
        serializer = self.serializer_class(promotion_history)
        
        # Step 7: Return the response
        return Response(
            {"message": "Promotion History updated successfully", "data": serializer.data},
            status=status.HTTP_200_OK
        )

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_promotionhistory")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "PromotionHistory IDs are required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = PromotionHistory.objects.get(id=id)
                delete_model.delete()
            except PromotionHistory.DoesNotExist:
                return Response({"message": f"PromotionHistory with ID {id} not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"message": "Promotion History deleted successfully"}, status=status.HTTP_200_OK)
# ================================AcademicPerformance========================
class AcademicPerformanceAPIView(GenericAPIView):
    serializer_class = AcademicPerformanceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_academicperformance")
        if error_response:
            return error_response
        performances = AcademicPerformance.objects.filter(student__school=school).order_by('-session__year')
        page = self.paginate_queryset(performances)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(performances, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_academicperformance")
        if error_response:
            return error_response
        data = request.data
        data['student'] = request.data.get('student')  # Assuming student ID is passed in the request
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Academic Performance Created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_academicperformance")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            academic_performance = AcademicPerformance.objects.get(id=model_id)
        except AcademicPerformance.DoesNotExist:
            return Response({"message": "AcademicPerformance not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(academic_performance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Academic Performance updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_academicperformance")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "AcademicPerformance IDs are required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = AcademicPerformance.objects.get(id=id)
                delete_model.delete()
            except AcademicPerformance.DoesNotExist:
                return Response({"message": f"AcademicPerformance with ID {id} not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"message": "Academic Performance deleted successfully"}, status=status.HTTP_200_OK)
# ====================================performance metric=================================
class PerformanceMetricsAPIView(GenericAPIView):
    serializer_class = PerformanceMetricsSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_performancemetrics")
        if error_response:
            return error_response
        metrics = PerformanceMetrics.objects.filter(student__school=school).order_by('-session__year')
        page = self.paginate_queryset(metrics)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(metrics, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_performancemetrics")
        if error_response:
            return error_response
        data = request.data
        data['student'] = request.data.get('student')  # Assuming student ID is passed in the request
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Performance Metrics Created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_performancemetrics")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            performance_metric = PerformanceMetrics.objects.get(id=model_id)
        except PerformanceMetrics.DoesNotExist:
            return Response({"message": "PerformanceMetrics not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(performance_metric, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Performance Metrics updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_performancemetrics")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "PerformanceMetrics IDs are required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = PerformanceMetrics.objects.get(id=id)
                delete_model.delete()
            except PerformanceMetrics.DoesNotExist:
                return Response({"message": f"PerformanceMetrics with ID {id} not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"message": "Performance Metrics deleted successfully"}, status=status.HTTP_200_OK)
# =============================================Enquiry type========================================================

class EnquiryTypeAPIView(GenericAPIView):
    serializer_class = EnquiryTypeSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_enquirytype")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        get_model = EnquiryType.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_enquirytype")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Enquiry Type Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_enquirytype")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = EnquiryType.objects.get(id=model_id)
        except EnquiryType.DoesNotExist:
            return Response({"message": "Enquiry Type not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Enquiry Type for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Enquiry Type updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_enquirytype")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Enquiry Type list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = EnquiryType.objects.get(id=id)
            except EnquiryType.DoesNotExist:
                return Response({"message": "Enquiry Type not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Enquiry Type for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Enquiry Type deleted successfully"}, status=status.HTTP_200_OK)
class EnquiryTypeListAPIView(GenericAPIView):
    serializer_class = EnquiryTypeSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_enquirytype")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subject_filters['active'] = True
        list_model = EnquiryType.objects.filter(**subject_filters).order_by('-created_at')
        names = list_model.values_list('name', flat=True)
        return Response({"message": "Enquiry Type List retrieved successfully", "data": list(names)}, status=status.HTTP_200_OK)
    
# ======================================enquiry================================

class EnquiryAPIView(GenericAPIView):
    serializer_class = EnquirySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_enquiry")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        enquiry_type = request.query_params.get('enquiry_type', None)
        status = request.query_params.get('status', None)
        if enquiry_type:
            subject_filters["enquiry_type"] = enquiry_type
        if status:
            subject_filters["status"] = status
        get_model = Enquiry.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_enquiry")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        data['user'] = request.user.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Enquiry Type Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_enquiry")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = Enquiry.objects.get(id=model_id)
        except Enquiry.DoesNotExist:
            return Response({"message": "Enquiry Type not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Enquiry Type for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Enquiry Type updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_enquiry")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Enquiry Type list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = Enquiry.objects.get(id=id)
            except Enquiry.DoesNotExist:
                return Response({"message": "Enquiry Type not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Enquiry Type for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Enquiry Type deleted successfully"}, status=status.HTTP_200_OK)

# ========================================================earning==========================================.
class EarningTypeAPIView(GenericAPIView):
    serializer_class = EarningTypeSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_earningtype")
        if error_response:
            return error_response
        filters = {'school': school}
        earning_types = EarningType.objects.filter(**filters).order_by('-created_at')
        page = self.paginate_queryset(earning_types)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(earning_types, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_earningtype")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Earning Type created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_earningtype")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = EarningType.objects.get(id=model_id)
        except EarningType.DoesNotExist:
            return Response({"message": "Earning Type not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Earning Types for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Earning Type updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_earningtype")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Earning Type list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = EarningType.objects.get(id=id)
            except EarningType.DoesNotExist:
                return Response({"message": "Earning Type not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only delete Earning Types for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Earning Type deleted successfully"}, status=status.HTTP_200_OK)

class EarningTypeListAPIView(GenericAPIView):
    serializer_class = EarningTypeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_earningtype")
        if error_response:
            return error_response
        filters = {'school': school, 'active': True}
        list_model = EarningType.objects.filter(**filters).order_by('-created_at')
        names = list_model.values_list('name', flat=True)
        return Response({"message": "Earning Type List retrieved successfully", "data": list(names)}, status=status.HTTP_200_OK)

class EarningAPIView(GenericAPIView):
    serializer_class = EarningSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_earning")
        if error_response:
            return error_response
        filters = {'school': school}
        earnings = Earning.objects.filter(**filters).order_by('-created_at')
        page = self.paginate_queryset(earnings)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(earnings, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_earning")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Earning created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_earning")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = Earning.objects.get(id=model_id)
        except Earning.DoesNotExist:
            return Response({"message": "Earning not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Earnings for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Earning updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_earning")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Earning list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = Earning.objects.get(id=id)
            except Earning.DoesNotExist:
                return Response({"message": "Earning not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only delete Earnings for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Earnings deleted successfully"}, status=status.HTTP_200_OK)
# =====================================================expensetype=================================================================
class ExpenseTypeAPIView(GenericAPIView):
    serializer_class = ExpenseTypeSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_expensetype")
        if error_response:
            return error_response
        filters = {'school': school}
        expense_types = ExpenseType.objects.filter(**filters).order_by('-created_at')
        page = self.paginate_queryset(expense_types)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(expense_types, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_expensetype")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Expense Type created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_expensetype")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            expense_type = ExpenseType.objects.get(id=model_id)
        except ExpenseType.DoesNotExist:
            return Response({"message": "Expense Type not found"}, status=status.HTTP_404_NOT_FOUND)
        if expense_type.school != school:
            return Response({"message": "You can only update Expense Types for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(expense_type, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Expense Type updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_expensetype")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Expense Type list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                expense_type = ExpenseType.objects.get(id=id)
            except ExpenseType.DoesNotExist:
                return Response({"message": f"Expense Type with ID {id} not found"}, status=status.HTTP_404_NOT_FOUND)
            if expense_type.school != school:
                return Response({"message": "You can only delete Expense Types for your own school."}, status=status.HTTP_403_FORBIDDEN)
            expense_type.delete()
        return Response({"message": "Expense Types deleted successfully"}, status=status.HTTP_200_OK)
class ExpenseTypeListAPIView(GenericAPIView):
    serializer_class = ExpenseTypeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_expensetype")
        if error_response:
            return error_response
        filters = {'school': school,"active":True}
        expense_types = ExpenseType.objects.filter(**filters).order_by('-created_at')
        names = expense_types.values_list('name', flat=True)
        return Response({"message": "Expense Type List retrieved successfully", "data": list(names)}, status=status.HTTP_200_OK)
class ExpenseAPIView(GenericAPIView):
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_expense")
        if error_response:
            return error_response
        filters = {'school': school}
        expenses = Expense.objects.filter(**filters).order_by('-created_at')
        page = self.paginate_queryset(expenses)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(expenses, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_expense")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Expense created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_expense")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            expense = Expense.objects.get(id=model_id)
        except Expense.DoesNotExist:
            return Response({"message": "Expense not found"}, status=status.HTTP_404_NOT_FOUND)
        if expense.school != school:
            return Response({"message": "You can only update expenses for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(expense, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Expense updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_expense")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Expense list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                expense = Expense.objects.get(id=id)
            except Expense.DoesNotExist:
                return Response({"message": f"Expense with ID {id} not found"}, status=status.HTTP_404_NOT_FOUND)
            if expense.school != school:
                return Response({"message": "You can only delete expenses for your own school."}, status=status.HTTP_403_FORBIDDEN)
            expense.delete()
        return Response({"message": "Expenses deleted successfully"}, status=status.HTTP_200_OK)

#####################   Audit   ##########################
class AuditAPIView(GenericAPIView):
    serializer_class = ActivityLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        user = request.user
        school, error_response = check_permission_and_get_school(request, "api_v1.view_activitylog")
        if error_response:
            return error_response
        filters = {'school': school}
        if user.role and user.role.name != "school":
            filters = {'user': user}
        expenses = ActivityLog.objects.all().order_by('-timestamp')
        page = self.paginate_queryset(expenses)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(expenses, many=True)
        return Response(serializer.data)


class LoginActivityLogAPIView(GenericAPIView):
    serializer_class = LoginActivityLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        user = request.user
        filters = {}

        # Determine the scope of logs based on the user's role
        if user.role:
            if user.role.name == "school":
                # School admin: See all logs for users under the same school
                filters['school'] = user.school
            elif user.role.name == "branch_admin":
                # Branch admin: See all logs for users under the same branch
                filters['branch'] = user.branch
            else:
                # Other roles: See only their own logs
                filters['user'] = user
        else:
            # No role: Restrict to their own logs
            filters['user'] = user

        # Fetch and order login logs
        login_logs = LoginActivityLog.objects.filter(**filters).order_by('-timestamp')

        # Handle no logs found case
        if not login_logs.exists():
            return Response({"message": "No login activity logs found."}, status=status.HTTP_404_NOT_FOUND)

        # Paginate and serialize logs
        page = self.paginate_queryset(login_logs)
        if page is not None:
            serializer = self.serializer_class(page, many=True, context={"request": request})
            return self.get_paginated_response(serializer.data)

        serializer = self.serializer_class(login_logs, many=True, context={"request": request})
        return Response(serializer.data)
    
#=========================================smisconfig=====================================
class SimsCofingAPIView(GenericAPIView):
    serializer_class = SimsConfigSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_simsconfig")
        if error_response:
            return error_response
        key_val = request.query_params.get('key', None)
        simscon = SimsConfig.objects.filter(key=key_val, school=school).order_by('-created_at')
        serializer = SimsConfigGetSerializer(simscon, many=True)  # `many=True` tells DRF it's a list of objects
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_simsconfig")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id
        key_val = data.get('key')

        if not key_val:
            return Response({"message": "Key is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if SimsConfig with the same key exists for the school
        simsconfig = SimsConfig.objects.filter(key=key_val, school=school).first()

        value_data = data.get('value', None)
        if value_data:
            try:
                # If value is passed as a string, try to parse it as JSON
                if isinstance(value_data, str):
                    value_data = json.loads(value_data)
            except json.JSONDecodeError:
                return Response({"message": "Invalid JSON format in 'value'"}, status=status.HTTP_400_BAD_REQUEST)
        
        if simsconfig:
            # Update existing SimsConfig
            simsconfig.value = value_data if value_data else simsconfig.value
            if 'image' in request.FILES:
                simsconfig.image = request.FILES['image']
            remove_image = request.data.get('remove_image', False)
            if remove_image:
                simsconfig.image = None
            simsconfig.save()
            
            return Response({
                "message": "SimsConfig updated successfully",
                "data": SimsConfigSerializer(simsconfig).data
            }, status=status.HTTP_200_OK)
        else:
            data['school'] = school.id  # Assign the school to the configuration
            serializer = self.serializer_class(data=data)

            if serializer.is_valid():
                if 'image' in request.FILES:
                    serializer.validated_data['image'] = request.FILES['image']
                remove_image = request.data.get('remove_image', False)
                if remove_image:
                    put_model.image = None
                simsconfig = serializer.save()

                return Response({
                    "message": "SimsConfig created successfully",
                    "data": SimsConfigSerializer(simsconfig).data
                }, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_simsconfig")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        
        try:
            put_model = SimsConfig.objects.get(id=model_id)
        except SimsConfig.DoesNotExist:
            return Response({"message": "SimsConfig not found"}, status=status.HTTP_404_NOT_FOUND)
        
        if put_model.school != school:
            return Response({"message": "You can only update SimsConfig for your own school."}, status=status.HTTP_403_FORBIDDEN)
        if 'image' in request.FILES:
            put_model.image = request.FILES['image']
        remove_image = request.data.get('remove_image', False)
        if remove_image:
            put_model.image = None
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "SimsConfig updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_simsconfig")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "SimsConfig list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = SimsConfig.objects.get(id=id)
            except SimsConfig.DoesNotExist:
                return Response({"message": "SimsConfig not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update SimsConfig for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "SimsConfig deleted successfully"}, status=status.HTTP_200_OK)
        
class UserImageUploadAPI(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        user_id = request.data.get('id', None)
        if not user_id:
            return Response({"message": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        if 'image' not in request.data:
            return Response({"message": "Image file is required"}, status=status.HTTP_400_BAD_REQUEST)
        # Validate the file size if required (e.g., max size 5MB)
        image = request.FILES['image']
        
        if image.size > 5 * 1024 * 1024:  # 5 MB limit
            return Response({"message": "File size exceeds the maximum limit of 5MB."}, status=status.HTTP_400_BAD_REQUEST)
        if hasattr(user, 'school') and user.school and user.role and user.role.name == "school":
            user.school.logo = image  # Update school logo
            user.school.save()
        user.image = image
        user.save()

        return Response({
            "message": "Profile image uploaded successfully",
            "data": {"user_id": user.id, "image_url": user.image.url}
        }, status=status.HTTP_200_OK)
        
        
class TotalEarningsAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None):
        school = request.user.school  # Assuming the user is linked to a school
        branch = request.query_params.get('branch')  # Optional branch filter
        year = int(request.query_params.get('year', datetime.now().year))  # Default to the current year
        period = request.query_params.get('period', 'yearly')  # Default period is yearly
        month = request.query_params.get('month')  # Optional month filter for monthly data

        # Base filters for Payment and Earning models
        payment_filter = Q(student_fee__school=school, payment_date__year=year)
        earning_filter = Q(school=school, date__year=year, amount__gt=0)

        if branch:
            payment_filter &= Q(student_fee__branch_id=branch)
            earning_filter &= Q(branch_id=branch)

        payments = Payment.objects.filter(payment_filter)
        earnings = Earning.objects.filter(earning_filter)

        def calculate_monthly_earnings(payments, earnings):
            # Aggregate earnings for each month
            monthly_payments = payments.annotate(month=ExtractMonth('payment_date')).values('month').annotate(
                total=Sum('amount_paid')).order_by('month')
            monthly_earnings = earnings.annotate(month=ExtractMonth('date')).values('month').annotate(
                total=Sum('amount')).order_by('month')

            combined_monthly = {month: 0 for month in range(1, 13)}  # Initialize all months with 0
            for item in monthly_payments:
                combined_monthly[item['month']] += item['total']
            for item in monthly_earnings:
                combined_monthly[item['month']] += item['total']

            return [
                {"month": month, "total": total} for month, total in combined_monthly.items()
            ]

        # Handle "monthly" period
        if period == 'monthly':
            if not month:
                return Response({"error": "Month parameter is required for 'monthly' period."}, status=400)

            try:
                month = int(month)
                if month < 1 or month > 12:
                    raise ValueError
            except ValueError:
                return Response({"error": "Invalid month. Provide a value between 1 and 12."}, status=400)

            payment_filter &= Q(payment_date__month=month)
            earning_filter &= Q(date__month=month)
            payments = payments.filter(payment_filter)
            earnings = earnings.filter(earning_filter)

            # Group data by day
            datewise_payments = payments.annotate(day=ExtractDay('payment_date')).values('day').annotate(
                total=Sum('amount_paid')).order_by('day')
            datewise_earnings = earnings.annotate(day=ExtractDay('date')).values('day').annotate(
                total=Sum('amount')).order_by('day')

            combined_datewise = {}
            for item in datewise_payments:
                day = item['day']
                combined_datewise[day] = combined_datewise.get(day, 0) + item['total']
            for item in datewise_earnings:
                day = item['day']
                combined_datewise[day] = combined_datewise.get(day, 0) + item['total']

            response_data = {
                "period": "monthly",
                "month": month,
                "year": year,
                "datewise_earnings": [
                    {"date": f"{year}-{month:02d}-{day:02d}", "total": total}
                    for day, total in sorted(combined_datewise.items())
                ]
            }
            return Response(response_data)

        # Handle "yearly" period with month-wise breakdown
        elif period == 'yearly':
            monthly_earnings = calculate_monthly_earnings(payments, earnings)
            response_data = {
                "period": "yearly",
                "year": year,
                "monthly_earnings": monthly_earnings,
            }
            return Response(response_data)

        # Handle "quarterly" period with month-wise breakdown
        elif period == 'quarterly':
            quarters = {
                'Q1': [1, 2, 3],
                'Q2': [4, 5, 6],
                'Q3': [7, 8, 9],
                'Q4': [10, 11, 12],
            }

            quarterly_data = {}
            for quarter, months in quarters.items():
                payments_quarter = payments.filter(payment_date__month__in=months)
                earnings_quarter = earnings.filter(date__month__in=months)
                monthly_earnings = calculate_monthly_earnings(payments_quarter, earnings_quarter)
                quarterly_data[quarter] = monthly_earnings

            response_data = {
                "period": "quarterly",
                "year": year,
                "quarterly_earnings": quarterly_data,
            }
            return Response(response_data)

        # Handle "halfyearly" period with month-wise breakdown
        elif period == 'halfyearly':
            halves = {
                'H1': [1, 2, 3, 4, 5, 6],
                'H2': [7, 8, 9, 10, 11, 12],
            }

            half_yearly_data = {}
            for half, months in halves.items():
                payments_half = payments.filter(payment_date__month__in=months)
                earnings_half = earnings.filter(date__month__in=months)
                monthly_earnings = calculate_monthly_earnings(payments_half, earnings_half)
                half_yearly_data[half] = monthly_earnings

            response_data = {
                "period": "halfyearly",
                "year": year,
                "half_yearly_earnings": half_yearly_data,
            }
            return Response(response_data)

        return Response({
            "error": "Invalid period specified. Use 'yearly', 'halfyearly', 'quarterly', or 'monthly' with a valid 'month' parameter."
        }, status=400)
        
        
        
        
        
class ExtractTextAPIView(APIView):
    """
    API to extract text from an uploaded image and return it as structured JSON.
    """

    def post(self, request):
        photo = request.FILES.get('photo')  # Get the uploaded photo file

        if not photo:
            return Response(
                {"error": "The 'photo' field is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Open and process the image using PIL
            img = Image.open(photo)
            extracted_text = pytesseract.image_to_string(img)

            # Split the extracted text into lines and remove empty lines
            text_lines = [line.strip() for line in extracted_text.splitlines() if line.strip()]

            # Return the extracted text as JSON array
            return Response(
                {"data": text_lines},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"error": "Failed to process the photo.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ClassRoomAPIView(GenericAPIView):
    serializer_class = ClassRoomSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_classroom")
        if error_response:
            return error_response

        # Filter classrooms by school
        classroom_filters = {'school': school}
        if ClassRoom.objects.filter(school = school,creator = request.user).exists():
            classroom_filters['creator']=request.user
        elif ClassRoom.objects.filter(school=school, users=request.user).exists():
            classroom_filters['users'] = request.user
        else:
            return Response({"detail": "User is not associated with any classrooms."}, status=status.HTTP_404_NOT_FOUND)

            
        classrooms = ClassRoom.objects.filter(**classroom_filters).order_by('-created_at')

        serializer = self.get_serializer(classrooms, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.add_classroom")
        if error_response:
            return error_response

        # Set the creator as the logged-in user
        data = request.data.copy()
        data['school'] = school.id
        data['creator'] = request.user.id

        # Validate and save
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Classroom created successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.change_classroom")
        if error_response:
            return error_response

        # Validate classroom existence
        classroom_id = request.data.get('classroom_id', None)
        if not classroom_id:
            return Response({"message": "Classroom ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        classroom = get_object_or_404(ClassRoom, id=classroom_id)
        if classroom.creator.school != school:
            return Response({
                "message": "You can only update classrooms for your own school."
            }, status=status.HTTP_403_FORBIDDEN)

        # Update classroom
        serializer = self.serializer_class(classroom, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Classroom updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_classroom")
        if error_response:
            return error_response

        # Delete classrooms by IDs
        ids = request.data.get('classroom_id', [])
        if not ids:
            return Response({"message": "Classroom IDs are required"}, status=status.HTTP_400_BAD_REQUEST)

        for id in ids:
            classroom = get_object_or_404(ClassRoom, id=id)
            if classroom.creator.school != school:
                return Response({
                    "message": "You can only delete classrooms for your own school."
                }, status=status.HTTP_403_FORBIDDEN)
            classroom.delete()

        return Response({"message": "Classrooms deleted successfully"}, status=status.HTTP_200_OK)

class ClassRoomMessageAPIView(GenericAPIView):
    serializer_class = ClassRoomMessageSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
    # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_classroommessage")
        if error_response:
            return error_response

        # Filter classroom messages by school
        classroom_id = request.data.get('classroom_id', None)
        if not classroom_id:
            return Response({"message": "Classroom ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        classroom = get_object_or_404(ClassRoom, id=classroom_id, creator__school=school)
        messages = ClassroomMessage.objects.filter(classroom=classroom, reply__isnull=True).order_by('-created_at')

        page = self.paginate_queryset(messages)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(messages, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_classroommessage")
        if error_response:
            return error_response

        data = request.data.copy()
        data['sender'] = request.user.id  # Authenticated user as the sender

        message_text = data.get('message', '').strip()
        attached_file = data.get('file', None)
        classroom_id = data.get('classroom_id')

        if not classroom_id:
            return Response({"message": "Classroom ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        if not message_text and not attached_file:
            return Response({"message": "Either message or file must be provided"}, status=status.HTTP_400_BAD_REQUEST)

        classroom = get_object_or_404(ClassRoom, id=classroom_id, creator__school=request.user.school)
        data['classroom'] = classroom.id

        # Handle reply if reply is provided
        reply = data.get('reply', None)
        if reply:
            reply = get_object_or_404(ClassroomMessage, id=reply, classroom=classroom)
            data['reply'] = reply.id

        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Message sent successfully",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_classroommessage")
        if error_response:
            return error_response

        message_id = request.data.get('message_id', None)
        if not message_id:
            return Response({"message": "Message ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        message = get_object_or_404(ClassroomMessage, id=message_id)
        if message.classroom.creator.school != request.user.school:
            return Response({"message": "You can only update messages for your own school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(message, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Message updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_classroommessage")
        if error_response:
            return error_response

        message_ids = request.data.get('message_id', [])
        if not message_ids:
            return Response({"message": "Message IDs are required"}, status=status.HTTP_400_BAD_REQUEST)

        for msg_id in message_ids:
            message = get_object_or_404(ClassroomMessage, id=msg_id)
            if message.classroom.creator.school != request.user.school:
                return Response({"message": "You can only delete messages for your own school."}, status=status.HTTP_403_FORBIDDEN)
            message.delete()

        return Response({"message": "Messages deleted successfully"}, status=status.HTTP_200_OK)
#======================================user list===================================================
class UserRoleListAPIView(GenericAPIView):
    serializer_class = UserRoleListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_user")
        if error_response:
            return error_response

        # Extract 'role' from query parameters
        role = request.query_params.get('role')

        if not role:
            return Response({"error": "Role parameter is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Initialize the base search filter with the school
        search_filter = {'school': school}

        # Apply role-based filters
        if role.name == 'student':
            school_class = request.query_params.get('school_class')
            section = request.query_params.get('section')
            house = request.query_params.get('house')
            club = request.query_params.get('club')

            if school_class:
                search_filter['student_profile__school_class__id'] = school_class
            if section:
                search_filter['student_profile__section__id'] = section
            if house:
                search_filter['student_profile__house__id'] = house
            if club:
                search_filter['student_profile__club__id'] = club

        elif role.name == 'teacher':
            department = request.query_params.get('department')
            designation = request.query_params.get('designation')

            if department:
                search_filter['teacher_profile__department__id'] = department
            if designation:
                search_filter['teacher_profile__designation__id'] = designation

        elif role.name == 'parent':
            school_class = request.query_params.get('school_class')
            section = request.query_params.get('section')

            if school_class:
                search_filter['parent_profile__students__school_class__id'] = school_class
            if section:
                search_filter['parent_profile__students__section__id'] = section

        else:
            return Response({"error": "Invalid role. Allowed roles are 'student', 'teacher', and 'parent'."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Fetch filtered users
        users = User.objects.filter(**search_filter).distinct()
        serializer = self.serializer_class(users, many=True)
        return Response({"message": "User list retrieved successfully", "data": serializer.data},
                        status=status.HTTP_200_OK)


# =====================================================notifiication================================================
class NotificationAPIView(GenericAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_notification")
        if error_response:
            return error_response

        notifications = Notification.objects.filter(receiver=request.user, school=school).order_by('-created_at')
        page = self.paginate_queryset(notifications)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(notifications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_notification")
        if error_response:
            return error_response

        data = request.data
        receiver_ids = data.get('receiver_ids', [])
        message = data.get('message', '')
        file = data.get('file', None)
        medium = data.get('medium', [])  # e.g., ['email', 'whatsapp', 'sms']

        if not receiver_ids:
            return Response({"message": "Receiver list is required."}, status=status.HTTP_400_BAD_REQUEST)

        # The current user is automatically the sender
        sender = request.user

        # Create notification without sender for now
        notification = Notification.objects.create(
            message=message,
            file=file,
            school=school,
            medium=medium,
            sender = sender
        )

        notification.receiver.set(User.objects.filter(id__in=receiver_ids))

        # Send notifications based on selected mediums
        for user in notification.receiver.all():
            if 'email' in medium:
                email_sent = send_email('Notification', message, user.email, file)
                if not email_sent:
                    return Response({"error": f"Failed to send email to {user.email}."},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            if 'whatsapp' in medium:
                try:
                    send_whatsapp_message(user.mobile_no, message)
                except Exception as e:
                    return Response({"error": f"Failed to send WhatsApp to {user.mobile_no}: {str(e)}"},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            if 'sms' in medium:
                try:
                    send_sms(user.mobile_no, message)
                except Exception as e:
                    return Response({"error": f"Failed to send SMS to {user.mobile_no}: {str(e)}"},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Notifications sent successfully."}, status=status.HTTP_201_CREATED)

    def delete(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_notification")
        if error_response:
            return error_response

        Notification.objects.filter(receiver=request.user, school=school).delete()
        return Response({"message": "Notifications cleared successfully."}, status=status.HTTP_200_OK)

    def put(self, request):
        notification_id = request.data.get('id')
        if not notification_id:
            return Response({"message": "Notification ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            notification = Notification.objects.get(id=notification_id, school=request.user.school)
        except Notification.DoesNotExist:
            return Response({"message": "Notification not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(notification, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Notification updated successfully.", "data": serializer.data},
                            status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_batch_emails(self, email_addresses, message):
        if len(email_addresses) > 250:
            email_addresses = email_addresses[:250]  # Restrict to max of 250 recipients

        email_sent = send_email('Notification', message, email_addresses)
        if not email_sent:
            print(f"Failed to send email to {email_addresses}: Error sending email")
            return False  # Return False if email sending fails
        return True  # Return True if email is sent successfully

    def send_whatsapp_notifications(self, mobile_numbers, message):
        # Implement sending WhatsApp messages here
        print(f"Sent WhatsApp message to {mobile_numbers}: {message}")
        return True  # Assume success for now

    def send_sms_notifications(self, mobile_numbers, message):
        # Implement sending SMS messages here
        print(f"Sent SMS to {mobile_numbers}: {message}")
        return True  # Assume success for now    
class SendMessageView(APIView):
    def post(self, request):
        message_type = request.data.get('type', 'whatsapp')  # Default to WhatsApp
        to = request.data.get('to')  # Recipient's number
        message = request.data.get('message')  # Message content

        if not to or not message:
            return Response({"error": "Both 'to' and 'message' fields are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            if message_type == 'whatsapp':
                sid = send_whatsapp_message(f'whatsapp:{to}', message)
            elif message_type == 'sms':
                sid = send_sms(to, message)
            else:
                return Response({"error": "Invalid message type. Use 'whatsapp' or 'sms'."}, status=status.HTTP_400_BAD_REQUEST)

            return Response({"message": "Message sent successfully.", "sid": sid}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)






class SendEmailView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = EmailSerializer(data=request.data)
        if serializer.is_valid():
            recipient_email = serializer.validated_data['recipient_email']
            subject = serializer.validated_data['subject']
            message = serializer.validated_data['message']
            attachment = serializer.validated_data.get('attachment', None)

            # Send the email using the helper function
            email_sent = send_email(subject, message, recipient_email, attachment)

            if email_sent:
                return Response({"message": "Email sent successfully!"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Failed to send email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#-----------------------------------------attendance register=========================================
class AttendanceRegisterAPIView(GenericAPIView):
    serializer_class = AttendanceSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_attendance")
        if error_response:
            return error_response

        search_filter = {"school": school}
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        class_id = request.query_params.get('class_id')
        section_id = request.query_params.get('section_id')
        student_id = request.query_params.get('student_id')

        if not class_id and not (year and month):
            return Response({"message": "class_id or both year and month are required"}, status=status.HTTP_400_BAD_REQUEST)

        if month:
            search_filter["date__month"] = month
        if year:
            search_filter["date__year"] = year
        if class_id:
            sh_class = get_object_or_404(SchoolClass, id=class_id)
            search_filter["school_class"] = sh_class
        if section_id:
            section = get_object_or_404(Section, id=section_id)
            search_filter["section"] = section
        if student_id:
            student = get_object_or_404(Student, id=student_id)
            search_filter["student"] = student

        attendance_records = Attendance.objects.filter(**search_filter).order_by('-date')
        if not attendance_records.exists():
            return Response({"message": "No attendance records found for the given parameters."}, status=status.HTTP_404_NOT_FOUND)

        response_data = {}
        for record in attendance_records:
            student_data = {
                "id": record.student.id,
                "name": record.student.name,
                "roll_no": record.student.roll_no,
            }

            attendance_data = {
                "date": record.date.strftime('%Y-%m-%d'),
                "month": record.date.strftime('%B'),
                "status": record.status,
            }

            if student_data["id"] not in response_data:
                response_data[student_data["id"]] = {
                    "student": student_data,
                    "attendance": [],
                }

            response_data[student_data["id"]]["attendance"].append(attendance_data)

        return Response(list(response_data.values()), status=status.HTTP_200_OK)

 


 ################################### Leave  #############################
class LeaveDashboardView(APIView):
    def get(self, request, *args, **kwargs):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_leaves")
        if error_response:
            return error_response

        # Filter leaves by school
        leave_filters = {'school': school}

        month = request.query_params.get('month')
        if month:
            try:
                # Validate that month is an integer and within range
                month = int(month)
                if 1 <= month <= 12:
                    leave_filters['from_date__month'] = month  
                    leave_filters['to_date__month'] = month  
                else:
                    return Response({'error': 'Invalid month value. Must be between 1 and 12.'}, status=status.HTTP_400_BAD_REQUEST)
            except ValueError:
                return Response({'error': 'Month must be an integer.'}, status=status.HTTP_400_BAD_REQUEST)


        leaves = Leaves.objects.filter(**leave_filters)

        # Aggregate leave counts by status
        total_leaves = leaves.count()
        approved_count = leaves.filter(status='Approved').count()
        pending_count = leaves.filter(status='Pending').count()
        rejected_count = leaves.filter(status='Rejected').count()

        data = {
            'total_leaves': total_leaves,
            'approved': approved_count,
            'pending': pending_count,
            'rejected': rejected_count
        }
        return Response(data, status=status.HTTP_200_OK)

class EnquiryDashboardView(APIView): 
    def get(self, request, *args, **kwargs):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_enquiry")
        if error_response:
            return error_response
        # Get query parameters
        branch_id = request.query_params.get('branch_id')
        # Filter enquiries by school and optionally branch
        enquiry_filters = {'school': school}
        if branch_id:
            enquiry_filters['branch_id'] = branch_id
        
        month = request.query_params.get('month')
        if month:
            try:
                # Validate that month is an integer and within range
                month = int(month)
                if 1 <= month <= 12:
                    enquiry_filters['created_at__month'] = month  
 
                else:
                    return Response({'error': 'Invalid month value. Must be between 1 and 12.'}, status=status.HTTP_400_BAD_REQUEST)
            except ValueError:
                return Response({'error': 'Month must be an integer.'}, status=status.HTTP_400_BAD_REQUEST)

        enquiries = Enquiry.objects.filter(**enquiry_filters)
        # Calculate counts for different statuses
        total_enquiries = enquiries.count()
        new_count = enquiries.filter(status='new').count()
        in_progress_count = enquiries.filter(status='in_progress').count()
        closed_count = enquiries.filter(status='closed').count()
        # Prepare response data
        data = {
            'total_enquiries': total_enquiries,
            'new': new_count,
            'in_progress': in_progress_count,
            'closed': closed_count,
        }
        return Response(data, status=status.HTTP_200_OK)
    
class DepartmentDashboardView(APIView):
    def get(self, request, *args, **kwargs):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_department")
        if error_response:
            return error_response
        # Get query parameters
        branch_id = request.query_params.get('branch_id')
        department_id = request.query_params.get('department_id')
        designation_id = request.query_params.get('designation_id')
        # Filter departments by school and optionally branch/department
        department_filters = {'school': school}
        if branch_id:
            department_filters['branch_id'] = branch_id
        if department_id:
            department_filters['id'] = department_id
        departments = Department.objects.filter(**department_filters)
        # Count total departments
        total_departments = departments.count()
        total_employee = departments.count()
        # Prepare data for each department
        data = []
        for department in departments:
            designations = department.designation_set.all()
            # Filter designations if designation_id is provided
            if designation_id:
                designations = designations.filter(id=designation_id)
            # Prepare designation data
            designation_data = []
            for designation in designations:
                employee_count = designation.teacher_set.filter(department=department).count()
                designation_data.append({
                    'designation': designation.name,
                    'employee_count': employee_count
                })
            # Sum up total employees in the department
            total_employees = sum(d['employee_count'] for d in designation_data)
            data.append({
                'department': department.name,
                'total_employees': total_employees,
                'designations': designation_data
            })
        # Prepare the final response
        response_data = {
            'total_departments': total_departments,
            'total_employees': total_employee,
            'departments': data
        }
        return Response(response_data, status=status.HTTP_200_OK)
    
from django.db.models import Count
class ClubDashboardView(APIView):
    def get(self, request, *args, **kwargs):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_club")
        if error_response:
            return error_response
        # Retrieve and filter clubs by the school
        clubs = Club.objects.filter(school=school).annotate(student_count=Count('students'))  # Use related_name 'club'
        # Prepare the response data
        data = {
            'total_clubs': clubs.count(),
            'clubs': [
                {
                    'club_name': club.name,
                    'student_count': club.student_count
                }
                for club in clubs
            ]
        }
        return Response(data, status=status.HTTP_200_OK)
    
class HouseDashboardView(APIView):
    def get(self, request, *args, **kwargs):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_house")
        if error_response:
            return error_response
        # Fetch all houses for the given school and count students related to each house
        houses = House.objects.filter(school=school).annotate(student_count=Count('student'))
        # Prepare the response data
        data = {
            'total_houses': houses.count(),
            'houses': [
                {
                    'house_name': house.name,
                    'student_count': house.student_count
                }
                for house in houses
            ]
        }
        return Response(data, status=status.HTTP_200_OK)



class DormitoryOverviewAPIView(APIView):
    """
    API to provide a dashboard overview of dormitories and hostel rooms with school-specific permissions.
    """
    def get(self, request, *args, **kwargs):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_dormitoryoverview")
        if error_response:
            return error_response

        # Metrics for the school
        total_dormitories = Dormitory.objects.filter(school=school).count()
        total_dormitory_rooms = DormitoryRoom.objects.filter(dormitory__school=school).count()
        total_hostel_rooms = HostelRoom.objects.filter(dormitory__school=school).count()
        total_hostel_categories = HostelCategory.objects.filter(dormitory__school=school).count()
        total_beds = HostelRoom.objects.filter(dormitory__school=school).aggregate(total_beds=Sum('number_of_beds'))['total_beds'] or 0

        # Occupied and available beds logic (if tracking exists, replace with actual logic)
        occupied_beds = 0  # Replace with occupancy tracking logic
        available_beds = total_beds - occupied_beds

        # Dormitory details
        dormitories = Dormitory.objects.filter(school=school).annotate(
            total_rooms=Count('dormitoryroom'),
        ).values('name', 'capacity', 'address', 'description', 'total_rooms')

        # Hostel room details
        hostel_rooms = HostelRoom.objects.filter(dormitory__school=school).values(
            'name', 'room_type', 'number_of_beds', 'cost_per_bed', 'description'
        )

        # Hostel categories
        hostel_categories = HostelCategory.objects.filter(dormitory__school=school).annotate(
            associated_dormitories=Count('dormitory')
        ).values('name', 'description', 'associated_dormitories')

        # Response data
        data = {
            "total_dormitories": total_dormitories,
            "total_dormitory_rooms": total_dormitory_rooms,
            "total_hostel_rooms": total_hostel_rooms,
            "total_hostel_categories": total_hostel_categories,
            "total_beds": total_beds,
            "occupied_beds": occupied_beds,
            "available_beds": available_beds,
            "dormitories": list(dormitories),
            "hostel_rooms": list(hostel_rooms),
            "categories": list(hostel_categories),
        }
        return Response(data, status=status.HTTP_200_OK)
        
# =========================================School Gallery============================================
class SchoolGalleryPagination(PageNumberPagination):
    page_size = 15  # You can adjust the page size as needed
    page_size_query_param = 'page_size'
    max_page_size = 100  # Limit the max page size to avoid huge data responses

class SchoolGalleryAPIView(GenericAPIView):
    serializer_class = SchoolGallerySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = SchoolGalleryPagination
    def get_categories(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_schoolgallery")
        if error_response:
            return error_response
        type = request.query_params.get('type')
        categories = SchoolGallery.objects.filter(school=school,type=type).values('category', 'description').distinct()
        categories_with_images = []
    
        for category in categories:
            image_instance = SchoolGallery.objects.filter(
                school=school, 
                type=type,
                category=category['category']
            ).first()
            
            category_data = {
                'id':image_instance.id,
                'category': category['category'],
                'description': category['description'],
                'image': image_instance.image.url if image_instance and image_instance.image else None,
                'created_at':image_instance.created_at,
                'updated_at':image_instance.updated_at
            }
            categories_with_images.append(category_data)
    
        page = self.paginate_queryset(categories_with_images)
        if page is not None:
            return self.get_paginated_response(page)
    
        return Response({"categories": categories_with_images}, status=status.HTTP_200_OK)
    def get_images_by_category(self, request, category):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_schoolgallery")
        if error_response:
            return error_response
        type = request.query_params.get('type', None)
        images = SchoolGallery.objects.filter(school=school, category=category,type=type).order_by('-created_at')
        serializer = self.serializer_class(images, many=True)
        return Response(serializer.data)
    def get(self, request, category=None):
        if category:
            return self.get_images_by_category(request, category)
        else:
            return self.get_categories(request)
    def post(self, request):
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.add_schoolgallery")
        if error_response:
            return error_response
        
        # Get the category and description from the data
        category = request.data.get('category', '')  # Get the category
        description = request.data.get('description', '')  # Get the description
        type = request.data.get('type', '') 
        # Check if any images are provided
        images = request.FILES.getlist('images')  # images will be a list of InMemoryUploadedFile objects
        if not images:
            return Response({"error": "No images provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        created_images = []  # List to store successfully created image records
        errors = []  # List to collect errors
        
        # Iterate through each image file
        for image in images:
            image_data = {
                "image": image,  # Assign the image file
                "school": school.id,  # Assign the school
                "category": category,  # Assign the category
                "description": description,  # Assign the description
                "type":type
            }
            
            # Serialize and validate the image data
            serializer = self.serializer_class(data=image_data)
            if serializer.is_valid():
                created_image = serializer.save()  # Save the image
                created_images.append(serializer.data)  # Add to success list
            else:
                errors.append(serializer.errors)  # Add validation errors

        if errors:
            return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)
        
        # Return the response with success message and created images
        return Response({
            "message": f"{len(created_images)} images created successfully",
            "created_images": created_images
        }, status=status.HTTP_200_OK)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_schoolgallery")
        if error_response:
            return error_response
        studentcat_id = request.data.get('id', None)
        try:
            schoolgallery = SchoolGallery.objects.get(id=studentcat_id)
        except SchoolGallery.DoesNotExist:
            return Response({"message": "School Gallery not found"}, status=status.HTTP_404_NOT_FOUND)
        if schoolgallery.school != school:
            return Response({"message": "You can only update School Gallery for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(schoolgallery, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "School Gallery updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_schoolgallery")
        if error_response:
            return error_response
        subject_ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not subject_ids:
            return Response({"message": "School Gallery is required"}, status=status.HTTP_400_BAD_REQUEST)
        for subject_id in subject_ids:
            try:
                schoolgallery = SchoolGallery.objects.get(id=subject_id)
            except SchoolGallery.DoesNotExist:
                return Response({"message": "student category not found"}, status=status.HTTP_404_NOT_FOUND)
            if schoolgallery.school != school:
                return Response({"message": "You can only update School Gallery for your own school."}, status=status.HTTP_403_FORBIDDEN)
            schoolgallery.delete()
        return Response({"message": "School Gallery deleted successfully"}, status=status.HTTP_200_OK)
#===================================user document========================================

class UserDocumentAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]  

    def get(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_userdocument")
        if error_response:
            return error_response
        user_id = request.query_params.get('user_id', None)
        document_filters = {'school': school}
        if not user_id:
            return Response({"message": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        document_filters['user_id'] = user_id
        documents = UserDocument.objects.filter(**document_filters).order_by('-created_at')
        serializer = UserDocumentSerializer(documents, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_userdocument")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] =school.id
        serializer = UserDocumentSerializer(data=data)
        if serializer.is_valid():
            serializer.save()  # Save the document to the database
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_userdocument")
        if error_response:
            return error_response
        document_id = request.data.get('id', None)
        if not document_id:
            return Response({"detail": "Document ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            document = UserDocument.objects.get(id=document_id)
        except UserDocument.DoesNotExist:
            return Response({"detail": "Document not found."}, status=status.HTTP_404_NOT_FOUND)
        if document.school != school:
            return Response({"message": "You can only update document for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = UserDocumentSerializer(document, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_userdocument")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Document list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = UserDocument.objects.get(id=id)
            except UserDocument.DoesNotExist:
                return Response({"message": "Document not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Document for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Document deleted successfully"}, status=status.HTTP_200_OK)
#====================================================store========================================================
class StoreAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    pagination_class = CustomPagination

    def get(self, request):
        get_model = Store.objects.all()
        # Pagination
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(get_model, request)
        if result_page is not None:
            serializer = StoreSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)
        serializer = StoreSerializer(get_model, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_store")
        if error_response:
            return error_response
        
        data = request.data
        serializer = StoreSerializer(data=data)
        
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Store created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_store")
        if error_response:
            return error_response
        
        model_id = request.data.get('id', None)
        try:
            put_model = Store.objects.get(id=model_id)
        except Store.DoesNotExist:
            return Response({"message": "Store not found"}, status=status.HTTP_404_NOT_FOUND)

        if put_model.school != school:
            return Response({"message": "You can only update Store for your own school."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = StoreSerializer(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Store updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_store")
        if error_response:
            return error_response
        
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Store list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for id in ids:
            try:
                delete_model = Store.objects.get(id=id)
            except Store.DoesNotExist:
                return Response({"message": "Store not found"}, status=status.HTTP_404_NOT_FOUND)

            if delete_model.school != school:
                return Response({"message": "You can only delete Store for your own school."}, status=status.HTTP_403_FORBIDDEN)
            
            delete_model.delete()

        return Response({"message": "Store deleted successfully"}, status=status.HTTP_200_OK)
#======================================================visitors===========================================
class VisitorAPIView(GenericAPIView):
    serializer_class = VisitorSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_visitor")
        if error_response:
            return error_response

        search_filter = {"school": school}
        user = request.user

        # If the user is a student, filter visitors for that student
        if request.user.role and request.user.role.name == "student":
            search_filter['user'] = request.user
            permanent_visitor = {
                "user": UserVisitorSerializer(user).data,
            }
            # Fetch temporary visitors (non-permanent visitors)
            temporary_visitors = Visitor.objects.filter(**search_filter).order_by('-created_at')
            temporary_page = self.paginate_queryset(temporary_visitors)
          
            if temporary_page is not None:
                temporary_serializer = VisitorGetSerializer(temporary_page, many=True)
                return self.get_paginated_response({
                    "temporary_visitors": temporary_serializer.data,
                    "permanent_visitor": permanent_visitor,
                })
            else:
                temporary_visitors_data = VisitorGetSerializer(temporary_visitors, many=True).data
                return Response({
                    "message": "Visitor data retrieved successfully.",
                    "temporary_visitors": temporary_visitors_data,
                    "permanent_visitor": permanent_visitor,
                })

        # For non-student users, fetch all visitors for the school
        visitors = Visitor.objects.filter(**search_filter).order_by('-created_at')
        page = self.paginate_queryset(visitors)
        if page is not None:
            vistor_serializer = VisitorGetSerializer(page, many=True)
            return self.get_paginated_response(vistor_serializer.data)

        visitors_data = VisitorGetSerializer(visitors, many=True).data
        return Response(visitors_data.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_visitor")
        if error_response:
            return error_response
        data = request.data.copy()
        data['user']= request.user.id
        data['school'] = school.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Visitor created successfully", "data": serializer.data},
                            status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_visitor")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = Visitor.objects.get(id=model_id)
        except Visitor.DoesNotExist:
            return Response({"message": "Visitor not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update Visitor for your own school."},
                            status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Visitor updated successfully", "data": serializer.data},
                            status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_visitor")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Visitor list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = Visitor.objects.get(id=id)
            except Visitor.DoesNotExist:
                return Response({"message": "Visitor not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only delete Visitor for your own school."},
                                status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Visitor deleted successfully"}, status=status.HTTP_200_OK)

#=============================================================================qrcode===================================================


SECRET_KEY = "1234567890123456"
class QRCodeAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    
    def get_qr_code_config(self):
        try:
            sims_config = SimsConfig.objects.get(key='qr-code')  # Assuming you're looking for the config with key 'qr-code'
            qr_code_value = sims_config.value  # Get the JSON field

            url = qr_code_value.get('url', '')  # Extract 'url' from the JSON field

            image_path = None
            if sims_config.image:
                image_path = self.request.build_absolute_uri(sims_config.image.url)  # Build full URL
            
            return {"url": url, "image_path": image_path}
        except SimsConfig.DoesNotExist:
            return {"url": "", "image_path": None}

    def encrypt_qr_id(self, qr_id):
        cipher = AES.new(SECRET_KEY.encode('utf-8'), AES.MODE_CBC)
        iv = cipher.iv
        padded_qr_id = pad(str(qr_id).encode('utf-8'), AES.block_size)
        encrypted_qr_id = cipher.encrypt(padded_qr_id)
        encrypted_data = base64.urlsafe_b64encode(iv + encrypted_qr_id).decode('utf-8')
        return encrypted_data

    def decrypt_user_id(self, encrypted_data):
        """Decrypt the encrypted user ID using AES decryption."""
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data)
            iv = decoded_data[:AES.block_size]  # Extract IV from encrypted data
            encrypted_user_id = decoded_data[AES.block_size:]
            cipher = AES.new(SECRET_KEY.encode('utf-8'), AES.MODE_CBC, iv)
            decrypted_user_id = unpad(cipher.decrypt(encrypted_user_id), AES.block_size)
            return decrypted_user_id.decode('utf-8')
        except Exception as e:
            return None

    def get(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_qrcode")
        if error_response:
            return error_response
        filters = {"school": school}
        type = request.query_params.get('type', None)
        if type:
            filters["type"] = type
        user_id = request.query_params.get('user_id')
        if user_id:
            # Check if a QR code already exists for the given user_id
            try:
                qr_code_instance = QRCode.objects.get(name=user_id, school=school)
                serializer = QRCodeSerializer(qr_code_instance)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except QRCode.DoesNotExist:
                return Response({"message": "QRCode not found"}, status=status.HTTP_404_NOT_FOUND)
        qr_code_id = self.decrypt_user_id(request.query_params.get('encrypted_id'))
        if qr_code_id:
            try:
                qr_code_instance = QRCode.objects.get(id=qr_code_id, school=school)
                return Response({"data": qr_code_instance.data}, status=status.HTTP_200_OK)
            except QRCode.DoesNotExist:
                return Response({"message": "QRCode not found"}, status=status.HTTP_404_NOT_FOUND)
        qr_code_instances = QRCode.objects.filter(**filters).order_by('-created_at')
        page = self.paginate_queryset(qr_code_instances)
        if page is not None:
            serializer = QRCodeSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = QRCodeSerializer(qr_code_instances, many=True)
        return Response(serializer.data)


    def post(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_qrcode")
        if error_response:
            return error_response
        
        config = self.get_qr_code_config()
        print(config)
        url = config.get('url', '')
        # logo_url = config.get('image_path', None)
        data = request.data.get('data')
        name = request.data.get('name')
        type = request.data.get('type')

        # Ensure data is provided
        if not data or not name:
            return Response({"message": "Data field is required"}, status=status.HTTP_400_BAD_REQUEST)
        exists, conflict_response = check_if_exists(QRCode,name=name,school=school)
        if conflict_response:
            return conflict_response
        qr_code_instance = QRCode.objects.create(name=name,data=data,type=type, school=school)
        
        encrypted_qr_id = self.encrypt_qr_id(qr_code_instance.id)
        qr_code_data = f"{url}/?qr={encrypted_qr_id}"

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_code_data)
        qr.make(fit=True)
        img = qr.make_image(fill='white', back_color='white')

        # if logo_url:
        #     response = requests.get(logo_url, stream=True)
        #     if response.status_code == 200:
        #         logo_image = Image.open(BytesIO(response.content))
        #         logo_size = 100
        #         logo_image = logo_image.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
        #         qr_width, qr_height = img.size
        #         img.paste(logo_image, ((qr_width - logo_size) // 2, (qr_height - logo_size) // 2))

        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        qr_code_image = ContentFile(buffer.read(), name=f'qrcodes/generated_qr_code_{qr_code_instance.id}.png')
        qr_code_instance.qr_code_image = qr_code_image
        qr_code_instance.save()
        
        serializer = QRCodeSerializer(qr_code_instance)
        return Response(serializer.data, status=status.HTTP_200_OK)    # def post(self, request, *args, **kwargs):

    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_qrcode")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "QRCode list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = QRCode.objects.get(id=id)
            except QRCode.DoesNotExist:
                return Response({"message": "QRCode not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only Delete QRCode for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "QRCode deleted successfully"}, status=status.HTTP_200_OK)

#=========================================================fees manager=======================================================================
def get_months_between_dates(start_date, end_date):
    current_date = start_date.replace(day=1)  # Ensure we start from the 1st day of the start month
    months = []
    
    while current_date <= end_date:
        months.append(current_date)
        current_date += relativedelta(months=1)
        
    return months

# Helper function to calculate late fee
def calculate_late_fee(payment_date, last_due_date, late_fee_per_day):
    late_days = (payment_date - last_due_date).days
    if late_days > 0:
        return late_days * late_fee_per_day  # Late fee per day from fee structure
    return 0

class StudentFeesManage(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def post(self, request, *args, **kwargs):
        student_fee_id = request.data.get('student_fee_id')
        student_fee = get_object_or_404(StudentFee, id=student_fee_id, student=request.user.student_profile)
        
        payment_amount = Decimal(request.data.get('amount_paid'))
        payment_method = request.data.get('payment_method')
        transaction_id = request.data.get('transaction_id', None)
        cheque_number = request.data.get('cheque_number', None)
        bank_name = request.data.get('bank_name', None)
        payment_months_str = request.data.get('payment_months', None)
        
        if not payment_months_str or not isinstance(payment_months_str, list):
            return Response({"error": "Payment months are required and should be a list."}, status=status.HTTP_400_BAD_REQUEST)
    
        payment_months = []
        for month_str in payment_months_str:
            try:
                month = datetime.strptime(month_str, "%Y-%m")
                payment_months.append(month)
            except ValueError:
                return Response({"error": f"Invalid payment month format: {month_str}. Use 'YYYY-MM'."}, status=status.HTTP_400_BAD_REQUEST)
    
        response_data = []
        total_paid = 0
        total_due = Decimal(0)
        discounts = student_fee.discounts.all()
        fee_structure = student_fee.fee_structure
        late_fee = fee_structure.late_fee
        
        for i, payment_month in enumerate(payment_months):
            month_key = f"{payment_month.year}-{payment_month.month:02d}-01"
    
            month_due = fee_structure.amount
    
            for discount in discounts:
                if discount.valid_until and discount.valid_until < payment_month.date():
                    continue
    
                discount_amount = discount.discount_amount
                if discount.discount_type == "Fixed":
                    month_due -= discount_amount
                elif discount.discount_type == "Percentage":
                    month_due -= (month_due * (discount_amount / 100))
                elif discount.discount_type == "Fixed Payable Once" and payment_month == payment_months[0]:
                    month_due -= discount_amount
                elif discount.discount_type == "Percentage Payable Once" and payment_month == payment_months[0]:
                    month_due -= (month_due * (discount_amount / 100))
    
            # Convert fee_structure.effective_from to an integer before using it
            try:
                effective_from_day = int(fee_structure.effective_from)
            except ValueError:
                return Response({"error": "Invalid value for effective_from, it should be an integer."}, status=status.HTTP_400_BAD_REQUEST)

            # Ensure the due_date uses a valid day
            due_date = payment_month.replace(day=effective_from_day)
            
            today = datetime.now().date()
            
            # Ensure both today and due_date are of type datetime.date
            if today > due_date.date():
                month_due += late_fee
    
            month_due = max(Decimal(0), month_due)
            total_due += month_due
    
            existing_payment = Payment.objects.filter(
                student_fee=student_fee,
                payment_date__year=payment_month.year,
                payment_date__month=payment_month.month
            ).exists()
    
            if existing_payment:
                return Response({"error": f"Payment has already been made for the month {payment_month.strftime('%Y-%m')}."},
                                status=status.HTTP_400_BAD_REQUEST)
    
        if payment_amount > total_due:
            return Response({"error": "Payment amount exceeds the total amount due."}, status=status.HTTP_400_BAD_REQUEST)
    
        for i, payment_month in enumerate(payment_months):
            month_due = fee_structure.amount
    
            for discount in discounts:
                if discount.valid_until and discount.valid_until < payment_month.date():
                    continue
                discount_amount = discount.discount_amount
                if discount.discount_type == "Fixed":
                    month_due -= discount_amount
                elif discount.discount_type == "Percentage":
                    month_due -= (month_due * (discount_amount / 100))
                elif discount.discount_type == "Fixed Payable Once" and payment_month == payment_months[0]:
                    month_due -= discount_amount
                elif discount.discount_type == "Percentage Payable Once" and payment_month == payment_months[0]:
                    month_due -= (month_due * (discount_amount / 100))
    
            today = datetime.now().date()
            due_date = payment_month.replace(day=effective_from_day)  # Use effective day here
            
            # Ensure both today and due_date are of type datetime.date
            if today > due_date.date():
                month_due += late_fee
    
            month_due = max(Decimal(0), month_due)
    
            payment = Payment.objects.create(
                student_fee=student_fee,
                amount_paid=month_due,
                payment_method=payment_method,
                transaction_id=transaction_id,
                cheque_number=cheque_number,
                bank_name=bank_name,
                payment_date=payment_month
            )
    
            receipt = FeeReceipt.objects.create(
                student_fee=student_fee,
                payment=payment,
                total_paid=month_due
            )
    
            response_data.append({
                "receipt_number": receipt.receipt_number,
                "payment_month": payment_month.strftime("%Y-%m"),
                "total_paid": month_due,
            })
    
        return Response({"message": "Payments recorded successfully.", "payments": response_data}, status=status.HTTP_200_OK)
    def get(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_studentfee")
        if error_response:
            return error_response
    
        # Ensure the user is a student
        if not hasattr(request.user, 'role') or request.user.role.name != 'student':
            return Response({"message": 'This action is only allowed for students'}, status=status.HTTP_400_BAD_REQUEST)
    
        fee_id = request.query_params.get('fee_id', None)
        if not fee_id:
            return Response({"error": "Fee ID is required."}, status=status.HTTP_400_BAD_REQUEST)
    
        # Fetch the student fee based on the provided fee_id
        try:
            student_fee = StudentFee.objects.prefetch_related('discounts').get(id=fee_id, student=request.user.student_profile)
        except StudentFee.DoesNotExist:
            return Response({"error": "Student Fee not found or does not belong to this student."}, status=status.HTTP_404_NOT_FOUND)
    
        # Prepare monthly payments dictionary
        monthly_payments = defaultdict(lambda: {
            'total_due': 0, 
            'total_paid': 0, 
            'late_fee': 0, 
            'due_date': None, 
            'overdue_amount': 0, 
            'fee_id': 0,
            'discounts': []
        })
    
        fee_structure = student_fee.fee_structure
        last_due_day = fee_structure.effective_until or fee_structure.effective_from  # Use as day number
        late_fee = fee_structure.late_fee  # Fixed late fee to add if overdue
    
        # Get payments for this fee
        payments = Payment.objects.filter(student_fee=student_fee)
    
        # Fetch any applicable discounts for this student fee
        discounts = student_fee.discounts.all()
    
        # Get academic session months
        if student_fee.academic_session:
            session_months = get_months_between_dates(student_fee.academic_session.start_date, student_fee.academic_session.end_date)
    
            # Process payments based on the fee term (Monthly, Quarterly, Yearly)
            for month in session_months:
                month_key = f"{month.year}-{month.month:02d}-01"
    
                # Apply discount amount based on discount type
                total_due = fee_structure.amount
    
                for discount in discounts:
                    discount_amount = discount.discount_amount
                    if discount.valid_until:
                        if discount.valid_until < month:
                            continue
    
                    if discount.discount_type == "Fixed":
                        total_due -= discount_amount
    
                    elif discount.discount_type == "Percentage":
                        total_due -= (total_due * (discount_amount / 100))
    
                    elif discount.discount_type == "Fixed Payable Once":
                        if month == session_months[0]:
                            total_due -= discount_amount
    
                    elif discount.discount_type == "Percentage Payable Once":
                        if month == session_months[0]:
                            total_due -= (total_due * (discount_amount / 100))
    
                    # Add discount details to the monthly payment
                    monthly_payments[month_key]['discounts'].append({
                        'name': discount.discount_name.name,
                        'description': discount.discount_name.description,
                        'discount_amount': discount_amount,
                        'discount_type': discount.discount_type
                    })
    
                # Now, set total_due based on the fee term
                if fee_structure.term == "Monthly":
                    monthly_payments[month_key]['total_due'] = total_due  # Monthly amount adjusted for discount
    
                elif fee_structure.term == "Quarterly":
                    if month in session_months[::3]:  # Every third month for quarterly payment
                        monthly_payments[month_key]['total_due'] = total_due
    
                elif fee_structure.term == "Yearly":
                    if month == session_months[0]:  # First month of the session for yearly payment
                        monthly_payments[month_key]['total_due'] = total_due
    
                elif fee_structure.term == "Payable Once":
                    if month == session_months[0]:
                        monthly_payments[month_key]['total_due'] = total_due
    
                # Set the due date for the month using the `effective_from` or `effective_until` day
                if last_due_day:
                    due_date = month.replace(day=int(last_due_day))
                else:
                    due_date = month.replace(day=12)  # Default due date (12th of the month)
    
                monthly_payments[month_key]['due_date'] = due_date
    
                # Check if the payment is overdue and apply late fee if needed
                today = datetime.now().date()
                if today > due_date:
                    total_paid = sum(payment.amount_paid for payment in payments if payment.payment_date.month == month.month and payment.payment_date.year == month.year)
                    monthly_payments[month_key]['total_paid'] = total_paid
    
                    if total_paid < monthly_payments[month_key]['total_due']:
                        overdue_amount = monthly_payments[month_key]['total_due'] - total_paid
                        monthly_payments[month_key]['overdue_amount'] = overdue_amount
    
                        # Apply late fee if payment is overdue
                        monthly_payments[month_key]['late_fee'] = late_fee  # Add the fixed late fee
                        monthly_payments[month_key]['fee_id'] = student_fee.id
    
        return Response(monthly_payments)
        
class StudentPaymentStatusAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_studentfee")
        if error_response:
            return error_response
        
        month_str = request.query_params.get('month', None)
        class_id = request.query_params.get('class_id', None)
        section_id = request.query_params.get('section_id', None)
        paidstatus = request.query_params.get('status', None)  # 'paid' or 'unpaid'
        academicsession_id = request.query_params.get('academicsession', None)
        
        if academicsession_id:
            academic_session = AcademicSession.objects.get(id=academicsession_id, school=school)
        
        if not month_str:
            return Response({"error": "Month (YYYY-MM) is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Convert the month string to a date object (first day of the selected month)
        try:
            selected_month = datetime.strptime(month_str, "%Y-%m").date()  # Convert to date
        except ValueError:
            return Response({"error": f"Invalid month format: {month_str}. Use 'YYYY-MM'."}, status=status.HTTP_400_BAD_REQUEST)

        # Filter students by class section
        studentfilter = {"school": school} 
        if not class_id:
            return Response({"error": "Class is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        schoolclass = get_object_or_404(SchoolClass, id=class_id)
        studentfilter["school_class"] = schoolclass
        
        if section_id:
            section = get_object_or_404(Section, id=section_id)
            studentfilter["section"] = section
        
        students = Student.objects.filter(**studentfilter)
        response_data = []
        
        for student in students:
            student_fees = StudentFee.objects.filter(student=student, academic_session=academic_session)
            total_paid = 0
            total_due = 0
            previous_due = 0
            payment_status = "unpaid"

            # Check for the selected month payment
            payment_for_selected_month = Payment.objects.filter(
                student_fee__in=student_fees,
                payment_date__year=selected_month.year,
                payment_date__month=selected_month.month
            ).exists()

            if payment_for_selected_month:
                payment_status = "paid"

            # Calculate the dues for previous months
            for fee in student_fees:
                fee_structure = fee.fee_structure
                session_months = get_months_between_dates(fee.academic_session.start_date, fee.academic_session.end_date)

                for session_month in session_months:
                    # Convert session_month to a date if it's a datetime object
                    if isinstance(session_month, datetime):
                        session_month = session_month.date()

                    if session_month < selected_month:
                        # Check if payment has been made for this month
                        payment_exists = Payment.objects.filter(
                            student_fee=fee,
                            payment_date__year=session_month.year,
                            payment_date__month=session_month.month
                        ).exists()

                        # If no payment exists for the past month, add to the previous due
                        if not payment_exists:
                            previous_due += fee.total_amount / len(session_months)

            if paidstatus == 'paid' and payment_status == 'unpaid':
                continue
            elif paidstatus == 'unpaid' and payment_status == 'paid':
                continue
            student_serializer = StudentGetListSerializer(student)
            fee_serializer = StudentFeegetSerializer(student_fees, many=True)
            response_data.append({
                "student": student_serializer.data,
                "fees": fee_serializer.data,
                "payment_status": payment_status,
                "previous_due": previous_due
            })

        return Response(response_data, status=status.HTTP_200_OK)

#=====================================google meet =================================================================
class MeetingAPIView(GenericAPIView):
    serializer_class = MeetingSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_meeting")
        if error_response:
            return error_response
        meeting_filters = {'school': school}
        
        type_m = request.query_params.get('type', None)
        if type_m:
            meeting_filters['type'] = type_m
        if Meeting.objects.filter(creator=request.user).exists():
            meeting_filters['creator'] = request.user
        else:
            meeting_filters['attendees'] = request.user
            meeting_filters['active']=True
        get_model = Meeting.objects.filter(**meeting_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = MeetingGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = MeetingGetSerializer(get_model, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_meeting")
        if error_response:
            return error_response

        data = request.data.copy()
        data['active']=True
        data['school'] = school.id  # Add school ID to request data
        data['creator'] = request.user.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Meeting created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_meeting")
        if error_response:
            return error_response

        model_id = request.data.get('id', None)
        try:
            put_model = Meeting.objects.get(id=model_id)
        except Meeting.DoesNotExist:
            return Response({"message": "Meeting not found"}, status=status.HTTP_404_NOT_FOUND)

        if put_model.school != school:
            return Response({"message": "You can only update meetings for your own school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Meeting updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def patch(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_meeting")
        if error_response:
            return error_response

        meeting_id = request.data.get("meeting_id", None)
        attendees_ids = request.data.get("attendees", [])
        
        if not meeting_id:
            return Response({"message": "Meeting ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not attendees_ids:
            return Response({"message": "Attendees list is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            meeting = Meeting.objects.get(id=meeting_id)
        except Meeting.DoesNotExist:
            return Response({"message": "Meeting not found"}, status=status.HTTP_404_NOT_FOUND)

        if meeting.school != school:
            return Response({"message": "You can only modify attendees for meetings in your school."}, status=status.HTTP_403_FORBIDDEN)

        attendees_to_add = []
        attendees_to_remove = []

        for attendee_id in attendees_ids:
            try:
                attendee = User.objects.get(student_profile__id=attendee_id)
                if meeting.attendees.filter(id=attendee.id).exists():
                    # Attendee exists in the meeting, so remove them
                    attendees_to_remove.append(attendee)
                else:
                    # Attendee does not exist, so add them
                    attendees_to_add.append(attendee)
            except User.DoesNotExist:
                return Response({"message": f"User with id {attendee_id} not found"}, status=status.HTTP_404_NOT_FOUND)

        # Add new attendees
        if attendees_to_add:
            meeting.attendees.add(*attendees_to_add)

        # Remove existing attendees
        if attendees_to_remove:
            meeting.attendees.remove(*attendees_to_remove)

        meeting.save()  # Save the meeting with updated attendees

        updated_attendees = meeting.attendees.all()

        return Response({
            "message": "Meeting attendees updated successfully",
            "data": {
                "meeting_id": meeting_id,
                "added_attendees": [attendee.id for attendee in attendees_to_add],
                "removed_attendees": [attendee.id for attendee in attendees_to_remove],
                "updated_attendees": [attendee.id for attendee in updated_attendees],
            }
        }, status=status.HTTP_200_OK)
    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_meeting")
        if error_response:
            return error_response

        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Meeting list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for id in ids:
            try:
                delete_model = Meeting.objects.get(id=id)
            except Meeting.DoesNotExist:
                return Response({"message": "Meeting not found"}, status=status.HTTP_404_NOT_FOUND)

            if delete_model.school != school:
                return Response({"message": "You can only delete meetings for your own school."}, status=status.HTTP_403_FORBIDDEN)

            delete_model.delete()
        return Response({"message": "Meetings deleted successfully"}, status=status.HTTP_200_OK)
# ===========================================================help and support==========================================
class HelpSupportAPIView(GenericAPIView):
    serializer_class = HelpSupportSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_helpsupport")
        if error_response:
            return error_response
        meeting_filters = {'school': school}
        if request.user.role.name != "school":
            meeting_filters['user'] = request.user
        get_model = HelpSupport.objects.filter(**meeting_filters)
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_helpsupport")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id  # Add school ID to request data
        data['user'] = request.user.id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Request created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_helpsupport")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = HelpSupport.objects.get(id=model_id)
        except HelpSupport.DoesNotExist:
            return Response({"message": "Request not found"}, status=status.HTTP_404_NOT_FOUND)

        if put_model.school != school:
            return Response({"message": "You can only update Request for your own school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Request updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_helpsupport")
        if error_response:
            return error_response

        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Request list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for id in ids:
            try:
                delete_model = HelpSupport.objects.get(id=id)
            except HelpSupport.DoesNotExist:
                return Response({"message": "Request not found"}, status=status.HTTP_404_NOT_FOUND)

            if delete_model.school != school:
                return Response({"message": "You can only delete Request for your own school."}, status=status.HTTP_403_FORBIDDEN)

            delete_model.delete()
        return Response({"message": "Request deleted successfully"}, status=status.HTTP_200_OK)


class AuditNewAPIView(GenericAPIView):
    serializer_class = CRUDEventSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        # Get the current authenticated user
        user = request.user
        
        # Check permissions and get the school (you can replace this with your actual permission check)
        school, error_response = check_permission_and_get_school(request, "easyaudit.view_crudevent")
        if error_response:
            return error_response
        
        # Set up the filters for the query
        filters = {'user__school': school}
        
        # Filter by user role (if not 'school')
        if user.role and user.role.name != "school":
            filters['user'] = user
        
        # Get the CRUDEvent data (audit log data)
        events = CRUDEvent.objects.filter(**filters)

        page = self.paginate_queryset(events)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(events, many=True)
        return Response(serializer.data)
class LoginALoginEventAPIView(GenericAPIView):
    serializer_class = LoginEventSerializer  # Your login event serializer
    permission_classes = [permissions.IsAuthenticated]  # Only authenticated users can access
    pagination_class = CustomPagination  # Custom pagination

    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"easyaudit.view_loginevent")
        if error_response:
            return error_response
        user = request.user
        filters = {'user__school':school}

        # Determine the scope of logs based on the user's role
        if user.role and user.role.name != "school":
            filters['user'] = user
        # Fetch and order login logs
        login_logs = LoginEvent.objects.filter(**filters)

        if not login_logs.exists():
            return Response({"message": "No login activity logs found."}, status=status.HTTP_404_NOT_FOUND)

        # Paginate and serialize logs
        page = self.paginate_queryset(login_logs)
        if page is not None:
            serializer = self.serializer_class(page, many=True, context={"request": request})
            return self.get_paginated_response(serializer.data)

        serializer = self.serializer_class(login_logs, many=True, context={"request": request})
        return Response(serializer.data)

# =============================================shopping cart=====================================================

class VendorNewAPIView(GenericAPIView):
    serializer_class = VendorProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_vendorprofile")
        if error_response:
            return error_response
        subject_filters = {'user__school': school}
        try:
            role_instance = Role.objects.get(name='vendor',school=school)
        except Role.DoesNotExist:
            return Response({"message": "Role not Found"}, status=status.HTTP_400_BAD_REQUEST)
        subject_filters = {'user__role': role_instance}

        get_model = VendorProfile.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = VendorGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = VendorGetSerializer(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_vendorprofile")
        if error_response:
            return error_response
        role_vendor, role_created = Role.objects.get_or_create(
            name='vendor',
            school=school,
        )
        
        data = request.data.copy()
        data['school'] = school.id
        if "store_name" in data:
            data["username"] = generate_username(data["store_name"], prefix="VN-")
        with transaction.atomic():
            user_data = {
                'username': data.get("username"),
                'password': data.get("mobile_no","0000"),  # You may want to handle this field more securely
                'mobile_no': data.get("mobile_no"),
                'email': data.get("email"),
                'name': data.get("store_name"),
                'school': school.id,
                'branch': data.get("branch_id"),
                'role': role_vendor.id
            }
            user_serializer = UserVendorSerializer(data=user_data)
            if user_serializer.is_valid():
                user_instance = user_serializer.save()
                group_name = f"{school.school_code}_{role_vendor.name}"
                group, created = Group.objects.get_or_create(name=group_name)
                user_instance.groups.add(group)
                if role_created:
                    role_vendor.group = group  # Set the group's one-to-one relationship with role
                    role_vendor.save()
                if not QRCode.objects.filter(name=user_instance.id).exists():
                    qr_data = {"id":str(user_instance.id),"name":user_instance.name if user_instance.name else "" }
                    create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school)
            else:
                return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            profile_data = {
                'user': user_instance.id,  # Associate the created user with the vendor profile
                'store_name': data.get("store_name"),
                'description': data.get("description", ""),
                'address': data.get("address"),
                'gst_no': data.get("gst_no")
            }
            vendor_serializer = VendorProfileSerializer(data=profile_data)
            if vendor_serializer.is_valid():
                vendor_serializer.save()
            else:
                return Response(vendor_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Vendor created successfully", "data": vendor_serializer.data}, status=status.HTTP_200_OK)
    def put(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_teacher")
        if error_response:
            return error_response

        model_id = request.data.get('id', None)
        if not model_id:
            return Response({"message": "Vendor ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            vendor_instance = VendorProfile.objects.get(id=model_id, user__school=school)
            user_instance = vendor_instance.user
        except User.DoesNotExist:
            return Response({"message": "Vendor not found"}, status=status.HTTP_404_NOT_FOUND)
        with transaction.atomic():
            vendor_serializer = VendorProfileSerializer(vendor_instance, data=request.data, partial=True)
            if vendor_serializer.is_valid():
                vendor_serializer.save()
            else:
                return Response(vendor_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            user_data = {}
            if 'mobile_no' in request.data:
                user_data['mobile_no'] = request.data.get('mobile_no')
            if 'store_name' in request.data:
                user_data['name'] = request.data.get('store_name')
            if 'email' in request.data:
                user_data['email'] = request.data.get('email')
            if user_data:
                user_serializer = UserVendorSerializer(user_instance, data=user_data, partial=True)
                if user_serializer.is_valid():
                    user_instance = user_serializer.save()
                    if not QRCode.objects.filter(name=user_instance.id).exists():
                        qr_data = {"id":str(user_instance.id),"name":user_instance.name if user_instance.name else "" }
                        create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school)
                else:
                    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Vendor updated successfully"}, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_teacher")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Teacher ID list is required"}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            for user_id in ids:
                try:
                    vendor_instance = VendorProfile.objects.get(id=user_id)
                    user_instance = vendor_instance.user
                except User.DoesNotExist:
                    return Response({"message": f"Vendor with ID {user_id} not found"}, status=status.HTTP_404_NOT_FOUND)
                # Verify if the student belongs to the current school
                if user_instance.school != school:
                    return Response({"message": "You can only delete Vendor from your own school."}, status=status.HTTP_403_FORBIDDEN)
                # Delete both the student and user instance
                vendor_instance.delete()
                user_instance.delete()
        return Response({"message": "Vendor deleted successfully"}, status=status.HTTP_200_OK)

# ============================================category========================================================

class CategoryAPIView(GenericAPIView):
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_category")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        get_model = Category.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_category")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id 
        data['active']=True
        category_name = data.get('category_name')
        exists, conflict_response = check_if_exists(Category, category_name=category_name,school=school)
        if conflict_response:
            return conflict_response
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Category Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_category")
        if error_response:
            return error_response

        model_id = request.data.get('id')
        try:
            put_model = Category.objects.get(id=model_id)
        except Category.DoesNotExist:
            return Response({"message": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
        category_name = request.data.get('category_name')

        if category_name and category_name != put_model.category_name:
            exists, conflict_response = check_if_exists(Category, category_name=category_name, school=school)
            if conflict_response:
                return conflict_response
        if put_model.school != school:
            return Response({"message": "You can only update Category for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Category updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_category")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "Category list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = Category.objects.get(id=id)
            except Category.DoesNotExist:
                return Response({"message": "Category not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update Category for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "Category deleted successfully"}, status=status.HTTP_200_OK)
class CategoryListAPIView(GenericAPIView):
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_category")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        subject_filters['active']=True
        list_model = Category.objects.filter(**subject_filters).order_by('-created_at')
        serializer = CategoryGetListSerializer(list_model, many=True)
        return  Response({"message": "Category List retrieved successfully","data":serializer.data}, status=status.HTTP_200_OK)  
class ProductAPIView(GenericAPIView):
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    # GET: Fetch all products with pagination
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_product")
        if error_response:
            return error_response

        product_filters = {'school': school}
        if request.user.role and request.user.role.name != "school":
            product_filters['user'] = request.user
        products = Product.objects.filter(**product_filters).order_by('-created_at')
        page = self.paginate_queryset(products)
        if page is not None:
            serializer = ProductGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = ProductGetSerializer(products, many=True)
        return Response(serializer.data)

    # POST: Create a new product
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_product")
        if error_response:
            return error_response

        data = request.data.copy()
        data['school'] = school.id
        data['user'] = request.user.id
        # Handle main image if provided
        main_image = request.FILES.get('main_image')
        if main_image:
            data['main_image'] = main_image

        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Product created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # PUT: Update a product by ID
    def put(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_product")
        if error_response:
            return error_response

        product_id = request.data.get('id')
        try:
            product = Product.objects.get(id=product_id, school=school)
        except Product.DoesNotExist:
            return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

        data = request.data.copy()
        if 'main_image' in request.FILES:
            data['main_image'] = request.FILES['main_image']

        serializer = self.serializer_class(product, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Product updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # DELETE: Delete products by ID list
    def delete(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_product")
        if error_response:
            return error_response

        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Product list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for product_id in ids:
            try:
                product = Product.objects.get(id=product_id, school=school)
            except Product.DoesNotExist:
                return Response({"message": f"Product with id {product_id} not found"}, status=status.HTTP_404_NOT_FOUND)

            product.delete()
        return Response({"message": "Products deleted successfully"}, status=status.HTTP_200_OK)
class ProductlistAPIView(GenericAPIView):
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    # GET: Fetch all products with pagination
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_product")
        if error_response:
            return error_response

        product_filters = {'school': school, 'publish': True, 'active': True}
        query = request.query_params.get('search', None)
        sort = request.query_params.get('sort', None)
        category = request.query_params.get('category', None)

        if query:
            product_filters['product_name__icontains'] = query
        if category:
            product_filters['category']=category

        products = Product.objects.filter(**product_filters).order_by('-created_at')

        if sort:
            if sort == 'price_low_to_high':
                products = products.order_by('price')
            elif sort == 'price_high_to_low':
                products = products.order_by('-price')  # Assuming rating field exists

        # Paginate the products
        page = self.paginate_queryset(products)
        if page is not None:
            serializer = ProductGetListSerializer(page, many=True,context={'request': request})
            return self.get_paginated_response(serializer.data)

        # If no pagination, return the serialized products
        serializer = ProductGetListSerializer(products, many=True,context={'request': request})
        return Response(serializer.data)
class ProductDetailAPIView(GenericAPIView):
    serializer_class = ProductDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        product_id = kwargs.get('pk')  # Get the product ID from the URL

        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the product details
        serializer = self.get_serializer(product, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
class SpecificationAPIView(GenericAPIView):
    serializer_class = SpecificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    # GET: Fetch all products with pagination
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_specification")
        if error_response:
            return error_response
        product_filters = {'school': school}
        product_id = request.query_params.get('product_id', None)
        if not product_id:
            return Response({"message": "Product Id is required"}, status=status.HTTP_400_BAD_REQUEST)
        if product_id:
            product_filters['product'] =  product_id
        products = Specification.objects.filter(**product_filters).order_by('-created_at')
        serializer = self.serializer_class(products, many=True)
        return Response(serializer.data)

    # POST: Create a new product
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_specification")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id 
        product_id = request.data.get('product_id')
        if not product_id:
            return Response({"message": "Product Id is required"}, status=status.HTTP_400_BAD_REQUEST)
        if product_id:
            data['product'] = product_id
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Specification Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_specification")
        if error_response:
            return error_response
        id_image = request.data.get('id', [])
        if not id_image:
            return Response({"message": "Id is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            product = Specification.objects.get(id=id_image, school=school)
        except Specification.DoesNotExist:
            return Response({"message": f"Product Specification with id {id_image} not found"}, status=status.HTTP_404_NOT_FOUND)
        product.delete()
        return Response({"message": "Product Specification deleted successfully"}, status=status.HTTP_200_OK)

class ProductImageAPIView(GenericAPIView):
    serializer_class = ProductImageSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    # GET: Fetch all products with pagination
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_productimage")
        if error_response:
            return error_response
        product_filters = {'school': school}
        product_id = request.query_params.get('product_id', None)
        if not product_id:
            return Response({"message": "Product Id is required"}, status=status.HTTP_400_BAD_REQUEST)
        if product_id:
            product_filters['product'] =  product_id
        products = ProductImage.objects.filter(**product_filters).order_by('-created_at')
        serializer = self.serializer_class(products, many=True)
        return Response(serializer.data)

    # POST: Create a new product
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_productimage")
        if error_response:
            return error_response
        product_id = request.data.get('product_id')
        images = request.FILES.getlist('images')  # Assuming images are sent as multiple files under 'images'
        if not product_id:
            return Response({"message": "Product ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not images:
            return Response({"message": "At least one image is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            product = Product.objects.get(id=product_id, school=school)
        except Product.DoesNotExist:
            return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
        product_images = []
        for image in images:
            product_images.append(ProductImage(
                product=product,
                image=image,
                school=school,
            ))
        with transaction.atomic():
            ProductImage.objects.bulk_create(product_images)
        return Response({"message": "Product images added successfully"}, status=status.HTTP_200_OK)
    def delete(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_productimage")
        if error_response:
            return error_response
        id_image = request.data.get('id', [])
        if not id_image:
            return Response({"message": "Id is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            product = ProductImage.objects.get(id=id_image, school=school)
        except ProductImage.DoesNotExist:
            return Response({"message": f"Product Image with id {id_image} not found"}, status=status.HTTP_404_NOT_FOUND)
        product.delete()
        return Response({"message": "Product Image deleted successfully"}, status=status.HTTP_200_OK)

class WhishlistAPIView(GenericAPIView): 
    serializer_class = WhistListSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    # GET: Fetch all products with pagination
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_wishlist")
        if error_response:
            return error_response
        products = Wishlist.objects.filter(user=request.user, school=school).order_by('-created_at')
        page = self.paginate_queryset(products)
        if page is not None:
            serializer = WhistListGetSerializer(page, many=True,context={'request': request})
            return self.get_paginated_response(serializer.data)
        serializer = WhistListGetSerializer(products, many=True,context={'request': request})
        return Response(serializer.data)

    # POST: Create a new product
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_wishlist")
        if error_response:
            return error_response
        product_id = request.query_params.get('product_id', None)
        if not product_id:
            return Response({"message": "Product ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
        wishlist, created = Wishlist.objects.get_or_create(user=request.user, school=school)
        if product in wishlist.products.all():
            wishlist.products.remove(product)
            return Response({"message": "Product removed from wishlist successfully"}, status=status.HTTP_200_OK)
        else:
            wishlist.products.add(product)
            return Response({"message": "Product added to wishlist successfully"}, status=status.HTTP_200_OK)
class CartAPIView(GenericAPIView): 
    serializer_class = CartSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    # GET: Fetch all products with pagination
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_productimage")
        if error_response:
            return error_response
        cart = Cart.objects.filter(school= school,is_paid=False,user=request.user).order_by('-created_at')
        page = self.paginate_queryset(cart)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(cart, many=True)
        return Response(serializer.data)

    # POST: Create a new product
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_cart")
        if error_response:
            return error_response
        product_id = request.query_params.get('product_id', None)
        if not product_id:
            return Response({"message": "Product ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
        cart, created = Cart.objects.get_or_create(user=request.user, school=school, is_paid = False)
        cartitem, _ = CartItems.objects.get_or_create(cart = cart , product = product)
        if not _:
            cartitem.quantity+=1
            cartitem.save()
        else:
            pass
        return Response({"message": "Item Added to Cart successfully"}, status=status.HTTP_200_OK)

    def delete(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_cart")
        if error_response:
            return error_response
        cartitem_id = request.query_params.get('cartitem_id', None)
        if not cartitem_id:
            return Response({"message": "Cartitem  is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            cartitem = CartItems.objects.get(id=cartitem_id)
        except Product.DoesNotExist:
            return Response({"message": "Cart Item not found"}, status=status.HTTP_404_NOT_FOUND)
        cartitem.delete()
        return Response({"message": "Item Remove from Cart successfully"}, status=status.HTTP_200_OK)
        
class CartWishNotiCountView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        # Cart items count
        cart_item_count = CartItems.objects.filter(cart__is_paid=False, cart__user=user).count()
        # Wishlist items count
        wishlist = Wishlist.objects.filter(user=user).first()
        wishlist_count = wishlist.products.count() if wishlist else 0
        # Notifications count
        notification_count = Notification.objects.filter(receiver=user).count()

        # Consolidated response
        data = {
            'cart_item_count': cart_item_count,
            'wishlist_count': wishlist_count,
            'notification_count': notification_count,
        }
        return Response(data)
#===============================================google meeting====================================================

def increase_time_by_minutes(input_time,duration):
    input_datetime = datetime.strptime(input_time, '%H:%M')
    timedelta_minutes = timedelta(minutes=int(duration))  # Define the time delta for minutes
    new_datetime = input_datetime + timedelta_minutes  # Add  minutes
    return new_datetime.strftime('%H:%M')  # Return the updated time as a string in 'HH:MM' format

class ScheduleMeetingView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_meeting")
        if error_response:
            return error_response
        user = request.user
        school_class = request.data.get('school_class')
        section = request.data.get('section')
        time1 = request.data.get('start_time')
        date = request.data.get('start_date')
        if not time1 or not date:
            return Response({'message': 'Start time and start date are required.'}, status=status.HTTP_400_BAD_REQUEST)
        start_time_str = f"{date}T{time1}:00"
        try:
            start_time = datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            return Response({'message': 'Invalid start time format. Please use the format HH:MM.'}, status=status.HTTP_400_BAD_REQUEST)
        time2 = increase_time_by_minutes(time1,request.data.get('time_duration'))
        end_time_str = f"{date}T{time2}:00"
        try:
            end_time = datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            return Response({'message': 'Invalid end time format. Please use the format HH:MM.'}, status=status.HTTP_400_BAD_REQUEST)
        SCOPES = ['https://www.googleapis.com/auth/calendar']
        credentials = None
        token_path = os.path.join(settings.BASE_DIR, 'token.json')

        if os.path.exists(token_path):
            credentials = Credentials.from_authorized_user_file(token_path, SCOPES)

        if not credentials or not credentials.valid:
            if credentials and credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    settings.GOOGLE_CREDENTIALS_FILE, SCOPES
                )
                credentials = flow.run_local_server(port=0)
            with open(token_path, 'w') as token:
                token.write(credentials.to_json())

        service = build('calendar', 'v3', credentials=credentials)

        start_time_utc = start_time.replace(tzinfo=pytz.utc)
        end_time_utc = end_time.replace(tzinfo=pytz.utc)

        title = request.data.get('description', 'Schools meeting')

        attendees_ids = request.data.get('attendees', [])
        guests_emails = request.data.get('guests', [])

        attendees = User.objects.filter(id__in=attendees_ids)
        attendees_emails = [attendee.email for attendee in attendees]

        attendees_emails.append(user.email)

        all_mails = attendees_emails + guests_emails
        all_emails = []
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$'
        for i in all_mails:
            if re.match(email_regex,i):
                all_emails.append(i)
        # Prepare event data for Google Calendar
        event = {
            'summary': title,
            'start': {'dateTime': start_time_utc.isoformat()},
            'end': {'dateTime': end_time_utc.isoformat()},
            'attendees': [{'email': email} for email in all_emails],
            'conferenceData': {
                'createRequest': {
                    'requestId': 'sample123',
                    'conferenceSolutionKey': {
                        'type': 'hangoutsMeet'
                    },
                    'status': {
                        'statusCode': 'success'
                    }
                }
            }
        }

        try:
            # Create Google Calendar Event
            event = service.events().insert(
                calendarId='primary',
                body=event,
                conferenceDataVersion=1
            ).execute()

            # Extract the Meet link
            meet_link = event.get('conferenceData').get('entryPoints')[0].get('uri')

            # Save the meeting to the database
            meeting = Meeting.objects.create(
                creator=user,
                type="google meeting",
                school_class=school_class,
                section=section,
                start_date=start_time_utc,
                start_time=start_time_utc.time(),
                time_duration=timedelta(minutes=60),  # Assuming a fixed 60 minutes duration
                meeting_link=meet_link,
                guests=guests_emails,  # Store the guest emails
                school=school,
                description = title
            )
            meeting.attendees.set(attendees)

            return Response({
                'message': 'Meeting scheduled successfully',
                'event_link': event.get('htmlLink'),
                'meet_link': meet_link,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ZoomMeetingView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_meeting")
        if error_response:
            return error_response
        user = request.user
        try:
            # Extract start_time (in HH:MM format) from the request data
            school_class = request.data.get('school_class')
            section = request.data.get('section')
            start_time_str = request.data.get("start_time")
            if not start_time_str:
                return Response({"message": "start_time is required."}, status=status.HTTP_400_BAD_REQUEST)

            # 1. Parse the start_time string to a datetime object (using today's date)
            try:
                start_time = datetime.strptime(start_time_str, "%H:%M")
            except ValueError:
                return Response({"message": "Invalid start_time format. Please use 'HH:MM' format."}, status=status.HTTP_400_BAD_REQUEST)

            # Combine the parsed time with today's date (or any date you want)
            today_date = datetime.today().date()
            start_time = datetime.combine(today_date, start_time.time())

            # 2. Convert the parsed start_time to UTC first, then to IST
            start_time_utc = pytz.timezone("Asia/Kolkata").localize(start_time)  # Localize to IST
            start_time_utc = start_time_utc.astimezone(pytz.utc)  # Convert to UTC

            # Now, convert to IST
            ist_time = start_time_utc.astimezone(pytz.timezone("Asia/Kolkata"))
            start_time_ist = ist_time.isoformat()

            # 3. Generate Authorization Headers for Zoom
            auth_string = f"{settings.ZOOM_CLIENT_ID}:{settings.ZOOM_CLIENT_SECRET}"
            encoded_auth_string = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
            headers = {
                "Authorization": f"Basic {encoded_auth_string}",
                "Content-Type": "application/json",
            }

            # 4. Generate Zoom Access Token
            url = f"https://zoom.us/oauth/token?grant_type=account_credentials&account_id={settings.ZOOM_ACCOUNT_ID}"
            response = requests.post(url, headers=headers)
            response.raise_for_status()  # Raise an error for bad status
            json_response = response.json()

            zoom_access_token = json_response.get("access_token")
            if not zoom_access_token:
                return Response({"message": "Failed to obtain Zoom access token."}, status=status.HTTP_400_BAD_REQUEST)

            # Extract additional parameters from the request
            title = request.data.get('title', 'Schools meeting')
            attendees_ids = request.data.get('attendees', [])
            time_duration = int(request.data.get('time_duration', 60))
            guests = request.data.get('guests', [])

            # Retrieve users by their IDs using get_user_model()
            if attendees_ids:
                attendees = User.objects.filter(id__in=attendees_ids)
                attendees_emails = [attendee.email for attendee in attendees]
            else:
                attendees_emails = []

            attendees_emails.append(request.user.email)

            guests_mails = [guest_email for guest_email in guests]
            guests_mails += [attendees_mail for attendees_mail in attendees_emails]
            guests_emails = []
            email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$'
            for i in guests_mails:
                if re.match(email_regex,i):
                    guests_emails.append(i)

            # 5. Prepare Meeting Data for Zoom
            meeting_data = {
                        "agenda": title,
                        "default_password": False,
                        "duration": time_duration,
                        "password": "",
                        "settings": {
                            "allow_multiple_devices": True,
                            "alternative_hosts_email_notification": True,  # Ensure email notifications are sent to alternative hosts
                            "email_notification": True,  # Enable email notification
                            "join_before_host": True,  # Set Join Before Host to True
                            "breakout_room": {
                                "enable": True,
                                "rooms": [
                                    {
                                        "name": "Class",
                                        "participants": guests_emails,
                                    }
                                ],
                            },
                            "calendar_type": 1,
                            "contact_email": "info@eduuxpert.com",
                            "contact_name": "ASV",
                            "encryption_type": "enhanced_encryption",
                            "focus_mode": True,
                            "host_video": True,
                            "meeting_authentication": True,
                            "meeting_invitees": [{"email": guest_email} for guest_email in guests_emails],  # Guests emails
                            "mute_upon_entry": True,
                            "participant_video": True,
                            "private_meeting": True,
                            "waiting_room": False,
                            "watermark": False,
                            "continuous_meeting_chat": {
                                "enable": True,
                            },
                        },
                        "start_time": start_time_ist,
                        "timezone": "Asia/Kolkata",
                        "topic": title,
                        "type": 2,  # 1 -> Instant Meeting, 2 -> Scheduled Meeting
                    }

            # 6. Create Zoom Meeting
            meeting_url = f"https://api.zoom.us/v2/users/me/meetings"
            meeting_headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {zoom_access_token}",
            }

            meeting_response = requests.post(meeting_url, headers=meeting_headers, data=json.dumps(meeting_data))

            meeting_response.raise_for_status()
            meeting_info = meeting_response.json()

            meeting_link = meeting_info.get("join_url")
            start_time = ist_time.replace(tzinfo=None)
            meeting_duration = timedelta(minutes=time_duration)

            online_meeting = Meeting.objects.create(
                type="zoom meeting",
                creator=user,
                school_class=school_class,
                section=section,
                start_date=start_time,
                start_time=start_time.time(),
                time_duration=meeting_duration,
                meeting_link=meeting_link,
                guests=guests_emails,
                school=school,
                description = title
            )
            online_meeting.attendees.set(attendees)

            serializer = MeetingSerializer(online_meeting)
            self.send_guest_invitation(set(guests_emails), meeting_link, start_time)

            return Response(
                {
                    "message": "Zoom meeting created successfully.",
                    "meeting_link": meeting_link,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as error:
            return Response(
                {"message": str(error)}, status=status.HTTP_400_BAD_REQUEST
            )

    def send_guest_invitation(self, guest_emails, meeting_link, start_time):

        subject = "You are invited to a Zoom meeting"
        message = f"Hello, you have been invited to a Zoom meeting. Here is the meeting link: {meeting_link} at {start_time}"
        from django.core.mail import send_mail
        
        send_mail(
            subject,
            message,
            settings.EMAIL_HOST_USER,
            guest_emails,
            fail_silently=False,
        )

#===========================================assessment===========================================
class AssessmentView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request, pk=None):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_assessment")
        if error_response:
            return error_response
        
        assessment_filters = {}
        if pk:
            assessment_filters['pk'] = pk
        assessments = Assessment.objects.filter(**assessment_filters)
        
        # Pagination
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(assessments, request)
        if result_page is not None:
            serializer = AssessmentSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)
        
        serializer = AssessmentSerializer(assessments, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_assessment")
        if error_response:
            return error_response
        
        data = request.data
        data['school'] = school.id
        serializer = AssessmentSerializer(data=data)
        
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Assessment created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_assessment")
        if error_response:
            return error_response
        
        try:
            assessment = Assessment.objects.get(pk=pk)
        except Assessment.DoesNotExist:
            return Response({"message": "Assessment not found"}, status=status.HTTP_404_NOT_FOUND)

        if assessment.school != school:
            return Response({"message": "You can only update assessments for your own school."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = AssessmentSerializer(assessment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Assessment updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_assessment")
        if error_response:
            return error_response
        
        try:
            assessment = Assessment.objects.get(pk=pk)
        except Assessment.DoesNotExist:
            return Response({"message": "Assessment not found"}, status=status.HTTP_404_NOT_FOUND)

        if assessment.school != school:
            return Response({"message": "You can only delete assessments for your own school."}, status=status.HTTP_403_FORBIDDEN)
        
        assessment.delete()
        return Response({"message": "Assessment deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


class QuestionView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request, pk=None):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_assessment")
        if error_response:
            return error_response
        
        questions_filters = {}
        if pk:
            questions_filters['pk'] = pk
        questions = Question.objects.filter(**questions_filters)
        
        # Pagination
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(questions, request)
        if result_page is not None:
            serializer = QuestionSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)
        
        serializer = QuestionSerializer(questions, many=True)
        return Response(serializer.data)


    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_question")
        if error_response:
            return error_response

        data = request.data
        data['school'] = school.id

        # Ensure that 'assessment' is passed in the request
        if 'assessment' not in data:
            return Response({"message": "Assessment is required."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = QuestionSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Question created successfully", "data": serializer.data}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_question")
        if error_response:
            return error_response
        
        try:
            question = Question.objects.get(pk=pk)
        except Question.DoesNotExist:
            return Response({"message": "Question not found"}, status=status.HTTP_404_NOT_FOUND)

        if question.school != school:
            return Response({"message": "You can only update questions for your own school."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = QuestionSerializer(question, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Question updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_question")
        if error_response:
            return error_response
        
        try:
            question = Question.objects.get(pk=pk)
        except Question.DoesNotExist:
            return Response({"message": "Question not found"}, status=status.HTTP_404_NOT_FOUND)

        if question.school != school:
            return Response({"message": "You can only delete questions for your own school."}, status=status.HTTP_403_FORBIDDEN)
        
        question.delete()
        return Response({"message": "Question deleted successfully"}, status=status.HTTP_204_NO_CONTENT)



class SubmitAssessmentView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user_id = request.data.get("user_id")
        if user_id:
            assessments = UserAssessment.objects.filter(status="Checked", user_id=user_id)
        else:
            assessments = UserAssessment.objects.filter(status="Checked")
        
        serializer = UserAssessmentSerializer(assessments, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        data = request.data.copy()  
        data['user'] = request.user.id  

        serializer = UserAssessmentSerializer(data=data)
        
        if serializer.is_valid():
            serializer.save(user=request.user, status="Pending")  
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class CheckAssessmentView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user_id = request.data.get("user_id")
        if user_id:
            assessments = UserAssessment.objects.filter(status="Pending", user_id=user_id)
        else:
            assessments = UserAssessment.objects.filter(status="Pending")
        
        serializer = UserAssessmentSerializer(assessments, many=True)
        return Response(serializer.data)

    def put(self, request):
        assessment_id = request.data.get("assessment_id")
        if not assessment_id:
            return Response({"error": "Assessment ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            assessment = UserAssessment.objects.get(id=assessment_id, status="Pending")
        except UserAssessment.DoesNotExist:
            return Response({"error": "Assessment not found or already checked."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = AssessmentCheckSerializer(assessment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(checked_by=request.user, status="Checked")
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
#=======================================gate pass===================================

class GatePassAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    decryption_key = "1234567890123456"  # Ensure this is a 32-character key

    def decrypt_user_id(self, encrypted_data, key):
        """Decrypt the encrypted user ID using AES decryption."""
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data)
            iv = decoded_data[:AES.block_size]  # Extract IV from encrypted data
            encrypted_user_id = decoded_data[AES.block_size:]
            cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
            decrypted_user_id = unpad(cipher.decrypt(encrypted_user_id), AES.block_size)
            return decrypted_user_id.decode('utf-8')
        except Exception as e:
            return None  # Return None if decryption fails
    def get(self, request):
        """
        Retrieve all GatePass records for the authenticated user with pagination.
        """
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.view_gatepass")
        if error_response:
            return error_response

        # Initialize filters based on user and school
        user = request.user
        filters = {"user__school": school}

        # Apply specific filtering based on the user's role
        if user.role and user.role.name != "school":
            filters["user"] = user

        # Fetch GatePass records based on filters
        gatepasses = GatePass.objects.filter(**filters).order_by("-created_at")

        # Apply pagination
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(gatepasses, request)
        if result_page is not None:
            serializer = GatePassGetSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)
        
        serializer = GatePassGetSerializer(gatepasses, many=True)
        return Response(serializer.data)

    def post(self, request):
        """
        Create a new GatePass record, ensuring time_interval between requests 
        and validating user ID via decryption.
        """
        # Step 1: Permission check
        school, error_response = check_permission_and_get_school(request, "api_v1.add_gatepass")
        if error_response:
            return error_response

        # Step 2: Validate and decrypt user ID
        encrypted_data = request.data.get("encrypted_user_id")
        method_type = request.data.get("method")
        if not encrypted_data:
            return Response({"message": "Encrypted user ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        decrypted_user_id = self.decrypt_user_id(encrypted_data, self.decryption_key)
        if not decrypted_user_id:
            return Response({"message": "Failed to decrypt user ID."}, status=status.HTTP_400_BAD_REQUEST)

        # Step 3: Verify QRCode entry
        try:
            qr_code_entry = QRCode.objects.get(id=decrypted_user_id)
        except QRCode.DoesNotExist:
            return Response({"message": "QRCode entry not found."}, status=status.HTTP_400_BAD_REQUEST)

        match = json.loads(qr_code_entry.data)
        user_id = match.get("id")

        # Step 4: Ensure that the user_id is a valid UUID
        try:
            user_id = uuid.UUID(user_id)  # Check if user_id is a valid UUID
        except ValueError:
            return Response({"message": "Invalid user ID in QR code (not a valid UUID)."}, status=status.HTTP_400_BAD_REQUEST)

        if not User.objects.filter(id=user_id).exists():
            return Response({"message": "User not found"}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.get(id = user_id)
        # Step 4: Check user access
        user_access_pass, created = AccessMethod.objects.get_or_create(
            name=method_type
        )
        if UserAccessPass.objects.filter(user=user, method=user_access_pass).exists():
            user_access = UserAccessPass.objects.get(user=user, method=user_access_pass)
            return Response({"message": f"Access restricted: {user_access.reason}"}, status=status.HTTP_403_FORBIDDEN)

        # Step 5: Fetch the user's most recent GatePass
        last_gatepass = GatePass.objects.filter(user=user).order_by("-created_at").first()

        # Step 6: Verify GateType
        gate_type_name = request.data.get("type")
        gate_type = GateType.objects.filter(name=gate_type_name).first()
        if not gate_type:
            return Response({"message": "GateType not found."}, status=status.HTTP_404_NOT_FOUND)

        checkout_time = gate_type.checkout_time or timedelta(hours=1)

        # Step 7: Check time interval since the last GatePass
        if last_gatepass:
            time_elapsed = now() - last_gatepass.created_at
            if time_elapsed.total_seconds() < checkout_time.total_seconds():
                time_remaining = int(checkout_time.total_seconds() - time_elapsed.total_seconds())
                hours, remainder = divmod(time_remaining, 3600)
                minutes, seconds = divmod(remainder, 60)
                return Response(
                    {"message": f"Request denied. You can create another request after {hours:02}:{minutes:02}:{seconds:02}."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Step 8: Create a new GatePass
        data = request.data.copy()
        data["user"] = user.id
        serializer = GatePassSerializer(data=data)
        if serializer.is_valid():
            gatepass_instance = serializer.save()
            response_serializer = GatePassGetSerializer(gatepass_instance)
            return Response({"message": "GatePass entry created successfully", "data": response_serializer.data}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        """
        Delete a GatePass record for the authenticated user.
        """
        # Step 1: Permission check
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_gatepass")
        if error_response:
            return error_response

        # Step 2: Validate and retrieve GatePass
        gatepass_id = request.data.get("id")
        if not gatepass_id:
            return Response({"message": "GatePass ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            gatepass = GatePass.objects.get(id=gatepass_id, user=request.user)
        except GatePass.DoesNotExist:
            return Response({"message": "GatePass not found."}, status=status.HTTP_404_NOT_FOUND)

        # Step 3: Delete the GatePass
        gatepass.delete()
        return Response({"message": "GatePass deleted successfully."}, status=status.HTTP_200_OK)
        


# =======================================access method =========================================
class AccessMethodAPIView(GenericAPIView):
    serializer_class = AccessMethodSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_accessmethod")
        if error_response:
            return error_response
        get_model = AccessMethod.objects.filter(school=school).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_accessmethod")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        name = data.get('name')
        exists, conflict_response = check_if_exists(AccessMethod, name=name,school=school)
        if conflict_response:
            return conflict_response
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "AccessMethod Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_accessmethod")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = AccessMethod.objects.get(id=model_id)
        except AccessMethod.DoesNotExist:
            return Response({"message": "AccessMethod not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update AccessMethod for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "AccessMethod updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_feecategory")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "AccessMethod list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = AccessMethod.objects.get(id=id)
            except AccessMethod.DoesNotExist:
                return Response({"message": "AccessMethod not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update AccessMethod for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "AccessMethod deleted successfully"}, status=status.HTTP_200_OK)
class AccessMethodListAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_feeterm")
        if error_response:
            return error_response
        category_names = AccessMethod.objects.filter(
            school=school,active = True
        ).order_by('-created_at').values('id', 'name')
        return Response({
            "message": "AccessMethod List retrieved successfully",
           "data": list(category_names)
        }, status=status.HTTP_200_OK)  

class UserAccessPassAPIView(GenericAPIView):
    serializer_class = UserAccessPassSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_accessmethod")
        if error_response:
            return error_response
        user_id = request.query_params.get('user_id', None)
        if not user_id:
            return Response({"error": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=user_id)
            user_register = True if user.rfid_card_number else False
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        access_methods = AccessMethod.objects.filter(school=school)
        user_access_passes = UserAccessPass.objects.filter(school=school, user=user)
        access_status = []
        for method in access_methods:
            user_access_pass = user_access_passes.filter(method=method).first()
            if user_access_pass:
               access_status.append({
                "method_id": method.id,
                "method_name": method.name,
                "is_allowed": user_access_pass.is_allowed,
                "register":user_register if method.name == "RFID-Card" else True,
                "id":user_access_pass.id, # Return the allowed status if user has access
                "reason":user_access_pass.reason
                })  # If the user has access, return the allowed status
            else:
                access_status.append({
                "method_id": method.id,
                "method_name": method.name,
                "register":user_register if method.name == "RFID-Card" else True,
                "is_allowed": True  # Default to False if no access pass exists
                }) # If no access pass exists, default to False
        return Response(access_status, status=status.HTTP_200_OK)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_accessmethod")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id 
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "AccessMethod Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_feecategory")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "AccessMethod list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = UserAccessPass.objects.get(id=id)
            except UserAccessPass.DoesNotExist:
                return Response({"message": "AccessMethod not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update AccessMethod for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "AccessMethod deleted successfully"}, status=status.HTTP_200_OK)


class GateTypeAPIView(GenericAPIView):
    serializer_class = GateTypeSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_gatetype")
        if error_response:
            return error_response
        get_model = GateType.objects.filter(school=school).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.serializer_class(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_gatetype")
        if error_response:
            return error_response
        data = request.data
        data['school'] = school.id 
        name = data.get('name')
        exists, conflict_response = check_if_exists(GateType, name=name,school=school)
        if conflict_response:
            return conflict_response
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "GateType Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_gatetype")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = GateType.objects.get(id=model_id)
        except GateType.DoesNotExist:
            return Response({"message": "GateType not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update GateType for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "GateType updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_gatetype")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "GateType list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = GateType.objects.get(id=id)
            except GateType.DoesNotExist:
                return Response({"message": "GateType not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update GateType for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "GateType deleted successfully"}, status=status.HTTP_200_OK)
class GateTypeListAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_gatetype")
        if error_response:
            return error_response
        category_names = GateType.objects.filter(
            school=school,active = True
        ).order_by('-created_at').values_list('name', flat=True)
        return Response({
            "message": "GateType List retrieved successfully",
           "data": list(category_names)
        }, status=status.HTTP_200_OK)  
        
class AddEmployeeView(APIView):
    def post(self, request, *args, **kwargs):
        if  not hasattr(request.user, 'role') or request.user.role.name != 'school':
            return Response({'message': 'No permission to add employee' }, status=status.HTTP_400_BAD_REQUEST)
        school = request.user.school
        try:
            user_id = request.query_params.get('user_id', None)
            card_number = request.data.get('cardnumber')
            if not user_id or not User.objects.filter(id=user_id).exists():
                return Response({"message": "User is required."}, status=status.HTTP_400_BAD_REQUEST)
            user = User.objects.get(id=user_id)

            # Unpack the tuple returned by get_or_create()
            sims_confg, created = SimsConfig.objects.get_or_create(key="RFID-Card", school=school)
            
            # Construct the SOAP XML request body using the correct SimsConfig object
            soap_body = f"""<?xml version="1.0" encoding="utf-8"?>
                        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                        <soap:Body>
                            <AddEmployee xmlns="http://tempuri.org/">
                            <APIKey>{sims_confg.value['api_key']}</APIKey>
                            <EmployeeCode>{user.id}</EmployeeCode>
                            <EmployeeName>{user.name}</EmployeeName>
                            <CardNumber>{card_number}</CardNumber>
                            <SerialNumber>{sims_confg.value['serial_number']}</SerialNumber>
                            <UserName>{sims_confg.value['username']}</UserName>
                            <UserPassword>{sims_confg.value['password']}</UserPassword>
                            <CommandId>{sims_confg.value['command_id']}</CommandId>
                            </AddEmployee>
                        </soap:Body>
                        </soap:Envelope>
                        """

            # Send the request to the external SOAP API
            url = f"http://{sims_confg.value['ip']}/iclock/WebAPIService.asmx?op=AddEmployee"
            headers = {'Content-Type': 'text/xml'}

            response = requests.post(url, data=soap_body, headers=headers, verify=False)
            # Check if the external API returned a successful response
            if response.status_code == 200:
                user.rfid_card_number = card_number
                user.save()
                return Response({
                    'message': 'Employee added successfully to external API.'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'message': 'Failed to add employee to external API.',
                    'status_code': response.status_code,
                    'response': response.content.decode()  # Including the actual error message from the API
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class BlockUnblockUserView(APIView):
    def post(self, request, *args, **kwargs):
        if not hasattr(request.user, 'role') or request.user.role.name != 'school':
            return Response({'message': 'No permission to add employee'}, status=status.HTTP_400_BAD_REQUEST)
        school = request.user.school

        try:
            user_id = request.query_params.get('user_id', None)
            is_block = request.data.get('IsBlock')
            if not user_id or not User.objects.filter(id=user_id).exists():
                return Response({"message": "User is required."}, status=status.HTTP_400_BAD_REQUEST)
            user = User.objects.get(id=user_id)
            sims_confg, created = SimsConfig.objects.get_or_create(key="RFID-Card", school=school)

            soap_body = f"""
            <?xml version="1.0" encoding="utf-8"?>
            <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
              <soap:Body>
                <BlockUnblockUser xmlns="http://tempuri.org/">
                  <APIKey>{sims_confg.value['api_key']}</APIKey>
                  <EmployeeCode>{user.id}</EmployeeCode>
                  <EmployeeName>{user.name}</EmployeeName>
                  <SerialNumber>{sims_confg.value['serial_number']}</SerialNumber>
                  <IsBlock>{str(is_block).lower()}</IsBlock>
                  <UserName>{sims_confg.value['username']}</UserName>
                  <UserPassword>{sims_confg.value['password']}</UserPassword>
                  <CommandId>{sims_confg.value['command_id']}</CommandId>
                </BlockUnblockUser>
              </soap:Body>
            </soap:Envelope>
            """.strip()  # Using .strip() to remove any leading/trailing whitespace

            # Send the request to the external SOAP API
            url = f"http://{sims_confg.value['ip']}/iclock/WebAPIService.asmx?op=BlockUnblockUser"
            headers = {'Content-Type': 'text/xml'}
            response = requests.post(url, data=soap_body, headers=headers, verify=False)

            if response.status_code == 200:
                action = "blocked" if is_block else "unblocked"
                return Response({
                    'message': f'Employee {action}.'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'message': 'Failed to block/unblock employee.',
                    'status_code': response.status_code,
                    'response': response.content.decode()  # Including the actual error message from the API
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
#================================================qrcode detail get===============================
class QrCodeDetailAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    decryption_key = "1234567890123456"  # Ensure this is a 32-character key

    def decrypt_user_id(self, encrypted_data, key):
        """Decrypt the encrypted user ID using AES decryption."""
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data)
            iv = decoded_data[:AES.block_size]  # Extract IV from encrypted data
            encrypted_user_id = decoded_data[AES.block_size:]
            cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
            decrypted_user_id = unpad(cipher.decrypt(encrypted_user_id), AES.block_size)
            return decrypted_user_id.decode('utf-8')
        except Exception as e:
            return None  # Return None if decryption fails
    def get(self, request):
        # Step 2: Validate and decrypt user ID
        encrypted_data = request.query_params.get('encrypted_user_id', None)
        if not encrypted_data:
            return Response({"message": "Encrypted user ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        decrypted_user_id = self.decrypt_user_id(encrypted_data, self.decryption_key)
        if not decrypted_user_id:
            return Response({"message": "Failed to decrypt user ID."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            qr_code_entry = QRCode.objects.get(id=decrypted_user_id)
        except QRCode.DoesNotExist:
            return Response({"message": "QRCode entry not found."}, status=status.HTTP_400_BAD_REQUEST)
        qr_code_data = qr_code_entry.data.replace("'", '"')
        match = json.loads(qr_code_data)
        user_id = match.get("id")
        if User.objects.filter(id=user_id).exists():
            user = User.objects.get(id=user_id)
            serializer = UserDetailQRCodeSerializer(user)
            return Response({"qr_code_data":serializer.data}, status=status.HTTP_200_OK)
        return Response({"qr_code_data":match}, status=status.HTTP_200_OK)
#======================================================rrole base user created===================================
class UserCreateByRoleAPIView(GenericAPIView):
    serializer_class = RoleUserSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    def get(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.view_user")
        if error_response:
            return error_response
        subject_filters = {'school': school}
        role = request.query_params.get('role', None)
        try:
            role_instance = Role.objects.get(name=role,school=school)
        except Role.DoesNotExist:
            return Response({"message": "Role not Found"}, status=status.HTTP_400_BAD_REQUEST)
        subject_filters = {'role': role_instance}
        get_model = User.objects.filter(**subject_filters).order_by('-created_at')
        page = self.paginate_queryset(get_model)
        if page is not None:
            serializer = RoleUserGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = RoleUserGetSerializer(get_model, many=True)
        return Response(serializer.data)
    def post(self, request):
        school,error_response = check_permission_and_get_school(request,"api_v1.add_user")
        if error_response:
            return error_response
        role = request.query_params.get('role', None)
        if not role:
            return Response({"message": "Role not found"}, status=status.HTTP_404_NOT_FOUND)
        role_vendor, role_created = Role.objects.get_or_create(
            name= role,
            school=school,
        )
        data = request.data.copy()
        data['school'] = school.id 
        data['role']=role_vendor.id
        data['password']= '0000'
        if "name" in data:
            role_prefix = role_vendor.name[:2].upper()
            data["username"] = generate_username(data["name"], prefix=f"{role_prefix}-")
        print(data["username"])
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            user_instance= serializer.save()
            group_name = f"{school.school_code}_{role_vendor.name}"
            group, created = Group.objects.get_or_create(name=group_name)
            user_instance.groups.add(group)
            if role_created:
                role_vendor.group = group  # Set the group's one-to-one relationship with role
                role_vendor.save()
            if not QRCode.objects.filter(name=user_instance.id).exists():
                qr_data = {"id":str(user_instance.id),"name":user_instance.name if user_instance.name else "" }
                create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school)
            return Response({"message": "User Created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def put(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.change_user")
        if error_response:
            return error_response
        model_id = request.data.get('id', None)
        try:
            put_model = User.objects.get(id=model_id)
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        if put_model.school != school:
            return Response({"message": "You can only update User for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(put_model, data=request.data, partial=True)
        if serializer.is_valid():
            user_instance = serializer.save()
            if not QRCode.objects.filter(name=user_instance.id).exists():
                qr_data = {"id":str(user_instance.id),"name":user_instance.name if user_instance.name else "" }
                create_qrcode_url(self, qr_data, user_instance.id, user_instance.role.name,school)
            return Response({"message": "User updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, *args, **kwargs):
        school,error_response = check_permission_and_get_school(request,"api_v1.delete_user")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting list of IDs from the request body
        if not ids:
            return Response({"message": "User list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                delete_model = User.objects.get(id=id)
            except User.DoesNotExist:
                return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            if delete_model.school != school:
                return Response({"message": "You can only update User for your own school."}, status=status.HTTP_403_FORBIDDEN)
            delete_model.delete()
        return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)
#==============================================vehicle==========================================================================

class VehicleAPIView(GenericAPIView):
    serializer_class = VehicleSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_vehicle")
        if error_response:
            return error_response
        vehicles = Vehicle.objects.filter(school=school).order_by('-created_at')
        if request.query_params.get('filter_fields'):
            filter_dict = request.query_params.get('filter_fields', '{}')
            try:
                filter_dict = json.loads(filter_dict)
            except json.JSONDecodeError:
                return Response({"error": "Invalid JSON format in 'filter_fields' parameter."}, status=status.HTTP_400_BAD_REQUEST)
            filtered_queryset = filter_model_data(vehicles, filter_dict)
            if isinstance(filtered_queryset, dict) and 'error' in filtered_queryset:
                return Response(filtered_queryset, status=status.HTTP_400_BAD_REQUEST)
            vehicles = filtered_queryset
        page = self.paginate_queryset(vehicles)
        if page is not None:
            serializer = VehicleGetSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = VehicleGetSerializer(vehicles, many=True)
        return Response(serializer.data)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_vehicle")
        if error_response:
            return error_response
        data = request.data.copy()
        data['school'] = school.id
        data['active'] = True
        vehicle_number = data.get('vehicle_number')
        exists, conflict_response = check_if_exists(Vehicle,vehicle_number=vehicle_number,school=school)
        if conflict_response:
            return conflict_response
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Vehicle created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_vehicle")
        if error_response:
            return error_response
        vehicle_id = request.data.get('id', None)
        if not vehicle_id:
            return Response({"message": "Vehicle ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            vehicle = Vehicle.objects.get(id=vehicle_id)
        except Vehicle.DoesNotExist:
            return Response({"message": "Vehicle not found"}, status=status.HTTP_404_NOT_FOUND)
        if vehicle.school != school:
            return Response({"message": "You can only update vehicles for your own school."}, status=status.HTTP_403_FORBIDDEN)
        serializer = self.serializer_class(vehicle, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Vehicle updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_vehicle")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])
        if not ids:
            return Response({"message": "Vehicle list is required"}, status=status.HTTP_400_BAD_REQUEST)
        for id in ids:
            try:
                vehicle = Vehicle.objects.get(id=id)
            except Vehicle.DoesNotExist:
                return Response({"message": f"Vehicle with ID {id} not found"}, status=status.HTTP_404_NOT_FOUND)
            if vehicle.school != school:
                return Response({"message": "You can only delete vehicles for your own school."}, status=status.HTTP_403_FORBIDDEN)
            vehicle.delete()
        return Response({"message": "Vehicles deleted successfully"}, status=status.HTTP_200_OK)

#   ============================get vehicle list=============================
class VehicleListAPIView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_vehicle")
        if error_response:
            return error_response
        filters = {
            'school': school,
            'active': True
        }
        vehicles = Vehicle.objects.filter(**filters).order_by('-created_at').values('id', 'vehicle_number')
        vehicle_data = [
            {
                'name': vehicle['vehicle_number'],
                'id': vehicle['id'],
            }
            for vehicle in vehicles
        ]
        return Response(
            {
                "message": "Vehicles retrieved successfully",
                "data": vehicle_data
            }, 
            status=status.HTTP_200_OK
        )
class VehiclePassengerAPiView(GenericAPIView):
    serializer_class = VehiclePassengerSerializer

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_vehicle")
        if error_response:
            return error_response
        vehicle_id = request.query_params.get('vehicle_id')
        if not vehicle_id:
            return Response({"message": "Vehicle not found!"}, status=status.HTTP_403_FORBIDDEN)
        try:
            vehicle = Vehicle.objects.get(id=vehicle_id, school=school)
        except Vehicle.DoesNotExist:
            return Response({"message": "Vehicle does not exist!"}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(vehicle)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_vehicle")
        if error_response:
            return error_response
        vehicle_id = request.data.get('vehicle_id')
        if not vehicle_id:
            return Response({"message": "Vehicle ID is required!"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            vehicle = Vehicle.objects.get(id=vehicle_id, school=school)
        except Vehicle.DoesNotExist:
            return Response({"message": "Vehicle does not exist!"}, status=status.HTTP_404_NOT_FOUND)
        passenger_id = request.data.get('passenger_id')
        if not passenger_id:
            return Response({"message": "Passenger ID is required!"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            passenger = User.objects.get(id=passenger_id)
        except User.DoesNotExist:
            return Response({"message": "Passenger does not exist!"}, status=status.HTTP_404_NOT_FOUND)
        if passenger in vehicle.passenger.all():
            vehicle.passenger.remove(passenger)
            message = "Passenger removed from the vehicle successfully!"
        else:
            vehicle.passenger.add(passenger)
            message = "Passenger added to the vehicle successfully!"

        # Save the vehicle
        vehicle.save()
        return Response({"message": message}, status=status.HTTP_200_OK)

class DriverBusDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]  # Ensures that only authenticated users can access the API

    def get(self, request, *args, **kwargs):
        driver = request.user  # Get the authenticated user (driver)
        
        # Check if there is any bus assigned to this driver
        try:
            vehicle = Vehicle.objects.get(driver=driver)
            serializer = VehicleSerializer(vehicle)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Vehicle.DoesNotExist:
            return Response({"message": "No bus assigned."}, status=status.HTTP_404_NOT_FOUND)
class BusRouteStopAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]  # Ensures that only authenticated users can access the API

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_busroute")
        if error_response:
            return error_response
        arrive_stops_data = request.data.get('arrive_stops')  # List of dicts for arriving stops
        return_stops_data = request.data.get('return_stops')  # List of dicts for return stops
        vehicle_id = request.query_params.get('vehicle_id')

        if not vehicle_id:
            return Response({"message": "Vehicle not found!"}, status=status.HTTP_403_FORBIDDEN)

        try:
            vehicle = Vehicle.objects.get(id=vehicle_id)
        except Vehicle.DoesNotExist:
            return Response({"message": "Vehicle not found!"}, status=status.HTTP_404_NOT_FOUND)
        bus_route, created = BusRoute.objects.get_or_create(
            vehicle=vehicle,
            defaults={'route': f"ROUTE-{vehicle.vehicle_number}"}
        )
        if not arrive_stops_data and not return_stops_data:
            return Response({"message": "Missing stops for arrive or return!"}, status=status.HTTP_400_BAD_REQUEST)
        RouteStop.objects.filter(route=bus_route).delete()
        if arrive_stops_data:
            for stop in arrive_stops_data:
                try:
                    bus_station_id = stop.get('id')
                    stop_order = stop.get('stop_order')
                    if bus_station_id is None or stop_order is None:
                        return Response({"message": "Bus station or stop order is missing in the arrive stops data."}, status=status.HTTP_400_BAD_REQUEST)
                    bus_station = BusStation.objects.get(id=bus_station_id)
                    RouteStop.objects.create(route=bus_route, bus_station=bus_station,type="arrive", stop_order=stop_order)
                    bus_route.arrive_stop_points.add(bus_station)
                except BusStation.DoesNotExist:
                    return Response({"error": f"Bus station with ID {bus_station_id} not found!"}, status=status.HTTP_404_NOT_FOUND)
        if return_stops_data:
            for stop in return_stops_data:
                try:
                    bus_station_id = stop.get('id')
                    stop_order = stop.get('stop_order')
                    if bus_station_id is None or stop_order is None:
                        return Response({"message": "Bus station or stop order is missing in the return stops data."}, status=status.HTTP_400_BAD_REQUEST)
                    bus_station = BusStation.objects.get(id=bus_station_id)
                    RouteStop.objects.create(route=bus_route, bus_station=bus_station,type="return", stop_order=stop_order)
                    bus_route.return_stop_points.add(bus_station)
                except BusStation.DoesNotExist:
                    return Response({"error": f"Bus station with ID {bus_station_id} not found!"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"message": "Bus route stops updated successfully"}, status=status.HTTP_200_OK)
    def get(self, request, *args, **kwargs):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_busroute")
        if error_response:
            return error_response
        vehicle_id = request.query_params.get('vehicle_id')
        if not vehicle_id:
            return Response({"message": "Vehicle not found!"}, status=status.HTTP_403_FORBIDDEN)
        try:
            vehicle = Vehicle.objects.get(id=vehicle_id)
        except Vehicle.DoesNotExist:
            return Response({"message": "Vehicle not found!"}, status=status.HTTP_404_NOT_FOUND)

        bus_route, created = BusRoute.objects.get_or_create(
            vehicle=vehicle,
            school=school,
            defaults={'route': f"ROUTE-{vehicle.vehicle_number}"}
        )
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
        arrive_stops_data = RouteStopSerializer(arrive_stops, many=True).data
        return_stops_data = RouteStopSerializer(return_stops, many=True).data
        return Response({
            "route": bus_route.route,
            "arrive_stops": arrive_stops_data,
            "return_stops": return_stops_data
        }, status=status.HTTP_200_OK)


class BusStationAPIView(GenericAPIView):
    serializer_class = BusStationSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination

    def get(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.view_busstation")
        if error_response:
            return error_response
        bus_station_filters = {'school': school}
        vehicle_id = request.query_params.get('vehicle_id')
        if not vehicle_id:
            return Response({"message": "Vehicle not Found!."}, status=status.HTTP_403_FORBIDDEN)
        bus_station_filters['vehicle']=vehicle_id
        bus_stations = BusStation.objects.filter(**bus_station_filters).order_by('-created_at')       
        page = self.paginate_queryset(bus_stations)
        serializer = BusStationGetSerializer(bus_stations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.add_busstation")
        if error_response:
            return error_response
        data = request.data
        data['active'] = True
        data['place_name'] = get_place_namn_by_map(data['lat'], data['lon'])
        data['school'] = school.id  # Assign the school ID
        serializer = self.serializer_class(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Bus Station created successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.change_busstation")
        if error_response:
            return error_response

        model_id = request.data.get('id', None)
        try:
            bus_station = BusStation.objects.get(id=model_id)
        except BusStation.DoesNotExist:
            return Response({"message": "Bus Station not found"}, status=status.HTTP_404_NOT_FOUND)

        if bus_station.school != school:
            return Response({"message": "You can only update Bus Stations for your own school."}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(bus_station, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Bus Station updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        school, error_response = check_permission_and_get_school(request, "api_v1.delete_busstation")
        if error_response:
            return error_response
        ids = request.data.get('ids', [])  # Expecting a list of IDs from the request body
        if not ids:
            return Response({"message": "Bus Station list is required"}, status=status.HTTP_400_BAD_REQUEST)

        for id in ids:
            try:
                delete_model = BusStation.objects.get(id=id)
            except BusStation.DoesNotExist:
                return Response({"message": "Bus Station not found"}, status=status.HTTP_404_NOT_FOUND)

            if delete_model.school != school:
                return Response({"message": "You can only delete Bus Stations for your own school."}, status=status.HTTP_403_FORBIDDEN)

            delete_model.delete()

        return Response({"message": "Bus Stations deleted successfully"}, status=status.HTTP_200_OK)
#=====================================================bus attendance===================================================================
class BusAttendanceAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPagination
    decryption_key = "1234567890123456"  # Ensure this is a 16 or 32-character key

    def decrypt_user_id(self, encrypted_data, key):
        """Decrypt the encrypted user ID using AES decryption."""
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data)
            iv = decoded_data[:AES.block_size]  # Extract IV from encrypted data
            encrypted_user_id = decoded_data[AES.block_size:]
            cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
            decrypted_user_id = unpad(cipher.decrypt(encrypted_user_id), AES.block_size)
            return decrypted_user_id.decode('utf-8')
        except Exception:
            return None  # Return None if decryption fails

    def get(self, request):
        """
        Retrieve all GatePass records for the authenticated user with pagination.
        """
        # Check permissions and get the school
        school, error_response = check_permission_and_get_school(request, "api_v1.mark_bus_attendance")
        if error_response:
            return error_response

        # Initialize filters based on user and school
        user = request.user
        filters = {"user__school": school}

        # Apply specific filtering based on the user's role
        if user.role and user.role.name != "school":
            filters["user"] = user

        # Fetch GatePass records based on filters
        busattendance = BusAttendance.objects.filter(**filters).order_by("-created_at")

        # Apply pagination
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(busattendance, request)
        if result_page is not None:
            serializer = BusAttendanceSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)
        
        serializer = BusAttendanceSerializer(busattendance, many=True)
        return Response(serializer.data)


    def post(self, request):
        """
        Mark bus attendance, ensuring time_interval between requests 
        and validating user ID via decryption.
        """
        # Step 1: Permission check
        school, error_response = check_permission_and_get_school(request, "api_v1.mark_bus_attendance")
        if error_response:
            return error_response

        # Step 2: Validate and decrypt user ID
        encrypted_data = request.data.get("encrypted_user_id")
        method_type = request.data.get("method")
        
        if not encrypted_data:
            return Response({"message": "Encrypted user ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        if not method_type:
            return Response({"message": "Method type is required."}, status=status.HTTP_400_BAD_REQUEST)

        decrypted_user_id = self.decrypt_user_id(encrypted_data, self.decryption_key)
        if not decrypted_user_id:
            return Response({"message": "Failed to decrypt user ID."}, status=status.HTTP_400_BAD_REQUEST)

        # Step 3: Verify QRCode entry
        try:
            qr_code_entry = QRCode.objects.get(id=decrypted_user_id)
        except QRCode.DoesNotExist:
            return Response({"message": "QRCode entry not found."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            match = json.loads(qr_code_entry.data)
            user_id = match.get("id")
            user_id = uuid.UUID(user_id)  # Validate UUID
        except (ValueError, TypeError, json.JSONDecodeError):
            return Response({"message": "Invalid user ID in QR code."}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch user
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"message": "User not found."}, status=status.HTTP_400_BAD_REQUEST)

        # Step 4: Check user access method
        try:
            access_method = AccessMethod.objects.get(name=method_type)
        except AccessMethod.DoesNotExist:
            return Response({"message": f"Invalid access method: {method_type}."}, status=status.HTTP_400_BAD_REQUEST)

        restricted_access = UserAccessPass.objects.filter(user=user, method=access_method).first()
        if restricted_access:
            return Response({"message": f"Bus attendance restricted for method '{method_type}': {restricted_access.reason}"}, status=status.HTTP_403_FORBIDDEN)

        # Step 5: Fetch the user's most recent BusAttendance record
        last_attendance = BusAttendance.objects.filter(user=user).order_by("-created_at").first()

        # Step 6: Verify vehicle existence
        vehicle_number = request.data.get("vehicle_number")
        vehicle = Vehicle.objects.get(vehicle_number=vehicle_number)
        if not vehicle:
            return Response({"message": f"Vehicle - {vehicle_number} not found."}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user is a passenger of the vehicle
        if user not in vehicle.passenger.all():
            return Response({"message": f"User {user.id} is not a passenger of vehicle {vehicle_id}."}, status=status.HTTP_403_FORBIDDEN)

        checkout_time = vehicle.checkout_time or timedelta(hours=1)  # Default interval

        # Step 7: Check time interval since last attendance
        if last_attendance:
            time_elapsed = now() - last_attendance.created_at
            if time_elapsed.total_seconds() < checkout_time.total_seconds():
                time_remaining = int(checkout_time.total_seconds() - time_elapsed.total_seconds())
                hours, remainder = divmod(time_remaining, 3600)
                minutes, seconds = divmod(remainder, 60)
                return Response(
                    {"message": f"Bus attendance denied. You can mark attendance again after {hours:02}:{minutes:02}:{seconds:02}."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Step 8: Create a new BusAttendance record
        data = request.data.copy()
        data["user"] = user.id
        serializer = BusAttendanceSerializer(data=data)
        if serializer.is_valid():
            attendance_instance = serializer.save()
            response_serializer = BusAttendanceSerializer(attendance_instance)
            return Response(
                {"message": "Bus attendance marked successfully", "data": response_serializer.data}, 
                status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request):
        """
        Delete a GatePass record for the authenticated user.
        """
        # Step 1: Permission check
        school, error_response = check_permission_and_get_school(request, "api_v1.mark_bus_attendance")
        if error_response:
            return error_response

        # Step 2: Validate and retrieve GatePass
        attendance_id = request.data.get("id")
        if not attendance_id:
            return Response({"message": "Bus attendance ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            attendance = BusAttendance.objects.get(id=attendance_id, user=request.user)
        except BusAttendance.DoesNotExist:
            return Response({"message": "Bus attendance not found."}, status=status.HTTP_404_NOT_FOUND)

        # Step 3: Delete the GatePass
        attendance.delete()
        return Response({"message": "Bus attendance deleted successfully."}, status=status.HTTP_200_OK)