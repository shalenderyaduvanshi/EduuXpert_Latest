from rest_framework.response import Response
from rest_framework import status
from .models import *
from .serializers import *
from django.core.mail import EmailMessage
from django.conf import settings
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import qrcode
from io import BytesIO
from PIL import Image
from django.core.files.base import ContentFile

from django.apps import apps
from django.http import HttpResponse
import openpyxl
from django.contrib.auth.models import AbstractUser, AbstractBaseUser
import pandas as pd
from django.db import transaction, models
from django.core.exceptions import ValidationError
from django.db.models import Q
import json
import googlemaps

def check_permission_and_get_school(request, permission_codename):
    user = request.user
    school_id = request.query_params.get('school_id', None)
    # Check if the user has the required permission
    if not user.has_perm(permission_codename):
        return None, Response({"message": "You do not have the required permission."}, status=status.HTTP_403_FORBIDDEN)
    # If the user is a superuser, a school ID must be provided
    if user.is_superuser:
        if not school_id:
            return None, Response({"message": "School ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            if School.objects.filter(id=school_id).exists():
                school = School.objects.get(id=school_id)
            else:
                sch_user = User.objects.get(id=school_id)
                school = School.objects.get(id=sch_user.school.id)
        except School.DoesNotExist:
            return None, Response({"message": "Invalid school ID."}, status=status.HTTP_404_NOT_FOUND)
    else:
        # Set the school from the user's associated school
        school = user.school

    # Return the school instance if everything is fine
    return school, None
    
def check_if_exists(model, **kwargs):
    case_insensitive_kwargs = {}
    for key, value in kwargs.items():
        field = model._meta.get_field(key)
        if isinstance(field, models.CharField) or isinstance(field, models.TextField):
            case_insensitive_kwargs[f"{key}__iexact"] = value
        else:
            case_insensitive_kwargs[key] = value
    try:
        obj = model.objects.get(**case_insensitive_kwargs)
        return None, Response({
            "message": f"{model.__name__} with the provided details already exists."
        }, status=status.HTTP_400_BAD_REQUEST)
    except model.DoesNotExist:
        return True, None
      

# Helper function to send email with optional attachments
def send_email(subject, message, recipient_email, attachment=None):
    email_message = EmailMessage(
        subject=subject,
        body=message,
        from_email=settings.EMAIL_HOST_USER,
        to=[recipient_email]
    )

    # Attach file if provided
    if attachment:
        content_type, _ = mimetypes.guess_type(attachment.name)
        if content_type is None:
            content_type = 'application/octet-stream'  # Default to binary if unknown

        # Read and attach the file to the email
        email_message.attach(attachment.name, attachment.read(), content_type)

    try:
        # Send the email
        email_message.send(fail_silently=True)
        return True
    except Exception as e:
        # Handle errors (e.g., SMTPException or general Exception)
        print(f"Error sending email: {e}")
        return False 
        

SECRET_KEY = "1234567890123456"
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
    
def create_qrcode_url(self, data, name, typeqr,school):
    config = get_qr_code_config(self)
    url = config.get('url', '')
    # Ensure data is provided
    if not data or not name:
        return false
    qr_code_instance = QRCode.objects.create(name=name,data=data,type=typeqr, school=school)
    encrypted_qr_id = encrypt_qr_id(self,qr_code_instance.id)
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
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_code_image = ContentFile(buffer.read(), name=f'qrcodes/generated_qr_code_{qr_code_instance.id}.png')
    qr_code_instance.qr_code_image = qr_code_image
    qr_code_instance.save()
    
    serializer = QRCodeSerializer(qr_code_instance)
    return serializer.data
    



def generate_model_fields_excel(model_name, app_label='api_v1'):
    if not model_name:
        return Response({"error": "Model name is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        model = apps.get_model(app_label, model_name)
    except LookupError:
        return Response({"error": f"Model '{model_name}' not found in the '{app_label}' app."}, status=status.HTTP_404_NOT_FOUND)

    # Fields to exclude
    excluded_fields = {'id', 'created_at', 'updated_at', 'active','school','branch'}

    # If the model inherits from AbstractUser or AbstractBaseUser, exclude inherited fields
    inherited_fields = set()
    if issubclass(model, (AbstractUser, AbstractBaseUser)):
        for parent in model.__bases__:  # Get all parent classes
            if issubclass(parent, (AbstractUser, AbstractBaseUser)):
                inherited_fields.update(field.name for field in parent._meta.concrete_fields)
    if "password" in inherited_fields:
        inherited_fields.remove("password")
    if "username" in inherited_fields:
        inherited_fields.remove("username")

    fields = []
    field_data_types = []

    for field in model._meta.concrete_fields:
        if field.name in excluded_fields or field.name in inherited_fields:
            continue  # Skip inherited fields and excluded fields

        fields.append(field.name)

        # Determine data type
        if isinstance(field, models.CharField):
            data_type = "String"
        elif isinstance(field, models.IntegerField):
            data_type = "Integer"
        elif isinstance(field, models.FloatField):
            data_type = "Float"
        elif isinstance(field, models.BooleanField):
            data_type = "Boolean"
        elif isinstance(field, models.DateTimeField):
            data_type = "DateTime"
        elif isinstance(field, models.DateField):
            data_type = "Date"
        elif isinstance(field, models.ImageField):
            data_type = "Image"
        elif isinstance(field, models.TextField):
            data_type = "Text"
        elif isinstance(field, models.ForeignKey):
            related_field = field.target_field
            if isinstance(related_field, models.UUIDField):
                data_type = "UUID"
            elif isinstance(related_field, models.IntegerField):
                data_type = "Integer"
            else:
                data_type = "ForeignKey"
        else:
            data_type = "Unknown"

        # Mark required fields with '*'
        if not field.null and not field.blank:
            data_type += "*"

        field_data_types.append(data_type)

    if not fields:
        return Response({"error": "No exportable fields found for this model."}, status=status.HTTP_400_BAD_REQUEST)

    # Create Excel file
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(fields)  # Headers
    ws.append(field_data_types)  # Data types

    # Save to BytesIO and return response
    file_stream = BytesIO()
    wb.save(file_stream)
    file_stream.seek(0)

    response = HttpResponse(file_stream, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    response['Content-Disposition'] = f'attachment; filename="{model_name}_fields.xlsx"'
    return response

def import_bulk_data(request, model_name, file):
    if not model_name or not file:
        return Response({'error': 'model_name and file are required'}, status=status.HTTP_400_BAD_REQUEST)

    # Get model dynamically
    try:
        model = apps.get_model('api_v1', model_name)
        model_fields = {field.name: field for field in model._meta.fields}
    except LookupError:
        return Response({'error': 'Invalid model name'}, status=status.HTTP_400_BAD_REQUEST)

    # Detect file type and read content
    try:
        if file.name.endswith('.csv'):
            df = pd.read_csv(file, encoding='utf-8', errors='replace')
        elif file.name.endswith('.json'):
            df = pd.read_json(file)
        elif file.name.endswith('.xlsx'):
            df = pd.read_excel(file)
        else:
            return Response({'error': 'Unsupported file format. Use CSV, JSON, or XLSX'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': f'Error reading file: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

    uploaded_fields = df.columns.tolist()
    selected_fields = [field for field in uploaded_fields if field in model_fields]

    # Fetch School and Branch from request.user
    school = getattr(request.user, "school", None)
    branch = getattr(request.user, "branch", None)

    # Ensure School and Branch are model instances
    from api_v1.models import School, Branch  # Import models

    if isinstance(school, uuid.UUID):
        try:
            school = School.objects.get(pk=school)
        except School.DoesNotExist:
            return Response({'error': 'Invalid school_id. School not found'}, status=status.HTTP_400_BAD_REQUEST)

    if isinstance(branch, uuid.UUID):
        try:
            branch = Branch.objects.get(pk=branch)
        except Branch.DoesNotExist:
            return Response({'error': 'Invalid branch_id. Branch not found'}, status=status.HTTP_400_BAD_REQUEST)

    errors = []
    instances = []

    for index, row in df.iterrows():
        instance_data = {}

        for field in selected_fields:
            field_type = model_fields.get(field, None)
            if field_type is None or not hasattr(field_type, "name"):
                errors.append({"row": index + 2, "field": field, "error": "Invalid field reference"})
                continue

            try:
                if pd.isna(row[field]):
                    instance_data[field] = None

                elif isinstance(field_type, models.UUIDField):
                    instance_data[field] = uuid.UUID(str(row[field]))

                elif isinstance(field_type, models.ForeignKey):
                    related_model = field_type.related_model
                    primary_key_field = related_model._meta.pk

                    try:
                        if isinstance(primary_key_field, models.UUIDField):
                            instance_data[field] = related_model.objects.get(pk=uuid.UUID(str(row[field])))
                        else:
                            instance_data[field] = related_model.objects.get(pk=row[field])
                    except (ValueError, TypeError, related_model.DoesNotExist):
                        errors.append({"row": index + 2, "field": field, "error": "Invalid foreign key reference"})
                        continue

                elif isinstance(field_type, models.DateField):
                    try:
                        instance_data[field] = pd.to_datetime(row[field]).date()
                    except Exception:
                        errors.append({"row": index + 2, "field": field, "error": "Invalid date format"})
                        continue

                elif isinstance(field_type, models.DateTimeField):
                    try:
                        instance_data[field] = pd.to_datetime(row[field])
                    except Exception:
                        errors.append({"row": index + 2, "field": field, "error": "Invalid datetime format"})
                        continue

                else:
                    instance_data[field] = row[field]

            except Exception as e:
                errors.append({"row": index + 2, "field": field, "error": str(e)})

        # Assign School and Branch to the instance data
        if "school" in model_fields and school:
            instance_data["school"] = school
        if "branch" in model_fields and branch:
            instance_data["branch"] = branch

        # Validate and add to batch
        if not any(error["row"] == index + 2 for error in errors):
            instance = model(**instance_data)

            try:
                instance.full_clean()  # Validate constraints
                instances.append(instance)
            except ValidationError as e:
                errors.append({"row": index + 2, "error": str(e)})

    # Bulk insert data
    if instances:
        try:
            with transaction.atomic():
                model.objects.bulk_create(instances, batch_size=500)  # Adjust batch size as needed
        except Exception as e:
            return Response({'error': f'Database integrity error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Generate error summary
    field_errors = {}
    for error in errors:
        if "field" in error:
            field_errors.setdefault(error["field"], 0)
            field_errors[error["field"]] += 1

    return Response({
        "message": "Bulk import completed",
        "success_count": len(instances),
        "error_count": len(errors),
        "field_errors": field_errors,
        "errors": errors
    }, status=status.HTTP_201_CREATED if instances else status.HTTP_400_BAD_REQUEST)
def filter_model_data(queryset, filter_dict=None):
    if filter_dict:
        filters = Q()
        model = queryset.model  
        for field, values in filter_dict.items():
            if hasattr(model, field):  
                field_obj = model._meta.get_field(field)
                field_filter = Q()

                try:
                    for value in values if isinstance(values, list) else [values]:
                        if isinstance(field_obj, models.UUIDField):
                            value = uuid.UUID(value)  
                            field_filter |= Q(**{field: value})

                        elif isinstance(field_obj, models.ForeignKey):
                            field_filter |= Q(**{f"{field}__pk": value})

                        elif isinstance(field_obj, (models.DateField, models.DateTimeField)):
                            value = datetime.strptime(value, "%Y-%m-%d").date()  
                            field_filter |= Q(**{f"{field}__date": value})  

                        elif isinstance(field_obj, models.BooleanField):
                            value = value.lower() in ["true", "1", "yes"]  
                            field_filter |= Q(**{field: value})

                        elif isinstance(field_obj, (models.CharField, models.TextField)):
                            field_filter |= Q(**{f"{field}__icontains": value})

                        else:
                            field_filter |= Q(**{field: value})

                    filters &= field_filter

                except (ValueError, TypeError):
                    return {"error": f"Invalid format for field '{field}'."}

        queryset = queryset.filter(filters)

    return queryset


def get_distinct_values(request, model_name, fields, app_label="api_v1"):
    """
    Retrieves distinct values for the given fields from the specified model.
    Ensures that only data for the authenticated user's school is fetched.
    """
    try:
        model = apps.get_model(app_label, model_name)
    except LookupError:
        return Response({"error": f"Model '{model_name}' not found in app '{app_label}'."}, status=400)

    user_school = getattr(request.user, "school", None)
    if not user_school:
        return Response({"error": "Unauthorized access. User does not belong to any school."}, status=403)

    distinct_values = {}
    current_year = datetime.now().year
    current_month = datetime.now().month

    for field in fields:
        if not hasattr(model, field):
            distinct_values[field] = {"error": f"Field '{field}' does not exist in model '{model_name}'"}
            continue

        try:
            field_object = model._meta.get_field(field)

            if field_object.is_relation:
                related_model = field_object.related_model
                related_name_field = "name" if hasattr(related_model, "name") else None

                if related_name_field:
                    distinct_values[field] = list(
                        model.objects.filter(school=user_school)  # Ensure filtering by school
                        .values(field, f"{field}{related_name_field}")
                        .distinct()
                    )
                else:
                    distinct_values[field] = list(
                        model.objects.filter(school=user_school).values(field).distinct()
                    )
            else:
                values = list(
                    model.objects.filter(school=user_school)  # Filter by school
                    .values_list(field, flat=True).distinct()
                )

                # Process date values
                if field_object.get_internal_type() in ["DateField", "DateTimeField"]:
                    formatted_values = set()
                    for value in values:
                        if isinstance(value, str):
                            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                        if isinstance(value, datetime):
                            if value.year == current_year and value.month == current_month:
                                formatted_values.add(value.strftime("%Y-%m-%d"))
                            elif value.year == current_year:
                                formatted_values.add(value.strftime("%Y-%m"))
                            else:
                                formatted_values.add(value.strftime("%Y"))
                    distinct_values[field] = sorted(formatted_values)
                else:
                    distinct_values[field] = values

        except ValueError as e:
            distinct_values[field] = {"error": str(e)}

    return Response(distinct_values)

gmaps = googlemaps.Client(key=settings.GOOGLE_API_KEY)

def get_place_namn_by_map(lat, lng):
    if lat is None or lng is None:
        return "Unknown location"
    try:
        result = gmaps.reverse_geocode((lat, lng))
        if result and 'formatted_address' in result[0]:
            return result[0]["formatted_address"]
        else:
            return f"Coordinates: {lat}, {lng}"  # Fallback if no formatted address found
    except googlemaps.exceptions.ApiError as e:
        return f"message: Google Maps API Error - {str(e)}"
    except googlemaps.exceptions.Timeout as e:
        return "nessage: Timeout while trying to reach Google Maps API"
    except googlemaps.exceptions.TransportError as e:
        return "message: Network issue while trying to reach Google Maps API"
    except Exception as e:
        return f"message: Unexpected issue - {str(e)}"