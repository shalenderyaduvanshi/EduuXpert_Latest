# your_app/signals.py
import os
from django.db.models.signals import pre_save,pre_delete,post_save,post_delete
from django.dispatch import receiver
from .models import *
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_logged_out
from .utils import set_current_user, get_current_user

# Utility function to get the current user (adjust as per your logic)
def get_current_user():
    return get_user_model().objects.first()  # Modify this based on how you track the user.




def delete_old_file(instance, field_name):
    """Delete the old file if a new file is being uploaded."""
    old_file = getattr(instance, field_name)
    if old_file:
        old_file_path = os.path.join(settings.MEDIA_ROOT, old_file.name)
        if os.path.exists(old_file_path):
            os.remove(old_file_path)
def delete_file(file_path):
    """Delete the file if it exists."""
    if file_path and os.path.exists(file_path):
        os.remove(file_path)


@receiver(pre_save, sender=NoticeBoard)
def auto_delete_file_on_change(sender, instance, **kwargs):
    if not instance.pk:
        return

    try:
        old_instance = sender.objects.get(pk=instance.pk)
    except sender.DoesNotExist:
        return

    # Check if the file has changed and delete the old file
    if old_instance.attach and old_instance.attach != instance.attach:
        delete_old_file(old_instance, 'attach')

@receiver(pre_delete, sender=NoticeBoard)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    """Delete the associated file when the NoticeBoard instance is deleted."""
    if instance.attach:
        file_path = os.path.join(settings.MEDIA_ROOT, instance.attach.name)
        delete_file(file_path)

@receiver(pre_save, sender=Syllabus)
def auto_delete_file_on_change(sender, instance, **kwargs):
    if not instance.pk:
        return

    try:
        old_instance = sender.objects.get(pk=instance.pk)
    except sender.DoesNotExist:
        return

    # Check if the file has changed and delete the old file
    if old_instance.file and old_instance.file != instance.file:
        delete_old_file(old_instance, 'file')

@receiver(pre_delete, sender=Syllabus)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    """Delete the associated file when the NoticeBoard instance is deleted."""
    if instance.file:
        file_path = os.path.join(settings.MEDIA_ROOT, instance.file.name)
        delete_file(file_path)
@receiver(pre_save, sender=User)
def auto_delete_file_on_change(sender, instance, **kwargs):
    if not instance.pk:
        return

    try:
        old_instance = sender.objects.get(pk=instance.pk)
    except sender.DoesNotExist:
        return
    # Check if the file has changed and delete the old file
    if old_instance.image and old_instance.image != instance.image:
        delete_old_file(old_instance, 'image')

@receiver(pre_delete, sender=User)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    """Delete the associated file when the NoticeBoard instance is deleted."""
    if instance.image:
        file_path = os.path.join(settings.MEDIA_ROOT, instance.image.name)
        delete_file(file_path)

# ==============================sims_config========================
@receiver(pre_save, sender=SimsConfig)
def auto_delete_file_on_change(sender, instance, **kwargs):
    if not instance.pk:
        return
    try:
        old_instance = sender.objects.get(pk=instance.pk)
    except sender.DoesNotExist:
        return
    # Check if the file has changed and delete the old file
    if old_instance.image and old_instance.image != instance.image:
        delete_old_file(old_instance, 'image')

@receiver(pre_delete, sender=SimsConfig)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    """Delete the associated file when the NoticeBoard instance is deleted."""
    if instance.image:
        file_path = os.path.join(settings.MEDIA_ROOT, instance.image.name)
        delete_file(file_path)
#######################  Audit log #################################

# Utility function to get the current user (adjust as per your logic)
def get_current_user():
    return get_user_model().objects.first()  # Modify this based on how you track the user.

# Signal to log create or update actions
@receiver(post_save)
def log_create_or_update(sender, instance, created, **kwargs):
    """Logs the create or update actions for all models."""
    
    excluded_models = ['LoginActivityLog', 'ActivityLog', 'User']
    if sender.__name__ in excluded_models:
        return
    if sender._meta.app_label == 'api_v1':  # Ensure logging only for your app models
        action = 'CREATE' if created else 'UPDATE'
        print(f"Logging action for {sender.__name__} with instance id {instance.pk}") 
        user = get_current_user()  # Get the current user
        ActivityLog.objects.create(
            user=user,
            action=action,
            model_name=sender.__name__,  # Dynamically fetch the model name
            instance_id=instance.id,
            school=getattr(user,'school',None),
            status='Success'
        )

# Signal to log delete actions
@receiver(post_delete)
def log_delete(sender, instance, **kwargs):
    """Logs the delete actions for all models."""

    excluded_models = ['LoginActivityLog', 'ActivityLog', 'User']
    if sender.__name__ in excluded_models:
        return
    if sender._meta.app_label == 'api_v1':  
        user = get_current_user()
        ActivityLog.objects.create(
            user=user,
            action='DELETE',
            model_name=sender.__name__,  
            instance_id=instance.id,
            school=getattr(user,'school',None),
            status='Success'
        )
        
@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    set_current_user(user)
    LoginActivityLog.objects.create(
        user=user,
        description='login',
        school=user.school
    )


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    set_current_user(None)
    LoginActivityLog.objects.create(
        user=user,
        description='logout',
        school=user.school
    )