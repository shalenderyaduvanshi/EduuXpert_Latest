from django.db import models
import uuid
from datetime import datetime
from django.contrib.auth.models import AbstractUser, Permission, Group
from datetime import date
from django.contrib.auth.hashers import make_password, check_password
from django.utils.crypto import get_random_string
from autoslug import AutoSlugField
class Common(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    active = models.BooleanField(default=True)
    class Meta:
        abstract = True

class School(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    email = models.EmailField(null=True, blank=True)
    short_form = models.CharField(max_length=255,null=True,blank=True)
    fav_image = models.ImageField(upload_to="favicon/",null=True,blank=True)
    background_image = models.ImageField(upload_to="background/",null=True,blank=True)
    logo = models.ImageField(upload_to="logo/",null=True,blank=True)
    address = models.TextField(null=True,blank=True)
    school_code = models.CharField(max_length=150, unique=True)
    title =  models.TextField(null=True,blank=True)
    description =  models.TextField(null=True,blank=True)
    def __str__(self):
        return f"{self.name}"

class Branch(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    school = models.ForeignKey(School, on_delete=models.CASCADE, related_name='branches')
    name = models.CharField(max_length=255)
    email = models.EmailField(null=True, blank=True)
    fav_image = models.ImageField(upload_to="favicon/",null=True,blank=True)
    background_image = models.ImageField(upload_to="background/",null=True,blank=True)
    logo = models.ImageField(upload_to="logo/",null=True,blank=True)
    address = models.TextField()
    school_code = models.CharField(max_length=150, unique=True)
    title =  models.TextField(blank=True)
    description =  models.TextField(blank=True)
    
class AcademicSession(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    start_date = models.DateField()
    end_date = models.DateField()
    name = models.CharField(max_length=50)  # e.g., 2023-2024
    is_current = models.BooleanField(default=False)
    school = models.ForeignKey(School, on_delete=models.CASCADE)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    def __str__(self):
        return f"{self.name} - {self.school.name}"
    

class Role(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    group = models.OneToOneField(Group, on_delete=models.CASCADE,null=True,blank=True)
    def __str__(self):
        return f"{self.name} - {self.school.name}" 


class User(Common,AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200,null=True,blank=True)
    mobile_no = models.CharField(max_length=20,null=True,blank=True)
    image = models.ImageField(upload_to="profile/",null=True,blank=True)
    role = models.ForeignKey("Role", on_delete=models.SET_NULL,null = True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    plain_password = models.CharField(max_length=100, blank=True)
    student_profile = models.OneToOneField("Student", on_delete=models.CASCADE, null=True, blank=True)
    teacher_profile = models.OneToOneField("Teacher", on_delete=models.CASCADE, null=True, blank=True)
    parent_profile = models.OneToOneField("Parent", on_delete=models.CASCADE, null=True, blank=True)
    rfid_card_number = models.CharField(max_length=255, null=True, blank=True)
    finger_prints = models.CharField(max_length=255, null=True, blank=True)

class App(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    component_key = models.CharField(max_length=200, null=True, blank=True)
    icon = models.CharField(max_length=500)
    order = models.PositiveIntegerField(default=0) 
    role = models.JSONField(default=list,null=True,blank=True) 
    class Meta:
        ordering = ['order']
    
    
class AppItem(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    component_key = models.CharField(max_length=200, null=True, blank=True)
    app = models.ForeignKey(App, related_name='app_items', on_delete=models.CASCADE)
    order = models.PositiveIntegerField(default=0) 
    role = models.JSONField(default=list,null=True,blank=True) 

    class Meta:
        ordering = ['order']


class AppListPermission(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    appitem = models.ForeignKey(AppItem, related_name='app_list_permissions', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    order = models.PositiveIntegerField(default=0) 
    show_in_sidebar  = models.BooleanField(default=True)
    

class AppPermissions(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    app = models.ForeignKey(App, related_name='app_permissions', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    order = models.PositiveIntegerField(default=0) 
    show_in_sidebar  = models.BooleanField(default=True)
    
class StudentEnquiry(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50, blank=False)  # Required
    date_of_birth = models.DateField(null=True, blank=True)  # Optional
    gender = models.CharField(max_length=20, null=True, blank=True)  # Optional
    mother_tongue = models.CharField(max_length=20, null=True, blank=True)  # Optional
    religion = models.CharField(max_length=20, null=True, blank=True)  # Optional
    address = models.TextField(null=True, blank=True)  # Optional
    city = models.CharField(max_length=50, null=True, blank=True)  # Optional
    state = models.CharField(max_length=50, null=True, blank=True)  # Optional
    nationality = models.CharField(max_length=30, null=True, blank=True)  # Optional
    mobile_no = models.CharField(max_length=20, null=True, blank=True)  # Optional
    email = models.EmailField(null=True, blank=True)  # Optional
    previous_school = models.CharField(max_length=100, null=True, blank=True)  # Optional
    previous_class_study = models.CharField(max_length=100, null=True, blank=True)  # Optional
    status = models.CharField(
        max_length=20,
        choices=[('Pending', 'Pending'), ('Followed Up', 'Followed Up'), ('Closed', 'Closed')],
        default='Pending'
    )
    enquiry_no = models.CharField(max_length=50, null=True, blank=True)  # Optional
    remarks = models.TextField(null=True, blank=True)  # Optional
    school = models.ForeignKey(School, on_delete=models.CASCADE)  # Mandatory
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)  # Optional
    guardian_name = models.CharField(max_length=200, null=True, blank=True)
    guardian_relation = models.CharField(max_length=200, null=True, blank=True)  # Relation to guardian
    guardian_occupation = models.CharField(max_length=200, null=True, blank=True)  # Guardian's occupation
    guardian_phone = models.CharField(max_length=200, null=True, blank=True)  # Guardian's occupation
    father_name = models.CharField(max_length=200, null=True, blank=True)  # Father's name
    father_phone = models.CharField(max_length=200, null=True, blank=True)  # Father's name
    father_occupation = models.CharField(max_length=200, null=True, blank=True)  # Father's occupation
    mother_name = models.CharField(max_length=200, null=True, blank=True)  # Mother's name
    mother_phone = models.CharField(max_length=200, null=True, blank=True)  # Mother's name
    mother_occupation = models.CharField(max_length=200, null=True, blank=True)  # Mother's occupation
    school_class = models.ForeignKey("SchoolClass", on_delete=models.SET_NULL,null=True,blank=True)
    session =models.ForeignKey("AcademicSession", on_delete=models.SET_NULL,null=True,blank=True)
    category = models.CharField(max_length=200, null=True, blank=True)


class Student(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=30, blank=True)
    date_of_birth = models.DateField(null=True,blank=True)
    age = models.IntegerField(null=True,blank=True)
    birth_place = models.CharField(max_length=50, null=True,blank=True)
    gender = models.CharField(max_length=20, null=True,blank=True)
    mother_tongue = models.CharField(max_length=20, null=True,blank=True)
    religion = models.CharField(max_length=20, null=True,blank=True)
    blood_group = models.CharField(max_length=10, null=True,blank=True)
    address = models.CharField(max_length=500, null=True,blank=True)
    city = models.CharField(max_length=25, null=True,blank=True)
    state = models.CharField(max_length=25, null=True,blank=True)
    nationality = models.CharField(max_length=30, null=True,blank=True)
    mobile_no = models.CharField(max_length=20, null=True,blank=True)
    email = models.EmailField(null=True,blank=True)
    previous_attended = models.CharField(max_length=100, null=True,blank=True)
    previous_address = models.CharField(max_length=100, null=True,blank=True)
    previous_purpose = models.CharField(max_length=100, null=True,blank=True)
    previous_class_study = models.CharField(max_length=100, null=True,blank=True)
    previous_date_of_leaving = models.DateField(null=True,blank=True)
    date_of_leaving = models.DateField(null=True,blank=True)
    admission_date = models.DateField(null=True,blank=True)
    transfer_certificate = models.CharField(max_length=20, null=True,blank=True)
    dob_certificate = models.CharField(max_length=20, null=True,blank=True)
    physically_handicap = models.CharField(max_length=20, null=True,blank=True)
    school_class = models.ForeignKey("SchoolClass", on_delete=models.SET_NULL,null=True,blank=True)
    section = models.ForeignKey("Section", on_delete=models.SET_NULL,null=True,blank=True)
    roll_no = models.CharField(max_length=20, null=True,blank=True)
    transport = models.ForeignKey("Vehicle", on_delete=models.SET_NULL,null=True,blank=True)
    dormitory = models.ForeignKey("Dormitory", on_delete=models.SET_NULL,null=True,blank=True)
    house = models.ForeignKey("House", on_delete=models.SET_NULL,null=True,blank=True)
    student_category = models.ForeignKey("Student_Category", on_delete=models.SET_NULL,null=True,blank=True)
    club = models.ForeignKey("Club", on_delete=models.SET_NULL,null=True,blank=True,related_name='students',)
    session =models.ForeignKey("AcademicSession", on_delete=models.SET_NULL,null=True,blank=True)
    enroll_no=models.CharField(max_length=100, null=True,blank=True)
    card_number = models.CharField(max_length=100, null=True,blank=True)
    issue_date = models.DateField(null=True,blank=True)
    expiry_date = models.DateField(null=True,blank=True)
    dormitoryroom = models.ForeignKey("DormitoryRoom", on_delete=models.SET_NULL,null=True,blank=True)
    more_entries = models.IntegerField(null=True,blank=True)
    login_status = models.CharField(max_length=20, null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    grade = models.CharField(max_length=50,null=True,blank=True)
    is_active = models.BooleanField(default=True)
    category = models.CharField(max_length=200, null=True, blank=True)
    guardian_name = models.CharField(max_length=200, null=True, blank=True)
    guardian_relation = models.CharField(max_length=200, null=True, blank=True)  # Relation to guardian
    guardian_occupation = models.CharField(max_length=200, null=True, blank=True)  # Guardian's occupation
    father_name = models.CharField(max_length=200, null=True, blank=True)  # Father's name
    father_occupation = models.CharField(max_length=200, null=True, blank=True)  # Father's occupation
    mother_name = models.CharField(max_length=200, null=True, blank=True)  # Mother's name
    mother_occupation = models.CharField(max_length=200, null=True, blank=True)  # M
    guardian_phone = models.CharField(max_length=200, null=True, blank=True)  # Father's name
    mother_phone = models.CharField(max_length=200, null=True, blank=True)  # Father's name
    father_phone = models.CharField(max_length=200, null=True, blank=True)  # Father's name
    parents = models.ManyToManyField("Parent", related_name='parents', blank=True)
    def __str__(self):
        return f"{self.name} - {self.school.name}"
    
class SchoolClass(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50,null=True, blank=True)
    series = models.CharField(max_length=100,null=True, blank=True)
    teacher = models.ForeignKey("Teacher", on_delete=models.SET_NULL,null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    def __str__(self):
        return f"{self.name} - {self.school.name}"
        
class Section(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50,blank=True)
    nick_name = models.CharField(max_length=50,blank=True)
    school_class = models.ForeignKey(SchoolClass, on_delete=models.CASCADE,null=True,blank=True)
    teacher = models.ForeignKey("Teacher", on_delete=models.SET_NULL, null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    
class Department(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    department_code = models.CharField(max_length=50)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    
class Designation(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    
class Teacher(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    teacher_number = models.BigIntegerField(null=True,blank=True)
    date_of_birth = models.DateField(null=True,blank=True)
    gender = models.CharField(max_length=50,null=True,blank=True)
    religion = models.CharField(max_length=30,null=True,blank=True)
    blood_group = models.CharField(max_length=10,null=True, blank=True)
    address = models.CharField(max_length=500,null=True, blank=True)
    mobile_no = models.CharField(max_length=20)
    email = models.EmailField(null=True,blank=True)
    facebook = models.URLField(null=True,blank=True)
    twitter = models.URLField(null=True,blank=True)
    googleplus = models.URLField(null=True,blank=True)
    linkedin = models.URLField(null=True,blank=True)
    qualification = models.CharField(max_length=25,null=True,blank=True)
    marital_status = models.CharField(max_length=25,null=True,blank=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL,null=True,blank=True)
    designation = models.ForeignKey(Designation, on_delete=models.SET_NULL,null=True,blank=True)
    date_of_joining = models.DateField(null=True,blank=True)
    joining_salary = models.IntegerField(null=True,blank=True)
    status = models.BooleanField(default=True)
    date_of_leaving = models.DateField(null=True,blank=True)
    login_status = models.BooleanField(default=False)
    subjects = models.ManyToManyField("Subject", related_name='subjects', blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    is_active = models.BooleanField(default=True)
    account_holder_name = models.CharField(max_length=150,null=True,blank=True)
    account_number = models.BigIntegerField(null=True,blank=True)
    bank_name = models.CharField(max_length=100,null=True,blank=True)
    branch_name = models.CharField(max_length=200,null=True,blank=True)
    ifsc_code = models.CharField(max_length=30,null=True,blank=True)
     
class Club(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    description = models.TextField(null=True,blank=True)
    teacher = models.ForeignKey("Teacher", on_delete=models.SET_NULL, null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
class House(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    house_code = models.CharField(max_length=50, null=True,blank=True)
    description = models.TextField(null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    
class Dormitory(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    hostel_room = models.ForeignKey("HostelRoom", on_delete=models.SET_NULL,null=True,blank=True)
    hostel_category = models.ForeignKey("HostelCategory", on_delete=models.SET_NULL,null=True,blank=True)
    capacity = models.IntegerField(null=True,blank=True)
    address =models.TextField(null=True,blank=True)
    description =models.TextField(null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    
class DormitoryRoom(Common):
    dormitory = models.ForeignKey(Dormitory, on_delete=models.CASCADE)
    name = models.CharField(max_length=150)
    description = models.TextField(null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    
class HostelRoom(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150)
    room_type = models.CharField(max_length=150)
    number_of_beds = models.IntegerField()
    cost_per_bed = models.IntegerField()
    description = models.TextField(null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    
class HostelCategory(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    description = models.TextField(null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    

class Student_Category(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    description = models.TextField(null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    
class Parent(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    email = models.EmailField(null=True,blank=True)
    students = models.ManyToManyField(Student, related_name='student_child')
    relation = models.CharField(max_length=200,null=True,blank=True)
    mobile_no = models.CharField(max_length=20,null=True,blank=True)
    address = models.TextField(null=True,blank=True)
    profession = models.CharField(max_length=100,null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    is_active = models.BooleanField(default=True)
    
class Subject(Common,models.Model):
    name = models.CharField(max_length=50)
    subject_code = models.CharField(max_length=50,null=True,blank=True)
    active = models.BooleanField(default=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
    school_class = models.ForeignKey(SchoolClass, on_delete=models.CASCADE,null=True,blank=True)
    
class Leaves(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    type = models.CharField(max_length=250)
    purpose = models.TextField(null=True,blank=True)
    sender = models.ForeignKey(User,related_name="sender", on_delete=models.SET_NULL,null=True, blank=True)
    reciever = models.ForeignKey(School,related_name="reciever", on_delete=models.SET_NULL,null=True, blank=True)
    from_date = models.DateField(null=True,blank=True)
    to_date = models.DateField(null=True,blank=True)
    from_time = models.TimeField(null=True,blank=True)
    to_time = models.TimeField(null=True,blank=True)
    contact_leave = models.CharField(max_length=50,null=True,blank=True)
    address = models.TextField(null=True,blank=True)
    consent_relation = models.CharField(max_length=200,null=True,blank=True)
    relation_number = models.CharField(max_length=50,null=True,blank=True)
    hostel_return_date =  models.DateField(null=True,blank=True)
    hostel_return_time =  models.TimeField(null=True,blank=True)
    status = models.CharField(max_length=20,default='Pending')
    remark =  models.TextField(null=True,blank=True)
    status_updated_by = models.ForeignKey(User, related_name="leave_status_updates", null=True, blank=True, on_delete=models.SET_NULL)
    status_updated_dateandtime = models.DateTimeField(null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)


class Timetable(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    teacher = models.ForeignKey(Teacher,related_name="teacher", on_delete=models.SET_NULL,null=True, blank=True)
    day = models.CharField(max_length=10,null=True, blank=True)
    section = models.ForeignKey(Section, on_delete=models.CASCADE, related_name='timetable',null=True, blank=True)
    school_class = models.ForeignKey(SchoolClass, related_name='timetables', on_delete=models.CASCADE,null=True, blank=True)
    subject = models.ForeignKey(Subject, on_delete=models.SET_NULL,null=True, blank=True)
    period = models.ForeignKey('TimePeriods', on_delete=models.CASCADE, related_name='periods', null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)

class TimePeriods(models.Model):
    name = models.CharField(max_length=100)
    unique_name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    


class NoticeBoard(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.TextField(null=True,blank=True)
    message = models.TextField(null=True,blank=True)
    date = models.DateField(null=True, blank=True)
    attach = models.FileField(upload_to="noticeboard/",null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)

    
class Feedback(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    school_class = models.ForeignKey(SchoolClass, on_delete=models.SET_NULL, related_name='class_name',null=True, blank=True)
    section = models.ForeignKey(Section, on_delete=models.SET_NULL, related_name='section',null=True, blank=True)
    sender = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='teacher_feedbacks',null=True, blank=True)
    students = models.ManyToManyField(Student, related_name='student_feedbacks')
    feedback_text = models.TextField()
    rating= models.CharField(blank=True, max_length=150, null=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    
    
class Syllabus(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subject = models.ForeignKey(Subject, related_name='syllabus', on_delete=models.CASCADE)
    file = models.FileField(upload_to='syllabus_files/') 
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    

class Attendance(Common):
    student = models.ForeignKey(Student, on_delete=models.CASCADE,null=True, blank=True)
    date = models.DateField(null=True, blank=True)
    school_class = models.ForeignKey(SchoolClass, on_delete=models.SET_NULL, related_name='attend_class',null=True, blank=True)
    section = models.ForeignKey(Section, on_delete=models.SET_NULL, related_name='attend_section',null=True, blank=True)
    status = models.CharField(max_length=30,null=True,blank=True )
    generator = models.ForeignKey(User, on_delete=models.SET_NULL,null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)

  



    # ============================Exam==============================================================
class Exam(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    school_class = models.ForeignKey(SchoolClass, on_delete=models.SET_NULL, related_name='exam_class',null=True, blank=True)  
    section = models.ForeignKey(Section, on_delete=models.SET_NULL, related_name='exam_section',null=True, blank=True)
    examtype = models.ForeignKey("ExamType", on_delete=models.SET_NULL,null=True, blank=True) 
    date = models.DateField()
    mode = models.CharField(max_length=100, blank=True)
    description = models.TextField(null=True,blank=True)
    center = models.CharField(max_length=100, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
   
     
class ExamType(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, blank=True) 
    description = models.TextField(null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)


class ExamSubject(Common):
    exam = models.ForeignKey(Exam, on_delete=models.CASCADE,related_name="subject_exam",null=True, blank=True )
    subject = models.ForeignKey(Subject, on_delete=models.SET_NULL,null=True, blank=True )
    total_marks = models.FloatField()
    subject_date = models.DateField()  
    start_time = models.TimeField()
    end_time = models.TimeField()
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)




class Result(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    exam_subject = models.ForeignKey(ExamSubject, on_delete=models.SET_NULL, null=True, blank=True)
    marks_obtained = models.FloatField()
    grade = models.CharField(max_length=2, blank=True, null=True)  # Store grade as a CharField
    grading_scale = models.ForeignKey("GradingScale", on_delete=models.SET_NULL, null=True, blank=True, related_name="applied_grading_scale")
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)

    # def save(self, *args, **kwargs):
    #     # Check if a specific grading scale is set for this result
    #     if self.grading_scale:
    #         # Find the grade within the chosen grading scale based on marks obtained
    #         grading_scale_entry = GradingScale.objects.filter(
    #             name=self.grading_scale.name,
    #             min_percentage__lte=self.marks_obtained,
    #             max_percentage__gte=self.marks_obtained
    #         ).first()
            
    #         # Set the grade as a string if found
    #         if grading_scale_entry:
    #             self.grade = grading_scale_entry.grade
    #         else:
    #             self.grade = None  # Or handle according to your requirement

    #     super().save(*args, **kwargs)

    

class GradingScale(Common):
    name = models.CharField(max_length=200,null=True,blank=True)
    grade = models.CharField(max_length=5)
    min_percentage = models.FloatField()
    max_percentage = models.FloatField()
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)

    
class AdmitCard(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    student = models.ForeignKey(Student, on_delete=models.SET_NULL,null=True, blank=True )
    exam = models.ForeignKey(Exam, on_delete=models.SET_NULL,related_name="admit_exam",null=True, blank=True )
    exam_subjects = models.ManyToManyField(ExamSubject)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)

    
# =====================================event====================================================
class Event(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    date = models.DateField()
    description = models.TextField(null=True,blank=True)
    title = models.CharField(max_length=500,null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)

    
# ==============================================teacher payroll===================================
class Payroll(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='payrolls')
    month = models.CharField(max_length=20,default=0)  # Store month as a string, e.g., 'January 2024'
    day_in_month = models.IntegerField(null=True,blank=True)  # Total days in the month
    payable_days = models.IntegerField(null=True,blank=True)  # Payable/Salary days
    basic_salary = models.DecimalField(max_digits=10, decimal_places=2,null=True,blank=True)
    gross_salary = models.DecimalField(max_digits=10, decimal_places=2,null=True, blank=True)  # Gross Salary
    allowance = models.JSONField(default=list,null=True,blank=True) 
    deduction = models.JSONField(default=list,null=True,blank=True) 
    total_deduction = models.DecimalField(max_digits=10, decimal_places=2,default=0.0)  # Total Deduction
    net_salary = models.DecimalField(max_digits=10, decimal_places=2,default=0.0)  # Net Salary (In Hand)
    epf = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)  # EPF 12%
    epf_edli = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)  # EPF+EDLI (1%)
    esic = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)  # ESIC 3.25%
    gratuity = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)  # Gratuity
    bonus = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)  # Bonus (8.33%-20%)
    ctc = models.DecimalField(max_digits=10, decimal_places=2,null=True, blank=True)  # Cost to Company (CTC)
    status = models.CharField(max_length=20, choices=[('Pending', 'Pending'), ('Paid', 'Paid')], default='Pending')
    payment_date = models.DateField(null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    
###############################  FEES ###############################################
# Fee Category Model
class FeeCategory(Common):
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
    def __str__(self):
        return f"{self.name} - {self.school.name}"
class FeeTerm(Common):
    name = models.CharField(max_length=255)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
    def __str__(self):
        return f"{self.name} - {self.school.name}"
# Fee Structure Model
class FeeStructure(Common):
    fee_category = models.ForeignKey(FeeCategory, on_delete=models.CASCADE)
    class_assigned = models.ForeignKey('SchoolClass', on_delete=models.SET_NULL,null=True, blank=True)
    term = models.CharField(max_length=50)  # e.g., "Monthly", "Quarterly", "Yearly"
    amount = models.DecimalField(max_digits=10, decimal_places=2,null=True, blank=True)  # Corrected field type
    late_fee = models.DecimalField(max_digits=10, decimal_places=2,null=True, blank=True)
    session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE,null=True,blank=True)
    effective_from = models.CharField(max_length=50,null=True, blank=True)
    effective_until = models.CharField(max_length=50,null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
    def __str__(self):
        return f"{self.term} - {self.school.name}"
        
class FeeNote(Common):
    content = models.TextField()
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True )

    def __str__(self):
        return f"Note for {self.school.name}"
# Student Fee Model
class StudentFee(Common):
    student = models.ForeignKey('Student', on_delete=models.CASCADE)
    fee_structure = models.ForeignKey(FeeStructure, on_delete=models.SET_NULL,null=True, blank=True)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)  # Corrected field type
    paid_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)  # Corrected field type
    is_paid = models.BooleanField(default=False)
    due_balance = models.DecimalField(max_digits=10, decimal_places=2,default=0)
    payment_date = models.DateField(null=True, blank=True)
    academic_session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE, null=True, blank=True)
    school = models.ForeignKey('School', on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey('Branch', on_delete=models.CASCADE, null=True, blank=True)
    def __str__(self):
        return f"{self.payment_date} - {self.school.name}"
    

    def save(self, *args, **kwargs):
        # Update is_paid status based on paid_amount and total_amount
        self.is_paid = self.paid_amount >= self.total_amount
        super().save(*args, **kwargs)

# Payment Model
class Payment(Common):
    student_fee = models.ForeignKey(StudentFee, on_delete=models.SET_NULL,null=True, blank=True)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=50)  # e.g., "Cash", "Online", "Card"
    payment_date = models.DateField(null=True, blank=True)
    transaction_id = models.CharField(max_length=255, null=True, blank=True)
    cheque_number = models.CharField(max_length=100, null=True, blank=True)
    bank_name = models.CharField(max_length=100, null=True, blank=True)
        
    
class Discount(Common):
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    school = models.ForeignKey('School', on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey('Branch', on_delete=models.CASCADE, null=True, blank=True)
    def __str__(self):
        return f"{self.name} - {self.school.name}"
class FeeDiscount(Common):
    student = models.ForeignKey('Student', on_delete=models.CASCADE,null=True, blank=True)
    fee = models.ForeignKey('StudentFee', on_delete=models.CASCADE,null=True, blank=True, related_name='discounts')
    discount_name = models.ForeignKey('Discount', on_delete=models.SET_NULL,null=True, blank=True)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2)
    discount_type = models.CharField(max_length=200,null=True, blank=True)
    valid_until = models.DateField(null=True, blank=True)
    school = models.ForeignKey('School', on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey('Branch', on_delete=models.CASCADE, null=True, blank=True)
    def __str__(self):
        return f"{self.student.name} - {self.school.name} - {self.discount_name.name}"

# Fee Receipt Model
class FeeReceipt(Common):
    student_fee = models.ForeignKey(StudentFee, on_delete=models.SET_NULL,null=True, blank=True)
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE,null=True, blank=True, related_name='feereceipt')
    receipt_number = models.CharField(max_length=50, unique=True)
    total_paid = models.DecimalField(max_digits=10, decimal_places=2)
    def save(self, *args, **kwargs):
        # Generate receipt number only when the receipt is being created for the first time
        if not self.pk:  # If this is a new receipt (not an update)
            # Get the school short form from the associated student fee
            school_short_form = self.student_fee.academic_session.school.short_form

            # Get the latest receipt number for the current school
            latest_receipt = FeeReceipt.objects.filter(
                student_fee__academic_session__school=self.student_fee.academic_session.school
            ).order_by('-receipt_date').first()

            # Determine the next receipt number with leading zeros (e.g., SBC-0000001)
            if latest_receipt:
                last_series_number = int(latest_receipt.receipt_number.split('-')[-1])  # Get the last series number
                next_series_number = last_series_number + 1
            else:
                next_series_number = 1  # Start from 1 if no previous receipt exists

            # Format the receipt number: SchoolShortForm-0000001 (7-digit series number with leading zeros)
            receipt_number = f"{school_short_form}-{next_series_number:07d}"

            self.receipt_number = receipt_number

        super().save(*args, **kwargs)



# ===========================student progression==================
class PromotionHistory(Common):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    from_class = models.ForeignKey(SchoolClass, on_delete=models.SET_NULL, related_name='promotions_from', null=True)
    to_class = models.ForeignKey(SchoolClass, on_delete=models.SET_NULL, related_name='promotions_to', null=True)
    from_section = models.ForeignKey(Section, on_delete=models.SET_NULL, related_name='promotions_from', null=True)
    to_section = models.ForeignKey(Section, on_delete=models.SET_NULL, related_name='promotions_to', null=True)
    session = models.ForeignKey(AcademicSession, on_delete=models.CASCADE)
    promotion_date = models.DateField(auto_now_add=True)
    remarks = models.TextField(null=True, blank=True)  # Optional remarks about the promotion
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)  # Assuming you have a User model
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
    
class AcademicPerformance(Common):
    student = models.ForeignKey(Student, on_delete=models.SET_NULL,null=True, blank=True)
    session = models.ForeignKey(AcademicSession, on_delete=models.SET_NULL,null=True, blank=True )
    subjects = models.JSONField()  # Store subject-wise performance (subject name and score)
    attendance_percentage = models.FloatField(null=True, blank=True)  # Attendance percentage
    overall_grade = models.CharField(max_length=5, null=True, blank=True)  # E.g., A, B, C
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
    
class PerformanceMetrics(Common):
    student = models.ForeignKey(Student, on_delete=models.SET_NULL,null=True, blank=True)
    session = models.ForeignKey(AcademicSession, on_delete=models.SET_NULL,null=True, blank=True )
    subject = models.CharField(max_length=30)  # Subject name (e.g., "Mathematics")
    score = models.FloatField(null=True, blank=True)  # Score out of 100
    attendance_percentage = models.FloatField(null=True, blank=True)  # Attendance percentage
    behavior_score = models.IntegerField(null=True, blank=True)  # Score for behavior (e.g., 1-10 scale)
    assignment_completion_rate = models.FloatField(null=True, blank=True)  # Percentage of assignments completed
    remarks = models.TextField(null=True, blank=True)  # Any additional remarks
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
    

# ==================================enquiry==========================================
class EnquiryType(Common):
    name = models.CharField(max_length=100, blank=True) 
    description = models.TextField(null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
    
class Enquiry(Common):
    ENQUIRY_STATUS_CHOICES = [
        ('new', 'New'),
        ('in_progress', 'In Progress'),
        ('closed', 'Closed'),
    ]
    user = models.ForeignKey(User, on_delete=models.SET_NULL,null=True, blank=True)
    enquiry_type = models.CharField(max_length=200, null=True, blank=True) 
    message = models.TextField() 
    status = models.CharField(
        max_length=20,
        choices=ENQUIRY_STATUS_CHOICES,
        default='new'
    )
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
    


# ===============================earning type===========================
class EarningType(Common):
    name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
    

class Earning(Common):
    name = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    type =models.CharField(max_length=200)
    date = models.DateField(null=True, blank=True)
    phone_no = models.CharField(max_length=15,null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    remark = models.TextField(null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
     
# ===============================Expense type===========================
class ExpenseType(Common):
    name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)
    

class Expense(Common):
    name = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    type =models.CharField(max_length=200)
    date = models.DateField(null=True, blank=True)
    phone_no = models.CharField(max_length=15,null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    remark = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=100)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True, blank=True )
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True, blank=True)

    

class ActivityLog(models.Model):
    ACTION_CHOICES = (
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
    )
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=6, choices=ACTION_CHOICES)
    model_name = models.CharField(max_length=255)
    instance_id = models.CharField(max_length=50)
    status = models.CharField(max_length=50, default='Success')

    timestamp = models.DateTimeField(auto_now_add=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    

class LoginActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    description = models.CharField(max_length=50,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)

class SimsConfig(Common):
    key = models.CharField(max_length=255)
    value = models.JSONField(default=list,null=True,blank=True) 
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    image = models.ImageField(upload_to="configs/images/", null=True, blank=True)
    
    
    
    
    
class Notification(Common):
    sender = models.ForeignKey(User, on_delete=models.SET_NULL,null=True, blank=True)
    receiver = models.ManyToManyField(User, related_name="receivers")
    message = models.TextField(blank=True, null=True)
    file = models.FileField(upload_to="message_files/", blank=True, null=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    medium = models.JSONField(default=list)  # e.g., ['email', 'whatsapp']
    seen = models.BooleanField(default=False)
    def __str__(self):
        return f"Notification from {self.sender} to {self.receiver}"
    
    
    
    
class ClassRoom(Common):
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name="creator")
    school_class = models.CharField(max_length=100,null=True, blank=True)
    section = models.CharField(max_length=100, null=True, blank=True)
    subject = models.CharField(max_length=255, null=True, blank=True)
    room =models.CharField(blank=True, max_length=250, null=True)
    users = models.ManyToManyField('User', blank=True,null=True, related_name="classrooms")  # Assuming you have a Student model
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)


class ClassroomMessage(Common):
    classroom = models.ForeignKey("Classroom", on_delete=models.CASCADE, related_name='classroom')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    message = models.TextField()
    reply = models.ForeignKey('self', null=True, blank=True, related_name='replies', on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/',blank=True)
    view = models.ManyToManyField(Student, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    
    
    
class HostelLeave(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    leave_type = models.CharField(max_length=250)  # Type of leave (e.g., Sick Leave, Vacation Leave)
    purpose = models.TextField(null=True, blank=True)  # Purpose of the leave
    sender = models.ForeignKey(User, related_name="hostel_leave_sender", on_delete=models.SET_NULL,null=True, blank=True)  # Leave requested by
    receiver = models.ForeignKey(HostelRoom, related_name="hostel_leave_receiver", on_delete=models.SET_NULL,null=True, blank=True)  # Hostel room related to leave
    from_date = models.DateField(null=True, blank=True)  # Leave start date
    to_date = models.DateField(null=True, blank=True)  # Leave end date
    from_time = models.TimeField(null=True, blank=True)  # Leave start time
    to_time = models.TimeField(null=True, blank=True)  # Leave end time
    contact_during_leave = models.CharField(max_length=50, null=True, blank=True)  # Contact number during leave
    leave_address = models.TextField(null=True, blank=True)  # Address during leave
    guardian_consent_relation = models.CharField(max_length=200, null=True, blank=True)  # Guardian consent relation
    guardian_contact_number = models.CharField(max_length=50, null=True, blank=True)  # Guardian contact number
    hostel_return_date = models.DateField(null=True, blank=True)  # Date of returning to the hostel
    hostel_return_time = models.TimeField(null=True, blank=True)  # Time of returning to the hostel
    status = models.CharField(max_length=20, default='Pending')  # Status (e.g., Pending, Approved, Rejected)
    status_updated_by = models.ForeignKey(User, related_name="hostel_leave_status_updates", null=True, blank=True, on_delete=models.SET_NULL)  # User who updated the status
    status_updated_dateandtime = models.DateTimeField(null=True, blank=True)  # Date and time of status update
    hostel = models.ForeignKey(HostelRoom, on_delete=models.SET_NULL, null=True, blank=True)  # Specific hostel room
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)  # School reference
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)  # Branch reference
    

# ==============================ducument=========================
class UserDocument(Common):
    user_type = models.CharField(max_length=200,blank=True, null=True)
    user_id = models.CharField(max_length=200,blank=True, null=True)
    name = models.CharField(max_length=200,blank=True, null=True)  
    document = models.FileField(upload_to='user_documents/',blank=True, null=True)
    description = models.TextField(max_length=500, blank=True, null=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
# ==============================gallery=========================
class SchoolGallery(Common):
    image = models.FileField(upload_to='gallery_images/',null=True,blank=True)
    description = models.TextField(max_length=500, blank=True, null=True)
    category = models.CharField(max_length=150,null=True,blank=True)
    type = models.CharField(max_length=150,null=True,blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
#=================================visitor================================
class Visitor(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='visitors', null=True, blank=True)
    name = models.CharField(max_length=100,blank=True, null=True)
    photo = models.ImageField(upload_to='visitor_photos/', null=True, blank=True)
    mobile_number = models.CharField(max_length=20, null=True, blank=True)
    relation_with_parent = models.CharField(max_length=50,blank=True, null=True)
    date = models.DateTimeField(null=True, blank=True)
    time_slot =models.TimeField(null=True, blank=True)
    reason=models.TextField(blank=True, null=True)
    status = models.CharField(max_length=50, default='Pending')
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
# ========================= Help & Support =========================================
class HelpSupport(Common):
    user = models.ForeignKey(User, on_delete=models.SET_NULL,null=True,blank=True, related_name='help_user')
    name = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField( blank=True, null=True)
    mobile = models.CharField(max_length=15, blank=True, null=True)
    message = models.TextField( blank=True, null=True)
    image = models.ImageField(upload_to='help_support_images/', blank=True, null=True)
    status = models.CharField(max_length=50,default="Pending")
    solved_at = models.DateTimeField(null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
#=============================store===================================================
class Store(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    image = models.ImageField(upload_to='store_images/')
    link = models.URLField(max_length=200, blank=True, null=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)

# ===============================================qrcode=====================================
class QRCode(Common):
    name = models.CharField(max_length=255, blank=True, null=True)
    data = models.TextField() 
    type = models.CharField(max_length=255, blank=True, null=True)
    qr_code_image = models.ImageField(upload_to="qrcodes/")  
    logo = models.ImageField(upload_to="qrcodes/logos/", null=True, blank=True)  
    school = models.ForeignKey(School, on_delete=models.CASCADE,null=True,blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE,null=True,blank=True)
#=============================================meeting=======================================
class Meeting(Common):
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name="meetingcreator")
    type = models.CharField(max_length=120)
    school_class = models.ForeignKey(SchoolClass, on_delete=models.CASCADE, blank=True, null=True)
    section = models.ForeignKey(Section, on_delete=models.SET_NULL, blank=True, null=True)
    attendees = models.ManyToManyField(User,blank=True)
    guests = models.JSONField(verbose_name="Guest Emails", default=list)
    description = models.TextField(verbose_name="Description", blank=True, null=True)
    meeting_link = models.URLField(verbose_name="Meeting Link", blank=True, null=True)
    code = models.CharField(max_length=150, verbose_name="Code", blank=True, null=True)
    start_date = models.DateTimeField(blank=True, null=True)
    start_time = models.TimeField(blank=True, null=True) 
    time_duration = models.DurationField(verbose_name="Time Duration")
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
#===============================================assessment==============================================
class Assessment(Common):
    name = models.CharField(max_length=255)
    description = models.TextField()
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    
class Question(Common):
    assessment = models.ForeignKey(Assessment, related_name='questions', on_delete=models.CASCADE)
    text = models.CharField(max_length=255,blank=True)
    question_type = models.CharField(max_length=50)
    options = models.JSONField(null=True,blank=True) 
    answer = models.CharField(max_length=255) 


class UserAssessment(Common):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True,)
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE)
    score = models.FloatField(default=0.0)
    completed_at = models.DateTimeField(auto_now_add=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    user_answers = models.JSONField()
    checked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="checked_assessments")
    status = models.CharField(max_length=20, default="Pending")
    feedback = models.TextField(null=True,blank=True)
# ==========================================vendor====================================================
class VendorProfile(Common):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='vendor_profile')
    store_name = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    gst_no = models.CharField(max_length=15, null=True, blank=True)
    
    def __str__(self):
        return self.store_name

class Category(Common):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    category_name = models.CharField(max_length=100)
    category_image = models.ImageField(upload_to='categories')
    cat_slug= AutoSlugField(populate_from='category_name',unique=True,null=True,default=None)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.category_name

class Product(Common):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='product_vendor',null=True, blank=True,)
    product_name = models.CharField(max_length=100,default=None )
    category = models.ForeignKey(Category , on_delete=models.SET_NULL , null=True, blank=True, related_name="products" )
    price = models.IntegerField( null=True, blank=True)
    mrp = models.IntegerField( null=True, blank=True)
    publish = models.BooleanField(default=False)
    main_image = models.ImageField(upload_to="product", null=True, blank=True)
    description = models.TextField( null=True, blank=True)
    brand = models.CharField(max_length=200 , null=True, blank=True )
    new_slug= AutoSlugField(populate_from='product_name',unique=True,null=True,default=None)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)

    def price_percentage(self):
        return 100*(self.price-self.mrp)/self.mrp
 
    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.product_name

class Specification(Common):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    product = models.ForeignKey(Product , on_delete=models.CASCADE , related_name="specification")
    key = models.CharField(max_length=400,default=None)
    value = models.CharField(max_length=400 ,default=None)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)

class ProductImage(Common):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    product = models.ForeignKey(Product , on_delete=models.CASCADE , related_name="product_images")
    image = models.ImageField(upload_to="product")
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)


class Wishlist(Common):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    user = models.OneToOneField(User,on_delete=models.CASCADE,related_name="wishlist")
    products = models.ManyToManyField(Product)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

class Coupon(Common):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    coupon_code = models.CharField(max_length=10)
    is_expired = models.BooleanField(default=False)
    discount_price = models.IntegerField(default=100)
    minimum_amount = models.IntegerField(default=500)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)


class Cart(Common):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    user = models.ForeignKey(User , on_delete=models.CASCADE, related_name='carts')
    coupon = models.ForeignKey(Coupon , on_delete=models.SET_NULL , null=True, blank=True)
    is_paid = models.BooleanField(default=False)
    name = models.CharField(max_length=200,default="None")
    type = models.CharField(max_length=50,default="None")
    phone = models.CharField(max_length=60,default="None")
    house = models.CharField(max_length=200,default="None")
    street = models.CharField(max_length=200,default="None")
    city = models.CharField(max_length=100,default="None")
    pincode = models.CharField(max_length=100,default="None")
    state = models.CharField(max_length=100,default="None")
    orderid = models.CharField(max_length=100,default="None") 
    razorpay_order_id = models.CharField(max_length=100, null=True, blank=True)
    razorpay_payment_id = models.CharField(max_length=100, null=True, blank=True)
    razorpay_payment_signature = models.CharField(max_length=100, null=True, blank=True)
    invoice = models.FileField(upload_to='pdfs',blank=True, null=True)
    payment_method = models.CharField(default='COD',max_length=100) 
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)


    class Meta:
        ordering = ['-created_at']


    def get_cart_total(self):
        cart_items = self.cart_items.all()
        price = []
        for cart_item in cart_items:
            price.append(cart_item.quantity * cart_item.product.price)
        if self.coupon:
            if self.coupon.minimum_amount < sum(price):
                return sum(price) - self.coupon.discount_price
        return sum(price)
    
    
    # def get_cart_count(self):
    #     return CartItems.objects.filter(cart__is_paid = False  ,cart__user = self.user).count()
 
    
class CartItems(Common):
    id = models.UUIDField(primary_key=True, editable=False, default=uuid.uuid4)
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE , related_name="cart_items" )
    product = models.ForeignKey(Product, on_delete=models.SET_NULL , null=True , blank=True)
    quantity = models.IntegerField(default=1)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)


    class Meta:
        ordering = ['-created_at']

    def get_product_total_price(self):
        return self.quantity * self.product.price
        
        
        

class AccessMethod(Common):
    name = models.CharField(max_length=50,null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)

class UserAccessPass(Common):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='access_methods')
    method = models.ForeignKey(AccessMethod, on_delete=models.CASCADE)
    reason = models.TextField(blank=True,null=True)
    is_allowed = models.BooleanField(default=False)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    class Meta:
        unique_together = ('user', 'method')

class GatePass(Common):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='gatepasses')
    status = models.CharField(max_length=100, default='active')
    method = models.CharField(max_length= 255)
    type = models.CharField(max_length= 255)
 
class GateType(Common):
    name = models.CharField(max_length=100, null=True)
    discription = models.CharField(max_length= 255, null=True)
    checkout_time= models.DurationField(null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    

class Vehicle(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50, null=True, blank=True)
    vehicle_number = models.CharField(max_length=50)
    vehicle_model = models.CharField(max_length=50, null=True, blank=True)
    vehicle_quantity = models.IntegerField()
    year_made = models.DateField(null=True, blank=True)
    driver = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,related_name="driver")
    description = models.CharField(max_length=500, null=True, blank=True)
    speed = models.FloatField(default=0)  # Speed field in km/h
    engine_status = models.CharField(max_length=10, default='off')
    route_incharge = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,related_name='route_incharge')
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    passenger = models.ManyToManyField(User, related_name='passenger', blank=True)
    checkout_time= models.DurationField(null=True, blank=True)



class BusStation(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, null=True, blank=True)
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, null=True, blank=True,related_name="vehicle")
    route_fair = models.CharField(max_length=10, null=True, blank=True)
    lat = models.FloatField(null=True, blank=True)
    lon = models.FloatField(null=True, blank=True)
    place_name = models.TextField(blank=True,null=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    def __str__(self):
        return f'{self.name} | {self.id}'
    
class BusRoute(Common):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, null=True, blank=True,related_name="vehicle_bus_route")
    route = models.CharField(max_length=50, blank=True)
    arrive_stop_points = models.ManyToManyField(BusStation, related_name='arrive_stop_points', blank=True)
    return_stop_points = models.ManyToManyField(BusStation, related_name='return_stop_points', blank=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, null=True, blank=True)
    def __str__(self):
        return f'{self.route} | {self.id}'

class RouteStop(Common):
    route = models.ForeignKey(BusRoute, on_delete=models.CASCADE, related_name='route_stops')
    bus_station = models.ForeignKey(BusStation, on_delete=models.CASCADE, related_name='route_stops')
    stop_order = models.PositiveIntegerField()
    type = models.CharField(max_length=50, blank=True)
    class Meta:
        ordering = ['stop_order']  # Orders the stops by stop_order

    def __str__(self):
        return f'{self.bus_station.name} - Order {self.stop_order}'

class BusAttendance(Common):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    vehicle = models.CharField(max_length= 255)
    time = models.DateTimeField(auto_now_add=True)
    method = models.CharField(max_length= 255)
