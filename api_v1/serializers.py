from rest_framework import serializers
from .models import *
from django.contrib.contenttypes.models import ContentType
from easyaudit.models import CRUDEvent,LoginEvent


class ParentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Parent
        fields = "__all__"

class TokenSerializer(serializers.Serializer):
    token = serializers.CharField()
class AcademicSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AcademicSession
        fields = "__all__"
class AcademicSessionListSerializer(serializers.ModelSerializer):
    class Meta:
        model = AcademicSession
        fields = ["id","name"]
class SchoolSerializer(serializers.ModelSerializer):
    class Meta:
        model = School
        fields = "__all__"
class SchoolGetSerializer(serializers.ModelSerializer):
    school = SchoolSerializer()
    class Meta:
        model = User
        fields = ['id','username','plain_password','email','name','role','school','mobile_no','image']
class UserSchoolSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password','name', 'image','mobile_no','email', 'school', 'branch', 'role',"plain_password"]
        extra_kwargs = {'image': {'required': False},'password': {'write_only': True},'plain_password': {'write_only': True}}

    def create(self, validated_data):
        # Create the user and hash the password
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.plain_password = password
        user.set_password(password)
        user.save()
       
        return user
class SchoolListSerializer(serializers.ModelSerializer):
    class Meta:
        model = School
        fields = ['id','name','school_code']
# ===============================school=============================
class TeacherListSerializer(serializers.ModelSerializer):
     class Meta:
        model = Teacher
        fields = ['id','name']
class SchoolClassSerializer(serializers.ModelSerializer):
    class Meta:
        model = SchoolClass
        fields = "__all__"
class SchoolClassGetSerializer(serializers.ModelSerializer):
    teacher = TeacherListSerializer()
    class Meta:
        model = SchoolClass
        fields = '__all__'
class SchoolClassListSerializer(serializers.ModelSerializer):
    class Meta:
        model = SchoolClass
        exclude = ['created_at','updated_at',"school",'branch','teacher']
#=========================================gate pass=======================
class AccessMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessMethod
        fields = "__all__"


class UserAccessPassSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAccessPass
        fields ="__all__"


class GatePassSerializer(serializers.ModelSerializer):
    class Meta:
        model = GatePass
        fields = "__all__"
class GatePassUserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["name","image","email","mobile_no","username"]
class GatePassGetSerializer(serializers.ModelSerializer):
    user = GatePassUserDetailSerializer(read_only=True)
    class Meta:
        model = GatePass
        fields = "__all__"

class GateTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = GateType
        fields = "__all__"
# =============================section============================
class SectionListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Section
        exclude = ['created_at','updated_at',"school",'branch','teacher','school_class']

class SectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Section
        fields = '__all__'
class SectionGetSerializer(serializers.ModelSerializer):
    school_class = SchoolClassSerializer()
    teacher = TeacherListSerializer()
    class Meta:
        model = Section
        fields = '__all__'
        
class StudentProfileSerializer(serializers.ModelSerializer):
    school_class= SchoolClassListSerializer()
    section = SectionGetSerializer()
    class Meta:
        model = Student
        fields = "__all__"
        
      
class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = "__all__"

class RolelistSerializer(serializers.ModelSerializer):
    school = SchoolSerializer()
    class Meta:
        model = Role
        fields = "__all__"

# ================================Appitem =============================
class AppItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppItem
        fields = ['id', 'name', 'order','component_key']

class AppSerializer(serializers.ModelSerializer):
    app_items = AppItemSerializer(many=True, read_only=True)  # Adjust related name
    class Meta:
        model = App
        fields = ["id", "name", "icon","app_items",'component_key']
class AppsidebarSerializer(serializers.ModelSerializer):
    app_items = AppItemSerializer(many=True, read_only=True)  # Adjust related name
    class Meta:
        model = App
        fields = ["id", "name", "icon","app_items",'component_key']
class AppPermissionSidebarSerializer(serializers.ModelSerializer):
    app = AppsidebarSerializer()
    class Meta:
        model = AppPermissions
        fields = ["app"]

    
class AppListPermissionSerializer(serializers.ModelSerializer):
    appitem = AppItemSerializer(read_only=True)  # Adjusted name and related serializer
    class Meta:
        model = AppListPermission
        fields = ['id', 'appitem',]

class AppPermissionlistSerializer(serializers.ModelSerializer):
    appitem = AppItemSerializer(read_only=True)  # Adjusted name and related serializer
    class Meta:
        model = AppPermissions
        fields = ['id', 'name', 'icon']

class AppPermissionSerializer(serializers.ModelSerializer):
    app_items = serializers.SerializerMethodField()

    class Meta:
        model = App
        fields = ['id', 'name', 'icon', 'app_items','component_key']

    def get_app_items(self, obj):
        user  = self.context['user']
        search_filter={}
        role_filter={}
        if user.role:
                role_name = user.role.name
                if role_name == "school":
                    search_filter['user'] = user
                else:
                    user_curr = User.objects.filter(school = user.school,role__name = "school").first() 
                    search_filter['user'] = user_curr
                    role_filter["role__contains"] = user.role.name
        app_items = AppItem.objects.filter(app=obj, id__in=AppListPermission.objects.filter(**search_filter).values_list('appitem', flat=True),**role_filter)
        return AppItemSerializer(app_items, many=True).data    

class AppPermissionRoleSerializer(serializers.ModelSerializer):
    app_items = serializers.SerializerMethodField()

    class Meta:
        model = App
        fields = ['id', 'name', 'icon', 'app_items','component_key']

    def get_app_items(self, obj):
        user  = self.context['user']
        user_role = user.role.name
        app_items = AppItem.objects.filter(app=obj, id__in=AppListPermission.objects.filter(user=user).values_list('appitem', flat=True),role__contains=[user_role])
        return AppItemSerializer(app_items, many=True).data    


# ==============================house=======================
class HouseSerializer(serializers.ModelSerializer):
    class Meta:
        model = House
        fields = '__all__'
class HouseListSerializer(serializers.ModelSerializer):
    class Meta:
        model = House
        exclude = ['created_at','updated_at',"description","school",'branch',]
# ================================Department=====================
class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        fields = "__all__"
class DepartmentListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Department
        exclude = ['created_at','updated_at',"school",'branch',]
# ================================Designation=====================
class DesignationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Designation
        fields = "__all__"
class DesignationListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Designation
        exclude = ['created_at','updated_at',"school",'branch','department']
class DesignationGetSerializer(serializers.ModelSerializer):
    department = DepartmentSerializer()
    class Meta:
        model = Designation
        fields = '__all__'

# ======================teacher========================
class TeachergetSerializer(serializers.ModelSerializer):
    department = DepartmentSerializer()
    designation = DesignationSerializer()
    class Meta:
        model = Teacher
        fields = "__all__"  
class UserTeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username','name', 'password', 'image','teacher_profile', 'mobile_no', 'school', 'branch', 'role',"plain_password"]
        extra_kwargs = {'image': {'required': False},'password': {'write_only': True},'plain_password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.plain_password = password
        user.set_password(password)
        user.save()
       
        return user

class TeacherSerializer(serializers.ModelSerializer):
    class Meta:
        model = Teacher
        fields = "__all__" 
class TeachergetlistSerializer(serializers.ModelSerializer):
    department = DepartmentListSerializer()
    designation = DesignationListSerializer()
    class Meta:
        model = Teacher
        fields = "__all__" 

class TeacherGetSerializer(serializers.ModelSerializer):
    teacher_profile = TeachergetlistSerializer()
    class Meta:
        model = User
        fields = ['id','username','plain_password','email','name','teacher_profile','mobile_no','image']

class StudentProfileLoginSerializer(serializers.ModelSerializer):
    # Custom method fields to handle null or missing names
    school_class = serializers.SerializerMethodField()
    section = serializers.SerializerMethodField()
    transport = serializers.SerializerMethodField()
    dormitory = serializers.SerializerMethodField()
    house = serializers.SerializerMethodField()
    student_category = serializers.SerializerMethodField()
    club = serializers.SerializerMethodField()
    session = serializers.SerializerMethodField()
    class Meta:
        model = Student
        fields = [
            'id', 'name', 'date_of_birth', 'age', 'birth_place', 'gender', 'mother_tongue',
            'religion', 'blood_group', 'address', 'city', 'state', 'nationality', 'mobile_no',
            'email', 'previous_attended', 'previous_address', 'previous_purpose',
            'previous_class_study', 'previous_date_of_leaving', 'date_of_leaving',
            'admission_date', 'transfer_certificate', 'dob_certificate', 'physically_handicap',
            'roll_no', 'enroll_no', 'card_number', 'issue_date', 'expiry_date', 'more_entries',
            'login_status', 'grade', 'is_active', 'category', 'guardian_name',
            'guardian_relation', 'guardian_occupation', 'father_name', 'father_occupation',
            'mother_name', 'mother_occupation', 'guardian_phone', 'mother_phone', 'father_phone',
            'school_class', 'section', 'transport', 'dormitory', 'house', 'student_category',
            'club', 'session'
        ]
    def get_school_class(self, obj):
        return getattr(obj.school_class, 'name', 'N/A')

    def get_section(self, obj):
        return getattr(obj.section, 'name', 'N/A')

    def get_transport(self, obj):
        return getattr(obj.transport, 'name', 'N/A')

    def get_dormitory(self, obj):
        return getattr(obj.dormitory, 'name', 'N/A')

    def get_house(self, obj):
        return getattr(obj.house, 'name', 'N/A')

    def get_student_category(self, obj):
        return getattr(obj.student_category, 'name', 'N/A')

    def get_club(self, obj):
        return getattr(obj.club, 'name', 'N/A')

    def get_session(self, obj):
        return getattr(obj.session, 'name', 'N/A')




class UserSerializer(serializers.ModelSerializer):
    school = SchoolSerializer()
    profile = serializers.SerializerMethodField()  # Dynamically handle role-based profile
    role = RoleSerializer()

    class Meta:
        model = User
        exclude = ['created_at', 'updated_at', 'password', 'student_profile', 'parent_profile', 'teacher_profile']

    def get_profile(self, instance):
        """
        Dynamically return the appropriate role-based profile
        """
        if instance.is_superuser:
            return None
        if instance.role.name == "student" and instance.student_profile:
            return StudentProfileLoginSerializer(instance.student_profile).data
        elif instance.role.name == "parent" and instance.parent_profile:
            return ParentSerializer(instance.parent_profile).data
        elif instance.role.name == "teacher" and instance.teacher_profile:
            return TeacherSerializer(instance.teacher_profile).data
        elif instance.role.name == "school" and instance.school:
            return SchoolSerializer(instance.school).data
        return None
class UserDetailTokenSerializer(serializers.ModelSerializer):
    school = SchoolSerializer()
    profile = serializers.SerializerMethodField()  # Dynamically handle role-based profile
    qrcode = serializers.SerializerMethodField()  # Dynamically handle role-based profile
    role = RoleSerializer()

    class Meta:
        model = User
        exclude = ['created_at', 'updated_at', 'password', 'student_profile', 'parent_profile', 'teacher_profile']

    def get_profile(self, instance):
        """
        Dynamically return the appropriate role-based profile
        """
        if instance.is_superuser:
            return None
        if instance.role.name == "student" and instance.student_profile:
            return StudentProfileLoginSerializer(instance.student_profile).data
        elif instance.role.name == "parent" and instance.parent_profile:
            return ParentSerializer(instance.parent_profile).data
        elif instance.role.name == "teacher" and instance.teacher_profile:
            return TeachergetlistSerializer(instance.teacher_profile).data
        elif instance.role.name == "school" and instance.school:
            return SchoolSerializer(instance.school).data
        return None
    def get_qrcode(self, instance):
        qr_code = None
        try:
            qr_code = QRCode.objects.filter(name=instance.id).first()
        except QRCode.DoesNotExist:
            return None
        if qr_code:
            return  qr_code.qr_code_image.url if qr_code.qr_code_image else None
        return None
class UserDetailQRCodeSerializer(serializers.ModelSerializer):
    school = SchoolSerializer()
    profile = serializers.SerializerMethodField()  # Dynamically handle role-based profile
    qrcode = serializers.SerializerMethodField()  # Dynamically handle role-based profile
    role = RoleSerializer()

    class Meta:
        model = User
        fields = ['school', 'name', 'username','image', 'email', 'mobile_no', 'role','profile','qrcode']

    def get_profile(self, instance):
        """
        Dynamically return the appropriate role-based profile
        """
        if instance.is_superuser:
            return None
        if instance.role.name == "student" and instance.student_profile:
            return StudentProfileLoginSerializer(instance.student_profile).data
        elif instance.role.name == "parent" and instance.parent_profile:
            return ParentSerializer(instance.parent_profile).data
        elif instance.role.name == "teacher" and instance.teacher_profile:
            return TeachergetlistSerializer(instance.teacher_profile).data
        elif instance.role.name == "school" and instance.school:
            return SchoolSerializer(instance.school).data
        return None
    def get_qrcode(self, instance):
        qr_code = None
        try:
            qr_code = QRCode.objects.filter(name=instance.id).first()
        except QRCode.DoesNotExist:
            return None
        if qr_code:
            return  qr_code.qr_code_image.url if qr_code.qr_code_image else None
        return None
    # ========================student category=====
class Student_CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Student_Category
        fields = '__all__'
class Student_CategorylistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student_Category
        fields = ["id","name"]
# ==========================================club==============================
class ClubSerializer(serializers.ModelSerializer):
    class Meta:
        model = Club
        fields = '__all__'
class ClubGetSerializer(serializers.ModelSerializer):
    teacher = TeacherListSerializer()
    class Meta:
        model = Club
        fields = '__all__'
class ClublistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Club
        fields = ["id","name"]
# ==========================================Hostel==============================
class HostelRoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostelRoom
        fields = '__all__'

class HostelRoomlistSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostelRoom
        fields = ["id","name"]
class HostelCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = HostelCategory
        fields = '__all__'
class HostelCategorylistSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostelCategory
        fields = ["id","name"]
class DormitorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Dormitory
        fields = '__all__'
class DormitoryGetSerializer(serializers.ModelSerializer):
    hostel_room = HostelRoomlistSerializer()
    hostel_category = HostelCategorylistSerializer()
    class Meta:
        model = Dormitory
        fields = '__all__'
class DormitoryListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dormitory
        fields = ["id","name"]
class DormitoryRoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = DormitoryRoom
        fields = '__all__'
class DormitoryRoomGetSerializer(serializers.ModelSerializer):
    dormitory = DormitoryListSerializer()
    class Meta:
        model = DormitoryRoom
        fields = '__all__'
class DormitoryRoomListSerializer(serializers.ModelSerializer):
    class Meta:
        model = DormitoryRoom
        fields = ["id","name"]


# ==========================student===============================
class UserStudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'image','name','student_profile', 'mobile_no', 'school', 'branch', 'role',"plain_password"]
        extra_kwargs = {'image': {'required': False},'password': {'write_only': True},'plain_password': {'write_only': True}}

    def create(self, validated_data):
        # Create the user and hash the password
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.plain_password = password
        user.set_password(password)
        user.save()
       
        return user


class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = '__all__'
class StudentEnquirySerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentEnquiry
        fields = '__all__'
class StudentEnquiryGetSerializer(serializers.ModelSerializer):
    school_class = SchoolClassListSerializer()
    session = AcademicSessionListSerializer()
    class Meta:
        model = StudentEnquiry
        fields = '__all__'
class StudentEnquiryListSerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentEnquiry
        fields = ["name","id","enquiry_no"]

class StudentListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = ["id","name","roll_no"]

class StudentGetListSerializer(serializers.ModelSerializer):
    school_class = SchoolClassListSerializer()
    section = SectionListSerializer()
    session = AcademicSessionListSerializer()
    house = HouseListSerializer()
    dormitory = DormitoryListSerializer()
    club = ClublistSerializer()
    student_category = Student_CategorylistSerializer()

    class Meta:
        model = Student
        exclude = ['school','branch']
class StudentGetSerializer(serializers.ModelSerializer):
    student_profile = StudentGetListSerializer()
    role = RoleSerializer()
    class Meta:
        model = User
        fields = ['id','username','plain_password','email','name','role','student_profile','mobile_no','image']

 
#  ======================parent=================
class UserParentSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'image','parent_profile', 'mobile_no', 'school', 'branch', 'role']
        extra_kwargs = {'image': {'required': False},'password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.plain_password = password
        user.set_password(password)
        user.save()
       
        return user
class ParentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Parent
        fields = '__all__'
class ParentStudentSerializer(serializers.ModelSerializer):
    students = StudentGetListSerializer(many=True)
    class Meta:
        model = Parent
        fields = '__all__'
class ParentGetSerializer(serializers.ModelSerializer):
    school = SchoolSerializer()
    parent_profile = ParentStudentSerializer()
    role = RoleSerializer()
    class Meta:
        model = User
        fields = ['id', 'username','image','parent_profile', 'mobile_no', 'school', 'branch', 'role',"plain_password"]

# =======================subject=================================
class SubjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subject
        fields = "__all__"


class SubjectGetSerializer(serializers.ModelSerializer):
    teacher = TeacherListSerializer()
    school_class = SchoolClassListSerializer()
    class Meta:
        model = Subject
        fields = "__all__"
class SubjectListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subject
        fields = ['id','name']
# =======================leave apply===================
class LeaveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Leaves
        fields = "__all__"

class LeaveGetSerializer(serializers.ModelSerializer):
    sender =serializers.SerializerMethodField()
    reciever = SchoolSerializer()
    status_updated_by = serializers.SerializerMethodField()
    class Meta:
        model = Leaves
        fields = "__all__"
    def get_sender(self, obj):
        return self.get_user_details(obj.sender)

    def get_status_updated_by(self, obj):
        return self.get_user_details(obj.status_updated_by)  # Assuming status_updated_by is a User instance

    def get_user_details(self, user):
        """Helper method to get user details based on their role."""
        if user is None:
            return None
        if user.role.name == "teacher":
            # Return teacher-specific details
            return {
                "id": user.teacher_profile.id,
                "name": user.teacher_profile.name,
                "teacher_number": user.teacher_profile.teacher_number,
                "mobile_no": user.teacher_profile.mobile_no,
                "image": user.image.url if user.image else None,
                "role": "teacher"
            }
        elif user.role.name == "student":
            # Return student-specific details
            return {
                "id": user.student_profile.id,
                "name": user.student_profile.name,
                "roll_no": user.student_profile.roll_no,
                "image": user.image.url if user.image else None,
                "role": "student"
            }
        elif user.role.name == "school":
            # Return school-specific details
            return {
                "id": user.school.id,
                "name": user.school.name,
                "school_code": user.school.school_code,
                "image": user.school.logo.url if user.school.logo else None,
                "role": "school"
            }
        return None


class HostelLeaveSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostelLeave
        fields = "__all__"

class HostelLeaveGetSerializer(serializers.ModelSerializer):
    sender = serializers.SerializerMethodField()
    receiver = SchoolSerializer()
    status_updated_by = serializers.SerializerMethodField()

    class Meta:
        model = HostelLeave
        fields = "__all__"

    def get_sender(self, obj):
        return self.get_user_details(obj.sender)

    def get_status_updated_by(self, obj):
        return self.get_user_details(obj.status_updated_by)

    def get_user_details(self, user):
        """Helper method to get user details based on their role."""
        if user is None:
            return None
        if user.role.name == "teacher":
            # Return teacher-specific details
            return {
                "id": user.teacher_profile.id,
                "name": user.teacher_profile.name,
                "teacher_number": user.teacher_profile.teacher_number,
                "mobile_no": user.teacher_profile.mobile_no,
                "image": user.image.url if user.image else None,
                "role": "teacher"
            }
        elif user.role.name == "student":
            # Return student-specific details
            return {
                "id": user.student_profile.id,
                "name": user.student_profile.name,
                "roll_no": user.student_profile.roll_no,
                "image": user.image.url if user.image else None,
                "role": "student"
            }
        elif user.role.name == "school":
            # Return school-specific details
            return {
                "id": user.school.id,
                "name": user.school.name,
                "school_code": user.school.school_code,
                "image": user.school.logo.url if user.school.logo else None,
                "role": "school"
            }
        return None
# ======================noticeboard==========================
class NoticeBoardSerializer(serializers.ModelSerializer):
    class Meta:
        model = NoticeBoard
        fields = "__all__"
# ======================TimeTables==========================
class TimetableSerializer(serializers.ModelSerializer):
    class Meta:
        model = Timetable
        fields = "__all__"
class TimetableGetSerializer(serializers.ModelSerializer):
    section = SectionListSerializer()
    school_class = SchoolClassListSerializer()
    subject = SubjectListSerializer()
    teacher = TeacherListSerializer()
    class Meta:
        model = Timetable
        fields = "__all__"

class TimePeriodSerializer(serializers.ModelSerializer):
    class Meta:
        model = TimePeriods
        fields = "__all__"
        read_only_fields = ['school', 'branch']

class TimePeriodGetSerializer(serializers.ModelSerializer):
    class Meta:
        model = TimePeriods
        fields = "__all__"
# ======================syllabus========================
class SyllabusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Syllabus
        fields = "__all__"
class SyllabusGetSerializer(serializers.ModelSerializer):
    subject = SubjectListSerializer() 
    class Meta:
        model = Syllabus
        fields = "__all__"
# ======================feedback========================

class UserFeedbackSerializer(serializers.ModelSerializer):
    teacher_profile = TeachergetSerializer()
    class Meta:
        model = User
        fields =['id', 'username', 'password', 'image','teacher_profile', 'mobile_no', 'school', 'branch', 'role']
        # exclude = ['created_at','updated_at','password']
class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = "__all__"
class FeedbackGetSerializer(serializers.ModelSerializer):
    students = serializers.SerializerMethodField()
    sender = serializers.SerializerMethodField()  # Use SerializerMethodField for custom logic
    school_class = SchoolClassListSerializer()
    section = SectionListSerializer()

    class Meta:
        model = Feedback
        fields = "__all__"

    def get_students(self, obj):
        user = self.context.get('request').user
        if user.role and user.role.name == "student":
            return [
                {
                    "id": user.student_profile.id,
                    "name": user.student_profile.name,
                    "roll_no": user.student_profile.roll_no,
                }
            ]
        else:
            return [
                {
                    "id": student.id,
                    "name": student.name,
                    "roll_no": student.roll_no,
                }
                for student in obj.students.all()
            ]

    def get_sender(self, obj):
        if obj.sender.role.name == "teacher":
            # Return teacher-specific details
            return {
                "id": obj.sender.teacher_profile.id,
                "name": obj.sender.teacher_profile.name,
                "teacher_number": obj.sender.teacher_profile.teacher_number,
                "mobile_no": obj.sender.teacher_profile.mobile_no,
                "image": obj.sender.image.url if obj.sender.image else None,
                "role": "teacher"
            }
        elif obj.sender.role.name == "school":
            # Return school-specific details
            return {
                "id": obj.sender.school.id,
                "name": obj.sender.school.name,
                "school_code": obj.sender.school.school_code,
                "image": obj.sender.school.logo.url if obj.sender.school.logo else None,
                "role": "school"
            }
        return None
# ================================attendance=======================
class AttendanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attendance
        fields = '__all__'     # Teacher who marks attendance
    def create(self, validated_data):
        # Create and return a new `Attendance` instance, given the validated data
        return Attendance.objects.create(**validated_data)
    
class AttendanceGetSerializer(serializers.ModelSerializer):
    student =  StudentListSerializer()
    school_class = SchoolClassListSerializer()
    section = SectionListSerializer()
    generator = serializers.SerializerMethodField() 
    class Meta:
        model = Attendance
        fields = '__all__'

    # def get_data(self,obj):
    #     response_data = {}
    #     for record in obj:
    #         student_data = {
    #             "id": record.student.id,
    #             "name": record.student.name,
    #             "roll_no": record.student.roll_no,
    #         }

    #         attendance_data = {
    #             "date": record.date.strftime('%Y-%m-%d'),
    #             "month": record.date.strftime('%B'),
    #             "status": record.status,
    #         }

    #         if student_data["id"] not in response_data:
    #             response_data[student_data["id"]] = {
    #                 "student": student_data,
    #                 "attendance": [],
    #             }

    #         response_data[student_data["id"]]["attendance"].append(attendance_data)
    #     return response_data
    
    def get_generator(self, obj):
        if obj.generator.role.name == "teacher":
            return {
                "id": obj.generator.teacher_profile.id,
                "name": obj.generator.teacher_profile.name,
                "teacher_number": obj.generator.teacher_profile.teacher_number,
                "mobile_no": obj.generator.teacher_profile.mobile_no,
                "image": obj.generator.image.url if obj.generator.image else None,
                "role": "teacher"
            }
        elif obj.generator.role.name == "school":
            return {
                "id": obj.generator.school.id,
                "name": obj.generator.school.name,
                "school_code": obj.generator.school.school_code,
                "image": obj.generator.school.logo.url if obj.generator.school.logo else None,
                "role": "school"
            }
        return None
#====================get permission-listCRud==========================
class ContentTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContentType
        fields = ['id', 'model', 'name']

class PermissionCRUDSerializer(serializers.ModelSerializer):
    content_type = ContentTypeSerializer()
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename', 'content_type']
# ===================permisssions===============

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename','content_type']

class GroupSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True)

    class Meta:
        model = Group
        fields = ['id', 'name', 'permissions']
# ==============================user permissions======================

class UserPermissionSerializer(serializers.Serializer):
    class Meta:
        model = Permission
        fields = "__all__"

class UserWithPermissionsSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'permissions']

# ==================================exam=============================

class ExamTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExamType
        fields = "__all__"    
class GradingScaleSerializer(serializers.ModelSerializer):
    class Meta:
        model = GradingScale
        fields = "__all__"  
class ResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = Result
        fields = "__all__"
class ExamSubjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExamSubject
        exclude = ['exam']
class ExamSerializer(serializers.ModelSerializer):
    examsubject = ExamSubjectSerializer(many=True, write_only=True)
    examsubject_details = ExamSubjectSerializer(source='examsubject_set', many=True, read_only=True)
    class Meta:
        model = Exam
        fields = "__all__"

    def create(self, validated_data):
        examsubject_data = validated_data.pop('examsubject', [])
        exam = Exam.objects.create(**validated_data)
        for subject_data in examsubject_data:
            ExamSubject.objects.create(exam=exam, **subject_data)
        return exam
class ExamGetSerializer(serializers.ModelSerializer):
    school_class = SchoolClassListSerializer()
    section = SectionListSerializer()
    examtype = ExamTypeSerializer()
    exam_subject = serializers.SerializerMethodField() 
    class Meta:
        model = Exam
        fields = "__all__"
    def get_exam_subject(self, obj):
        # Retrieve all ExamSubject objects associated with this exam
        exam_subjects = ExamSubject.objects.filter(exam=obj)
        # Serialize the ExamSubject objects
        return ExamSubjectSerializer(exam_subjects, many=True).data

class AdmitCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdmitCard
        fields = "__all__"
class ExamSubjectSerializer(serializers.ModelSerializer):
    subject = SubjectListSerializer()
    class Meta:
        model = ExamSubject
        fields = "__all__"
class StudentAdmitCardSerializer(serializers.ModelSerializer):
    school_class = SchoolClassListSerializer(read_only=True)
    section = SectionListSerializer(read_only=True)
    session = SectionListSerializer(read_only=True)
    user_image = serializers.SerializerMethodField()

    class Meta:
        model = Student
        fields = "__all__"  
        extra_fields = ['image']

    def get_user_image(self, obj):
        """
        This method retrieves the image of the user associated 
        with the student via the User model.
        """
        user = getattr(obj, 'user', None)  # Assuming reverse relationship is 'user'
        if user and user.image:
            return user.image.url
        return None
class AdmitCardGetSerializer(serializers.ModelSerializer):
    student = StudentAdmitCardSerializer()
    exam = ExamGetSerializer()
    exam_subjects = ExamSubjectSerializer(many=True)
    school = SchoolSerializer()
    class Meta:
        model = AdmitCard
        fields = "__all__"   
class ResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = Result
        fields = "__all__"
class StudentResultSerializer(serializers.ModelSerializer):
    section = serializers.CharField(source='section.name', allow_null=True)
    school_class = serializers.CharField(source='school_class.name', allow_null=True)
    dormitory = serializers.CharField(source='dormitory.name', allow_null=True)
    house = serializers.CharField(source='house.name', allow_null=True)
    Student_Category = serializers.CharField(source='Student_Category.name', allow_null=True)
    club = serializers.CharField(source='club.name', allow_null=True)
    session = serializers.CharField(source='session.name', allow_null=True)
    dormitoryroom = serializers.CharField(source='dormitoryroom.name', allow_null=True)
    dormitoryroom = serializers.CharField(source='dormitoryroom.name', allow_null=True)
    school= SchoolSerializer()
    user_image = serializers.SerializerMethodField()
    class Meta:
        model = Student
        exclude = ["branch",]
    def get_user_image(self, obj):
        user = getattr(obj, 'user', None)  # Assuming reverse relationship is 'user'
        if user and user.image:
            return user.image.url
        return None
class ExamResultSerializer(serializers.ModelSerializer):
    section = serializers.CharField(source='section.name', allow_null=True)
    school_class = serializers.CharField(source='school_class.name', allow_null=True)
    examtype = serializers.CharField(source='examtype.name', allow_null=True)
    class Meta:
        model = Exam
        exclude = ["school","branch","id"]
    def get_parents(self, obj):
        # Get all parents associated with the student
        return [parent.name for parent in obj.parents.all()]
class ResultGetSerializer(serializers.ModelSerializer):
    subject = serializers.CharField(source="exam_subject.subject.name", allow_null=True)
    total_marks = serializers.CharField(source="exam_subject.total_marks", allow_null=True)
    subject_date = serializers.CharField(source="exam_subject.subject_date", allow_null=True)

    class Meta:
        model = Result
        exclude = ["school","branch","id","exam_subject","grading_scale","student"]
# ===================================fees====================================
class PayrollSerializer(serializers.ModelSerializer):

    class Meta:
        model = Payroll
        fields = '__all__'
class UserPayrollSerializer(serializers.ModelSerializer):
    role = serializers.CharField(source="role.name", read_only=True)
    profile_data = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id","role","profile_data"]

    def get_profile_data(self, obj):
        """
        Returns the role-specific profile details based on the user's role.
        """
        if obj.role.name == 'teacher' and obj.teacher_profile:
            # Pass teacher_profile directly to TeacherGetSerializer
            return TeachergetSerializer(obj.teacher_profile).data
        elif obj.role.name == 'driver' and obj.driver_profile:
            # Pass driver_profile directly to DriverGetSerializer
            return None
        # Add additional roles here if needed
        return None
class PayrollGetSerializer(serializers.ModelSerializer):
    user = UserPayrollSerializer()
    class Meta:
        model = Payroll
        fields = '__all__'
# ==========================================promotion===============================
class StudentPromotionSerializer(serializers.ModelSerializer):
    section = serializers.CharField(source='section.name', allow_null=True)
    school_class = serializers.CharField(source='school_class.name', allow_null=True)
    parents = serializers.SerializerMethodField()
    dormitory = serializers.CharField(source='dormitory.name', allow_null=True)
    house = serializers.CharField(source='house.name', allow_null=True)
    Student_Category = serializers.CharField(source='Student_Category.name', allow_null=True)
    club = serializers.CharField(source='club.name', allow_null=True)
    session = AcademicSessionListSerializer()
    dormitoryroom = serializers.CharField(source='dormitoryroom.name', allow_null=True)
    dormitoryroom = serializers.CharField(source='dormitoryroom.name', allow_null=True)
    class Meta:
        model = Student
        exclude = ["school","branch",]
    def get_parents(self, obj):
        # Get all parents associated with the student
        return [parent.name for parent in obj.parents.all()]
class PromotionHistoryGetSerializer(serializers.ModelSerializer):
    student = StudentPromotionSerializer()
    from_class = SchoolClassListSerializer()
    to_class =  SchoolClassListSerializer()
    from_section = SectionListSerializer()
    to_section = SectionListSerializer()
    session = AcademicSessionListSerializer()
    approved_by = serializers.SerializerMethodField()
    class Meta:
        model = PromotionHistory
        fields = '__all__'
    def get_approved_by(self, obj):
        if obj.approved_by.role.name == "teacher":
            # Return teacher-specific details
            return {
                "id": obj.approved_by.teacher_profile.id,
                "name": obj.approved_by.teacher_profile.name,
                "teacher_number": obj.approved_by.teacher_profile.teacher_number,
                "mobile_no": obj.approved_by.teacher_profile.mobile_no,
                "image": obj.approved_by.image.url if obj.approved_by.image else None,
                "role": "teacher"
            }
        elif obj.approved_by.role.name == "school":
            # Return school-specific details
            return {
                "id": obj.approved_by.school.id,
                "name": obj.approved_by.school.name,
                "school_code": obj.approved_by.school.school_code,
                "image": obj.approved_by.school.logo.url if obj.approved_by.school.logo else None,
                "role": "school"
            }
        return None
class PromotionHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = PromotionHistory
        fields = '__all__'
class AcademicPerformanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = AcademicPerformance
        fields = '__all__'
class PerformanceMetricsSerializer(serializers.ModelSerializer):
    class Meta:
        model = PerformanceMetrics
        fields = '__all__'
# ===================================fees====================================
class FeeCategorySerializer(serializers.ModelSerializer):

    class Meta:
        model = FeeCategory
        fields = '__all__'
class FeeTermSerializer(serializers.ModelSerializer):

    class Meta:
        model = FeeTerm
        fields = '__all__'
class FeeNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeeNote
        fields = '__all__'
class FeeStructureGetSerializer(serializers.ModelSerializer):
    fee_category = FeeCategorySerializer()
    class_assigned = SchoolClassListSerializer()
    class Meta:
        model = FeeStructure
        fields = '__all__'
class FeeStructureSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeeStructure
        fields = '__all__'

class StudentFeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentFee
        fields = '__all__'

class DiscountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Discount
        fields = '__all__'

class FeeDiscountSerializer(serializers.ModelSerializer):
    discount_name = DiscountSerializer()  # Assuming DiscountSerializer exists and provides the discount's details

    class Meta:
        model = FeeDiscount
        fields = ['id', 'discount_name', 'discount_amount', 'discount_type', 'valid_until']
class StudentFeegetSerializer(serializers.ModelSerializer):
    fee_structure = FeeStructureGetSerializer()
    student = StudentGetListSerializer()
    discounts = FeeDiscountSerializer(many=True)
    school = SchoolSerializer()
    
    class Meta:
        model = StudentFee
        fields = '__all__'

class StudentFeegetforlistSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='fee_structure.fee_category.name')  # Get fee_category name from fee_structure
    class Meta:
        model = StudentFee
        fields = ['id', 'name']
class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'

class FeeReceiptSerializer(serializers.ModelSerializer):
    class Meta:
        model = FeeReceipt
        fields = '__all__'
class PaymentGetSerializer(serializers.ModelSerializer):
    student_fee = StudentFeegetSerializer()  # Use nested serializer to show detailed student fee information
    receipt = FeeReceiptSerializer(source='feereceipt', many=True, read_only=True)  # Use the default reverse relation

    class Meta:
        model = Payment
        fields = '__all__'
# =============================EVENT==========================
class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields='__all__'

# ============================enquirytype=======================
class EnquiryTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = EnquiryType
        fields = "__all__" 
class EnquirySerializer(serializers.ModelSerializer):
    class Meta:
        model = Enquiry
        fields = "__all__" 

# ============================earning=======================
class EarningTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = EarningType
        fields = "__all__" 
class EarningSerializer(serializers.ModelSerializer):
    class Meta:
        model = Earning
        fields = "__all__" 
# ============================Expense=======================
class ExpenseTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpenseType
        fields = "__all__" 
class ExpenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Expense
        fields = "__all__" 


class UserLogSerializer(serializers.ModelSerializer):
    school = SchoolSerializer()
    student_profile = StudentProfileSerializer()
    parent_profile = ParentSerializer()
    teacher_profile = TeacherSerializer()
    # role = RoleSerializer()
    class Meta:
        model = User
        exclude = ['created_at', 'updated_at', 'password']

    def to_representation(self, instance):
        representation = super().to_representation(instance)

        # Determine which profile to include based on the role
        role_based_profile = None
        if instance.role.name == "student" and instance.student_profile:
            role_based_profile = representation.pop("student_profile", None)
        elif instance.role.name == "parent" and instance.parent_profile:
            role_based_profile = representation.pop("parent_profile", None)
        elif instance.role.name == "teacher" and instance.teacher_profile:
            role_based_profile = representation.pop("teacher_profile", None)
        elif instance.role.name == "school" and instance.teacher_profile:
            role_based_profile = representation.pop("school", None)
        return {
            "username": representation.pop("username"),
            "role":instance.role.name,
            "profile": role_based_profile
        }


class ActivityLogSerializer(serializers.ModelSerializer):
    user = UserLogSerializer()
    class Meta:
        model = ActivityLog
        fields = "__all__"

class LoginActivityLogSerializer(serializers.ModelSerializer):
    user = UserLogSerializer()
    class Meta:
        model = LoginActivityLog
        fields = "__all__"



class ClassRoomSerializer(serializers.ModelSerializer):

    class Meta:
        model = ClassRoom
        fields = "__all__"

    def validate(self, data):
        # Ensure the creator is provided
        if 'creator' not in data:
            raise serializers.ValidationError("Creator is required.")
        return data

class ClassRoomMessageSerializer(serializers.ModelSerializer):
    replies = serializers.SerializerMethodField()
    class Meta:
        model = ClassroomMessage
        fields = "__all__"

    def validate(self, data):
        # Custom validation logic if needed
        if not data.get('message') and not data.get('file'):
            raise serializers.ValidationError("Either 'message' or 'file' or both must be provided.")
        return data
    
    def get_replies(self, obj):
        replies = obj.replies.all()
        return ClassRoomMessageSerializer(replies,many=True).data

##############################################################
class NotificationSerializer(serializers.ModelSerializer):
    sender_name = serializers.CharField(source='sender.name', read_only=True)
    receiver_name = serializers.CharField(source='receiver.name', read_only=True)

    class Meta:
        model = Notification
        fields = "__all__"

class UserRoleListSerializer(serializers.Serializer):
    class Meta:
        model = User
        fields = "__all__"
####################################################################
class DesignationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Designation
        fields = "__all__" 
class DepartmentDashboardSerializer(serializers.ModelSerializer):
    designations = DesignationSerializer(many=True)
    
    class Meta:
        model = Department
        fields = "__all__"

# ================================simsconfig===================================
class SimsConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = SimsConfig
        fields = "__all__"
class SimsConfigGetSerializer(serializers.ModelSerializer):
    school = SchoolSerializer()
    class Meta:
        model = SimsConfig
        fields = "__all__"
#====================================user document ===========================
class UserDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDocument
        fields = "__all__"
        
        
#==============================school galery=====================================        
class SchoolGallerySerializer(serializers.ModelSerializer):
    class Meta:
        model = SchoolGallery
        fields = "__all__"
#==============================================store===================================
class StoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = Store
        fields = "__all__"
#=======================================vissitor=======================================
class VisitorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Visitor
        fields = "__all__"

class UserVisitorSerializer(serializers.ModelSerializer):
    school = SchoolSerializer()
    profile = serializers.SerializerMethodField()  # Dynamically handle role-based profile
    qrcode = serializers.SerializerMethodField()  # Dynamically handle role-based profile
    role = RoleSerializer()

    class Meta:
        model = User
        fields = ['id','username','school', 'profile','image', 'qrcode', 'role']

    def get_profile(self, instance):
        """
        Dynamically return the appropriate role-based profile
        """
        if instance.is_superuser:
            return None
        if instance.role.name == "student" and instance.student_profile:
            return StudentProfileLoginSerializer(instance.student_profile).data
        elif instance.role.name == "parent" and instance.parent_profile:
            return ParentSerializer(instance.parent_profile).data
        elif instance.role.name == "teacher" and instance.teacher_profile:
            return TeachergetlistSerializer(instance.teacher_profile).data
        elif instance.role.name == "school" and instance.school:
            return SchoolSerializer(instance.school).data
        return None
    def get_qrcode(self, instance):
        qr_code = None
        try:
            qr_code = QRCode.objects.filter(name=instance.id).first()
        except QRCode.DoesNotExist:
            return None
        if qr_code:
            return  qr_code.qr_code_image.url if qr_code.qr_code_image else None
        return None
class VisitorGetSerializer(serializers.ModelSerializer):
    user = UserVisitorSerializer()
    class Meta:
        model = Visitor
        fields = "__all__"
#==================================help support======================================
class HelpSupportSerializer(serializers.ModelSerializer):
    class Meta:
        model = HelpSupport
        fields = "__all__"
#=======================================QRcode=======================================
class QRCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = QRCode
        fields = "__all__"
        read_only_fields = ['qr_code_image', 'created_at']
#==============================================meeting===============================
class MeetingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Meeting
        fields = '__all__'
class UserMeetSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name','mobile_no','email','username']
class MeetingGetSerializer(serializers.ModelSerializer):
    school_class = SchoolClassListSerializer()
    section = SectionListSerializer()
    creator = UserMeetSerializer()
    attendees = UserMeetSerializer(many=True)
    class Meta:
        model = Meeting
        fields = '__all__'
#==============================================audit===============================
class UserCRUDSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'username', 'email', 'mobile_no']
class CRUDEventSerializer(serializers.ModelSerializer):
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)
    school = serializers.CharField(source='user.school.name', read_only=True)
    user = UserCRUDSerializer()
    
    class Meta:
        model = CRUDEvent
        fields = "__all__"
        
class LoginEventSerializer(serializers.ModelSerializer):
    event_type_display = serializers.CharField(source='get_login_type_display', read_only=True)
    school = serializers.CharField(source='user.school.name', read_only=True)
    class Meta:
        model = LoginEvent
        fields = "__all__"
# ============================vendor=======================
class UserVendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username','name', 'image','mobile_no','email', 'school', 'branch', 'role','password',"plain_password"]
        extra_kwargs = {'image': {'required': False},'plain_password': {'write_only': True}}

    def create(self, validated_data):
        # Create the user and hash the password
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.plain_password = password
        user.set_password(password)
        user.save()
       
        return user
class VendorProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorProfile
        fields =  "__all__"
class UserVendorGetSerializer(serializers.ModelSerializer):
    role = RolelistSerializer()
    class Meta:
        model = User
        fields = ['id','username','plain_password','email','name','mobile_no','role','image']

class VendorGetSerializer(serializers.ModelSerializer):
    user = UserVendorGetSerializer()
    class Meta:
        model = VendorProfile
        fields = ['id','user','store_name','description','address','active','gst_no','created_at','updated_at']
# ============================category=====================
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"  
class CategoryGetListSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='category_name')  # Rename category_name to name

    class Meta:
        model = Category
        fields = ['id', 'name','category_image']
# ====================================product=================
class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = "__all__" 
class ProductGetSerializer(serializers.ModelSerializer):
    category = CategoryGetListSerializer()
    class Meta:
        model = Product
        fields = "__all__" 
class ProductGetListSerializer(serializers.ModelSerializer):
    is_in_wishlist = serializers.SerializerMethodField()
    category = CategoryGetListSerializer()

    class Meta:
        model = Product
        fields = ['id', 'product_name','main_image', 'price', 'mrp', 'category','new_slug', 'description', 'brand', 'created_at', 'updated_at', 'is_in_wishlist']  # Include other fields as needed

    def get_is_in_wishlist(self, obj):
        # Get the user from the request context
        user = self.context.get('request').user
        # Check if the user has a wishlist and if the product is in the wishlist
        if user.is_authenticated:
            return Wishlist.objects.filter(user=user, products=obj).exists()
        return False
class SpecificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Specification
        fields = "__all__" 
class ProductImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductImage
        fields = "__all__" 
class ProductDetailSerializer(serializers.ModelSerializer):
    is_in_wishlist = serializers.SerializerMethodField()
    specifications = SpecificationSerializer(many=True, read_only=True, source='specification')
    product_images = ProductImageSerializer(many=True, read_only=True)
    school = SchoolSerializer()

    class Meta:
        model = Product
        fields = [
            'id', 'product_name', 'category', 'price', 'mrp', 'active', 'main_image', 
            'description', 'brand', 'school', 'branch', 'specifications', 'product_images', 'is_in_wishlist'
        ]

    def get_is_in_wishlist(self, obj):
        # Get the user from the request context
        user = self.context.get('request').user
        # Check if the product is in the user's wishlist
        if user.is_authenticated:
            return Wishlist.objects.filter(user=user, products=obj).exists()
        return False
class WhistListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wishlist
        fields = "__all__" 
class WhistListGetSerializer(serializers.ModelSerializer):
    products = serializers.SerializerMethodField()

    class Meta:
        model = Wishlist
        fields = ['products']

    def get_products(self, obj):
        products = obj.products.all()
        return ProductGetListSerializer(products, many=True, context=self.context).data
class CartSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cart
        fields = "__all__" 
        
#========================================assessment==============================================
class QuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Question
        fields = ['id', 'text', 'question_type', 'options', 'assessment']

    def create(self, validated_data):
        assessment = validated_data.get('assessment')
        if not assessment:
            raise serializers.ValidationError("Assessment is required.")
        return super().create(validated_data)


class AssessmentSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True, read_only=True)

    class Meta:
        model = Assessment
        fields = ['id', 'name', 'description', 'questions']


class UserAssessmentSerializer(serializers.ModelSerializer):
    questions_with_answers = serializers.SerializerMethodField()

    class Meta:
        model = UserAssessment
        fields = ['id', 'user', 'assessment', 'score', 'completed_at', 'school', 'branch', 'user_answers', 'checked_by', 'status', 'feedback', 'questions_with_answers']

    def get_questions_with_answers(self, obj):
        questions = Question.objects.filter(assessment=obj.assessment)
        question_data = []
        for question in questions:
            question_data.append({
                'question': question.text,
                'answer': question.answer,
                'user_answer': obj.user_answers.get(str(question.id), None)
            })
        return question_data


class AssessmentCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAssessment
        fields = ['score', 'feedback', 'status']

    def validate(self, data):
        if data['status'] == 'Checked' and data.get('score') is None:
            raise serializers.ValidationError("Score is required when marking as Checked.")
        return data
#====================================role base user create=======================================
class RoleUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        extra_kwargs = {
            'password': {'write_only': True},
            'plain_password': {'write_only': True},
            'rfid_card_number': {'required': False},              # Make RFID card number optional
            'finger_prints': {'required': False},                 # Make fingerprints optional
        }
    def create(self, validated_data):
        # If password is provided, hash it
        password = validated_data.pop('password', None)
        user = User(**validated_data)
        if password:
            user.plain_password = password
            user.set_password(password)
        user.save()
        return user
class RoleUserGetSerializer(serializers.ModelSerializer):
    school = SchoolSerializer()
    role = RoleSerializer()
    class Meta:
        model = User
        fields = ['id','username','plain_password','email','name','role','school','mobile_no','active','image']


#----------------------===========================vehicle======================================================
class VehicleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vehicle
        fields = '__all__'
class VehicleUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','image','name','email','mobile_no']
class VehicleGetSerializer(serializers.ModelSerializer):
    driver = VehicleUserSerializer()
    route_incharge = VehicleUserSerializer()
    class Meta:
        model = Vehicle
        exclude = ['school','passenger','branch','speed','engine_status','latitude','longitude']
class BusStationSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusStation
        fields = "__all__"
class BusStationGetSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusStation
        exclude =['school','branch','created_at','updated_at','vehicle','active']
class RouteStopSerializer(serializers.ModelSerializer):
    bus_station =BusStationGetSerializer()
    class Meta:
        model = RouteStop
        fields = ['bus_station','stop_order']


class VehiclePassengerSerializer(serializers.ModelSerializer):
    passenger = VehicleUserSerializer(many=True)
    class Meta:
        model = Vehicle
        fields = ['passenger','vehicle_quantity','vehicle_number']

GOOGLE_API_KEY = "AIzaSyDR0mOByPyNTaYWDSOYVHcws3KBatZ-vk0" # Store the API key in Django settings


class BusAttendanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusAttendance
        fields = "__all__"