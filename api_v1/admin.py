from django.contrib import admin
from .models import *
from django.utils.html import format_html
# Register your models here.

class AppItemAdmin(admin.StackedInline):
    model=AppItem
@admin.register(App)
class CoursesAdmin(admin.ModelAdmin):
    list_display = ('name', 'order')  # Add fields relevant to your model
    search_fields = ('name',)  # Optional: To enable searching by specific fields
    list_filter = ('created_at', 'updated_at')  # Optional: To filter by date
    ordering = ('order',)
    inlines = [ AppItemAdmin]
admin.site.register(AppListPermission)
@admin.register(AppPermissions)
class AppPermissionAdmin(admin.ModelAdmin):
    list_display = ('get_app_name', 'get_user_name', 'order', 'show_in_sidebar')
    search_fields = ('app__name', 'user__name')  # Use double underscores for related model fields
    list_filter = ('created_at', 'updated_at')
    ordering = ('order',)
    # Method to display the related App's name
    def get_app_name(self, obj):
        return obj.app.name if obj.app else "-"
    get_app_name.short_description = 'App Name'  # Column header in the admin
    # Method to display the related User's name
    def get_user_name(self, obj):
        return obj.user.username if obj.user else "-"
    get_user_name.short_description = 'User Name'
# admin.site.register(Task)/
admin.site.register(AppItem)
admin.site.register(Subject)
admin.site.register(Feedback)
admin.site.register(ActivityLog)
admin.site.register(LoginActivityLog)
admin.site.register(EarningType)
class EarningAdmin(admin.ModelAdmin):
    list_display = ('name', 'amount', 'type', 'phone_no', 'email', 'school', 'branch','date')
    list_filter = ('school', 'branch')
    search_fields = ('name', 'type', 'email', 'phone_no')
    # Remove created_at and updated_at from editable fields, and add them to readonly_fields
    fields = ('name', 'amount', 'type', 'phone_no', 'email', 'remark', 'school', 'branch','date')
    readonly_fields = ('created_at', 'updated_at')
admin.site.register(Earning, EarningAdmin)
admin.site.register(Expense)
admin.site.register(Meeting)
admin.site.register(Visitor)
admin.site.register(ExpenseType)
admin.site.register(StudentEnquiry)
admin.site.register(Exam)
admin.site.register(Event)
admin.site.register(Store)
admin.site.register(HelpSupport)
admin.site.register(ClassRoom)
admin.site.register(ClassroomMessage)
admin.site.register(Notification)
admin.site.register(HostelLeave)
admin.site.register(Assessment)
admin.site.register(Question)


admin.site.register(FeeCategory)
admin.site.register(FeeStructure)
admin.site.register(StudentFee)
admin.site.register(Payment)
admin.site.register(FeeNote)
admin.site.register(FeeReceipt)
admin.site.register(UserDocument)
admin.site.register(Payroll)
admin.site.register(UserAccessPass)
@admin.register(SimsConfig)
class SimsconAdmin(admin.ModelAdmin):
    list_display = ['key', 'value', 'school']

@admin.register(Discount)
class DiscountAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'description']
    list_filter = ('school','name', 'branch')

@admin.register(FeeDiscount)
class FeeDiscountAdmin(admin.ModelAdmin):
    list_display = ['id', 'student', 'discount_amount','discount_type','valid_until']
    list_filter = ('school','student', 'branch')
    

@admin.register(School)
class SchoolAdmin(admin.ModelAdmin):
    list_display = ['name', 'school_code', 'address']
    search_fields = ['name', 'school_code']

@admin.register(Branch)
class BranchAdmin(admin.ModelAdmin):
    list_display = ['name', 'school', 'school_code']
    search_fields = ['name', 'school__name', 'school_code']

@admin.register(AcademicSession)
class AcademicSessionAdmin(admin.ModelAdmin):
    list_display = ['id','name', 'start_date','school', 'end_date', 'is_current']
    search_fields = ['name']
@admin.register(Attendance)
class AttendenceAdmin(admin.ModelAdmin):
    list_display = ['date', 'get_student_name', 'get_school_class_name', 'get_section_name']
    search_fields = ['student__name']  # Use double underscore for searching related fields

    def get_student_name(self, obj):
        return obj.student.name if obj.student else 'N/A'
    get_student_name.admin_order_field = 'student__name'
    get_student_name.short_description = 'Student Name'

    def get_school_class_name(self, obj):
        return obj.school_class.name if obj.school_class else 'N/A'
    get_school_class_name.admin_order_field = 'school_class__name'
    get_school_class_name.short_description = 'Class Name'

    def get_section_name(self, obj):
        return obj.section.name if obj.section else 'N/A'
    get_section_name.admin_order_field = 'section__name'
    get_section_name.short_description = 'Section Name'
@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ['name', 'school', 'branch']
    search_fields = ['name']
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id','username', 'email', 'role', 'school']
    search_fields = ['username', 'email']

@admin.register(Student)
class StudentAdmin(admin.ModelAdmin):
    list_display = ['name', 'date_of_birth', 'school']
    search_fields = ['name', 'school__name']
@admin.register(PromotionHistory)
class PromotionHistoryAdmin(admin.ModelAdmin):
    list_display = ['session', 'from_class', 'to_class',"student"]
    search_fields = ['student__name']
@admin.register(AcademicPerformance)
class AcademicPerformanceAdmin(admin.ModelAdmin):
    list_display = ['session', 'attendance_percentage', 'subjects',"student"]
    search_fields = ['student__name']
@admin.register(PerformanceMetrics)
class PerformanceMetricsAdmin(admin.ModelAdmin):
    list_display = ['session',"student", 'subject', 'score',"behavior_score"]
    search_fields = ['student__name']

@admin.register(SchoolClass)
class SchoolClassAdmin(admin.ModelAdmin):
    list_display = ['name', 'school', 'branch']
    search_fields = ['name']

@admin.register(Section)
class SectionAdmin(admin.ModelAdmin):
    list_display = ['name', 'school', 'school_class']
    search_fields = ['name', 'school__name']

@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ['name', 'department_code', 'school']
    search_fields = ['name', 'department_code']

@admin.register(Designation)
class DesignationAdmin(admin.ModelAdmin):
    list_display = ['name', 'department']
    search_fields = ['name']
@admin.register(Leaves)
class LeaveAdmin(admin.ModelAdmin):
    list_display = ['type', 'remark']
    search_fields = ['name']
@admin.register(Teacher)
class TeacherAdmin(admin.ModelAdmin):
    list_display = ['name', 'teacher_number', 'school']
    search_fields = ['name', 'school__name']

@admin.register(Club)
class ClubAdmin(admin.ModelAdmin):
    list_display = ['name', 'school']
    search_fields = ['name']

@admin.register(House)
class HouseAdmin(admin.ModelAdmin):
    list_display = ['name', 'school']
    search_fields = ['name']

@admin.register(Dormitory)
class DormitoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'school']
    search_fields = ['name']
@admin.register(DormitoryRoom)
class DormitoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'school']
    search_fields = ['name']
@admin.register(HostelRoom)
class HostelRoomAdmin(admin.ModelAdmin):
    list_display = ['name', 'room_type']
    search_fields = ['name']

@admin.register(HostelCategory)
class HostelCategoryAdmin(admin.ModelAdmin):
    list_display = ['name']
    search_fields = ['name']

@admin.register(BusRoute)
class BusRouteAdmin(admin.ModelAdmin):
    list_display = ['route','vehicle']
    search_fields = ['route']
    list_filter = ('school', 'branch')
    ordering = ('-created_at',)

@admin.register(BusStation)
class BusStationRouteAdmin(admin.ModelAdmin):
    list_display = ['name', 'route_fair','lat','lon']
    search_fields = ['name']
    list_filter = ('school', 'branch')
    ordering = ('-created_at',)
@admin.register(RouteStop)
class RouteStopAdmin(admin.ModelAdmin):
    list_display = ['route', 'bus_station','stop_order','type']
    list_filter = ('route', 'type')
    ordering = ('-created_at',)

@admin.register(Vehicle)
class VehicleAdmin(admin.ModelAdmin):
    list_display = ['name', 'vehicle_number','vehicle_model','vehicle_quantity', 'driver']
    search_fields = ['name', 'vehicle_number']
    list_filter = ('school', 'branch')
    ordering = ('-created_at',)
    autocomplete_fields = ['driver']  # Enable autocomplete for the driver field
    def get_search_fields(self, request):
        return super().get_search_fields(request)
        
@admin.register(Timetable)
class TimetableAdmin(admin.ModelAdmin):
    list_display = ['day', 'teacher','section','subject','school_class']
    list_filter = ('school', 'branch')
@admin.register(TimePeriods)
class TimeperiodsAdmin(admin.ModelAdmin):
    list_display = ['name', 'description','unique_name','start_time','end_time']
    list_filter = ('school', 'branch')
        
@admin.register(Student_Category)
class StudentCategoryAdmin(admin.ModelAdmin):
    list_display = ['name']
    search_fields = ['name']

@admin.register(NoticeBoard)
class NoticeBoardAdmin(admin.ModelAdmin):
    list_display = ['id','title','message']
    search_fields = ['message']
@admin.register(Parent)
class ParentAdmin(admin.ModelAdmin):
    list_display = ['name', 'email', 'mobile_no']
    search_fields = ['name', 'school__name']

@admin.register(SchoolGallery)
class SchoolGalleryAdmin(admin.ModelAdmin):
    list_display = ('id', 'image_preview', 'category','type', 'description', 'school', 'branch', 'created_at')
    list_filter = ('category', 'school', 'branch')
    search_fields = ('category', 'description', 'school__name', 'branch__name')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('Gallery Information', {
            'fields': ('image', 'description', 'category', 'school', 'branch','type')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )

    def image_preview(self, obj):
        if obj.image:
            return format_html(f'<img src="{obj.image.url}" style="width: 50px; height: 50px;" />')
        return "No Image"
    image_preview.short_description = "Image Preview"
    
@admin.register(QRCode)
class QRCodeAdmin(admin.ModelAdmin):
    list_display = ('name', 'type', 'school', 'branch', 'qr_code_image', 'logo')  # Display all relevant fields
    search_fields = ('name',)  # Enable search by name
    list_filter = ('school', 'type')  # Enable filtering by school and type

@admin.register(GatePass)
class GatePassAdmin(admin.ModelAdmin):
    list_display = ('user', 'status', 'method', 'type','created_at')  # Display all relevant fields
    search_fields = ('user','method')  # Enable search by name
    list_filter = ('type','method')
# ==========================cart-===============================

class ProductImageAdmin(admin.StackedInline):
    model = ProductImage
class  SpecificationAdmin(admin.StackedInline):
    model = Specification
class ProductAdmin(admin.ModelAdmin):
    inlines = [ProductImageAdmin,SpecificationAdmin]

admin.site.register(Cart)
admin.site.register(VendorProfile)
admin.site.register(CartItems)
admin.site.register(Coupon)
admin.site.register(Wishlist)
admin.site.register(Category)
admin.site.register(Product, ProductAdmin)
admin.site.register(ProductImage)
admin.site.register(Specification)