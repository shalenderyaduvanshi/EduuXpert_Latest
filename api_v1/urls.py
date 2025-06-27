"""
URL configuration for sms project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from .views import  *

urlpatterns = [
    path('users/', UserAPI.as_view(), name='user-create'),
    path('users-detail/', UserDetailByTokenAPI.as_view(), name='user-detail'),
    path('reset-password/<uuid:id>/', UpdatePasswordView.as_view(), name='reset-password'),
    path('users-list/', SchoolListAPIView.as_view(), name='user-list'),
    path('user-list/', UserListView.as_view(), name='user-list'),
    path('role-by-user/', UserCreateByRoleAPIView.as_view(), name='role-by-user'),
    path('permission-user-list/', SearchByUserList.as_view(), name='perm-user-list'),
    path('filter-list/', GetFilterListAPiView.as_view(), name='filter-list'),
    path('import/', ImportBulkData.as_view(), name='import'),
    path('login/', LoginAPI.as_view(), name='login'),
    path('token-valid/', CheckTokenAPI.as_view(), name='token'),
    path('logout/', LogoutAPI.as_view(), name='logout'),
    path('school-code-valid/', SchoolCodeValidateAPI.as_view(), name='school_code_valid'),
    path('school-detail/<school_code>/', SchoolDetailOnLogin.as_view(), name='school detail'),
    path('class-list/', SchoolClassListAPIView.as_view(),name='class-list'),
    path('classes/', SchoolClassAPIView.as_view()),
    path('section/', SectionAPIView.as_view(), name='section-list'),
    path('section-list/', SectionListAPIView.as_view(), name='section-detail'),
    path('role/', RoleAPIView.as_view(), name='role'),
    path('role-list/', RoleListAPIView.as_view(), name='role-list'),
    path('session/', AcademicSessionAPIView.as_view(), name='session'),
    path('session-list/', AcedemicSessionListAPIView.as_view(), name='session-list'),
    path('department/', DepartmentAPIView.as_view(), name='department'),
    path('department-list/', DepartmentListAPIView.as_view(), name='department-list'),
    path('designation/', DesignationAPIView.as_view(), name='department'),
    path('designation-list/', DesignationListAPIView.as_view(), name='designation-list'),
    path('house/', HouseAPIView.as_view(), name='house'),
    path('house-list/', HouseListAPIView.as_view(), name='house-list'),
    path('teacher/', TeacherNewAPIView.as_view(), name='teacher'),
    path('teacher-list/', TeacherListAPIView.as_view(), name='teacher'),
    path('subject/', SubjectAPIView.as_view(), name='subject'),
    path('subject-list/', SubjectListAPIView.as_view(), name='subject-list'),
    path('syllabus/', SyllabusAPIView.as_view(), name='syllabus'),
 #=======================================teacher timetable============================================== 
    path('timetable/', TimetableAPIView.as_view(), name='timetable'),
    path('timeperiod/', TimePeriodAPIView.as_view(), name='timeperiod'),
# ============================permissions===============================================================
    path('apps/', AppApi.as_view(), name='app-list'),
    path('apps/<uuid:id>/', AppApi.as_view(), name='app-delete'),
    path('apps-permissions/', AppPermissionApi.as_view(), name='app-permission'),
    path('apps-permissions/<uuid:user_id>/<str:role>/', AppPermissionApi.as_view(), name='app-permission'),
    path('permissions/<uuid:id>/<uuid:app_id>/', AppPermissionApi.as_view(), name='app-permission-update'),
    path('role-permissions/', AppSidebarItemApi.as_view(), name='role-permission'),
    path('model-permissions/', PermissionListView.as_view(), name='permission-list'),
# ====================================leaves==============================================================
    path('leave/', LeaveAPIView.as_view(), name='leave'),
    path('attendance/', AttendanceAPIView.as_view(), name='attendance-api'),
    path('attendance-register/',AttendanceRegisterAPIView.as_view(), name='attendance-register'),

# ==========================================NoticeBoard====================================
    path('notice/', NoticeBoardAPIView.as_view(), name='notice'),
    # ==========================================feedback====================================
    path('feedback/', FeedbackAPIView.as_view(), name='feedback'),
# ============================================school===================================================
    path('school/', SchoolNewAPIView.as_view(), name='school'),    

# ====================================student===================================================
    path('student/', StudentNewAPIView.as_view(), name='student'),
    path('student-bulk/', StudentBulkNewAPIView.as_view(), name='student-bulk'),
    path('student-enquiry/', StudentEnquiryAPIView.as_view(), name='student-enquiry'),
    path('student-enquiry-id/', StudentEnquiryByIdAPIView.as_view(), name='student-enquiry-id'),
    path('student-enquiry-list/', StudentEnquiryListAPIView.as_view(), name='student-enquiry-list'),
    path('student-list/', StudentListNewAPIView.as_view(), name='student-list'),
   
# ====================================parent===================================================
    path('parent/', ParentAPIView.as_view(), name='parent'),
    path('parent-list/', ParentListAPIView.as_view(), name='parent-list'),
    # ====================================student category===================================================
    path('student-category/', StudentCategoryAPIView.as_view(), name='student-category'),
    path('student-category-list/', StudentCategoryListAPIView.as_view(), name='student-category-list'),
     # ====================================club===================================================
    path('club/', ClubAPIView.as_view(), name='club'),
    path('club-list/', ClubListAPIView.as_view(), name='club-list'),
      # ====================================hostel room===================================================
    path('dormitory/', DormitoryAPIView.as_view(), name='dormitory'),
    path('dormitory-list/', DormitoryListAPIView.as_view(), name='dormitory-list'),
    path('dormitory-room/', DormitoryRoomAPIView.as_view(), name='dormitory-room'),
    path('dormitory-room-list/', DormitoryRoomListAPIView.as_view(), name='dormitory-room-list'),
    path('hostel-room/', HostelRoomAPIView.as_view(), name='hostel-room'),
    path('hostel-room-list/', HostelRoomListAPIView.as_view(), name='hostel-room-list'),
    path('hostel-category/', HostelCategoryAPIView.as_view(), name='hostel-category'),
    path('hostel-category-list/', HostelCategoryListAPIView.as_view(), name='hostel-category-list'),
# ====================================USer permissions===================================================
    path('permissions/<uuid:user_id>/', UserPermissionsView.as_view(), name='change_user_permissions'),
    path('permissions/', UserPermissionsView.as_view(), name='list-users-permissions'),
# ===========================================sql query========================================================
    path('generate-report/', ReportGenerateView.as_view(), name='group-list-create'),
    path('table-column/', TableColumnsView.as_view(), name='upload-column'),
    path('bulk-upload/', BulkUploadView.as_view(), name='Bulk-upload'),
    # ===========================================dashboard========================================================

    path('dashboard/', DashboardAPIView.as_view(), name='dashboard'),
    path('dashboard-event/', DashboardCalendarAPIView.as_view(), name='dashboard-calender'),
    # ===========================================payroll========================================================
    path('payroll/', PayrollAPIView.as_view(), name='payroll'),
    path('user-salary/', PayrollUserSalaryAPIView.as_view(), name='payroll'),
    # ======================================================promotion==============================================
    path('promotion-student/', PromotionStudentAPIView.as_view(), name='promotion-student'),
    path('promotion/', PromotionHistoryAPIView.as_view(), name='promotion'),

    # ===========================================permissions========================================================
    path('token-permission/', TokenPermissionAPIView.as_view(), name='group-list-create'),

    path('groups/', GroupPermissionAPIView.as_view(), name='group-list-create'),
    path('groups/<int:pk>/', GroupPermissionAPIView.as_view(), name='group-detail'),
 ###################  FEES ############################################
     path('testfee/', StudentFeesManage.as_view(), name='feetest'),
    path('testreportfee/', StudentPaymentStatusAPIView.as_view(), name='feetstuest'),
     path('assign-fee/<uuid:student_id>/', AssignStudentFeeView.as_view(), name='student_fee_slip'),
    path('assign-fee/', AssignStudentFeeView.as_view(), name='student_fee_slip'),
    path('assign-fee-discount/', AssignFeeDiscountAPIView.as_view(), name='fee-discount'),
    path('fee-note/', FeeNotesAPIView.as_view(), name='fee_note'),
    path('fee-term/', FeeTermAPIView.as_view(), name='fee_term'),
    path('fee-term-list/', FeeTermListAPIView.as_view(), name='fee_term_list'),
    path('fee-category/', FeeCategoryAPIView.as_view(), name='fee_category'),
    path('fee-category-list/', FeeCategoryListAPIView.as_view(), name='fee_category_detail'),
    path('fee-structure/', FeeStructureAPIView.as_view(), name='fee_structure_list_create'),
    path('fee-structure-list/', FeeStructureListAPIView.as_view(), name='fee_structure_list_create'),
    path('student-fee/', StudentFeeAPIView.as_view(), name='student_fee_create'),
    path('student-fee-list/', StudentFeeListAPIView.as_view(), name='student_fee_list_create'),
    path('student-fee/<int:pk>/', StudentFeeAPIView.as_view(), name='student_fee_detail'),
    path('payments/', PaymentAPIView.as_view(), name='payment_list_create'),
    path('payments/<int:pk>/', PaymentAPIView.as_view(), name='payment_detail'),
    path('discounts/', DiscountAPIView.as_view(), name='discount_list_create'),
    path('discounts-list/', DiscountListAPIView.as_view(), name='discount_detail_list'),
    path('feereceipts/', FeeReceiptAPIView.as_view(), name='feereceipt_list_create'),
    path('feereceipts/<int:pk>/', FeeReceiptAPIView.as_view(), name='feereceipt_detail'),
# ==========================================EVENT=============================================
    path('event/', CalendarAPIView.as_view(), name='event-by-month-api'),
 # ====================================Exam===================================================
    path('exam/', ExamAPIView.as_view(), name='exam'),
    path('exam-result/', ResultAPIView.as_view(), name='exam-result'),
    path('exam-list/', ExamListAPIView.as_view(), name='exam-list'),
    path('admit-card/', AdmitCardAPIView.as_view(), name='admit-card'),
    path('exam-type/', ExamTypeAPIView.as_view(), name='exam-type'),
    path('exam-type-list/', ExamTypeListAPIView.as_view(), name='exam-type-list'),
    path('exam-grade/', GradeScaleAPIView.as_view(), name='exam-grade'),
    path('exam-grade-list/', GradeScaleListAPIView.as_view(), name='exam-grade-list'),
  # ====================================Enquiry===================================================
    path('enquiry-type/', EnquiryTypeAPIView.as_view(), name='enquiry-type'),
    path('enquiry-type-list/', EnquiryTypeListAPIView.as_view(), name='enquiry-type-list'),
    path('enquiry/', EnquiryAPIView.as_view(), name='enquiry'),
  # ====================================Expense===================================================
    path('expense-type/', ExpenseTypeAPIView.as_view(), name='expense-type'),
    path('expense-type-list/', ExpenseTypeListAPIView.as_view(), name='expense-type-list'),
    path('expense/', ExpenseAPIView.as_view(), name='expense'),
  # ====================================Earning===================================================
    path('earning-type/', EarningTypeAPIView.as_view(), name='earning-type'),
    path('earning-type-list/', EarningTypeListAPIView.as_view(), name='earning-type-list'),
    path('earning/', EarningAPIView.as_view(), name='arning'),
  # ====================================audit===================================================
    path('audit/', AuditAPIView.as_view(), name='activity-log-list'),
    path('login-audit/', LoginActivityLogAPIView.as_view(), name='activity-log-list'),
    path('user-upload-image/', UserImageUploadAPI.as_view(), name='user-upload-image'),

# ==========================================================================================================
# =====================================================sims config=====================================================
    
    path('sims-config/', SimsCofingAPIView.as_view(), name='sims-config'),
    path('total-earnings/', TotalEarningsAPIView.as_view(), name='total-earnings'),
    
    
# ==========================================================================================================
    path('extract-text-to-json/', ExtractTextAPIView.as_view(), name='extract-text-to-csv'),
    path('classroom/', ClassRoomAPIView.as_view(), name='classroom_api'),
    path('classroom-messages/', ClassRoomMessageAPIView.as_view(), name='classroom_message_api'),
    path('notification/', NotificationAPIView.as_view(), name='notification_message_api'),
    path('leave-count/', LeaveDashboardView.as_view(), name='leave-status-count'),
    path('enquiry-count/', EnquiryDashboardView.as_view(), name='enquiry-status-count'),
    path('department-count/', DepartmentDashboardView.as_view(), name='department-status-count'),
    path('club-count/', ClubDashboardView.as_view(), name='club-status-count'),
    path('house-count/', HouseDashboardView.as_view(), name='house-status-count'),
    path('dashboard-overview/', ClassRoomAPIView.as_view(), name='dashboard-overview'),
    # =====================================================gallery=====================================================
    path('user-documents/', UserDocumentAPIView.as_view(), name='user_documents'),

    path('gallery/categories/', SchoolGalleryAPIView.as_view(), name='get_categories'),  # Get all categories
    path('gallery/images/<str:category>/', SchoolGalleryAPIView.as_view(), name='get_images_by_category'),  # Get images by category 
    #======================================store====================================================
    path('stores/', StoreAPIView.as_view(), name='store-list'),
    #======================================qrcode====================================================
    path('generate-qr/', QRCodeAPIView.as_view(), name='generate_qr'),
    #======================================meeting====================================================
    path('meeting/',MeetingAPIView.as_view(),name = 'meeting'),
    path('google-meeting/', ScheduleMeetingView.as_view(), name='schedule_meeting'),
    path('zoom-meeting/', ZoomMeetingView.as_view(), name='zoom_meeting'),    
     #======================================vistor====================================================
    path('visitor/',VisitorAPIView.as_view(),name = 'vistors'),
    #=========================================help and support========================================
    path('help-support/',HelpSupportAPIView.as_view(),name='help-support'),
    #============================================audiit=============================================
     path('audit-events/', AuditNewAPIView.as_view(), name='crud-event-list'),
    path('login-audits/', LoginALoginEventAPIView.as_view(), name='activity-log-list'),
#======================================Vendor====================================================
    path('vendor/', VendorNewAPIView.as_view(), name='Vendor'),
    path('wishlist/',WhishlistAPIView.as_view(),name = 'wishlist'),
    path('count-cart/',CartWishNotiCountView.as_view(),name ='count-noti-cart'),
    path('cart/',CartAPIView.as_view(),name = 'cart-product'),
    path('product-category/', CategoryAPIView.as_view(), name='category'),
    path('product-category-list/', CategoryListAPIView.as_view(), name='category-list'),
    path('product/', ProductAPIView.as_view(), name='product-add'),
    path('product/<uuid:pk>/', ProductDetailAPIView.as_view(), name='product-detail'),
    path('product-list/', ProductlistAPIView.as_view(), name='product-list'),
    path('product-specification/', SpecificationAPIView.as_view(), name='product-spec'),
    path('product-images/', ProductImageAPIView.as_view(), name='product-image'),
    path('send-email/', SendEmailView.as_view(), name='send-email'),
    path('send-message/', SendMessageView.as_view(), name='send-message'),
    path('users-list/', UserRoleListAPIView.as_view(), name='users-list'),
#=====================================assessment===================================================
    path('assessments/', AssessmentView.as_view(), name='assessment_list_create'),
    path('assessments/<int:pk>/', AssessmentView.as_view(), name='assessment_detail'),
    path('questions/', QuestionView.as_view(), name='question_create'),
    path('questions/<int:pk>/', QuestionView.as_view(), name='question_detail'),

    path('assessments/submit/', SubmitAssessmentView.as_view(), name='submit_assessment'),
    path('assessments/check/', CheckAssessmentView.as_view(), name='check_assessment_list'),
#==============================================gate pass============================================
    path('gatepass/', GatePassAPIView.as_view(), name='gatepass-api'),
    path('accessmethod/', AccessMethodAPIView.as_view(), name='accessmethod-api'),  
    path('accessmethod-list/', AccessMethodListAPIView.as_view(), name='accessmethod-list-api'), 
    path('user-accesspass/', UserAccessPassAPIView.as_view(), name='user-accesspass-api'),
    path('gatetype/', GateTypeAPIView.as_view(), name='gatetype-api'),  
    path('gatetype-list/', GateTypeListAPIView.as_view(), name='gatetype-list-api'),
    path('user-block-access/', BlockUnblockUserView.as_view(), name='block_unblock_user'),
    path('add-employee/', AddEmployeeView.as_view(), name='add-employee'),
    path('qr-detail/', QrCodeDetailAPIView.as_view(), name='qr-detail'),
#================================================vehicle===============================================
    path('vehicles/', VehicleAPIView.as_view(), name='vehicle'),
    path('vehicle-list/', VehicleListAPIView.as_view(), name='vehicle-list'),
    path('vehicle-passenger/', VehiclePassengerAPiView.as_view(), name='vehicle-passenger'),
    path('driver-vehicles-check/', DriverBusDetailView.as_view(), name='vehicle-assign'),
    path('bus-routes/', BusRouteStopAPIView.as_view(), name='bus_route_list_create'),
    path('bus-stations/', BusStationAPIView.as_view(), name='bus-stations'),

]
    