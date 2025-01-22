from django.urls import path, include
from . import views
import vulnerscanner

urlpatterns = [
    path("", views.login, name="login"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("logout/", views.logout, name="logout"),
    path("scanDelete/<str:pk>/", views.scanDelete, name="scanDelete"),
    path("scan/", views.scan, name="scan"),
    path("vulnerview/<str:pk>/", views.vulnerview, name="vulnerview"),
    path("generalsetting/", views.generalsetting, name="generalsetting"),
    path("generalsettingupdate/", views.generalsettingupdate,
         name="generalsettingupdate"),
    path("proxysetting/", views.proxysetting,
         name="proxysetting"),
    path("proxyadd/", views.proxyadd, name="proxyadd"),
    path("deleteProxy/", views.deleteProxy, name="deleteProxy"),
    path("context/", views.context, name="context"),
    path("updateContext/", views.updateContext, name="updateContext"),
    path("authSetting/", views.authSetting, name="authSetting"),
    path("createUser/", views.createUser, name="createUser"),
    path("deleteuser/<str:pk>/", views.deleteuser, name="deleteuser"),
    path("resetContext/", views.resetContext, name="resetContext"),
    path('activeForceUser/', views.activeForceUser, name="activeForceUser"),
    path('anticsrf/', views.antiCsrf, name="anticsrf"),
    path('addcsrf/', views.addcsrf, name="addcsrf"),
    path('deletecsrf/<str:name>/', views.deletecsrf, name="deletecsrf"),
    path('passivescan/', views.passivescan, name="passivescan"),
    path('spiderRule/', views.spiderRule, name="spiderRule"),
    path('updatespider/', views.updatespider, name="updatespider"),
    path('activescanpolicies/', views.activescanpolicies,
         name="activescanpolicies"),
    path('activescansetting/', views.activescansetting, name="activescansetting"),
    path('activeinput/', views.activeinput, name="activeinput"),
    path('updateinjectable/', views.updateinjectable, name="updateinjectable"),
    path('updateInput/', views.updateInput, name="updateInput"),
    path('addexclude/', views.addexclude, name="addexclude"),
    path('deleteeclude/<str:pk>/', views.deleteeclude, name="deleteeclude"),
    path('license/', views.license, name="license"),
    path('sendstatus/', views.sendstatus, name="sendstatus"),


]