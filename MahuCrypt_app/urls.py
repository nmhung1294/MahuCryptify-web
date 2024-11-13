from django.urls import path
from .views import ExampleView

urlpatterns = [
    path('api/example/', ExampleView.as_view(), name='example'),
    path('api/process/', ExampleView.process_data, name='process_data'),
    
]

