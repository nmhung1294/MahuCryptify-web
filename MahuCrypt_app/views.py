from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view

class ExampleView(APIView):
    def get(self, request):
        data = {"message": "Hello from Django!"}
        return Response(data)
    
    @api_view(['POST'])
    def process_data(request):
       # Lấy dữ liệu từ request
       data = request.data

       # Xử lý dữ liệu (ví dụ: mã hóa, tạo khóa, v.v.)
       # Đây chỉ là ví dụ đơn giản
       result = {
           'data': data,  # Đảo ngược chuỗi
       }

       return Response(result)