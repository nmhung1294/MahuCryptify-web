# Mahucrypt App

## Mô tả
Mahucrypt App là một dự án kết hợp Django và React, sử dụng MongoDB làm cơ sở dữ liệu. Dự án này cung cấp một hệ thống mã hóa và giải mã thông tin an toàn.

## Cài đặt

### Cài đặt các gói Python
1. Mở terminal và chuyển đến thư mục gốc của dự án.
2. Chạy các lệnh sau để cài đặt các gói cần thiết:
    ```bash
    python -m pip install "pymongo[srv]"==3.12
    pip install django
    pip install djangorestframework
    pip install django-cors-headers
    ```

### Cài đặt các gói JavaScript
1. Chuyển đến thư mục `ui`:
    ```bash
    cd ui
    ```
2. Cài đặt các gói React và Axios:
    ```bash
    npm install react
    npm install axios
    ```
## Chạy chương trình

### 1. Chạy Django Backend
Mở terminal thứ nhất và chuyển đến thư mục gốc của dự án, sau đó chạy lệnh:
```bash
python manage.py runserver
### 2. Chạy React Front end
Mở terminal thứ hai và chuyển đến thư mục gốc của dự án, chuyển đến thư mục `ui`:
    ```bash
    cd ui
    ```
Sau đó, để chạy chương trình, dùng lệnh:
```bash
    npm start
    ```

