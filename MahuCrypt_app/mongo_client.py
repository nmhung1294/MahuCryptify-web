from pymongo import MongoClient
from MahuCrypt_app.config import db_conf
# Chuỗi kết nối đến MongoDB
uri = f"mongodb+srv://{db_conf.USER_NAME}:{db_conf.PASSWORD}@mahucrypt.ofxgb.mongodb.net/?retryWrites=true&w=majority&appName=mahucrypt"

# Kết nối tới MongoDB
client = MongoClient(uri)

# Truy cập database của bạn, ví dụ: 'mahucrypt'
db_conf = client['MahuCrypt']
