from bson.objectid import ObjectId  # Import ObjectId để chuyển đổi id
from .mongo_client import db_conf

class UserModel:
    # @staticmethod
    # def get_blog_by_id(id):
    #     # Chuyển đổi id thành ObjectId
    #     blog = users_collection.find_one({"_id": ObjectId(id)})
    #     if blog:
    #         return blog.get("title")
    #     return None  
    @staticmethod
    def get_all_collection(collection_name):
        users_collection = db_conf[collection_name]
        data = users_collection.find()
        return data