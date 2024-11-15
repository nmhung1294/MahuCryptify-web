from bson.objectid import ObjectId  # Import ObjectId để chuyển đổi id
from .mongo_client import users_collection

class UserModel:
    @staticmethod
    def get_blog_by_id(id):
        # Chuyển đổi id thành ObjectId
        blog = users_collection.find_one({"_id": ObjectId(id)})
        if blog:
            return blog.get("title")
        return None  
    @staticmethod
    def get_all_blogs():
        blogs = users_collection.find()
        return blogs