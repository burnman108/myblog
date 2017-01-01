from flask import jsonify
from app.exceptions import ValidationError
from . import api

"""
    其他状态码都由web服务生成，因此可在蓝本的errors.py模块作为辅助函数实现
    web服务的视图函数可以调用这些辅助函数生成错误响应
"""
def bad_request(message):
    response = jsonify({'error': 'bad request', 'message': message})
    response.status_code = 400
    return response

def unauthorized(message):
    response = jsonify({'error': 'unauthorized', 'message': message})
    response.status_code = 401
    return response

def forbidden(message):
    response = jsonify({'error': 'forbidden', 'message': message})
    response.status_code = 403
    return response

@api.errorhandler(ValidationError)
def validation_error(e):
    """
    这里使用的errorhandler修饰器和注册HTTP状态码处理程序时使用的是同一个，只不过此时接受的参数是Exception类，只要抛出了指定类的异常，就会
    调用被修饰的函数，注意：这个修饰器从API蓝本中调用，所以只有当处理蓝本中的路由时抛出了异常才会调用这个处理程序。
    :param e:
    :return:
    """
    return bad_request(e.args[0])