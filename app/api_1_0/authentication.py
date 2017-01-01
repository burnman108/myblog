from flask_httpauth import HTTPBasicAuth
from flask import g, jsonify
from ..models import AnoymousUser, User
from .errors import unauthorized, forbidden
from . import api

auth = HTTPBasicAuth()  # 这种用户认证方式只在API蓝本中使用，所以这个扩展只在蓝本包中初始化

@auth.verify_password
def verify_password(email_or_token, password):
    """
    电子邮件和密码是由User模型中现有的方法验证，如果登录密令正确，这个验证回调函数就返回True；
    验证回调函数把通过认证的用户保存在Flask的全局对象g中，如此一来，视图函数便能进行访问。
    注意：匿名登录时，这个函数返回True并把Flask-login提供的AnonymousUser类实例赋值给g.current_user
    :param email:
    :param password:
    :return:
    """
    if email_or_token == '':
        # API蓝本支持匿名用户访问，此时客户端发送的电子邮件字段必须为空
        # 也即如果该字段为空，那么假定是匿名用户
        g.current_user = AnoymousUser()
        return True
    if password == '':
        # 如果密码为空，那就假定email_or_token参数提供的是令牌，按照令牌的方式进行认证。
        g.current_user = User.verify_auth_token(email_or_token)
        g.token_used = True
        return g.current_user is not None
    # 如果两个参数都不为空，假定使用常规的邮件地址和密码进行认证。
    user = User.query.filter_by(email=email_or_token).first()
    if not user:
        return False
    g.current_user = user
    g.token_used = False
    return user.verify_password(password)

@auth.error_handler
def auth_error():
    """
    如果认证密令不正确，服务器向客户端返回401错误，自定义错误响应
    :return:
    """
    return unauthorized('Invalid credentials')

@api.before_request
@auth.login_required
def before_request():
    """
    这个蓝本中的所有路由都要使用相同的方式进行保护，所以在before_request处理程序中使用一次login_required修饰器，应用到整个蓝本。
    此时所有路由都能进行自动认证，而且作为附加认证，before_request处理程序还会拒绝已通过认证但没有确认账户的用户
    :return:
    """
    if not g.current_user.is_anonymous and not g.current_user.confirmed:
        return forbidden('Unconfirmed account')

@api.route('/token')
def get_token():
    if g.current_user.is_anonymous or g.token_used:
        # 为了避免客户端使用旧令牌申请新令牌，在视图函数中检查g.token_used变量的值，如果使用令牌进行认证就拒绝请求
        return unauthorized('Invalid credentials')
    return jsonify({'token': g.current_user.generate_auth_token(expiration=3600), 'expiration': 3600})