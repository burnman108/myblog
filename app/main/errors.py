from flask import render_template, request, jsonify
from . import main

@main.app_errorhandler(404)
def page_not_found(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        # 检查Accept请求首部，根据首部的值决定客户端期望接收的响应格式。
        # 浏览器一般不限制响应的格式，所以只为接受json格式而不接受html格式的客户端生成josn格式的响应。
        response = jsonify({'error': 'not found'})
        response.status_code = 404
        return response
    return render_template('404.html'), 404

@main.app_errorhandler(500)
def internal_server_error(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        # 检查Accept请求首部，根据首部的值决定客户端期望接收的响应格式。
        # 浏览器一般不限制响应的格式，所以只为接受json格式而不接受html格式的客户端生成josn格式的响应。
        response = jsonify({'error': 'internal server error'})
        response.status_code = 500
        return response
    return render_template('500.html'), 500

@main.app_errorhandler(403)
def forbidden(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        # 检查Accept请求首部，根据首部的值决定客户端期望接收的响应格式。
        # 浏览器一般不限制响应的格式，所以只为接受json格式而不接受html格式的客户端生成josn格式的响应。
        response = jsonify({'error': 'forbidden'})
        response.status_code = 403
        return response
    return render_template('403.html'), 403