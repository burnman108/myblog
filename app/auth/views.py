from flask import render_template, redirect, request, url_for, flash
from . import auth
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, PasswordResetRequestForm, PasswordResetForm,\
    ChangeEmailForm
from ..models import User
from flask_login import login_user, login_required, logout_user, current_user
from .. import db
from ..email import send_email


@auth.before_app_request
def before_request():
    """
    在这里过滤为确认的账户,并在登录后的所有请求前都刷新用户最后访问时间
    :return: 如果账户为确认，任何请求都只显示一个页面，即重定向到/auth/unconfirmed路由
    """
    # if current_user.is_authenticated and not current_user.confirmed and request.endpoint[:5] != 'auth.' \
    #     and request.endpoint != 'static':
    #     return redirect(url_for('auth.unconfirmed'))
    if current_user.is_authenticated:  # 如果用户已经登录，必须返回True，否则返回False
        current_user.ping()  # 更新current_user的last_seen字段的值，更新为当前时刻
        if not current_user.confirmed and request.endpoint[:5] != 'auth.':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    """
    如果是匿名访问这个地址，或者账户已确认，就重定向到/index路由下
    :return: 渲染unconfirmed.html页面
    """
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/confirm')
@login_required
def resend_confirmation():
    """
    未认证用户登录看到的页面中有重新发送认证邮件的按钮，此时会查找到用户的user.id来重新生成令牌并发送邮件至用户注册邮箱
    :return:重定向到/index路由
    """
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    """
    登录路由
    :return: 渲染login.html页面
    """
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    """
    登出路由
    :return: 重定向到/index路由
    """
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    """
    注册账户，并且发送认证邮件到注册邮箱，重定向到/auth/login路由
    :return: 渲染register.html页面
    """
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()  # 应为该方法生成token需要用户的id，所以要手动提交用户信息到数据库
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    """
    认证邮件中的连接请求，调用的认证函数
    :param token: 注册账户时生成的令牌，跟提交新注册用户产生的user.id有关
    :return: 重定向到/index路由
    """
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    修改密码，在登录状态下，首先输入旧密码，判断是否正确，然后提交user模型，重定向到/index路由
    :return:渲染auth/change_password.html页面
    """
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            flash('Your password has been update.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid password.')
    return render_template('auth/change_password.html', form=form)


@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    """
    忘记密码的情况下，重置密码请求，输入注册邮箱，通过user.id生成令牌，向邮箱发送更改密码的验证邮件，重定向到auth.login路由
    :return: 渲染/auth/reset_password.html页面
    """
    if not current_user.is_anonymous:  # is_anonymous对普通用户必须返回False
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password',
                       user=user, token=token,
                       next=request.args.get('next'))
            flash('An email with instructions to reset your password has been sent to you.')
            return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    """
    点击重置密码的确认邮件中的请求按钮，确认注册邮箱没有问题后，再确认令牌，之后更改提交密码，重定向至auth.login路由
    :param token: 更改密码的确认邮件中的令牌
    :return: 渲染/auth/reset_password.html页面
    """
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    """
    在登录状态下，修改注册邮箱地址，判断输入的密码是否正确，从而根据user.id和new_email生成的令牌，发送验证邮箱至新邮箱地址，重定向
    到/index路由
    :return: 渲染auth/change_email.html页面
    """
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_change_email_token(new_email)
            send_email(new_email, 'Confirm your email address',
                       'auth/email/change_email', user=current_user, token=token)
            flash('An email with instructions to confirm your new email address has been sent to you.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password')
    return render_template('auth/change_email.html', form=form)


@auth.route('/change-email/<token>', methods=['GET', 'POST'])
@login_required
def change_email(token):
    """
    点击更改邮箱邮件中的click按钮，通过判断令牌是否符合要求，更新注册邮箱地址
    :param token: 更改邮箱邮件中的令牌
    :return: 更改后重定向到main.index路由
    """
    if current_user.change_email(token):
        flash('Your email address has been update.')
    else:
        flash('Invalid request.')
    return redirect(url_for('main.index'))
