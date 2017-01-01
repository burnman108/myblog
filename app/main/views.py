from .. import db
from flask import render_template, abort, flash, redirect, url_for, request, current_app, make_response
from . import main
from ..models import User, Role, Permission, Post, Comment
from flask_login import current_user, login_required
from .forms import EditProfileForm, EditProfileAdminForm, PostForm, CommentForm
from ..decorators import admin_required, permission_required




@main.route('/', methods=['GET', 'POST'])
def index():
    """
    个人主页，用户用来发表日志的输入框，并在框架展示所有文章，按时间倒序排开；
    若想查看第2页的内容，需要在浏览器地址栏中的URL后加上查询字符串?page=2；
    pagination()方法返回值是一个Pagination类对象，它包含许多属性和方法，
    用于在模板中生成分页链接。
    :return: 渲染index.html页面
    """
    form = PostForm()
    if form.validate_on_submit() and current_user.can(Permission.WRITE_ARTICLES):
        """
        变量current_user由Flask_login提供，和所有上下文变量一样，也是通过线程内的代理对象实现。
        这个对象的表现类似用户对象，但实际上却是一个轻度包装，包含真正的用户对象。数据库需要真正的
        用户对象，因此要调用_get_current_object()方法.
        """
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    show_followed = False  # 决定显示所有博客文章还是只显示所关注的用户文章的选项存储在cookie的show_followed字段中
    if current_user.is_authenticated:
        # 如果用户已经登录
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        # show_followed如果为True，则将query对象返回用户关注者的文章
        query = current_user.followed_posts
    else:
        # 如果为False则返回所有文章的query对象
        query = Post.query

    pagination = query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'], error_out=False
    )  # error_out参数设为出True时，如果请求页数超出范围会返回404错误，设为False时，会返回一个空列表
    posts = pagination.items
    return render_template('index.html', posts=posts, show_followed=show_followed, form=form, pagination=pagination)

@main.route('/all')
@login_required
def show_all():
    """
    指定路由的链接添加在首页模板中，点击这两个链接后会为show_followedcookie设定适当的值，然后重定向到首页
    :return:
    """
    resp = make_response(redirect(url_for('.index')))  # cookie只能在响应对象中设置，因此两个路由不能依赖Flask，要使用make_response()方法创建响应对象
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)  # 如果不设定max_age的话，浏览器关闭后cookie就会过期
    return resp

@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return resp

@main.route('/user/<username>')
def user(username):
    """
    个人资料页面
    :param username: 在base.html页面中重定向的时候传入current_user.username
    :return: 渲染user.html页面
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    posts = user.posts.order_by(Post.timestamp.desc()).all()
    return render_template('user.html', user=user, posts=posts)


@main.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    """
    编辑个人资料
    :return: 渲染edit_profile.html页面
    """
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


@main.route('/edit_profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    """
    管理员权限可以更改所有注册成员的资料
    :param id:
    :return:
    """
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('The profile has been update.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)


@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    """
    文章页面，文章下面有该文章的评论列表
    :param id:
    :return:
    """
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data, post=post, author=current_user._get_current_object())
        db.session.add(comment)
        flash('Your comment has been published.')
        return redirect(url_for('.post', id=post.id, page=-1))  # -1是一个特殊的页数，用来请求评论的最后一页
    page = request.args.get('page', 1, type=int)
    if page == -1:
        # 程序从查询字符串中获取页数，发现值为-1时，会计算评论的总数和总页数，得出真正要显示的页数
        page = (post.comments.count() - 1) // current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False
    )
    comments = pagination.items
    return render_template('post.html', posts=[post], form=form, comments=comments, pagination=pagination)

@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    """
    评论管理页面的路由
    :return:
    """
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False
    )
    comments = pagination.items
    return render_template('moderate.html', comments=comments, pagination=pagination, page=page)

@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    return redirect(url_for('.moderate', page=request.args.get('page', 1, type=int)))

@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    return redirect(url_for('.moderate', page=request.args.get('page', 1, type=int)))

@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    """
    编辑文章
    :param id:
    :return:
    """
    post = Post.query.get_or_404(id)
    if current_user != post.author and not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        flash('The post has been updated.')
        return redirect(url_for('.post', id=post.id))
    form.body.data = post.body
    return render_template('edit_post.html', form=form)

@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    """
    “关注”按钮的方法，current_user关注user
    :param username:
    :return:
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash('You are already following this user.')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    flash('You are now following %s.' % username)
    return redirect(url_for('.user', username=username))

@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    """
    “取消关注”按钮的方法，current_user取消关注user
    :param username:
    :return:
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash('You did not follow this user')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are not now following %s.' % username)
    return redirect(url_for('.user', username=username))

@main.route('/followers/<username>')
def followers(username):
    """
    转到user的粉丝列表——user的粉丝群体
    :param username:
    :return:
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False
    )
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title='Followers of',
                           endpoint='.followers', pagination=pagination,
                           follows=follows)

@main.route('/followed_by/<username>')
def followed_by(username):
    """
    转到user的关注列表，里面都是大V——user的关注者群体
    :param username:
    :return:
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWED_PER_PAGE'],
        error_out=False
    )
    followed = [{'user': item.followed, 'timestamp': item.timestamp}
                for item in pagination.items]
    return render_template('followers.html', user=user, title='Followed of',
                           endpoint='.followed_by', pagination=pagination,
                           follows=followed)
