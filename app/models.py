from . import db, login_manager
from flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, url_for
from datetime import datetime
import hashlib
from markdown import markdown
import bleach
from app.exceptions import ValidationError



class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)  # 关注者群体——粉丝聚集地
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)  # 被关注者群体——大V阵营
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    """
    is_following(self, user):
                    如果self对象的关注群体中包含user实例，那么该函数返回True
                    self在它的关注群体中查找followed_id(被关注者id，即大Vid)有没有=user.id的
    is_followed_by(self, user):
                    如果self对象的粉丝群体中包含user实例，那么该函数返回True
                    self在它的粉丝群体中查找follower_id(关注者id，即粉丝id)有没有=user.id的
    follow(self, user):
                    self对user点关注
    unfollow(self, user):
                    self对user取消了关注
    followed_posts(self):
                    获取self对象对应的用户所关注的人的文章
    generate_fake(count=100):
                    生成随机用户
    __init__(self, **kwargs):
                    用户在注册账户时，会被赋予适当的角色，如果邮箱地址的MD5字段为空，就计算后添加进去
    can(self, permissions):
                    如果角色中包含请求的所有权限位，则返回True
    is_administrator(self):
                    检查管理员权限的功能经常用到，因此使用单独的方法实现
    generate_confirmation_token(self, expiration=3600):
                    注册新用户的时候，生成确认令牌，有效默认时间为1小时
    confirm(self, token):
                    注册新用户的时候，检验传入的令牌，如果没有问题，就返回True
    password(self, password):
                    将password方法属性化，并设置成不可读；将password转化为哈希值，并设置成可写
    verify_password(self, password):
                    登录时判断密码是否正确
    generate_reset_token(self, expiration=3600):
                    重设密码，生成用于重设密码的令牌
    reset_password(self, token, new_password):
                    重设密码，通过验证传入的令牌是否符合来更新重置密码，
    generate_change_email_token(self, new_email, expiration=3600):
                    重设邮箱，生成用于重设登录邮箱的令牌
    change_email(self, token):
                    通过验证传入的令牌是否符合来更新重置登录邮箱，同时更新电子邮件地址的MD5散列值
    gravatar(self, size=100, default='identicon', rating='g'):
                    根据用户注册邮箱地址生成头像，用数据库中缓存
    add_self_follows():
                    更新数据库中的现有用户，使得自己关注自己

    """
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))  # User模型的实例可以通过user.role来访问role.id
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime())
    avatar_hash = db.Column(db.String(32))
    posts = db.relationship('Post', backref='author', lazy='dynamic')  # backref参数向Post模型中添加了author属性
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    followed = db.relationship('Follow',                                      # user的关注群体，此时user对象是粉丝身份，Follow模型可以通过.follower访问user
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Follow',                                      # user的粉丝群体，此时user对象是大V身份,Follow模型可以通过.followed访问user
                               foreign_keys=[Follow.followed_id],
                               backref=db.backref('followed', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')

    def is_following(self, user):
        """
        如果self对象的关注群体中包含user实例，那么该函数返回True
        self在它的关注群体中查找followed_id(被关注者id，即大Vid)有没有=user.id的
        :param user:
        :return:
        """
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        """
        如果self对象的粉丝群体中包含user实例，那么该函数返回True
        self在它的粉丝群体中查找follower_id(关注者id，即粉丝id)有没有=user.id的
        :param user:
        :return:
        """
        return self.followers.filter_by(follower_id=user.id).first() is not None

    def follow(self, user):
        """
        self对user点关注
        :param user:
        :return:
        """
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        """
        self对user取消了关注
        :param user:
        :return:
        """
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    @property
    def followed_posts(self):
        """
        @property将这个方法属性化，调用时无需加括号（），也就是说self对象直接调用这个方法即可得到self关注的用户的文章集合
        ------------------------------------------------------------------------------------------
        获取self对象对应的用户所关注的人的文章，具体逻辑如下：
            1.联结Post表和Follow表，条件是  大V人群的id==文章作者id
            2.之后在从Follow的粉丝集中营follower筛选出self对象对应用户的id，条件是  self的id==粉丝集中营用户的id
            也就是将self作为粉丝身份来筛选出她关注的用户群体
        :return:
        """
        return Post.query.join(Follow, Follow.followed_id==Post.author_id).filter(self.id==Follow.follower_id)

    @staticmethod
    def generate_fake(count=100):
        """
        ForgeryPy随机生成这些信息，因此有重复的风险，如果发生了这种不太可能出现的情况，提交数据库会话时会抛出
        IntergrityError异常。这个异常的处理方式是，在继续操作之前回滚会话。在循环中生成重复内容时不会把用户
        写入数据库，因此生成的虚拟用户总数可能会比预期少。
        :param count:
        :return:
        """
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(
                email=forgery_py.internet.email_address(),
                username=forgery_py.internet.user_name(True),
                password=forgery_py.lorem_ipsum.word(),
                confirmed=True,
                name=forgery_py.name.full_name(),
                location=forgery_py.address.city(),
                about_me=forgery_py.lorem_ipsum.sentence(),
                member_since=forgery_py.date.date(True)
            )
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    def __init__(self, **kwargs):
        """
        用户在注册账户时，会被赋予适当的角色，如果邮箱地址的MD5字段为空，就计算后添加进去
        :param kwargs:
        """
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        self.follow(self)  # 实现注册用户关注自己，从而能在followers列表中看到自己的文章

    def can(self, permissions):
        """
        如果角色中包含请求的所有权限位，则返回True
        :param permissions:
        :return:
        """
        return self.role is not None and (self.role.permissions & permissions) == permissions  # 位于运算？？？

    def is_administrator(self):
        """
        检查管理员权限的功能经常用到，因此使用单独的方法实现
        :return:
        """
        return self.can(Permission.ADMINISTER)

    def generate_confirmation_token(self, expiration=3600):
        """
        生成确认令牌，有效默认时间为1小时
        """
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        """
        检验传入的令牌，如果没有问题，就返回True
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    @property
    def password(self):
        """
        将password方法属性化，并设置成不可读
        """
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        """
        将password转化为哈希值，并设置成可写
        """
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """
        登录时判断密码是否正确
        """
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self, expiration=3600):
        """
        生成用于重设密码的令牌
        """
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        """
        通过验证传入的令牌是否符合来更新重置密码，
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password
        db.session.add(self)
        return True

    def generate_change_email_token(self, new_email, expiration=3600):
        """
        生成用于重设登录邮箱的令牌
        """
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self, token):
        """
        通过验证传入的令牌是否符合来更新重置登录邮箱，同时更新电子邮件地址的MD5散列值
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:  # 如果没有输入新邮箱地址，返回False
            return False
        if self.query.filter_by(email=new_email).first() is not None:  # 如果输入的邮箱地址已经被注册过了，返回False
            return False
        self.email = new_email
        self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        return True

    def gravatar(self, size=100, default='identicon', rating='g'):
        """
        根据用户注册邮箱地址生成头像，用数据库中缓存
        :param size: 图片大小，单位为像素
        :param default: 没有注册Gravatar服务的用户使用的默认图片生成方式，可选值有：‘404’；默认图片的URL；图片生成器‘mm'，
                        ’identicon‘，’monsterid'，‘wavatar'，’retro'，‘blank'
        :param rating: 图片级别，可选值有’g'，‘pg'，’r'，‘x'
        :return:
        """
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def __repr__(self):
        return '<User %s>' % self.username

    @staticmethod
    def add_self_follows():
        """
        更新数据库中的现有用户，使得自己关注自己
        :return:
        """
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def generate_auth_token(self, expiration):
        """
        使用编码后的用户id字段值生成一个签名令牌，还指定了以秒为单位的过期时间
        :param expiration:
        :return:
        """
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        """
        接受的参数是一个令牌，如果令牌可用就返回对应的用户；
        静态方法，因为只有解码令牌后才能知道用户是谁
        :param token:
        :return:
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])

    def to_json(self):
        """
        为了保护隐私，email和role没有加入响应
        :return:
        """
        json_user = {
            'url': url_for('api.get_user', id=self.id, _external=True),
            'username': self.username,
            'member_since': self.member_since,
            'last_seen': self.last_seen,
            'posts': url_for('api.get_user_posts', id=self.id, _external=True),
            'followed_posts': url_for('api.get_user_followed_posts', id=self.id, _external=True),
            'post_count': self.posts.count()
        }
        return json_user

class AnoymousUser(AnonymousUserMixin):
    """
    程序不用先检查用户是否登录，就能自由调用current_user.can()和current_user.is_administrator()
    """

    def can(self, permission):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnoymousUser


class Role(db.Model):
    """
    insert_roles():
                    在python虚拟环境下调用这个方法，创建角色数据
    load_user(user_id):
                    回调函数
    """
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')  # backref参数向User模型中添加了一个role属性

    @staticmethod
    def insert_roles():
        """
        在python环境下调用这个方法，创建角色数据
        :return:
        """
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Roel %s>' % self.name


@login_manager.user_loader
def load_user(user_id):
    """
    回调函数？？？？？？？
    """
    return User.query.get(int(user_id))


class Post(db.Model):
    """
    generate_fake(count=100):
                    生成随机文章
    on_changed_body(target, value, oldvalue, initiator):
                    将body字段中的文字渲染成HTML格式，结果保存在body_html中，自动且高效地完成Markdown文本到HTML的转换
    db.event.listen(Post.body, 'set', Post.on_changed_body)
                    该函数注册在body字段上，是SQLAlchemy“set”事件的监听程序，这意味着只要这个类实例的body字段设了新值，函数就会自动调用
    """
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # Post模型可以通过Post.author来访问user.id
    body_html = db.Column(db.Text)
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    @staticmethod
    def generate_fake(count=100):
        """
        随机生成文章时要为每篇文章随机指定一个用户，为此，我们使用offset()查询过滤器，这个过滤器会跳过参数中
        指定的记录数量。通过设定一个随机的偏移值，再调用first()方法，就能每次都获得一个不同的随机用户。
        :param count:
        :return:
        """
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count-1)).first()  # 偏移原查询返回的结果，返回一个新查询
            p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1, 3)),
                     timestamp=forgery_py.date.date(True),
                     author=u)
            db.session.add(p)
            db.session.commit()

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        """
        将body字段中的文字渲染成HTML格式，结果保存在body_html中，自动且高效地完成Markdown文本到HTML的转换
        :param target:
        :param value:
        :param oldvalue:
        :param initiator:
        :return:
        """
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i',
                        'li', 'ol', 'pre', 'strong', 'ul', 'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html'),
                                                       tags=allowed_tags, strip=True))
    def to_json(self):
        """
        所调用的路由在API蓝本中定义
        指定_external=True是为了生成完整的URL，而不是生成传统Web程序中经常使用的相对URL
        :return:
        """
        json_post = {
            'url': url_for('api.get_post', id=self.id, _external=True),
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp,
            'author': url_for('api.get_user', id=self.author_id, _external=True),
            'comments': url_for('api.get_post_comments', id=self.id, _external=True),
            'comment_count': self.comments.count()  # 表示资源时可以使用虚构的属性，comment_count并不是模型的真实属性
        }
        return json_post

    @staticmethod
    def from_json(json_post):
        """

        :param json_post:
        :return:
        """
        body = json_post.get('body')  # 选用body属性是因为只要该属性的值发生变化，就会触发一个SQLAlchemy事件，自动在服务器端渲染Markdown
        if body is None or body == '':
            raise ValidationError('post does not have a body')
        return Post(body=body)

db.event.listen(Post.body, 'set', Post.on_changed_body)  # 定义了一个事件


class Comment(db.Model):
    """
    on_changed_body(target, value, oldvalue, initiator):
                    将body字段中的文字渲染成HTML格式，结果保存在body_html中，自动且高效地完成Markdown文本到HTML的转换
    """
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)  # 协管员通过这个字段查禁不当评论
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_change_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i', 'strong']
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html'),
                                                       tags=allowed_tags, strip=True))

db.event.listen(Comment.body, 'set', Comment.on_change_body)

