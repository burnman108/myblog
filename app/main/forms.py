from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, \
    SelectField
from flask_pagedown.fields import PageDownField
from wtforms.validators import Length, DataRequired, Email, Regexp
from ..models import Role, User
from wtforms import ValidationError


class EditProfileForm(FlaskForm):
    """
    编辑个人资料的表单
    """
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')


class EditProfileAdminForm(FlaskForm):
    """
    管理员版：编辑个人资料的表单
    """
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[
        DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                              'Usernames must have only letters,'
                                              'numbers, dots, or underscores.')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)  # 是个选择器
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        """
        SelectField实例必须在其choices属性中设置各选项。选项必须是一个由元组组成的列表，各元组都包含两个元素
        选项标识符和显示在控件中的文本字符串。choices列表在表单的《构造函数》中设定，其值从Role模型中获取，使用
        一个查询按照角色名的字母顺序排列所有角色。元组中的标识符是角色的id，因为这是个整数，所以在SelectField
        构造函数中添加coerce=int参数，从而把字段的值转换为整数，而不使用默认的字符串。
        :param user: 创建实例时要有user用户对象作为参数，该用户对象是管理员要修改资料的对象，
        :param args:
        :param kwargs:
        """
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class PostForm(FlaskForm):
    body = PageDownField("what's on your mind?", validators=[DataRequired()])
    submit = SubmitField('Submit')


class CommentForm(FlaskForm):
    """
    评论输入与提交表单
    """
    body = StringField('Enter your comment', validators=[DataRequired()])
    submit = SubmitField('Submit')
