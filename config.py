import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    MAIL_SERVER = 'smtp.126.com'
    MAIL_PORT = 994   # 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'xxxxxxx@126.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'xxxxxx'
    FLASKY_MAIL_SUBJECT_PREFIX = 'xxxx'
    FLASKY_MAIL_SENDER = 'xxxxx <xxxxxx@126.com>'
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN') or 'xxxxxxx@126.com'
    FLASKY_POSTS_PER_PAGE = 5
    FLASKY_FOLLOWERS_PER_PAGE = 5
    FLASKY_FOLLOWED_PER_PAGE = 5
    FLASKY_COMMENTS_PER_PAGE = 5

    @staticmethod
    def init_app(app):
        """
        在这个方法里，可以执行对当前环境的配置初始化
        :param app: 参数是程序实例
        :return:
        """
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'mysql+pymysql://root:root@localhost/test_pymysql'


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'mysql+pymysql://root:root@localhost/climatetest1'

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
