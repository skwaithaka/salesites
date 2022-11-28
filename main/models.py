from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from main import database, login_manager, app
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(database.Model, UserMixin):
    id = database.Column(database.Integer, primary_key=True)
    username = database.Column(database.String(20), unique=True, nullable=False)
    email = database.Column(database.String(120), unique=True, nullable=False)
    phone_number = database.Column(database.String(120), unique=True, nullable=False)
    image_file = database.Column(database.String(20), nullable=False, default='default.jpg')
    activated = database.Column(database.Boolean, nullable=False, default=False)
    confirmed = database.Column(database.Boolean, nullable=False, default=False)
    password = database.Column(database.String(60), nullable=False)
    products = database.relationship('Post', backref='author', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Post(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    title = database.Column(database.String(100), nullable=False)
    date_posted = database.Column(database.DateTime, nullable=False, default=datetime.utcnow)
    content = database.Column(database.Text, nullable=False)
    price = database.Column(database.Integer,nullable=False, default=0)
    category = database.Column(database.Text, nullable=False,default='others')
    image_file = database.Column(database.String(20), nullable=False, default='default.jpg')
    image_file = database.Column(database.String(20), nullable=False, default='default.jpg')
    image_file = database.Column(database.String(20), nullable=False, default='default.jpg')
    user_id = database.Column(database.Integer, database.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}' ,  '{self.category}')"