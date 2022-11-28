from flask import render_template, flash, redirect, request, url_for,abort
from main import app, bcrypt,database,mail
from main.forms import LoginForm, RegistrationForm, ProductForm, SellForm, RequestResetForm, ResetPasswordForm
from main.models import User,Post
from flask_login import current_user, login_user, login_required, logout_user
import secrets
import os
from PIL import Image
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer,URLSafeTimedSerializer, SignatureExpired
from flask_mail import Message

s = URLSafeTimedSerializer('Thisisasecret!')



@app.route('/')
@app.route('/home')
def home():
    posts = Post.query.all()
    categorys = [6, 4, 5, 5, 5, 5]
    #image_file = url_for('static', filename='profile_pics/' + posts.image_file)
    return render_template("home.html", categorys=categorys, posts=posts)




@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(phone_number=form.phonenumber.data).first()
        if user:
            if user.confirmed == False:
                flash('Account email not confimed! please check your email for confimation link!','danger')
                redirect(url_for('home'))
            else:
                if user and bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user, remember=form.remember.data)
                    next_page = request.args.get('next')
                    return redirect(next_page) if next_page else redirect(url_for('home'))
                else:
                    flash('Login Unsuccessful. Please check email and password', 'danger')
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_token', token=token, _external=True)}
    If you did not make this request then simply ignore this email and no changes will be made.
    '''
    mail.send(msg)

@app.route("/reset_token/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        database.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)



@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))




@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        
        email = form.email.data
        token = s.dumps(form.email.data, salt='email-confirm')
        msg = Message('Confirm Email', sender='simonkinuhia002@gmail.com', recipients=[form.email.data])
        link = url_for('confirm_email', token=token,email=email, _external=True)
        msg.body = 'Your link is {}'.format(link)
        mail.send(msg)

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        username = form.first_name.data + form.last_name.data
        user = User(username=username, email=form.email.data,phone_number=form.phonenumber.data, password=hashed_password)
        database.session.add(user)
        database.session.commit()
        flash('Your account has been created! An email has been sent to you registered email. Please verify to be able to login!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)


@app.route('/confirm_email/<token>/<Email>')
def confirm_email(token,Email):
    try:
        s.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=Email).first()
        if user:
            user.confirmed = True
            database.session.commit()

        flash('Email confirmed You can now login','success')
    except SignatureExpired:
        flash('The token is expired!','danger')
    return redirect(url_for('login'))


@app.route('/sell', methods=['GET', 'POST'])
def sell():
    form = SellForm()
    if current_user.is_authenticated:
        user = User.query.filter_by(email=form.email.data).first()
        if user.activated == False:
            if form.validate_on_submit():
                current_user.activated = True
                database.session.commit()
                flash('Account activated you can now sell Your product', 'success')
                return redirect(url_for('home'))
        else:
            flash('Account already activated', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
    else:
        flash(f'please login first to sell your product', 'danger')
        return redirect(url_for('login'))

    return render_template('sell.html', form=form)


class Test:
    def __init__(self):
        self.electronics_count = Post.query.filter_by( category='electronics').count()
        self.bedding_count = Post.query.filter_by(category='bedding').count()
        self.clothes_count = Post.query.filter_by(category='clothes').count()
        self.furnitures_count = Post.query.filter_by(category='furnitures').count()
        self.others = Post.query.filter_by(category='others').count()
def fun():
    return Test()



@app.route('/categories/<category>')
def categories(category):
    posts = Post.query.filter_by(category=category)
    t=fun()
    return render_template('category.html', posts=posts,others=t.others,bedding_count=t.bedding_count, clothes_count=t.clothes_count, furnitures_count=t.furnitures_count, electronics_count=t.electronics_count)



@app.route('/products')
@login_required
def products():
    posts = Post.query.all()
    t = fun()
    return render_template('view_items.html', posts=posts, bedding_count=t.bedding_count, clothes_count=t.clothes_count, furnitures_count=t.furnitures_count, electronics_count=t.electronics_count)


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/images', picture_fn)

    output_size = (225, 325)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

@app.route('/product/new',  methods=['GET', 'POST'])
@login_required
def new_product():
    form = ProductForm()
    if form.validate_on_submit():
        if current_user.activated == False:
            picture_file1 = save_picture(form.image1.data)
            picture_file2 = save_picture(form.image2.data)
            picture_file3 = save_picture(form.image3.data)
            product = Post(
                title = form.name.data,
                content = form.content.data,
                price = form.price.data,
                category = form.category.data,
                author = current_user,
                image_file = picture_file1

                )
            database.session.add(product)
            database.session.commit()
            
            flash('Your Product Has Been Added', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            print(current_user.activated)
            print("not done")
            
    return render_template('add_item.html', form=form)




@app.route('/product/<id>')
def product(id):
    post = Post.query.filter_by(id=id).first()
    posts = Post.query.all()
    phonenumber = User.query.filter_by(id=post.user_id).first()
    
    t = fun()
    phonenumber = phonenumber.phone_number
    img = 'https://chukasales.herokuapp.com//product/{}'.format(post.id)
    url = "https://wa.me/254{}?text={}".format(phonenumber, img)
    return render_template('product.html', post=post, posts=posts, url=url, bedding_count=t.bedding_count, clothes_count=t.clothes_count, furnitures_count=t.furnitures_count, electronics_count=t.electronics_count)

@app.route('/product/<product_id>/delete')
@login_required
def delete_product(product_id):
    post = Post.query.get_or_404(product_id)
    if post.author != current_user:
        abort(403)
    database.session.delete(post)
    database.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route('/search', methods=['GET', 'POST'])
def search():
    search = request.form.get("search")
    posts = Post.query.filter_by(title=search,price=search,content=search)
    
    print(search)
    return render_template('products.html', posts=posts)

@app.errorhandler(401)
def page_not_found(e):
    return render_template('403.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('403.html')


@app.errorhandler(500)
def page_not_found(e):
    return render_template('403.html')



@app.errorhandler(410)
def page_not_found(e):
    return render_template('410.html')



"""









# page with categories


@app.route('/product/<product_id>/delete')
def delete_product(product_id):
    print(product_id)
    if mongo.db.posts.delete_many({ '_id': ObjectId(product_id)}):
        post = mongo.db.posts.find_one({ '_id': product_id})
        print(post)
    else:
        print('wwwww')

    return redirect(url_for('home'))

"""



"""
@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)"""