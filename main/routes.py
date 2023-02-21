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
import requests
from requests.auth import HTTPBasicAuth
import json
from datetime import datetime
import base64

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
        

        mail = form.email.data
        token = s.dumps(form.email.data, salt='email-confirm')
        msg = Message('Confirm Email', sender='kinuthiasimon002@gmail.com', recipients=[form.email.data])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = 'Your link is {}'.format(link)
        mail.send(msg)

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        username = form.first_name.data + form.last_name.data
        user = User(username=username,email=form.email.data,phone_number=form.phonenumber.data, password=hashed_password)
        database.session.add(user)
        database.session.commit()
        flash('Your account has been created! An email has been sent to you registered email. Please verify to be able to login!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)


@app.route('/confirm_email/<token>')
def confirm_email(token,email):
    try:
        s.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.confirmed = True
            database.session.commit()

        flash('Email confirmed You can now login','success')
    except SignatureExpired:
        flash('The token is expired!','danger')
    return redirect(url_for('login'))


@app.route('/sell', methods=['GET', 'POST'])
@login_required
def sell():
    form = SellForm()
    if current_user.activated == False:
        if form.validate_on_submit():
            endpoint = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
            access_token = _access_token()
            headers = { "Authorization": "Bearer %s" % access_token }
            my_endpoint = base_url + "/lnmo"
            Timestamp = datetime.now()
            times = Timestamp.strftime("%Y%m%d%H%M%S")
            password = "174379" + "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919" + times
            datapass = base64.b64encode(password.encode('utf-8'))

            data = {
                "BusinessShortCode": "174379",
                "Password": datapass.decode('utf-8') ,
                "Timestamp": times,
                "TransactionType": "CustomerPayBillOnline",
                "PartyA": 254791286569, # fill with your phone number
                "PartyB": "174379",
                "PhoneNumber": 254791286569, # fill with your phone number
                "CallBackURL": my_endpoint,
                "AccountReference": "TestPay",
                "TransactionDesc": "HelloTest",
                "Amount": 2
            }

            res = requests.post(endpoint, json = data, headers = headers)
            if res:
                current_user.activated = True
                database.session.commit()
            else:
                print('not valid')
            
            flash('Account activated you can now sell Your product', 'success')
            return redirect(url_for('home'))
    else:
        flash('Account already activated', 'success')
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('home'))
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
    if current_user.activated == False:
        flash('Your Account Hasn\'t Been Activated ', 'danger')
        return redirect(url_for('home'))
    if form.validate_on_submit():
        '''picture_file1 = save_picture(form.image1.data)
        picture_file2 = save_picture(form.image2.data)
        picture_file3 = save_picture(form.image3.data)'''
        product = Post(
            title = form.name.data,
            content = form.content.data,
            location=form.location.data,
            price = form.price.data,
            category = form.category.data,
            author = current_user,
            )
        database.session.add(product)
        database.session.commit()
            
        flash('Your Product Has Been Added', 'success')
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('home'))                
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










base_url = 'http://192.168.1.104:5000/'
consumer_key = 'NidEHbjj3J3aeksTXq3mqAOF4iHGJJv2'
consumer_secret = 'GjivG0p6j3QsEmL8'



@app.route('/access_token')
def get_access_token():
    consumer_key = consumer_key
    consumer_secret = consumer_secret
    endpoint = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'

    r = requests.get(endpoint, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    data = r.json()
    return data['access_token']

@app.route('/register')
def register_urls():
    endpoint = 'https://sandbox.safaricom.co.ke/mpesa/c2b/v1/registerurl'
    access_token = _access_token()
    my_endpoint = base_url + "c2b/"
    headers = { "Authorization": "Bearer %s" % access_token }
    r_data = {
        "ShortCode": "600383",
        "ResponseType": "Completed",
        "ConfirmationURL": my_endpoint + 'con',
        "ValidationURL": my_endpoint + 'val'
    }

    response = requests.post(endpoint, json = r_data, headers = headers)
    return response.json()


@app.route('/simulate')
def test_payment():
    endpoint = 'https://sandbox.safaricom.co.ke/mpesa/c2b/v1/simulate'
    access_token = _access_token()
    headers = { "Authorization": "Bearer %s" % access_token }

    data_s = {
        "Amount": 100,
        "ShortCode": "600383",
        "BillRefNumber": "test",
        "CommandID": "CustomerPayBillOnline",
        "Msisdn": "254708374149"
    }

    res = requests.post(endpoint, json= data_s, headers = headers)
    return res.json()

@app.route('/b2c')
def make_payment():
    endpoint = 'https://sandbox.safaricom.co.ke/mpesa/b2c/v1/paymentrequest'
    access_token = _access_token()
    headers = { "Authorization": "Bearer %s" % access_token }
    my_endpoint = base_url + "/b2c/"

    data = {
        "InitiatorName": "apitest342",
        "SecurityCredential": "SQFrXJpsdlADCsa986yt5KIVhkskagK+1UGBnfSu4Gp26eFRLM2eyNZeNvsqQhY9yHfNECES3xyxOWK/mG57Xsiw9skCI9egn5RvrzHOaijfe3VxVjA7S0+YYluzFpF6OO7Cw9qxiIlynYS0zI3NWv2F8HxJHj81y2Ix9WodKmCw68BT8KDge4OUMVo3BDN2XVv794T6J82t3/hPwkIRyJ1o5wC2teSQTgob1lDBXI5AwgbifDKe/7Y3p2nn7KCebNmRVwnsVwtcjgFs78+2wDtHF2HVwZBedmbnm7j09JO9cK8glTikiz6H7v0vcQO19HcyDw62psJcV2c4HDncWw==",
        "CommandID": "BusinessPayment",
        "Amount": "200",
        "PartyA": "601342",
        "PartyB": "254708374149",
        "Remarks": "Pay Salary",
        "QueueTimeOutURL": my_endpoint + "timeout",
        "ResultURL": my_endpoint + "result",
        "Occasion": "Salary"
    }

    res = requests.post(endpoint, json = data, headers = headers)
    return res.json()

@app.route('/lnmo')
def init_stk():
    endpoint = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
    access_token = _access_token()
    headers = { "Authorization": "Bearer %s" % access_token }
    my_endpoint = base_url + "/lnmo"
    Timestamp = datetime.now()
    times = Timestamp.strftime("%Y%m%d%H%M%S")
    password = "174379" + "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919" + times
    datapass = base64.b64encode(password.encode('utf-8'))

    data = {
        "BusinessShortCode": "174379",
        "Password": datapass.decode('utf-8') ,
        "Timestamp": times,
        "TransactionType": "CustomerPayBillOnline",
        "PartyA": 254791286569, # fill with your phone number
        "PartyB": "174379",
        "PhoneNumber": 254791286569, # fill with your phone number
        "CallBackURL": my_endpoint,
        "AccountReference": "TestPay",
        "TransactionDesc": "HelloTest",
        "Amount": 2
    }

    res = requests.post(endpoint, json = data, headers = headers)
    return res.json()

@app.route('/lnmo', methods=['POST'])
def lnmo_result():
    data = request.get_data()
    f = open('lnmo.json', 'a')
    f.write(data)
    f.close()

@app.route('/b2c/result', methods=['POST'])
def result_b2c():
    data = request.get_data()
    f = open('b2c.json', 'a')
    f.write(data)
    f.close()

@app.route('/b2c/timeout', methods=['POST'])
def b2c_timeout():
    data = request.get_json()
    f = open('b2ctimeout.json', 'a')
    f.write(data)
    f.close()

@app.route('/c2b/val', methods=['POST'])
def validate():
    data = request.get_data()
    f = open('data_v.json', 'a')
    f.write(data)
    f.close()

@app.route('/c2b/con', methods=['POST'])
def confirm():
    data = request.get_json()
    f = open('data_c.json', 'a')
    f.write(data)
    f.close()


def _access_token():
    consumer_key = 'NidEHbjj3J3aeksTXq3mqAOF4iHGJJv2'
    consumer_secret = 'GjivG0p6j3QsEmL8'
    endpoint = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'

    r = requests.get(endpoint, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    data = r.json()
    return data['access_token']




"""







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