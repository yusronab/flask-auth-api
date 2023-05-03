import pymysql
pymysql.install_as_MySQLdb()
from flask import Flask, render_template, current_app, make_response, request
from flask_mail import Mail, Message
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash

import jwt

app = Flask(__name__)
api = Api(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:g8LV4TW9mcyO7i01k5CI@containers-us-west-68.railway.app:5907/railway"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

app.config['JWT_SECRET_KEY'] = "Rahasia"
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "yusron.arly@gmail.com"
app.config['MAIL_PASSWORD'] = "nbmhvzewnfdaohji"

db = SQLAlchemy(app)

mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_verify = db.Column(db.Integer(), nullable=False)

parser4SignUp = reqparse.RequestParser()
parser4SignUp.add_argument('name', type=str, help='Fullname', location='json', required=True)
parser4SignUp.add_argument('email', type=str, help='Email Address', location='json', required=True)
parser4SignUp.add_argument('password', type=str, help='Password', location='json', required=True)
parser4SignUp.add_argument('re_password', type=str, help='Retype Password', location='json', required=True)

@api.route('/user/signup')
class Registration(Resource):
    @api.expect(parser4SignUp)
    def post(self):
        args = parser4SignUp.parse_args()
        name = args['name']
        email = args['email']
        password = args['password']
        rePassword = args['re_password']

        if(password != rePassword):
            return {'message' : 'Password is not match'}, 400

        user = db.session.execute(db.select(User).filter_by(email=email)).first()

        if(user):
            return {'message' : 'Your email address has been used'}, 409
        
        try:
            user = User(email=email, name=name, password=generate_password_hash(password), is_verify=False)
            
            db.session.add(user)
            db.session.commit()

            datas = db.session.execute(db.select(User).filter_by(email=email)).first()

            user_id = datas[0].id
            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")

            email_token = jwt.encode({"id": user_id}, jwt_secret_key, algorithm="HS256")
            # .decode("utf-8")
            url = f"https://api-subzero.up.railway.app/user/verify-account/{email_token}"

            data = {
                'name': name,
                'url': url
            }

            sender = "noreply@app.com"
            msg = Message(subject="Verify your email", sender=sender, recipients=[email])
            msg.html = render_template("verify-email.html", data=data)

            mail.send(msg)
            
            return {
                'message' : "Success create account, check email to verify"
            }, 201
        except Exception as e:
            print(e)
            return {
                'message' : f"Error {e}"
            }, 500

@api.route("/user/verify-account/<token>")
class VerifyAccount(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            print(f"{user_id} {decoded_token}")
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()[0]
            
            if not user:
                return {"message": "User not found"}, 404

            if user.is_verify:
                response = make_response(render_template('response.html', success=False, message='Account has been verified'), 400)
                response.headers['Content-Type'] = 'text/html'

                return response

            user.is_verify = True
            db.session.commit()

            response = make_response(render_template('response.html', success=True, message='Yeay... your account has been verified!'), 200)
            response.headers['Content-Type'] = 'text/html'

            return response

        except jwt.exceptions.ExpiredSignatureError:
            return {"message": "Token has expired."}, 401

        except (jwt.exceptions.InvalidTokenError, KeyError):
            return {"message": "Invalid token."}, 401

        except Exception as e:
            return {"message": f"Error {e}"}, 500

parser4SignIn = reqparse.RequestParser()
parser4SignIn.add_argument('email', type=str, help='Email Address', location='json', required=True)
parser4SignIn.add_argument('password', type=str, help='Password', location='json', required=True)

@api.route('/user/signin')
class Login(Resource):
    @api.expect(parser4SignIn)
    def post(self):
        args = parser4SignIn.parse_args()
        email = args['email']
        password = args['password']

        if not email or not password :
            return { "message" : "Please type email and passowrd" }, 400

        user = db.session.execute(db.select(User).filter_by(email=email)).first()
        
        if not user :
            return { "message" : "User not found, please do register" }, 400

        if not user[0].is_verify :
            return { "message" : "Accunt not actived, check email for verify" }, 401

        if check_password_hash(user[0].password, password):
            payload = {
                'id' : user[0].id,
                'name' : user[0].name,
                'email' : user[0].email
            }

            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")
            token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")

            return{ 'token' : token }, 200
        else:
            return { "message" : "Wrong password" }, 400

@api.route('/user/current')
class WhoIsLogin(Resource):
    def get(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404

            user = user[0]

            return {
                'status': "Success", 
                'data': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email
                }
            }, 200

        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401

user_parser = reqparse.RequestParser()
user_parser.add_argument('name', type=str, help='Fullname', location='json', required=True)
user_parser.add_argument('email', type=str, help='Email Address', location='json', required=True)

@api.route('/user/update')
class UpdateUser(Resource):
    def put(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404

            user = user[0]

            args = user_parser.parse_args()

            user.name = args['name']
            user.email = args['email']

            db.session.commit()

            try:
                db.session.commit()
                return {'message': 'Profile updated successfully'}, 200
            except:
                db.session.rollback()
                return {'message': 'Profile update failed'}, 400

        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401

forgot_password_parser = reqparse.RequestParser()
forgot_password_parser.add_argument('email', type=str, help='Email Address', location='json', required=True)

@api.route('/user/forgot-password')
class ForgetPassword(Resource):
    def post(self):
        try:
            args = forgot_password_parser.parse_args()
            email = args['email']

            user = db.session.execute(db.select(User).filter_by(email=email)).first()

            if not user:
                return {'message': 'Email does not match any user'}, 404

            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")

            email_token = jwt.encode({"id": user[0].id}, jwt_secret_key, algorithm="HS256")

            url = f"https://api-subzero.up.railway.app/user/reset-password/{email_token}"

            sender = "noreply@app.com"
            msg = Message(subject="Reset your password", sender=sender, recipients=[email])
            msg.html = render_template("reset-password.html", url=url)

            mail.send(msg)
            return {'message' : "Success send request, check email to verify"}, 200

        except Exception as e:
            return {"message": f"Error {e}"}, 500

@api.route('/user/reset-password/<token>')
class ViewResetPassword(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {"message": "User not found"}, 404

            response = make_response(render_template('form-reset-password.html', id=user[0].id), 200)
            response.headers['Content-Type'] = 'text/html'

            return response

        except jwt.exceptions.ExpiredSignatureError:
            return {"message": "Token has expired."}, 401

        except (jwt.exceptions.InvalidTokenError, KeyError):
            return {"message": "Invalid token."}, 401

        except Exception as e:
            return {"message": f"Error {e}"}, 500

reset_password_parser = reqparse.RequestParser()
reset_password_parser.add_argument('id', type=int, required=True, help='User ID is required')
reset_password_parser.add_argument('password', type=str, required=True, help='New password is required')
reset_password_parser.add_argument('confirmPassword', type=str, required=True, help='Confirm password is required')

@api.route('/user/reset-password', methods=['PUT', 'POST'])
class ResetPassword(Resource):
    def post(self):
        args = reset_password_parser.parse_args()
        password = args['password']

        user = db.session.execute(db.select(User).filter_by(id=args['id'])).first()
        if not user:
            return {'message': 'User not found'}, 404

        if password != args['confirmPassword']:
            return {'message': 'Passwords do not match'}, 400

        user[0].password = generate_password_hash(password)

        try:
            db.session.commit()
            response = make_response(render_template('response.html', success=True, message='Password has been reset successfully'), 200)
            response.headers['Content-Type'] = 'text/html'
            return response

        except:
            db.session.rollback()
            response = make_response(render_template('response.html', success=False, message='Reset password failed'), 400)
            response.headers['Content-Type'] = 'text/html'
            return response


class Menu(db.Model):
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    cooking_time = db.Column(db.String(10), nullable=False)
    category = db.Column(db.String(15), nullable=False)
    calories = db.Column(db.String(4), nullable=False)
    img_url = db.Column(db.String(255), nullable=False)
    core_ingredient = db.Column(db.JSON, nullable=True)
    other_ingredient = db.Column(db.JSON, nullable=True)
    step = db.Column(db.JSON, nullable=True)

    def as_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'cooking_time': self.cooking_time,
            'category': self.category,
            'calories': self.calories,
            'img_url': self.img_url,
            'core_ingredient': self.core_ingredient,
            'other_ingredient': self.other_ingredient,
            'step': self.step
        }

menu_parser = reqparse.RequestParser()
menu_parser.add_argument('name', type=str, location='json', required=True, help='The name of the menu')
menu_parser.add_argument('cooking_time', type=str, location='json', required=True, help='The cooking time of the menu')
menu_parser.add_argument('category', type=str, location='json', required=True, help='The category of the menu')
menu_parser.add_argument('calories', type=str, location='json', required=True, help='The calories of the menu')
menu_parser.add_argument('img_url', type=str, location='json', required=True, help='The image url of the menu')
menu_parser.add_argument('core_ingredient', type=list, location='json', required=True, help='The core ingredient of the menu as a JSON string')
menu_parser.add_argument('other_ingredient', type=list, location='json', help='The other ingredient of the menu as a JSON string')
menu_parser.add_argument('step', type=list, location='json', help='The step of cooking the menu as a JSON string')

@api.route('/menu')
class ActionMenu(Resource):
    def get(self):
        menu_list = [menu.as_dict() for menu in db.session.query(Menu).all()]
        return {
            'status': 'Get all data successfully',
            'data': menu_list
        }, 200

    @api.expect(menu_parser)
    def post(self):
        args = menu_parser.parse_args()
        name = args['name']
        cooking_time = args['cooking_time']
        category = args['category']
        calories = args['calories']
        img_url = args['img_url']
        core_ingredient = args['core_ingredient']
        other_ingredient = args['other_ingredient']
        step = args['step']

        new_menu = Menu(name=name, cooking_time=cooking_time, category=category,
                        calories=calories, img_url=img_url, core_ingredient=core_ingredient,
                        other_ingredient=other_ingredient, step=step)

        db.session.add(new_menu)
        db.session.commit()

        return {'message': 'Menu added successfully'}, 201

if __name__ == '__main__':
    app.run(ssl_context='adhoc',debug=True)