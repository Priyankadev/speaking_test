from flask import Flask, request, make_response, render_template, jsonify,\
    session, url_for, redirect, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required,\
                        logout_user, current_user
from flask_admin import Admin, BaseView, expose
import uuid
from uuid import getnode as get_mac
from flask.ext.bcrypt import Bcrypt
from bson.objectid import ObjectId
from functools import wraps
import time
from datetime import datetime, timedelta
import datetime
import traceback
import flask_login
import flask
import json
import jwt
import os
from db import Mdb

# from eve import Eve

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'templates')

# app = Eve('', template_folder=tmpl_dir)

app = Flask(__name__)

bcrypt = Bcrypt(app)
mdb = Mdb()


#############################################
#                                           #
#              WORKING  SESSION             #
#                                           #
#############################################
@app.before_request
def before_request():
    flask.session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=30)
    flask.session.modified = True
    flask.g.user = flask_login.current_user


app.config['secretkey'] = 'some-strong+secret#key'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'

# setup login manager
login_manager = LoginManager()
login_manager.init_app(app)


#############################################
#                                           #
#        _id of mongodb record was not      #
#           getting JSON encoded, so        #
#           using this custom one           #
#                                           #
#############################################
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


#############################################
#                                           #
#                SESSION COUNTER            #
#                                           #
#############################################
def sumSessionCounter():
    try:
        session['counter'] += 1
    except KeyError:
        session['counter'] = 1


##############################################
#                                            #
#           Login Manager                    #
#                                            #
##############################################
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/')


#############################################
#                                           #
#              TOKEN REQUIRED               #
#                                           #
#############################################
app.config['secretkey'] = 'some-strong+secret#key'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        # ensure that token is specified in the request
        if not token:
            return jsonify({'message': 'Missing token!'})

        # ensure that token is valid
        try:
            data = jwt.decode(token, app.config['secretkey'])
        except:
            return jsonify({'message': 'Invalid token!'})
############################################################################
#                                                                          #
#            CHECK EMAIL USER ALREADY REGISTERED OR NOT                    #
#                                                                          #
############################################################################

        return f(*args, **kwargs)

    return decorated


############################################################################                                           #
#                                                                          #
#                                                                          #
#                              CANDIDATE PANNEL                            #
#                                                                          #
#                                                                          #
#                                                                          #
############################################################################
############################################################################
#                                                                          #
#                              CANDIDATE ROUTE                             #
#                                                                          #
############################################################################
@app.route('/candidate')
@app.route('/')
def candidate():
    templateData = {'title': 'Login Page'}
    return render_template('candidate/home.html', session=session, **templateData)


############################################################################
#                                                                          #
#                              CANDIDATE SIGNUP                            #
#                                                                          #
############################################################################
@app.route('/candidate/signup')
def candidate_signup():
    templateData = {'title': 'Signup page'}
    return render_template('candidate/signup.html', session=session, **templateData)


############################################################################
#                                                                          #
#          CHECK CANDIDATE ALREADY REGISTERED OR NOT THEN REGISTER         #
#                            PASSWORD BCRYBY                               #
#                                                                          #
############################################################################
@app.route('/candidate/add_candidate', methods=['POST'])
def add_candidate():
    try:
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        age = request.form['age']
        phone = request.form['phone']
        address = request.form['address']
        gender = request.form['gender']

        # password bcrypt  #
        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        check = mdb.check_email(email)
        if check:
            print("This Email Already Used")
            templateData = {'title': 'Signup Page'}
            return render_template('candidate/signup.html', **templateData)

        else:
            mdb.add_candidate(name, email, pw_hash, age, phone, address, gender)
            print('User Is Added Successfully')

            return render_template('candidate/home.html', session=session)

    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())


############################################################################
#                                                                          #
#                              CANDIDATE LOGIN                             #
#        STORED INFORMATION[SESSION_ID, MAC_ADDRESS, IP OR BROWSER]        #
#     SEESION TIME 30 MIN (SEESION LOGOUT AUTOMATICALLY AFTER 30 MINs      #
#                                                                          #
############################################################################
@app.route('/candidate/login', methods=['POST'])
def candidate_login():
    ret = {'err': 0}
    try:
        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']

        if mdb.user_exists(email):
            pw_hash = mdb.get_password(email)
            print ('password in server, get from db class', pw_hash)
            passw = bcrypt.check_password_hash(pw_hash, password)

            if passw == True:
                name = mdb.get_name(email)
                session['name'] = name
                session['email'] = email

                # Login Successful!
                expiry = datetime.datetime.utcnow() + datetime.\
                    timedelta(minutes=30)

                token = jwt.encode({'user': email, 'exp': expiry},
                                   app.config['secretkey'], algorithm='HS256')
                # flask_login.login_user(user, remember=False)
                ret['msg'] = 'Login successful'
                ret['err'] = 0
                ret['token'] = token.decode('UTF-8')
                templateData = {'title': 'singin page'}
            else:
                return render_template('candidate/home.html', session=session)

        else:
            # Login Failed!
            return render_template('candidate/home.html', session=session)

            ret['msg'] = 'Login Failed'
            ret['err'] = 1

        LOGIN_TYPE = 'Candidate Login'
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr

        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
    # return jsonify(ret)
    return render_template('candidate/home.html', session=session)


############################################################################
#                                                                          #
#                       CANDIDATE SESSION LOGOUT                           #
#     STOREED CANDIDATES INFORMATION WHEN CANDIDATE LOGOUT ALL DEATAILS.   #
#                                                                          #
############################################################################
@app.route('/clear')
def clearsession():
    try:
        LOGIN_TYPE = 'Candidate Logout'
        sumSessionCounter()
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)
        session.clear()
        return render_template('candidate/home.html', session=session)
    except Exception as exp:
        return 'clearsession() :: Got Exception: %s' % exp


##############################################################################
#                                                                            #
#                                                                            #
#                                                                            #
#                               MAIN SERVER                                  #
#                                                                            #
#                                                                            #
#                                                                            #
##############################################################################
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
