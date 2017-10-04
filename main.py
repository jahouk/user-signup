import os
from flask import Flask, request, redirect, render_template
import jinja2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

app = Flask(__name__)
app.config['DEBUG'] = True 


#    The user leaves any of the following fields empty: username, password, verify password.
#    The user's username or password is not valid -- for example, 
#      it contains a space character or 
#      it consists of less than 3 characters or more than 20 characters 
#      (e.g., a username or password of "me" would be invalid).
#    The user's password and password-confirmation do not match.
#    The user provides an email, but it's not a valid email. 
#      Note: the email field may be left empty, but if there is content in it, 
#      then it must be validated. The criteria for a valid email address in 
#      this assignment are that it has a single @, a single ., 
#      contains no spaces, and is between 3 and 20 characters long.


def validate_username(username):
    username_error = ""
    if username == "":
        username_error = "Please specify a username"
    elif len(username) < 3 or len(username) > 20:
        username_error = "Username must be between 3 and 20 characters in length"
    elif " " in username:
        username_error = "Username can not contain a space"
    return username_error

def validate_password(password):
    password_error = ""
    if password == "":
        password_error = "Please specify a password"
    elif len(password) < 3 or len(password) > 20:
        password_error = "Password must be between 3 and 20 characters in length"
    elif " " in password:
        password_error = "Password can not contain a space"
    return password_error

def validate_verify(password, verify):
    verify_error = ""
    if password != verify:
        verify_error = "Password and Verify Password do not match"
    return verify_error

def validate_email(email):
    email_error = ""
    if email:
        if len(email) < 3 or len(email) > 20:
            email_error = "Email must be between 3 and 20 characters in length"
        elif " " in email:
            email_error = "Email can not contain a space"
        elif "@" not in email:
            email_error = "Valid email addresses must contain an @ symbol"
        elif "." not in email:
            email_error = "Valid email addresses must contain an . symbol"
        elif email.count("@") > 1:
            email_error = "Valid email addresses can only contain one @ symbol"
        elif email.count(".") > 1:
            email_error = "Email address can only contain one . symbol"
    return email_error


@app.route("/", methods=['POST'])
def validate():
    username = request.form['username']
    password = request.form['password']
    verify = request.form['verify']
    email = request.form['email']

    username_error = validate_username(username)
    password_error = validate_password(password)
    verify_error = validate_verify(password, verify)
    email_error = validate_email(email)

    if ((username_error=="") and (password_error=="") 
        and (verify_error=="") and (email_error=="")):

        template = jinja_env.get_template('welcome.html')
        return template.render(username = username)


    template = jinja_env.get_template('index.html')
    return template.render(   
        username = username,
        username_error = username_error,
        password_error = password_error,
        verify_error = verify_error,
        email = email,
        email_error = email_error)


@app.route("/")
def index():
    template = jinja_env.get_template('index.html')
    return template.render()


app.run()

