import smtplib, ssl
import random
import string
import re

from email.message import EmailMessage


def read_credentials():
    sender = password = ""
    with open("credentials.txt", "r") as f:
        file = f.readlines()
        sender = file[0].strip()
        password = file[1].strip()

    return sender, password


def otp_generator(size):
    # Takes random choices from
    # ascii_letters and digits
    generate_pass = ''.join([random.choice(string.ascii_uppercase +
                                           string.ascii_lowercase +
                                           string.digits)
                             for n in range(size)])

    return generate_pass


def email_syntax(email):
    regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if re.search(regex, email):
        email_valid = True
    else:
        email_valid = False

    return email_valid


def send_email_otp(email):
    port = 465
    sender, password = read_credentials()
    email_formatter = EmailMessage()
    otp = otp_generator(10)
    email_formatter['Subject'] = 'Registration Verification code'
    email_formatter['From'] = sender
    email_formatter['To'] = email
    email_formatter.set_content('<font color="black">Your OTP Verification code is: </font>' + '<font color="blue">' +
                                otp + '</font>', subtype='html')

    context = ssl.create_default_context()
    print("Starting to send")
    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
        server.login(sender, password)
        server.send_message(email_formatter)

    print("sent email!")
    return otp
