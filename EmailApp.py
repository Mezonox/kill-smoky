#!/usr/bin/python

#import statements
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

fromaddr = "phoncey@gmail.com"
toaddr = "phoncey@gmail.com"
msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = "Python test email"

body = "\n Hi! this is a test!\n\n-Dion"
msg.attach(MIMEText(body, 'plain'))

server = smtplib.SMTP('smtp.gmail.com', 587)

#gmail services
server.ehlo()
server.starttls()
server.ehlo()

#login creditials
server.login("phoncey", "thisisjustadreamcunty")

text = msg.as_string()

server.sendmail("phoncey@gmail.com", "phoncey@gmail.com", text)