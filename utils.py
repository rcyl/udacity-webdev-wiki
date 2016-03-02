
import jinja2
import re
import hashlib
import hmac
import string
import os
import random

from datetime import datetime, timedelta

from google.appengine.api import memcache
from google.appengine.ext import db


SECRET = "icannotell"
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=False)

def valid_username(username):
    return re.match(USER_RE, username)

def valid_password(password):
    return re.match(PASS_RE, password)

def valid_email(email):
    return not email or re.match(EMAIL_RE, email)

def make_secure_val(val):
    #takes in a user id 
    # mixes it with a secret
    # hash it
    # return a pipe seperated string of value and hash value
    h = hmac.new(SECRET,val).hexdigest();
    return "%s|%s" % (val, h)

def check_secure_val(val):
    #takes in a user id and hash
    key = val.split("|")[0];
    if (make_secure_val(key) == val):
      return key

def make_salt():
    return ''.join(random.sample(string.letters,5))

def make_pw_salt(name, pw,salt=None):
    #method used in both setting and verification
    #so need to distinguish between setting and verification
    # don't want to generate new salt for verification!  
    #add salt and user name and pw
    #return salt and salted hash
    if not salt:
      salt = make_salt()
    h = hashlib.sha256(salt+name+pw).hexdigest();
    return "%s,%s" % (salt, h)

def verify_pw(name, pw, h):
    #get h
    salt = h.split(",")[0]
    return h==make_pw_salt(name,pw,salt)  

def age_set(key, val):
    save_time = datetime.utcnow();
    memcache.set(key, (val, save_time))        

def age_get(key):
    r = memcache.get(key)
    if r:
      val, save_time = r
      age = (datetime.utcnow()-save_time).total_seconds()
    else:
      val, age = None, 0
    return val, age

def age_str(age):
    s = "Last queried: %d seconds ago"
    if age ==1 or age==0: 
       s.replace("seconds", "second")
    return s % age

def top_blogs(update= False):
    key = 'top'
    blogs, age = age_get(key)
    if update or blogs is None:
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        blogs = list(blogs)
        age_set(key, blogs)
    return blogs, age

def page_key(name):
  return db.Key.from_path("pages", name)

def set_mem(key, val):
    memcache.set(key, val)

def gem_mem(key):
    return memcache.get(key)



