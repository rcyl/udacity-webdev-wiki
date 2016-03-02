
import os

import jinja2
import  webapp2
import time
import json
from datetime import datetime, timedelta
import math
import logging
import hashlib
import hmac
import string 
import random
import re
import utils

from google.appengine.api import memcache
from google.appengine.ext import db


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = utils.jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_Json(self, d):
        json_txt = json.dumps(d);
        self.response.headers['Content-Type'] = 'application/json; charset:UTF-8'
        self.write(json_txt)

    def get_secure_cookie(self, key):
        cookie_val = self.request.cookies.get(key)
        return cookie_val and utils.check_secure_val(cookie_val)

    def set_secure_cookie(self, key, val):
        cookie_val = utils.make_secure_val(val)
        self.response.set_cookie(key, cookie_val, path="/")
        
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        if self.request.url.endswith('.json'):
            self.format = "json"
        else:
            self.format = "html"
        #checking whether uid in cookie
        uid = self.get_secure_cookie('User-id')
        self.user = uid and Users.by_id(int(uid))

class Users(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty

    @classmethod
    def by_name(cls, name):
        u = db.GqlQuery("SELECT * FROM Users WHERE username=:name", name=name).get()
        return u

    @classmethod  
    def by_id(cls, uid):
        #give id, return entity
        return cls.get_by_id(uid)

    @classmethod    
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and utils.verify_pw(name, pw, u.pw_hash):
            return u

    @classmethod        
    def create(cls, name, pw, email):
        return Users(username = name, 
                      pw_hash = utils.make_pw_salt(name, pw), 
                      email = email)

class loginHandler(Handler):
    def get(self, name):
        self.render("login.html")
    def post(self, name):
        username = self.request.get("username")
        password = self.request.get("password")
        #verify username and password
        u = Users.login(username, password)
        if u: 
           self.set_secure_cookie('User-id',str(u.key().id()))
          # can choose between setting username in cookie or user id
           # storing user id allows quicker access to entities in database (i think)
           self.redirect(name)
        else:
            error_msg = "Invalid login/password. Please try again"
            self.render("login.html", error = error_msg)

class logoutHandler(Handler):
    def get(self, name):
        self.response.delete_cookie("User-id")
        self.redirect(name)

class signupHandler(Handler):
    def get(self, name):
        self.render("signup.html")

    def post(self, name):
        username = self.request.get("username")
        password = self.request.get("password")
        vpass = self.request.get("vpass")
        email = self.request.get("email")

        have_error = False;
        words={"username": username, "email":email}

        if not utils.valid_username(username):
            words["error_msg_user"] = "That is not a valid user name"
            have_error = True
        if not utils.valid_password(password):
            words["error_msg_pass"] = "That is not a valid password"
            have_error = True
        if password!=vpass:
            words["error_msg_vpass"] = "Your passwords did not match"
            have_error = True
        if not utils.valid_email(email):
            words["error_msg_email"] = "That is not a valid email address"
            have_error=True

        if have_error:
            self.render("signup.html", **words)
        else:
            # check if users already exist
            if Users.by_name(username):
                words["error_msg_user"] = "That username is already taken"
                self.render("signup.html", **words)
            else:
                u = Users.create(username, password, email)
                u.put()
                self.set_secure_cookie('User-id', str(u.key().id()))
                self.redirect(name)

 #queries both memcache and database for all entry for a certain page
def get_history(name,update=False):
    hiskey = "_history" + name
    pages = utils.gem_mem(hiskey)
    if update or pages is None:
        pages = Pages.all().ancestor(utils.page_key(name)).order('-created')
        utils.set_mem(hiskey, pages)
    return pages

def query_db(name, view): #query single entry in database
    if view:
        key = db.Key.from_path('Pages', int(view), parent = utils.page_key(name)) 
        p = db.get(key)
    else:
        p = Pages.all().ancestor(utils.page_key(name)).order('-created').get()
        #gets first entry in case no view id
    return p

def get_pages(name, view): #queries both mememcache and database for single entry
    viewkey = name + view 
    pages = utils.gem_mem(viewkey)
    if pages is None:
       pages = query_db(name, view)
       utils.set_mem(viewkey, pages)
    return pages


class Pages(db.Model):
    content = db.StringProperty(required=True, multiline=True)
    created= db.DateTimeProperty(auto_now_add=True)

class WikiPage(Handler):
    def get(self, name):
        view = self.request.get("v")
        p= get_pages(name, view)
        vURL = ""
        if view:
            vURL = "?v=" + view
        if p is None:
           self.redirect("/_edit" + name) 
        else: 
            self.render("base.html", 
                        name = name, 
                        content = p.content, 
                        vURL = vURL,
                        user= self.user)

class EditPage(Handler):
    def get(self, name):
        if not self.user:
            self.redirect("/_login" + name)
        else:
            view = self.request.get("v")
            p = get_pages(name, view)
            content =""
            if p:
                content = p.content
            self.render("edit.html", 
                        name=name, 
                        content=content,
                        user= self.user)     

    def post(self,name):
        content = self.request.get("content")
        p = Pages(content = content, parent = utils.page_key(name))
        p.put() #inserting in database

        viewkey = name + str(p.key().id()) 
        utils.set_mem(viewkey, p)
        #setting memcache with entity 
        #viewkey changed upon insertion into database

        utils.set_mem(name, p) #updating base page's cache
        get_history(name, update=True) #updating history cache 

        self.redirect(name)

class HistoryPage(Handler):
    def get(self, name):
        if not self.user:
            self.redirect("/_login")
        else:
            p = get_history(name)
            self.render("history.html", 
                        pages=p, 
                        name=name,
                        user= self.user)

#PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([('/_signup' + utils.PAGE_RE, signupHandler)
                               ,('/_login' + utils.PAGE_RE, loginHandler)
                               ,('/_logout' + utils.PAGE_RE, logoutHandler)
                               ,('/_edit' + utils.PAGE_RE, EditPage)
                               ,('/_history' + utils.PAGE_RE, HistoryPage)
                               ,(utils.PAGE_RE, WikiPage)]
                               ,debug=True)