#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from google.appengine.ext.webapp import template
from google.appengine.ext import ndb

import logging
import os.path
import webapp2

from google.appengine.api import mail
from webapp2_extras import auth
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """Shortcut to access the auth instance as a property."""
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.
    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.
    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.
    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """Returns the implementation of the user model.
    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """    
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")

  def render_template(self, view_filename, params=None):
    if not params:
      params = {}
    user = self.user_info
    params['user'] = user
    path = os.path.join(os.path.dirname(__file__), 'partials', view_filename)
    self.response.out.write(template.render(path, params))

  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    self.render_template('message.html', params)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)

      try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
      finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)


class ContactsHandler(BaseHandler):
  def get(self):
    self.render_template('contacts.html')

class ArHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('101ar.html')    

class HomeHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('home.html')    

class LinkHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('link.html')

class Facehandler(BaseHandler):
  def get(self):
    self.render_template('facebook.html')    

class Mainhandler(BaseHandler):
  def get(self):
    self.render_template('index.html')


  def post(self):
    user_name = self.request.get('username')
    email = self.request.get('email')
    password = self.request.get('password')
    
    unique_properties = ['user_name']
    user_data = self.user_model.create_user(email,
      unique_properties,
      user_name=user_name, password_raw=password, 
      verified=False)
    if not user_data[0]: #user_data is a tuple
      self.display_message('Unable to create user for email %s because of \
        duplicate keys %s' % (email, user_data[1]))
      return
    
    user = user_data[1]
    user_id = user.get_id()

    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='v', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Send an email to user in order to verify their address. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'
    confirmation_url = verification_url
    sender_address = "cloudleo89@gmail.com"
    subject = "Confirm your registration"
    body = """
Thank you for creating an account! Please confirm your email address by
clicking on the link below:

%s
""" % confirmation_url
    mail.send_mail(sender_address, email, subject, body)
    self.display_message("Check your email address for confirmation " + confirmation_url )

class ForgotPasswordHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    email = self.request.get('email')

    user = self.user_model.get_by_auth_id(email)
    if not user:
      logging.info('Could not find any user entry for email %s', email)
      self._serve_page(not_found=True)
      return

    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='p', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Send an email to user in order to reset their password. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'

    self.display_message(msg.format(url=verification_url))
  
  def _serve_page(self, not_found=False):
    email = self.request.get('email')
    params = {
      'email': email,
      'not_found': not_found
    }
    self.render_template('forgot.html', params)


class VerificationHandler(BaseHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']
    print(self.user_model, signup_token)
    # it should be something more concise like
    # self.auth.get_user_by_token(user_id, signup_token)
    # unfortunately the auth interface does not (yet) allow to manipulate
    # signup tokens concisely
    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token , 'signup')
    
    if not user:
      logging.info('Could not find any user with id "%s" signup token "%s"',
        user_id, signup_token)

      self.abort(404)
    
    # store user data in the session
    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

    if verification_type == 'v':
      # remove signup token, we don't want users to come back with an old link
      self.user_model.delete_signup_token(user.get_id(), signup_token)

      if not user.verified:
        user.verified = True
        user.put()

      self.display_message('User email address has been verified.')
      return
    elif verification_type == 'p':
      # supply user to the page
      params = {
        'user': user,
        'token': signup_token
      }
      self.render_template('resetpassword.html', params)
    else:
      logging.info('verification type not supported')
      self.abort(404)

class SetPasswordHandler(BaseHandler):

  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')

    if not password or password != self.request.get('confirm_password'):
      self.display_message('passwords do not match')
      return

    user = self.user
    user.set_password(password)
    user.put()

    # remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)
    
    self.display_message('Password updated')

class LoginHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    email = self.request.get('email')
    password = self.request.get('password')
    print('STUFF')
    try:
      u = self.auth.get_user_by_password(email, password, remember=True,
        save_session=True)
      self.redirect(self.uri_for('authenticated'))
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for email %s because of %s', email, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    email = self.request.get('email')
    params = {
      'email': email,
      'failed': failed
    }
    self.render_template('login.html', params)

class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('home'))

class AuthenticatedHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('profile.html')

config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['user_name']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}

app = webapp2.WSGIApplication([
  webapp2.Route('/', Mainhandler,  name='home'),
  webapp2.Route('/face', Facehandler),
  webapp2.Route('/101ar', ArHandler),
  webapp2.Route('/home', HomeHandler),
    webapp2.Route('/contacts', ContactsHandler),
    webapp2.Route('/link', LinkHandler),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
      handler=VerificationHandler, name='verification'),
    webapp2.Route('/password', SetPasswordHandler),
    webapp2.Route('/login', LoginHandler, name='login'),
    webapp2.Route('/logout', LogoutHandler, name='logout'),
    webapp2.Route('/forgot', ForgotPasswordHandler, name='forgot'),
    webapp2.Route('/profile', AuthenticatedHandler, name='authenticated')
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)