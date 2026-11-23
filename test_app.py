import os,io,json,tempfile,unittest,time
from urllib.parse import urlencode,urlsplit
from http.cookies import SimpleCookie
os.environ.update(SECRET_KEY='test-only-not-for-production-01234567890123456789',APP_ENV='development',PUBLIC_URL='http://127.0.0.1:5000',DATA_DIR=tempfile.mkdtemp(prefix='gl-tests-'),SMTP_HOST='mock.invalid',SMTP_FROM='academia@example.invalid',PRIVACY_APPROVED='1')
import app
class Client:
 def __init__(self):self.cookie=''
 def request(self,path,method='GET',data=None,headers=None):
  raw=urlencode(data or {}).encode();env={'PATH_INFO':urlsplit(path).path,'REQUEST_METHOD':method,'wsgi.input':io.BytesIO(raw),'CONTENT_LENGTH':str(len(raw)),'CONTENT_TYPE':'application/x-www-form-urlencoded','HTTP_COOKIE':self.cookie,'REMOTE_ADDR':'127.0.0.1'}
  if headers:env.update(headers)
  r={}
  def start(status,hs):r.update(status=int(status.split()[0]),headers=dict(hs))
  r['body']=b''.join(app.application(env,start));c=SimpleCookie();c.load(r['headers']['Set-Cookie']);self.cookie='gl_session='+c['gl_session'].value
  try:r['json']=json.loads(r['body'])
  except ValueError:pass
  return r
 def session(self):return self.request('/api/session')['json']
class Tests(unittest.TestCase):
 def setUp(self):
  self.c=Client();self.mail=[];app.send_mail=lambda a,l:self.mail.append((a,l))
  with app.database() as db:db.executescript('DELETE FROM tokens;DELETE FROM users;DELETE FROM attempts;')
  os.environ['PRIVACY_APPROVED']='1'
 def signup(self):return self.c.request('/cadastro','POST',{'name':'Pessoa Teste','email':'teste@example.invalid','privacy':'yes','course':'renda-fixa','csrf':self.c.session()['csrf']})
 def test_full_flow(self):
  self.assertEqual(self.c.request('/api/lesson/renda-fixa-1')['status'],401)
  self.assertEqual(self.signup()['status'],200);link=self.mail[0][1]
  self.assertEqual(self.c.request(link)['status'],200)
  self.assertEqual(self.c.request('/api/lesson/renda-fixa-1')['status'],401)
  self.assertEqual(self.c.request(link,'POST',{'csrf':self.c.session()['csrf']})['status'],303)
  self.assertEqual(self.c.request('/api/lesson/renda-fixa-1')['status'],200)
  self.assertEqual(self.c.request(link)['status'],400)
  self.assertEqual(self.c.request('/sair','POST',headers={'HTTP_X_CSRF_TOKEN':self.c.session()['csrf']})['status'],200)
  self.assertEqual(self.c.request('/api/lesson/renda-fixa-1')['status'],401)
 def test_private_files_blocked(self):
  for p in ['/private/lessons.json','/instance/academy.sqlite3','/.env','/app.py']:self.assertEqual(self.c.request(p)['status'],404)
 def test_csrf_origin(self):
  self.assertEqual(self.c.request('/cadastro','POST',{'name':'x'})['status'],403)
  self.assertEqual(self.c.request('/cadastro','POST',{'csrf':self.c.session()['csrf']},headers={'HTTP_ORIGIN':'https://evil.invalid'})['status'],403)
 def test_null_origin(self):
  self.signup();link=self.mail[0][1];self.assertEqual(self.c.request(link,'POST',{'csrf':self.c.session()['csrf']},headers={'HTTP_ORIGIN':'null'})['status'],303)
 def test_expired(self):
  self.signup();link=self.mail[0][1]
  with app.database() as db:db.execute('UPDATE tokens SET expires=?',(int(time.time())-1,))
  self.assertEqual(self.c.request(link)['status'],400)
 def test_smtp_failure(self):
  def fail(*a):raise RuntimeError('mock')
  app.send_mail=fail;self.assertEqual(self.signup()['status'],502)
  with app.database() as db:self.assertEqual(db.execute('SELECT count(*) FROM tokens').fetchone()[0],0)
 def test_rate_limit(self):
  for i in range(3):self.assertEqual(self.signup()['status'],200)
  self.assertEqual(self.signup()['status'],429)
 def test_disabled(self):
  os.environ['PRIVACY_APPROVED']='0';self.assertFalse(self.c.session()['ready']);self.assertEqual(self.signup()['status'],503)
 def test_tamper(self):
  self.signup();link=self.mail[0][1];self.c.request(link,'POST',{'csrf':self.c.session()['csrf']});self.c.cookie+='x';self.assertFalse(self.c.session()['authenticated'])
if __name__=='__main__':unittest.main()
