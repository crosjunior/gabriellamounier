import os,json,sqlite3,secrets,hashlib,hmac,base64,smtplib,ssl,time,re,html
from pathlib import Path
from email.message import EmailMessage
from urllib.parse import parse_qs,urlsplit
from http.cookies import SimpleCookie
from wsgiref.simple_server import make_server,WSGIRequestHandler
BASE=Path(__file__).resolve().parent
SECRET=os.environ.get('SECRET_KEY','')
if len(SECRET)<32:raise RuntimeError('Defina SECRET_KEY com pelo menos 32 caracteres aleatórios.')
PUBLIC_URL=os.environ.get('PUBLIC_URL','http://127.0.0.1:5000').rstrip('/')
DEV=os.environ.get('APP_ENV','production')=='development'
if not DEV and not PUBLIC_URL.startswith('https://'):raise RuntimeError('PUBLIC_URL deve usar HTTPS em produção.')
STATE=Path(os.environ.get('DATA_DIR',str(BASE/'instance')));STATE.mkdir(parents=True,exist_ok=True);DB=STATE/'academy.sqlite3'
LESSONS={x['id']:x for x in json.loads((BASE/'private'/'lessons.json').read_text())}
COURSES=json.loads((BASE/'private'/'courses.json').read_text());COURSE_IDS={x['id'] for x in COURSES}
with sqlite3.connect(DB) as db:
 db.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,created INTEGER NOT NULL,confirmed INTEGER,privacy_version TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens(digest TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires INTEGER NOT NULL,course TEXT NOT NULL,used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS attempts(key TEXT NOT NULL,created INTEGER NOT NULL);CREATE INDEX IF NOT EXISTS attempts_idx ON attempts(key,created);''')
def database():
 db=sqlite3.connect(DB);db.row_factory=sqlite3.Row;return db
def b64(raw):return base64.urlsafe_b64encode(raw).decode().rstrip('=')
def sign(value):return hmac.new(SECRET.encode(),value.encode(),hashlib.sha256).hexdigest()
def read_session(environ):
 try:
  cookies=SimpleCookie();cookies.load(environ.get('HTTP_COOKIE',''));value=cookies['gl_session'].value;body,sig=value.rsplit('.',1)
  if not hmac.compare_digest(sign(body),sig):raise ValueError()
  data=json.loads(base64.urlsafe_b64decode(body+'='*(-len(body)%4)))
  if not 0<=time.time()-data['created']<604800:raise ValueError()
  return data
 except Exception:return {'created':int(time.time()),'csrf':secrets.token_urlsafe(32)}
def cookie(session):
 body=b64(json.dumps(session,separators=(',',':')).encode());c=SimpleCookie();c['gl_session']=body+'.'+sign(body);m=c['gl_session'];m['httponly']=True;m['samesite']='Lax';m['path']='/';m['max-age']=604800
 if not DEV:m['secure']=True
 return m.OutputString()
def csrf_ok(environ,fields,session):
 received=fields.get('csrf','') or environ.get('HTTP_X_CSRF_TOKEN','');origin=environ.get('HTTP_ORIGIN')
 if origin and origin!='null':
  a=urlsplit(origin);b=urlsplit(PUBLIC_URL)
  if (a.scheme,a.netloc)!=(b.scheme,b.netloc):return False
 return bool(received and hmac.compare_digest(received,session.get('csrf','')))
def ready():return bool(os.environ.get('SMTP_HOST') and os.environ.get('SMTP_FROM') and os.environ.get('PRIVACY_APPROVED')=='1')
def current_user(session):
 uid=session.get('uid')
 if not uid:return None
 with database() as db:return db.execute('SELECT id,name FROM users WHERE id=? AND confirmed IS NOT NULL',(uid,)).fetchone()
def send_mail(address,link):
 m=EmailMessage();m['Subject']='Confirme seu acesso gratuito à Academia GL';m['From']=os.environ['SMTP_FROM'];m['To']=address
 m.set_content('Olá!\n\nVocê solicitou acesso gratuito à Academia GL. Abra o link abaixo e confirme seu acesso na página. O link expira em 30 minutos:\n\n'+link+'\n\nSe não solicitou, ignore este e-mail. Nenhuma inscrição promocional foi realizada.')
 host=os.environ['SMTP_HOST'];port=int(os.environ.get('SMTP_PORT','587'))
 if os.environ.get('SMTP_SSL')=='1':conn=smtplib.SMTP_SSL(host,port,context=ssl.create_default_context(),timeout=20)
 else:conn=smtplib.SMTP(host,port,timeout=20);conn.ehlo();conn.starttls(context=ssl.create_default_context());conn.ehlo()
 with conn:
  if os.environ.get('SMTP_USER'):conn.login(os.environ['SMTP_USER'],os.environ['SMTP_PASSWORD'])
  conn.send_message(m)
def confirm_page(active,csrf):
 title='Seu próximo passo é aprender.' if active else 'Este link expirou ou já foi usado.'
 action=('<form method="post"><input type="hidden" name="csrf" value="'+html.escape(csrf,quote=True)+'"><button>Confirmar meu acesso gratuito →</button></form>') if active else '<a href="/academia.html#cadastro">Solicitar um novo link</a>'
 return ('<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Confirmar acesso | Academia GL</title><style>body{background:#120d26;color:white;font:16px/1.8 Arial;padding:60px 25px}main{max-width:530px;margin:50px auto}button,a{background:#ff6b00;color:#130c20;border:0;border-radius:10px;padding:15px 25px;display:inline-block;font:inherit;text-decoration:none}h1{line-height:1.15}</style></head><body><main><p>ACADEMIA GL · ACESSO GRATUITO</p><h1>'+title+'</h1><p>Confirme seu endereço para abrir as aulas. Nenhuma senha é necessária.</p>'+action+'</main></body></html>').encode()
def application(environ,start_response):
 session=read_session(environ);path=environ.get('PATH_INFO','/');method=environ.get('REQUEST_METHOD','GET')
 def respond(status,body,kind='application/json; charset=utf-8',extra=None):
  if isinstance(body,dict):body=json.dumps(body,ensure_ascii=False).encode()
  if isinstance(body,str):body=body.encode()
  hs=[('Content-Type',kind),('Content-Length',str(len(body))),('Set-Cookie',cookie(session)),('Cache-Control','no-store'),('Referrer-Policy','no-referrer'),('X-Content-Type-Options','nosniff'),('X-Frame-Options','DENY')]
  if not DEV:hs.append(('Strict-Transport-Security','max-age=31536000'))
  if extra:hs.extend(extra)
  start_response(status,hs);return [body]
 try:
  length=int(environ.get('CONTENT_LENGTH') or 0)
  if length<0 or length>8192:return respond('413 Payload Too Large',{'error':'Solicitação muito grande.'})
  if method=='POST' and length and not environ.get('CONTENT_TYPE','').startswith('application/x-www-form-urlencoded'):return respond('415 Unsupported Media Type',{'error':'Formato de solicitação inválido.'})
  fields={k:v[0] for k,v in parse_qs(environ['wsgi.input'].read(length).decode('utf-8'),max_num_fields=20).items()} if method=='POST' and length else {}
  if method=='GET' and path in ('/','/index.html','/academia.html'):
   return respond('200 OK',(BASE/'public'/('academia.html' if path=='/academia.html' else 'index.html')).read_bytes(),'text/html; charset=utf-8')
  if method=='GET' and path=='/api/session':
   u=current_user(session);return respond('200 OK',{'authenticated':bool(u),'name':u['name'] if u else None,'csrf':session['csrf'],'ready':ready()})
  if method=='GET' and path.startswith('/api/lesson/'):
   if not current_user(session):return respond('401 Unauthorized',{'error':'Confirme seu e-mail para acessar as aulas gratuitas.'})
   lesson=LESSONS.get(path.rsplit('/',1)[-1]);return respond('200 OK',lesson) if lesson else respond('404 Not Found',{'error':'Aula não encontrada.'})
  if method=='POST' and path=='/cadastro':
   if not csrf_ok(environ,fields,session):return respond('403 Forbidden',{'error':'Sessão expirada. Atualize a página e tente novamente.'})
   if not ready():return respond('503 Service Unavailable',{'error':'Cadastro ainda não ativado pelo responsável.'})
   name=fields.get('name','').strip();email=fields.get('email','').strip().lower();course=fields.get('course','primeiros-passos')
   if not 2<=len(name)<=80 or any(ord(c)<32 for c in name):return respond('400 Bad Request',{'error':'Informe um nome entre 2 e 80 caracteres.'})
   if len(email)>254 or not re.fullmatch(r'[^\s@<>\r\n]+@[^\s@<>\r\n]+\.[^\s@<>\r\n]+',email):return respond('400 Bad Request',{'error':'Informe um e-mail válido.'})
   if fields.get('privacy')!='yes':return respond('400 Bad Request',{'error':'Solicite o uso dos dados para criar o acesso.'})
   if course not in COURSE_IDS:course='primeiros-passos'
   now=int(time.time());keys=[('ip:'+environ.get('REMOTE_ADDR','unknown'),5),('email:'+email,3)]
   with database() as db:
    db.execute('BEGIN IMMEDIATE');db.execute('DELETE FROM attempts WHERE created<?',(now-900,));db.execute('DELETE FROM tokens WHERE expires<?',(now-86400,))
    for key,limit in keys:
     if db.execute('SELECT count(*) FROM attempts WHERE key=? AND created>?',(sign(key),now-900)).fetchone()[0]>=limit:return respond('429 Too Many Requests',{'error':'Aguarde alguns minutos antes de solicitar outro link.'})
    for key,limit in keys:db.execute('INSERT INTO attempts VALUES(?,?)',(sign(key),now))
    row=db.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()
    uid=row['id'] if row else db.execute('INSERT INTO users(name,email,created,privacy_version) VALUES(?,?,?,?)',(name,email,now,'v1-approved-by-operator')).lastrowid
    token=secrets.token_urlsafe(40);digest=hashlib.sha256(token.encode()).hexdigest();db.execute('INSERT INTO tokens(digest,user_id,expires,course) VALUES(?,?,?,?)',(digest,uid,now+1800,course))
   try:send_mail(email,PUBLIC_URL+'/confirmar/'+token)
   except Exception:
    with database() as db:db.execute('DELETE FROM tokens WHERE digest=?',(digest,))
    return respond('502 Bad Gateway',{'error':'Não foi possível enviar o e-mail. Tente mais tarde ou avise o responsável.'})
   return respond('200 OK',{'message':'Solicitação recebida. Confira seu e-mail e a pasta de spam. O link expira em 30 minutos.'})
  if path.startswith('/confirmar/') and method in ('GET','POST'):
   digest=hashlib.sha256(path.rsplit('/',1)[-1].encode()).hexdigest();now=int(time.time())
   with database() as db:
    if method=='POST':db.execute('BEGIN IMMEDIATE')
    row=db.execute('SELECT * FROM tokens WHERE digest=? AND used=0 AND expires>?',(digest,now)).fetchone()
    if not row:return respond('400 Bad Request',confirm_page(False,session['csrf']),'text/html; charset=utf-8')
    if method=='GET':return respond('200 OK',confirm_page(True,session['csrf']),'text/html; charset=utf-8')
    if not csrf_ok(environ,fields,session):return respond('403 Forbidden',{'error':'Sessão inválida. Atualize a página.'})
    db.execute('UPDATE tokens SET used=1 WHERE digest=?',(digest,));db.execute('UPDATE users SET confirmed=COALESCE(confirmed,?) WHERE id=?',(now,row['user_id']));uid=row['user_id'];course=row['course']
   session.clear();session.update(uid=uid,created=now,csrf=secrets.token_urlsafe(32));return respond('303 See Other','',extra=[('Location','/academia.html?curso='+course+'#minhas-aulas')])
  if method=='POST' and path=='/sair':
   if not csrf_ok(environ,fields,session):return respond('403 Forbidden',{'error':'Sessão inválida.'})
   session.clear();session.update(created=int(time.time()),csrf=secrets.token_urlsafe(32));return respond('200 OK',{'ok':True})
  return respond('404 Not Found',{'error':'Página não encontrada.'})
 except Exception:return respond('500 Internal Server Error',{'error':'Não foi possível concluir a solicitação. Avise o responsável.'})
class SafeHandler(WSGIRequestHandler):
 def log_message(self,format,*args):
  if '/confirmar/' not in self.path:super().log_message(format,*args)
if __name__=='__main__':
 port=int(os.environ.get('PORT','5000'));print('Academia GL (desenvolvimento): '+PUBLIC_URL)
 with make_server('127.0.0.1',port,application,handler_class=SafeHandler) as httpd:httpd.serve_forever()
