import json,subprocess,socket,time,sys
sys.path.insert(0,'.')
from xconv import config
Z=None;X=None
def wait(port):
    for _ in range(40):
        try: socket.create_connection(('127.0.0.1',port),0.1).close(); return
        except OSError: time.sleep(0.1)
def probe(port):
    best=None
    for _ in range(2):
        o=subprocess.run(['curl','-s','-o','/dev/null','-x',f'socks5h://127.0.0.1:{port}','-m','8','-w','%{http_code} %{time_total}','https://cp.cloudflare.com/generate_204'],capture_output=True,text=True).stdout.split()
        if o and o[0]=='204': best=min(best or 99,float(o[1]))
    return best
def run_x(link,port):
    X=globals()["X"]
    try: c=config(link,port)
    except Exception as e: return 'conv'
    f=f'cfg/x{port}.json'; json.dump(c,open(f,'w'))
    p=subprocess.Popen([X,'run','-c',f],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try: wait(port); return probe(port)
    finally: p.kill(); p.wait()
def run_z(link,port):
    Z=globals()["Z"]
    f=f'cfg/z{port}.json'
    if subprocess.run([Z,'preset','iran',link,'--socks-port',str(port),'--http-port','off','--no-assets','--no-ad-block','--anti-sanction','none','--local-dns','cloudflare','-o',f],capture_output=True).returncode: return 'preset'
    p=subprocess.Popen([Z,'run',f],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try: wait(port); return probe(port)
    finally: p.kill(); p.wait()
def both(a):
    l,port=a; return l,run_x(l,port),run_z(l,port+1)
