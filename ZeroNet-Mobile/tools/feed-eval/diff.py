import sys,json,subprocess,socket,time,random,asyncio,concurrent.futures as cf
sys.path.insert(0,'.'); from xconv import config
from pipe import hostport, tcp_stage
Z,X,N=sys.argv[1],sys.argv[2],int(sys.argv[3]); names=sys.argv[4:]
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
    try: c=config(link,port)
    except Exception as e: return 'conv'
    f=f'cfg/x{port}.json'; json.dump(c,open(f,'w'))
    p=subprocess.Popen([X,'run','-c',f],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try: wait(port); return probe(port)
    finally: p.kill(); p.wait()
def run_z(link,port):
    f=f'cfg/z{port}.json'
    if subprocess.run([Z,'preset','iran',link,'--socks-port',str(port),'--http-port','off','--no-assets','--no-ad-block','--anti-sanction','none','--local-dns','cloudflare','-o',f],capture_output=True).returncode: return 'preset'
    p=subprocess.Popen([Z,'run',f],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try: wait(port); return probe(port)
    finally: p.kill(); p.wait()
def both(a):
    l,port=a; return l,run_x(l,port),run_z(l,port+1)
port=40000; allres={}
for n in names:
    links=[l for l in open(f'plain/{n}.txt').read().splitlines() if l]
    random.seed(3); s=random.sample(links,min(600,len(links)))
    op=asyncio.run(tcp_stage(s)); op.sort(key=lambda x:x[1]); cand=[l for l,_ in op[:N]]
    jobs=[(l,port+2*i) for i,l in enumerate(cand)]; port+=2*len(cand)+2
    with cf.ThreadPoolExecutor(16) as ex: rs=list(ex.map(both,jobs))
    xa=sum(1 for _,x,_ in rs if isinstance(x,float)); za=sum(1 for _,_,z in rs if isinstance(z,float))
    xonly=[(l,x,z) for l,x,z in rs if isinstance(x,float) and not isinstance(z,float)]
    print(f"{n:11} tested={len(rs)} xray_alive={xa} zray_alive={za} xray_only={len(xonly)}",flush=True)
    allres[n]=rs
json.dump(allres,open('diff_results.json','w'))
