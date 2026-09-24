import json,sys,random,asyncio,subprocess,socket,time,base64,urllib.parse,concurrent.futures as cf
sys.path.insert(0,'.')
from xconv import config
from pipe import tcp_stage
X=sys.argv[1]; N=int(sys.argv[2])
R=json.load(open('rejected.json'))
def ssm(l):
    ui=urllib.parse.unquote(l[5:].split('@')[0]).replace('-','+').replace('_','/')
    try: return base64.b64decode(ui+'='*(-len(ui)%4)).decode('utf-8','replace').split(':')[0]
    except Exception: return ''
def vm(l):
    b=l[8:].split('#')[0]
    try: return json.loads(base64.b64decode(b+'='*(-len(b)%4)))
    except Exception: return {}
CATS={
 'vmess_type_nonhttp': lambda l,e:'header type' in e and str(vm(l).get('type')).lower()!='http',
 'vmess_type_http_tcp': lambda l,e:'header type "http"' in e,
 'vmess_alterid': lambda l,e:'alterId' in e,
 'ss2022_chacha': lambda l,e:l.startswith('ss://') and ('2022-blake3-chacha20' in e or ssm(l)=='2022-blake3-chacha20-poly1305'),
 'reality_grpc': lambda l,e:'REALITY is not supported over grpc' in e,
 'non_uuid_id': lambda l,e:'invalid UUID' in e,
 'reality_empty_fp': lambda l,e:'Unshaped has no X25519' in e,
 'tls_fp_unsafe': lambda l,e:'unknown fingerprint "unsafe"' in e,
 'vless_mlkem': lambda l,e:'VLESS encryption' in e and 'mlkem768' in e,
 'transport_case': lambda l,e:'unsupported transport type' in e and any(t in e for t in ('"Tcp"','"TCP"','"Ws"','"WS"','"Grpc"','"GRPC"')),
 'vision_xhttp': lambda l,e:'needs a direct stream' in e,
}
def wait(p):
    for _ in range(40):
        try: socket.create_connection(('127.0.0.1',p),0.1).close(); return
        except OSError: time.sleep(0.1)
def xtest(a):
    l,port=a
    try: c=config(l,port)
    except Exception as ex: return 'conv'
    f=f'cfg/c{port}.json'; json.dump(c,open(f,'w'))
    if subprocess.run([X,'run','-test','-c',f],capture_output=True).returncode: return 'xray_rejects'
    p=subprocess.Popen([X,'run','-c',f],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        wait(port)
        o=subprocess.run(['curl','-s','-o','/dev/null','-x',f'socks5h://127.0.0.1:{port}','-m','7','-w','%{http_code} %{time_total}','https://cp.cloudflare.com/generate_204'],capture_output=True,text=True).stdout.split()
        return float(o[1]) if o and o[0]=='204' else 'dead'
    finally: p.kill(); p.wait()
out={}; port=52000
for name,pred in CATS.items():
    links=[l for l,e,k in R if pred(l,e)]
    random.seed(9); random.shuffle(links); links=links[:800]
    op=asyncio.run(tcp_stage(links)); cand=[l for l,_ in op][:N]
    jobs=[(l,port+i) for i,l in enumerate(cand)]; port+=len(cand)+1
    with cf.ThreadPoolExecutor(20) as ex: rs=list(ex.map(xtest,jobs))
    alive=[(l,r) for l,r in zip(cand,rs) if isinstance(r,float)]
    rej=sum(1 for r in rs if r=='xray_rejects'); conv=sum(1 for r in rs if r=='conv')
    print(f"{name:20} total={sum(1 for l,e,k in R if pred(l,e)):5} tcp_open={len(op)} xray_tested={len(cand)} xray_rejects={rej} conv_err={conv} XRAY_ALIVE={len(alive)}",flush=True)
    out[name]=dict(alive=alive,xray_rejects=[l for l,r in zip(cand,rs) if r=='xray_rejects'][:3])
json.dump(out,open('catx_results.json','w'))
