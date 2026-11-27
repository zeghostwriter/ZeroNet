import json,sys,random,asyncio,glob,urllib.parse,base64,collections,concurrent.futures as cf
sys.path.insert(0,'.')
import pipe, diff_core
from pipe import tcp_stage
Z,X,N=sys.argv[1],sys.argv[2],int(sys.argv[3]); pipe.Z=Z; diff_core.Z=Z; diff_core.X=X
rej={l.split('#')[0] for l,e,k in json.load(open('rejected.json'))}
def cls(l):
    s=l.split('://')[0].lower()
    if s=='vmess':
        b=l[8:].split('#')[0]
        try: j=json.loads(base64.b64decode(b+'='*(-len(b)%4)))
        except Exception: return None
        return f"vmess/{str(j.get('net','tcp')).lower()}/{'tls' if j.get('tls')=='tls' else 'none'}"
    if s not in ('vless','trojan','ss'): return None
    q=dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(l.split('#')[0]).query))
    t=q.get('type','tcp').lower(); sec=q.get('security','tls' if s=='trojan' else 'none').lower()
    if s=='ss': return 'ss'
    ex='+extra' if t=='xhttp' and 'extra' in q else ''
    fl='+vision' if q.get('flow')=='xtls-rprx-vision' else ''
    return f"{s}/{t}{ex}/{sec}{fl}"
pool=collections.defaultdict(set)
for f in glob.glob('plain/*.txt'):
    for l in open(f).read().splitlines():
        if not l or l.split('#')[0] in rej: continue
        c=cls(l)
        if c: pool[c].add(l)
classes=[c for c,v in sorted(pool.items(),key=lambda x:-len(x[1])) if len(v)>=40]
print('classes:',[(c,len(pool[c])) for c in classes],flush=True)
port=56000; out={}
for c in classes:
    links=list(pool[c]); random.seed(13); random.shuffle(links); links=links[:900]
    op=asyncio.run(tcp_stage(links)); cand=[l for l,_ in op][:N]
    jobs=[(l,port+2*i) for i,l in enumerate(cand)]; port+=2*len(cand)+2
    with cf.ThreadPoolExecutor(24) as ex: xr=list(ex.map(lambda a:diff_core.run_x(*a),jobs))
    xal=[(l,p) for (l,p),x in zip(jobs,xr) if isinstance(x,float)]
    def zz(a):
        for _ in range(3):
            z=diff_core.run_z(a[0],a[1]+1)
            if isinstance(z,float): return z
        return z
    with cf.ThreadPoolExecutor(12) as ex: zr=dict(zip([l for l,_ in xal],ex.map(zz,xal)))
    rs=[(l,x,zr.get(l)) for (l,_),x in zip(jobs,xr)]
    xa=[r for r in rs if isinstance(r[1],float)]; za=[r for r in rs if isinstance(r[2],float)]
    xo=[r for r in rs if isinstance(r[1],float) and not isinstance(r[2],float)]
    zo=[r for r in rs if isinstance(r[2],float) and not isinstance(r[1],float)]
    print(f"{c:32} tested={len(rs):3} xray={len(xa):2} zray={len(za):2} XRAY_ONLY={len(xo)} zray_only={len(zo)}",flush=True)
    out[c]=dict(xray_only=xo,zray_only=zo,both=[r for r in rs if isinstance(r[1],float) and isinstance(r[2],float)])
    json.dump(out,open('sdiff_results.json','w'))
