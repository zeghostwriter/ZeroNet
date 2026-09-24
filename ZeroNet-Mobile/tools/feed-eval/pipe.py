import subprocess,random,sys,os,json,time,re,socket,base64,asyncio,urllib.parse,concurrent.futures as cf
os.makedirs('cfg',exist_ok=True); os.makedirs('plain',exist_ok=True)
def decode(t):
    if '://' in t[:3000]: return t
    s=''.join(t.split())
    try: return base64.b64decode(s+'='*(-len(s)%4)).decode('utf-8','ignore')
    except Exception: return t
def hostport(l):
    sch=l.split('://')[0].lower()
    try:
        if sch=='vmess':
            b=l[8:].split('#')[0]; j=json.loads(base64.b64decode(b+'='*(-len(b)%4))); return j['add'],int(j['port'])
        u=urllib.parse.urlsplit(l.split('#')[0]); return u.hostname,u.port
    except Exception: return None
def ok_links(name, Z=None):
    Z=Z or globals().get("Z")
    t=decode(open(name+'.txt',encoding='utf-8',errors='ignore').read())
    lines=[l.strip() for l in t.splitlines() if l.strip() and not l.strip().startswith('#')]
    p=f'plain/{name}.txt'; open(p,'w').write('\n'.join(lines))
    out=subprocess.run([Z,'check',p],capture_output=True,text=True).stdout
    bad={int(m) for m in re.findall(r'^\[(\d+)\] ERROR',out,re.M)}
    good=[l for i,l in enumerate(lines) if i not in bad]
    seen=set(); res=[]
    for l in good:
        k=l.split('#')[0]
        if k not in seen: seen.add(k); res.append(l)
    return len(lines),res
async def tcp(h,p,sem):
    async with sem:
        t=time.perf_counter()
        try:
            r,w=await asyncio.wait_for(asyncio.open_connection(h,p),2.5); w.close(); return time.perf_counter()-t
        except Exception: return None
async def tcp_stage(links):
    sem=asyncio.Semaphore(300); hp=[hostport(l) for l in links]
    rs=await asyncio.gather(*[tcp(h,p,sem) if h and p else asyncio.sleep(0) for h,p in [x or (None,None) for x in hp]])
    return [(l,r) for l,r in zip(links,rs) if r]
def real(args):
    link,port=args; c=f'cfg/{port}.json'
    r=subprocess.run([Z,'preset','iran',link,'--socks-port',str(port),'--http-port','off','--no-assets','--no-ad-block','--anti-sanction','none','--local-dns','cloudflare','-o',c],capture_output=True,text=True)
    if r.returncode: return None
    p=subprocess.Popen([Z,'run',c],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):
            try: socket.create_connection(('127.0.0.1',port),0.1).close(); break
            except OSError: time.sleep(0.1)
        best=None
        for _ in range(2):
            o=subprocess.run(['curl','-s','-o','/dev/null','-x',f'socks5h://127.0.0.1:{port}','-m','6','-w','%{http_code} %{time_total}','https://cp.cloudflare.com/generate_204'],capture_output=True,text=True).stdout.split()
            if o and o[0]=='204': best=min(best or 99,float(o[1]))
            elif _==0: break
        return best
    finally: p.kill(); p.wait()
if __name__=='__main__':
  Z=sys.argv[1]; CAP=int(sys.argv[2]); REAL=int(sys.argv[3]); feeds=sys.argv[4:]
  port=30000; out={}
  for name in feeds:
      total,links=ok_links(name); random.seed(11); s=random.sample(links,min(CAP,len(links)))
      t0=time.time(); open_=asyncio.run(tcp_stage(s)); open_.sort(key=lambda x:x[1])
      random.seed(5); cand=random.sample([l for l,_ in open_],min(REAL,len(open_))); jobs=[(l,port+i) for i,l in enumerate(cand)]; port+=len(cand)+1
      with cf.ThreadPoolExecutor(20) as ex: rs=list(ex.map(real,jobs))
      alive=sorted(r for r in rs if r)
      out[name]=dict(total=total,parsed_unique=len(links),sampled=len(s),tcp_open=len(open_),real_tested=len(cand),alive=len(alive),alive_links=[l for l,r in zip(cand,rs) if r],rtts=alive)
      med=alive[len(alive)//2] if alive else None
      print(f"{name:11} lines={total:6} zray_ok_uniq={len(links):6} sampled={len(s):5} tcp_open={len(open_):5} ({100*len(open_)//max(1,len(s))}%) real={len(cand):3} alive={len(alive):3} median={med and round(med,2)} t={int(time.time()-t0)}s",flush=True)
      json.dump(out,open('pipe_results.json','w'))
