import json,glob,collections,random,asyncio,sys,concurrent.futures as cf
import pipe
from pipe import hostport,tcp_stage
pipe.Z=sys.argv[1]
cnt=collections.Counter(); link_by={}
for f in glob.glob('plain/*.txt'):
    if 'barryfar' in f: continue
    seen=set()
    for l in open(f).read().splitlines():
        hp=hostport(l)
        if not hp or not hp[0] or not hp[1]: continue
        if hp not in seen: seen.add(hp); cnt[hp]+=1
        link_by.setdefault(hp,l)
res={}
port=50000
for name,pred in (('1 feed',lambda c:c==1),('>=5 feeds',lambda c:c>=5)):
    pool=[hp for hp,c in cnt.items() if pred(c)]; random.seed(21); random.shuffle(pool)
    links=[link_by[hp] for hp in pool[:1500]]
    op=asyncio.run(tcp_stage(links)); random.seed(4); cand=random.sample([l for l,_ in op],min(120,len(op)))
    jobs=[(l,port+i) for i,l in enumerate(cand)]; port+=len(cand)+1
    with cf.ThreadPoolExecutor(20) as ex: rs=list(ex.map(pipe.real,jobs))
    a=sum(1 for x in rs if x); print(f"{name:10} servers={len(pool)} tcp_open={len(op)}/1500 real={len(cand)} alive={a}",flush=True)
