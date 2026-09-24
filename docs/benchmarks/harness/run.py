import subprocess, time, json, os, statistics, sys
ZRAY=os.environ.get('ZRAY','../../../target/release/zray'); XRAY=os.environ.get('XRAY','./xray')
LG='./loadgen/target/release/loadgen'
TCK=os.sysconf('SC_CLK_TCK')
def cpu(pid):
    f=open(f'/proc/{pid}/stat').read().rsplit(')',1)[1].split()
    return (int(f[11])+int(f[12]))/TCK
def mem(pid,key):
    for l in open(f'/proc/{pid}/status'):
        if l.startswith(key): return int(l.split()[1])/1024
def start(core,cfg):
    cmd=[XRAY,'run','-c',cfg] if core=='xray' else [ZRAY,'run',cfg]
    p=subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(1.5); return p
srv=subprocess.Popen([XRAY,'run','-c','server.json'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
sink=subprocess.Popen([LG,'sink','30000'])
time.sleep(1.5)
GB=2*10**9
tests=[('download 1 stream','down',1,GB),('download 8 streams','down',8,GB),('upload 1 stream','up',1,GB),('download 64 streams','down',64,GB)]
res={}
for mode in ['tls','plain']:
  for core in ['xray','zray']:
    runs={}
    for rep in range(3):
        p=start(core,f'client-{mode}.json')
        idle=mem(p.pid,'VmRSS')
        for name,d,st,b in tests:
            c0=cpu(p.pid); t0=time.time()
            out=subprocess.run([LG,'run','10808','30000',str(b),str(st),d],capture_output=True,text=True,timeout=300)
            c1=cpu(p.pid)
            if out.returncode: print(core,mode,name,'FAILED',out.stderr[-300:]); continue
            runs.setdefault(name,[]).append((float(out.stdout),(c1-c0)/(b/1e9)))
        runs.setdefault('_idle',[]).append(idle); runs.setdefault('_peak',[]).append(mem(p.pid,'VmHWM'))
        p.terminate(); p.wait()
    r={'idle_rss_mb':statistics.median(runs.pop('_idle')),'peak_rss_mb':statistics.median(runs.pop('_peak'))}
    for k,v in runs.items():
        r[k]={'MBps':statistics.median(x[0] for x in v),'cpu_s_per_GB':statistics.median(x[1] for x in v)}
    res[f'{mode}/{core}']=r
    print(mode,core,json.dumps(r),flush=True)
srv.terminate(); sink.terminate()
json.dump(res,open('results.json','w'),indent=1)
