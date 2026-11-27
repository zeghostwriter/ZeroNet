import json,urllib.parse,base64,ipaddress,glob,collections
r=json.load(open('pipe_results.json'))
CF=[ipaddress.ip_network(n) for n in "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22".split()]
def desc(l):
    s=l.split('://')[0].lower(); q={}
    if s=='vmess':
        b=l[8:].split('#')[0]; j=json.loads(base64.b64decode(b+'='*(-len(b)%4))); h=j.get('add'); net=j.get('net'); sec='tls' if j.get('tls')=='tls' else 'none'; port=j.get('port')
    else:
        u=urllib.parse.urlsplit(l.split('#')[0]); q=dict(urllib.parse.parse_qsl(u.query)); h=u.hostname; net=q.get('type','tcp'); sec=q.get('security','none' if s!='trojan' else 'tls'); port=u.port
    try: cf=any(ipaddress.ip_address(h) in n for n in CF); kind='ip'
    except ValueError: cf=None; kind='domain'
    return s,net,sec,kind,cf,port,h
# which feeds contain each alive link
plain={f.split('/')[1][:-4]:set(x.split('#')[0] for x in open(f).read().splitlines()) for f in glob.glob('plain/*.txt')}
alive=set()
for n,d in r.items():
    for l in d['alive_links']: alive.add(l)
print("unique alive:",len(alive))
for l in sorted(alive):
    k=l.split('#')[0]; srcs=[n for n,s in plain.items() if k in s]
    print(desc(l), 'in', srcs)
