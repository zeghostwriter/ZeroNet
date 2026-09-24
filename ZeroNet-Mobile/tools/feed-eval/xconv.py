import json,base64,urllib.parse
def b64(s): s=s.strip(); return base64.b64decode(s+'='*(-len(s)%4)).decode('utf-8','ignore') if '-' not in s and '_' not in s else base64.urlsafe_b64decode(s+'='*(-len(s)%4)).decode('utf-8','ignore')
def stream(net,sec,q):
    net=(net or 'tcp').lower(); st={'network':{'h2':'http'}.get(net,net),'security':sec or 'none'}
    host=q.get('host',''); path=urllib.parse.unquote(q.get('path','/') or '/')
    if net=='ws': st['wsSettings']={'path':path,'headers':{'Host':host} if host else {}}
    elif net=='grpc': st['grpcSettings']={'serviceName':urllib.parse.unquote(q.get('serviceName','')),'multiMode':q.get('mode')=='multi'}
    elif net=='httpupgrade': st['httpupgradeSettings']={'path':path,'host':host}
    elif net=='xhttp':
        x={'path':path,'host':host,'mode':q.get('mode','auto')}
        if q.get('extra'):
            try: x['extra']=json.loads(urllib.parse.unquote(q['extra']))
            except Exception: pass
        st['xhttpSettings']=x
    elif net=='tcp' and q.get('headerType')=='http':
        st['tcpSettings']={'header':{'type':'http','request':{'path':[path],'headers':{'Host':[host]} if host else {}}}}
    sni=q.get('sni') or q.get('peer') or host; fp=q.get('fp') or 'chrome'
    alpn=[a for a in urllib.parse.unquote(q.get('alpn','')).split(',') if a]
    if sec=='tls': st['tlsSettings']={'serverName':sni,'fingerprint':fp,**({'alpn':alpn} if alpn else {}),'allowInsecure':q.get('allowInsecure') in ('1','true') or q.get('insecure') in ('1','true')}
    if sec=='reality': st['realitySettings']={'serverName':sni,'fingerprint':fp,'publicKey':q.get('pbk',''),'shortId':q.get('sid',''),'spiderX':urllib.parse.unquote(q.get('spx',''))}
    return st
def outbound(link):
    sch,rest=link.split('://',1); sch=sch.lower(); rest=rest.split('#')[0]
    if sch=='vmess':
        j=json.loads(b64(rest)); q={'host':j.get('host',''),'path':j.get('path',''),'sni':j.get('sni',''),'fp':j.get('fp',''),'alpn':j.get('alpn',''),'serviceName':j.get('path',''),'headerType':j.get('type','')}
        sec='tls' if j.get('tls')=='tls' else 'none'
        return {'protocol':'vmess','settings':{'vnext':[{'address':j['add'],'port':int(j['port']),'users':[{'id':j['id'],'alterId':int(j.get('aid') or 0),'security':j.get('scy') or 'auto'}]}]},'streamSettings':stream(j.get('net'),sec,q)}
    u=urllib.parse.urlsplit(sch+'://'+rest); q=dict(urllib.parse.parse_qsl(u.query)); host,port=u.hostname,u.port
    if sch=='vless':
        return {'protocol':'vless','settings':{'vnext':[{'address':host,'port':port,'users':[{'id':urllib.parse.unquote(u.username),'encryption':q.get('encryption','none'),'flow':q.get('flow','')}]}]},'streamSettings':stream(q.get('type'),q.get('security','none'),q)}
    if sch=='trojan':
        return {'protocol':'trojan','settings':{'servers':[{'address':host,'port':port,'password':urllib.parse.unquote(u.username)}]},'streamSettings':stream(q.get('type'),q.get('security','tls'),q)}
    if sch=='ss':
        ui=urllib.parse.unquote(u.username or '')
        if u.password is not None: m,p=ui,urllib.parse.unquote(u.password)
        else: m,p=b64(ui).split(':',1)
        return {'protocol':'shadowsocks','settings':{'servers':[{'address':host,'port':port,'method':m,'password':p}]}}
    raise ValueError(sch)
def config(link,port):
    o=outbound(link); o['tag']='proxy'
    return {'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':False}}],'outbounds':[o]}
