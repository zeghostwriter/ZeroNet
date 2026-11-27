import json, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager
r=json.load(open('results.json'))
GOLD='#FBBF24'; GREY='#6B7280'; BG='#0D0F12'; FG='#E5E7EB'
plt.rcParams.update({'figure.facecolor':BG,'axes.facecolor':BG,'axes.edgecolor':'#374151','text.color':FG,
  'axes.labelcolor':FG,'xtick.color':FG,'ytick.color':FG,'font.size':12})
def bars(ax,labels,x,z,title,unit,better):
    import numpy as np
    i=np.arange(len(labels)); w=0.38
    b1=ax.bar(i-w/2,x,w,color=GREY,label='Xray-core'); b2=ax.bar(i+w/2,z,w,color=GOLD,label='Zray-core')
    for b,v in list(zip(b1,x))+list(zip(b2,z)):
        ax.text(b.get_x()+b.get_width()/2,b.get_height(),f'{v:,.0f}' if v>=5 else f'{v:.2f}',ha='center',va='bottom',fontsize=10,color=FG)
    ax.set_xticks(i); ax.set_xticklabels(labels); ax.set_title(title,fontsize=14,color=FG,pad=12)
    ax.set_ylabel(f'{unit}  ({better})'); ax.spines[['top','right']].set_visible(False)
    ax.legend(frameon=False)
tests=['download 1 stream','download 8 streams','download 64 streams','upload 1 stream']
lab=['1 stream\n↓','8 streams\n↓','64 streams\n↓','1 stream\n↑']
for mode,name in [('tls','VLESS + TLS'),('plain','VLESS (TCP)')]:
    X=r[f'{mode}/xray']; Z=r[f'{mode}/zray']
    fig,ax=plt.subplots(figsize=(10,5)); bars(ax,lab,[X[t]['MBps'] for t in tests],[Z[t]['MBps'] for t in tests],f'Throughput — {name}','MB/s','higher is better')
    fig.tight_layout(); fig.savefig(f'throughput-{mode}.png',dpi=110); plt.close(fig)
    fig,ax=plt.subplots(figsize=(10,5)); bars(ax,lab,[X[t]['cpu_s_per_GB'] for t in tests],[Z[t]['cpu_s_per_GB'] for t in tests],f'CPU time per GB transferred — {name}','CPU seconds / GB','lower is better')
    fig.tight_layout(); fig.savefig(f'cpu-{mode}.png',dpi=110); plt.close(fig)
X=r['tls/xray']; Z=r['tls/zray']
fig,ax=plt.subplots(figsize=(10,5)); bars(ax,['idle','peak (under load)'],[X['idle_rss_mb'],X['peak_rss_mb']],[Z['idle_rss_mb'],Z['peak_rss_mb']],'Memory (resident set size)','MB','lower is better')
fig.tight_layout(); fig.savefig('memory.png',dpi=110); plt.close(fig)
