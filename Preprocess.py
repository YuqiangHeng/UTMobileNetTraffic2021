# -*- coding: utf-8 -*-
"""
Created on Wed Dec 23 01:54:18 2020

@author: ethan
"""

import numpy as np
import pandas as pd
from tqdm import tqdm

from os import listdir
from os.path import isfile, join
mypath = 'D:/Network Traffic Dataset/Data/Randomized Automated Data'
onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
apps = np.unique([f.split('_')[0] for f in onlyfiles])
print(apps, len(apps), len(onlyfiles))
app_actions = np.unique(['_'.join(f.split('_')[:2]) for f in onlyfiles])
print(app_actions, len(app_actions))

# sel_apps = ['dropbox' 'facebook' 'gmail' 'google-drive' 'hulu' 'instagram'
#  'messenger' 'netflix' 'pandora' 'pinterest' 'spotify' 'twitter'
#  'youtube']

sel_apps = ['dropbox', 'facebook', 'gmail', 'instagram', 'netflix', 'spotify', 'twitter', 'youtube']
sel_app_files = {i:[] for i in sel_apps}

for fname in onlyfiles:
    app_name = fname.split('_')[0]
    if app_name in sel_apps:
        sel_app_files[app_name].append(fname)

columns = ['frame.number',
 'frame.time',
 'frame.len',
 'frame.cap_len',
 'ip.hdr_len',
 'ip.dsfield.ecn',
 'ip.len',
 'ip.frag_offset',
 'ip.ttl',
 'ip.proto',
 'ip.src',
 'ip.dst',
 'tcp.hdr_len',
 'tcp.len',
 'tcp.srcport',
 'tcp.dstport',
 'tcp.flags.ns',
 'tcp.flags.fin',
 'tcp.window_size_value',
 'tcp.urgent_pointer',
 'tcp.option_kind',
 'tcp.option_len',
 'udp.srcport',
 'udp.dstport',
 'udp.length']
# df = pd.read_csv(join(mypath,onlyfiles[1]),usecols = columns,low_memory=False)
# df = df[df['ip.src'].notna()]
# df.head()

def process_df(df, app, num_pkt = 10):
    processed_df = pd.DataFrame()
    for i in tqdm(range(df.shape[0]-num_pkt)):
        sub_df = df.iloc[i:i+num_pkt,:]
        ip_src = sub_df['ip.src'].unique()
        ip_len = sub_df['ip.len'].astype(int)
        is_udp = sub_df['tcp.hdr_len'].isna()
        is_tcp = sub_df['udp.srcport'].isna()
        iat = pd.to_datetime(sub_df['frame.time']).diff(1).dt.total_seconds().iloc[1:]
        udp_src_port = sub_df[sub_df['tcp.hdr_len'].isna()]['udp.srcport']
        udp_dst_port = sub_df[sub_df['tcp.hdr_len'].isna()]['udp.dstport']
        tcp_src_port = sub_df[sub_df['udp.srcport'].isna()]['tcp.srcport']
        tcp_dst_port = sub_df[sub_df['udp.srcport'].isna()]['tcp.dstport']
        processed_df = processed_df.append({'num_tcp':is_tcp.sum(), 'num_udp':is_udp.sum(), 'num_unique_src_ports':udp_src_port.unique().shape[0]+tcp_src_port.unique().shape[0],
                             'num_unique_dst_ports':udp_dst_port.unique().shape[0]+tcp_dst_port.unique().shape[0], 'dl_iat_mean':iat.mean(),
                             'dl_iat_min':iat.min(),'dl_iat_max':iat.max(),'dl_iat_std':iat.std(),
                            'dl_bps':ip_len.sum()/iat.sum(), 'dl_npkt_ps':num_pkt/iat.sum(),'dur':iat.sum(),'app':app}, ignore_index=True)
    return processed_df

# df_try = process_df(df,'dropbox')
df_all = pd.DataFrame()
for app in sel_apps:
    integrity = True
    df_app = pd.DataFrame()
    for fname in sel_app_files[app]:
        df = pd.read_csv(join(mypath,fname),usecols = columns,low_memory=False)
        # DL pkts only
        df = df[df['ip.src'].notna()]
        try:
            processed_df = process_df(df, app, num_pkt = 20)
            df_app = df_app.append(processed_df)
        except:
            integrity = False
            print('\n Error while processing {}. \n'.format(fname))
            break           
    if integrity:
        df_app.to_csv('{}_20pkt_dl.csv'.format(app))