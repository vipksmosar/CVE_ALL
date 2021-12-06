import pandas as pd
import requests
import html5lib
from tqdm import tqdm
import threading
import time

thco = threading.active_count()

def req_to_cve (i):
    try:
        href = 'https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page={}&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=1000&year=0&month=0&cweid=0&order=1&trc=161982&sha=993d30d08247c0f98abf5d2e900d995b57342eae'.format(i)
        req = requests.get(href)
        DF = pd.read_html(req.content)[4]
        DF.drop(DF.index[[i for i in range(1,100, 2)]], inplace=True)
        DF.to_excel('D:/CSV/CVE/{}_CVE.xlsx'.format(i), index=False)
    except:
        list_error.append(href)

list_error=[]
for i in tqdm(range(3241)):
    thred_cve = threading.Thread(target=req_to_cve, kwargs={'i':i})
    thred_cve.start()
    while threading.active_count()>thco+12:
        time.sleep(0.5)
        
