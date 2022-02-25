import pandas
import os


WDIR = "./db_org/"
OUTPUTDIR = "./db_out/"


FLIST = {
    "main.ldb":[";",["target","engine","rid","rules"]], 
    "daily.ldb":[";",["target","engine","rid","rules"]], 
    
    "main.ndb":[":",["target","type","offset","hexsig"]],
    "daily.ndb":[":",["target","type","offset","hexsig"]],
}

total_types = set(
    {'Xml', 'W32S', 'Pdf', 'Ttf', 'Unix', 'Doc', 'Ios', 'Osx', 
     'Heuristics', 'Html', 'Gif', 'Xls', 'Andr', 'Swf', 'Ppt', 
     'Vbs', 'Archive', 'Phish', 'Legacy', 'Img', 'Multios', 'Emf', 
     'Svg', 'Php', 'Mkv', 'Lnk', 'Rat', 'Dos', 'Js', 'Phishtank', 
     'Symbos', 'Py', 'Clamav', 'Txt', 'Tif', 'Java', 'Hwp', 'Email', 
     'Rtf', 'Mp4', 'Asp', 'Win'}
    )

total_class = set(
    {'Coinminer', 'Exploit', 'Adware', 'Rootkit', 'Trojan', 'Test', 'Worm', 
    'Tool', 'Macro', 'File', 'Packer', 'Malware', 'Joke', 'Keylogger', 
    'Phishing', 'Proxy', 'Virus', 'Dropper',
    'Ircbot', 'Countermeasure', 
    'Ransomware', 'Downloader', 'Spyware', 'Packed'}
)

unwanted=set(
{
    "Win","Ios","Phishtank","Email","Phish","W32S","Vbs"
})

wanted = set({
    'Txt', 'Php','Clamav','Unix','Legacy', 'Html','Java','Archive',
    'Js', 'Rtf', 'Tif', 'Symbos', 'Py', 'Rat',
    'Xml', 'Multios', 'Asp'
})


def Getdata(wdir,name,info):
    sep = info[0]
    names = info[1]
    usecols = len(info[1]) - 1
    totals = []
    with open(wdir+name) as f:
        data = f.readlines()
    for each in data:
        if each.startswith("#"):
            continue
        totals.append(each.strip().split(sep,usecols))
    
    return pandas.DataFrame(totals,columns=names)

def GetData(name):
    return Getdata(WDIR,name,FLIST[name])

def GetAllDBFilterd(unwanted):
    dbs = dict({})
    for each in FLIST:
        if each.endswith("fp"):
            continue
        dbs[each] = GetData(each)
        ntdf = dbs[each]['target'].str.split('.', 3, True)
        ntdf.columns =["p0","p1","p2"]
        dbs[each] = pandas.concat([dbs[each],ntdf],axis=1)
        dbs[each] = dbs[each][~dbs[each]["p0"].isin(unwanted)]
    return dbs

def GetAllDBWanted(wanted):
    dbs = dict({})
    for each in FLIST:
        if each.endswith("fp"):
            continue
        dbs[each] = GetData(each)
        ntdf = dbs[each]['target'].str.split('.', 3, True)
        ntdf.columns =["p0","p1","p2"]
        dbs[each] = pandas.concat([dbs[each],ntdf],axis=1)
        dbs[each] = dbs[each][dbs[each]["p0"].isin(wanted)]
    return dbs

def SaveDB(dbs,fpath):
    for each in dbs:
        tmp = dbs[each].drop(columns=["p0","p1","p2"])
        f = open(fpath + each,"a")
        if each.endswith(".ldb"):
            f.write('# There must always be one line in the file\n')
        for line in tmp.iterrows():
            f.write(FLIST[each][0].join(line[1])+"\n")       
        f.close()
        
def GetAllTargetType(dbs):
    target_set = set()
    for each in dbs:
        target_set.update(set(dbs[each]["target"]))
    
    target_list_format = [each.split(".") for each in target_set]
    return pandas.DataFrame(target_list_format)


def ClamavUpdate():
    dbs = GetAllDBWanted(wanted)

    dbs["main.ldb"] = pandas.concat([dbs["main.ldb"],dbs["daily.ldb"]])
    dbs["main.ldb"].drop_duplicates(keep="first")
    del dbs["daily.ldb"]

    dbs["main.ndb"] = pandas.concat([dbs["main.ndb"],dbs["daily.ndb"]])
    dbs["main.ndb"].drop_duplicates(keep="first")
    del dbs["daily.ndb"]

    SaveDB(dbs,OUTPUTDIR)

ClamavUpdate()
