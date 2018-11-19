import os
import time
import psutil
import urllib
import tarfile
import ipaddress
import ConfigParser
try:
    import sqlite3
except:
    pass
try:
    import httpbl
except:
    pass

try:
    import geoip2.database
except:
    pass
    
def get_process_name(pid):
    try:
        if pid==None:
            return 'None'
        else:
            p_name=psutil.Process(pid).name()  
            return p_name
    except:        
        return 'None'
        
def project_honey_pot(ip,key):
    bl = httpbl.HttpBL(key)
    response = bl.query(ip)
    return response['threat_score'],response['days_since_last_activity']

def validIP(address):
    parts = address.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        if not 0 <= int(item) <= 255:
            return False
    return True

def extract_ip(x,ip=True):
    try:
        if validIP(x[0])==True and ip==True:
            return x[0]
        elif validIP(x[0])==True and ip==False:
            return x[1]
        else:
            return None
    except:        
        return None


def geoip2_location(directory,ip):
    try:
        reader = geoip2.database.Reader(directory+"GeioLite2_City/GeoLite2-City.mmdb")
        response = reader.city(ip)
        country=str(response.country.name)
        city=str(response.city.name)
        reader.close()
        return ','.join([city,country])
    except:
        print("Error")
        return None


def geolite2_download(directory):
    geoip_path=directory+"GeioLite2_City/"
    web="https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz"
    try:
        if not os.path.isfile(geoip_path+"GeoLite2-City.mmdb"):
            if not os.path.exists(geoip_path):
                os.makedirs(geoip_path)
            print "Downloading GeoIP location file from maxmind.com"
            print "Please wait."
            urllib.urlretrieve(web,geoip_path+"GeoLite2-City.tar.gz")
            print "Download complete"            
            print "Extracting files from  GeoLite2-City.tar.gz"
            tar = tarfile.open(geoip_path+"GeoLite2-City.tar.gz", "r:gz")
            #tar.extractall(geoip_path=geoip_path)
            s= tar.getnames()
            s=[s for s in s if "GeoLite2-City.mmdb" in s]
            tar.extract(s[0],geoip_path)
            tar.close()
            print "Moving files to Geolite2-City"
            for i in os.listdir(geoip_path):    
                if os.path.isdir(geoip_path+i):                    
                    os.rename(geoip_path+i+"/"+"GeoLite2-City.mmdb",\
                    geoip_path+"GeoLite2-City.mmdb")
                    print "Removing tar file"
                    os.remove(geoip_path+"GeoLite2-City.tar.gz")
                    os.rmdir(geoip_path+i)

            print "Download complete"
        else:
            print "GeoIP location loaded"
    except:
        print "Error while downloading GeoIP location file from maxmind"
        print "Please check your network connection"
    


def config_para(directory,configfile_name):
    VERSION="0.1.7.5.2"    
    # Check if there a directory exists or not
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # Check if there is already a configurtion file
    Config = ConfigParser.ConfigParser()
    if not os.path.isfile(directory+configfile_name):
        # Create the configuration file as it doesn't exist yet
        cfgfile = open(directory+configfile_name, 'w')
        
        # Add content to the file       
        Config.add_section('pyort')
        Config.set('pyort', 'db_path', directory)
        Config.set('pyort', 'db_name','pyort.db')
        Config.set('pyort', 'interval',10)
        Config.set('pyort', 'kind',"all")
        Config.set('pyort', 'geo_ip','')
        Config.set('pyort', 'project_honey_pot_key','')
        Config.set('pyort', 'threat_update_count',1000)
        Config.set('pyort', 'version',VERSION)
        Config.write(cfgfile)
        cfgfile.close()
  
    try:
        Config.read(directory+configfile_name)
        Config.set('pyort', 'version',VERSION)
        with open(directory+configfile_name, 'wb') as configfile:
            Config.write(configfile)
        db_path= Config.get('pyort','db_path')
        db_name= Config.get('pyort','db_name')
        slp= Config.get('pyort','interval')
        kd= Config.get('pyort','kind')
        geo_ip=Config.get('pyort', 'geo_ip')
        hp_key=Config.get('pyort', 'project_honey_pot_key')
        threat_update=Config.get('pyort', 'threat_update_count')
        version=Config.get('pyort', 'version')        
    except Exception as e:
        print e.__doc__
        print e.message
        print("Got some error in [config.ini], Deleting old one and creating new [config.ini].")        
        os.remove(directory+configfile_name)
        config_para(directory,configfile_name)  
    
    return db_path,db_name,slp,kd,hp_key,threat_update,version,geo_ip
    

def sqlite_conn(db_path,db_name):
    try:
        db_conn= sqlite3.connect(db_path+db_name)        
        db_conn.execute('''CREATE TABLE IF NOT EXISTS pyort
                        (id INTEGER PRIMARY KEY,
                         first_time  DATETIME DEFAULT CURRENT_TIMESTAMP,
                         last_time  DATETIME DEFAULT CURRENT_TIMESTAMP,
                         fd TEXT NOT NULL,
                         family TEXT NOT NULL,
                         conn_type TEXT NOT NULL,
                         local_ip TEXT NOT NULL,
                         local_port TEXT NOT NULL,
                         remote_ip TEXT NOT NULL,
                         remote_port TEXT NOT NULL,                                                
                         status TEXT NOT NULL,
                         pid TEXT NOT NULL,
                         process_name TEXT NOT NULL,
                         today_count INT NOT NULL,
                         threat_score TEXT NOT NULL,
                         last_active TEXT NOT NULL,   
                         location TEXT NOT NULL   
                        
                         );''')
        print "Database connected"
        return db_conn
    except Error as e:
        print e
        print "Error"
        
    

def print_database(records):
    template="{:<20}| {:>15}|{:>6} |{:>15}|{:>6} | {:<6} |{:<6} |{:<7}|{:<15}|{:<}"
    print template.format("Recent"," Local","Port", "Foreign", "Port", "PID","Threat",\
    "Count","Process","Location")  
    for i in records:
        local_ip=i[6]
        local_port=i[7]
        remote_ip=i[8]
        remote_port=i[9]
        p_id=i[11]
        p_name=i[12]
        loc_name=i[16]
        '''
        print("Recent= {:<20} Local= {:>15}:{:<6} Foreign= {:>15}:{:<6} PID= {:<6} Threat= {:<4} Count= {:<4} "\
                .format(str(i[2]),str(local_ip),str(local_port),str(remote_ip),str(remote_port),str(p_id),\
                str(i[-2]),str(i[-3])))'''
        print template.format(str(i[2]),str(local_ip),str(local_port),str(remote_ip),str(remote_port),str(p_id),\
                str(i[-2]),str(i[-3]),str(p_name),str(loc_name))
    return None

def record_exists(db_conn,ip=None,job=None, limit=1):
    if ip != None and job ==None:
        sql_query="SELECT * FROM pyort WHERE remote_ip=? ORDER BY id DESC  LIMIT ? "
        cursor=db_conn.execute(sql_query,(ip,limit))
        exist=cursor.fetchone()
        if exist is None:            
            return False, [0]*30 #return a zero array
        else:            
            return True, exist
    elif job !=None:
        if job == "count":
            sql_query="SELECT * FROM pyort WHERE DATE(first_time)=DATE('now') OR DATE(last_time)=DATE('now')  ORDER BY today_count DESC  LIMIT ? "
            cursor=db_conn.execute(sql_query,(limit,))
        elif job == "ip":
            sql_query="SELECT * FROM pyort WHERE remote_ip=? ORDER BY id DESC  LIMIT ? "
            cursor=db_conn.execute(sql_query,(ip,limit))
        exist=cursor.fetchall()
        if exist is None:            
            return False,[0]*30 #return a zero array
        else:            
            return True, exist
    else:
        False, [0]*30 #return a zero array   
