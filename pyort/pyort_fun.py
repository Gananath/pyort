import os
import time
import psutil
import sqlite3
import ipaddress
import ConfigParser
try:
    import httpbl
except:
    pass


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




def config_para(directory,configfile_name):
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
        Config.set('pyort', 'project_honey_pot_key','')
        Config.set('pyort', 'threat_update_count',1000)
        Config.write(cfgfile)
        cfgfile.close()    
    
    Config.read(directory+configfile_name)
    db_path= Config.get('pyort','db_path')
    db_name= Config.get('pyort','db_name')
    slp= Config.get('pyort','interval')
    kd= Config.get('pyort','kind')
    hp_key=Config.get('pyort', 'project_honey_pot_key')
    threat_update=Config.get('pyort', 'threat_update_count')
    return db_path,db_name,slp,kd,hp_key,threat_update

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
                         today_count INT NOT NULL,
                         threat_score TEXT NOT NULL,
                         last_active TEXT NOT NULL      
                        
                         );''')
        print "Database connected"
        return db_conn
    except Error as e:
        print e
        print "Error"
        
    

def print_database(records):
    for i in records:
        local_ip=i[6]
        local_port=i[7]
        remote_ip=i[8]
        remote_port=i[9]
        p_id=i[11]
        print("Recent= {:<20} Local= {:>15}:{:<6} Foreign= {:>15}:{:<6} PID= {:<6} Threat= {:<4} Count= {:<4} "\
                .format(str(i[2]),str(local_ip),str(local_port),str(remote_ip),str(remote_port),str(p_id),\
                str(i[-2]),str(i[-3])))
    return None

def record_exists(db_conn,ip=None,job=None, limit=1):
    if ip != None and job ==None:
        sql_query="SELECT * FROM pyort WHERE remote_ip=? ORDER BY id DESC  LIMIT ? "
        cursor=db_conn.execute(sql_query,(ip,limit))
        exist=cursor.fetchone()
        if exist is None:
            #return False,'None','None'
            return False,None
        else:
            #return True,exist[-3],exist[-2]
            return True, exist
    elif job !=None:
        if job == "COUNT":
            sql_query="SELECT * FROM pyort WHERE DATE(first_time)=DATE('now') OR DATE(last_time)=DATE('now')  ORDER BY today_count DESC  LIMIT ? "
            cursor=db_conn.execute(sql_query,(limit,))
        elif job == "IP":
            sql_query="SELECT * FROM pyort WHERE remote_ip=? ORDER BY id DESC  LIMIT ? "
            cursor=db_conn.execute(sql_query,(ip,limit))
        exist=cursor.fetchall()
        if exist is None:
            #return False,'None','None'
            return False,None
        else:
            #return True,exist[-3],exist[-2]
            return True, exist
    else:
        False, None    
