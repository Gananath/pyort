import sys
#sys.path.append("../pyort/pyort/")
import argparse
from .pyort_fun import *

def main():    
    parser = argparse.ArgumentParser()
    parser.add_argument('-s','--start',action='store_true', help="Start monitoring of foregin IP's")
    parser.add_argument('-k','--kind',type=str,help="Similar to [kind] parameter in psutil.net_connections")
    args = parser.parse_args()
    sys.stdout.write(str(pyort_start(args)))
    
def pyort_start(args):     
    if args.start==True:
        configfile_name = "config.ini"
        directory=os.path.expanduser("~")+"/.config/pyort/" 
        db_path,db_name,time_interval,kd=config_para(directory,configfile_name)
        if args.kind != None: #kind argument from command line
            kd=args.kind
        print("\nMonitoring "+kd+" connections\n") 
        db_conn=sqlite_conn(db_path,db_name)
        while True:
            conn=psutil.net_connections(kind=kd)
            for c in conn:
                fd= c[0]
                family_code=c[1]
                type_code=c[2]
                local_ip=extract_ip(c[3])
                local_port=extract_ip(c[3],False)
                remote_ip=extract_ip(c[4])
                remote_port=extract_ip(c[4],False)
                status_code=c[5]
                p_id=c[6]
                if remote_ip==None or ipaddress.ip_address(unicode(remote_ip)).is_private==True:
                    continue
                is_record_exists, count=record_exists(db_conn,remote_ip)
                if is_record_exists==False:
                    count=1
                    sql_query="""INSERT INTO pyort(fd,family,
                                       conn_type,local_ip,local_port,remote_ip,remote_port,
                                       status,pid,today_count)
                                       VALUES(?,?,?,?,?,?,?,?,?,?)"""

                    db_conn.execute(sql_query,(fd, family_code, type_code,str(local_ip),str(local_port),
                                               str(remote_ip),str(remote_port),status_code,str(p_id),
                                                                         count))
                else:            
                    sql_query="""UPDATE pyort SET last_time=DATETIME('now'),
                                 today_count=today_count+1 where remote_ip=?"""
                    db_conn.execute(sql_query,(remote_ip,))
                print("Local= "+str(local_ip)+":"+str(local_port)+\
                      "  Foreign= "+str(remote_ip)+":"+str(remote_port)+\
                      " PID= "+str(p_id)+" Count:"+str(count))


            db_conn.commit()

            time.sleep(float(time_interval))

        

if __name__=='__main__':     
    main()
