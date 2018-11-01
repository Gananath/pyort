import sys
import argparse
#sys.path.append("../pyort/pyort/")
#from pyort_fun import *
from .pyort_fun import *



def main():
    parser = argparse.ArgumentParser()
    #monitoring and logging
    parser.add_argument('-s','--start',action='store_true', help="Start monitoring of foregin IP's")
    parser.add_argument('-k','--kind',type=str,help="Similar to [kind] parameter in psutil.net_connections")
    parser.add_argument('-Sv','--save',action='store_true',help="Saving output in database")
    parser.add_argument('-x','--silent',action='store_true',help="Silent mode, will not print any output")
    #for viewing database
    parser.add_argument('-d','--database',action='store_true',help="Fetch recent rows from database")
    parser.add_argument('-o','--order',nargs='?',type=str,default='count',help="Fetch by [ip] or [count]")
    parser.add_argument('-c','--constant',type=str,help="Add ip details here")
    parser.add_argument('-l','--limit',nargs='?',type=int,default=10,help="Fetch rows from database")
    #version
    parser.add_argument('-v','--version',action='store_true',help="Print program version and exit")
    args = parser.parse_args()
    sys.stdout.write(str(pyort_start(args)))
    
def pyort_start(args):

    #config file and location
    configfile_name = "config.ini"
    directory=os.path.expanduser("~")+"/.config/pyort/"     
   
    #fetch values from config file
    db_path,db_name,time_interval,kd,hp_key,threat_update,VERSION,geo_ip=config_para(directory,configfile_name)

   
   
    
    if args.start == True or args.database == True:
        #connecting to database
        db_conn=sqlite_conn(db_path,db_name)
        
    if args.kind != None: 
        #kind argument from command line. uses the same parameter in psutil.net_connections
        kd=args.kind
    
    #validating input values and fetches rows from database
    if args.database == False and args.start ==False and args.version==False:
        print ("Warning: please specify -d or -s or -v.") 
        exit
    elif args.version == True and args.database == False and args.start == False:
        #print version and exit
        print(VERSION)
        exit
    elif args.database == True and args.start == True:
        print "Warning: -d and -s parameters are not allowed together."
        exit     
    elif args.database == True and args.start ==False:               
        if args.order==None:
            #default order is count
            args.order="count"
        if args.limit ==None:
            #default limit is 10
            limit=10
        else:
            limit=args.limit
        if args.order=="ip":
            if args.constant==None:
                print ("Please provide the [ip] in -c.")
            else:
                print("\nRecent records selected according to the foregin IP.\n")
                _,records=record_exists(db_conn,ip=args.constant,job="ip",limit=limit)
                print_database(records)
        elif args.order=="count":            
            print("\nToday's records selected according to the count of incidence.\n")
            _,records=record_exists(db_conn,job="count",limit=limit)
            print_database(records)
           
         
    #starts monitioring
    if args.start==True and args.database == False:
        
         #GeoIP location data download from maxmind
        if geo_ip !='' and geo_ip in ['True','true', 'Yes','yes','Y', 'y', '1']:
            geolite2_download(directory)        
        elif geo_ip !=''  and geo_ip not in ['True','true', 'Yes','yes','Y', 'y', '1']:
            print("\n Warning: Please add Yes/Y/True to [geo_ip] in [config.ini] file to enble GeoIP")
            print(" or \n To disable keept [geo_ip] empty \n")
            
        print("\nMonitoring "+kd+" connections.\n")  
        #Loop till exit
        #Print format
        template="{:<20}| {:>15}|{:>6} |{:>15}|{:>6} | {:<6} |{:<6} |{:<7}|{:<15}|{:<}"
        print template.format("Recent"," Local","Port", "Foreign", "Port", "PID","Threat","Count","Process","Location") 
        while True:
            count=0
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
                p_name= get_process_name(p_id)            
                #if not an ip or a private ip then escape the loop
                if remote_ip==None or ipaddress.ip_address(unicode(remote_ip)).is_private==True:
                    continue
                           
                #verfiy if the ip exists in the database
                is_record_exists, t_count=record_exists(db_conn,remote_ip)

                #GeoIP location
                if geo_ip !=''  and geo_ip in ['True','true', 'Yes','yes','Y', 'y', '1']:
                    loc_name =geoip2_location(directory,remote_ip)       
                   
                else:
                    loc_name=None
                    
                #updating project_honey_pot threat_score
                if hp_key!='' and int(count)%int(threat_update)==0 and args.save==True:
                    threat_score,last_active=project_honey_pot(remote_ip,hp_key)
                else:
                    threat_score,last_active=None,None
                
                if args.save==True:                    
                    if is_record_exists==False:                    
                        sql_query="""INSERT INTO pyort(fd,family,
                                           conn_type,local_ip,local_port,remote_ip,remote_port,
                                           status,pid,process_name,today_count,threat_score,last_active,location)
                                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""

                        db_conn.execute(sql_query,(fd, family_code, type_code,str(local_ip),str(local_port),\
                                                   str(remote_ip),str(remote_port),status_code,str(p_id),\
                                                    str(p_name),count,str(threat_score),str(last_active),str(loc_name)))
                       
                    else:            
                        sql_query="""UPDATE pyort SET last_time=DATETIME('now'),
                             today_count=today_count+1,threat_score=?,last_active=?,pid=?,process_name=? where remote_ip=?"""
                        db_conn.execute(sql_query,(str(threat_score),str(last_active),str(p_id),str(p_name),remote_ip))
                if args.silent!=True: 
                    '''
                    if is_record_exists==False:
                        #suppressing nonetype error
                        tcount=[0]*10                 
                    print("Recent= {:<20} Local= {:>15}:{:<6} Foreign= {:>15}:{:<6} PID= {:<6} Threat= {:<4} Count= {:<4} "\
                    .format(str(t_count[2]),str(local_ip),str(local_port),str(remote_ip),\
                     str(remote_port),str(p_id),str(t_count[-2]),str(t_count[-3])))                 
                     '''
                    print template.format(str(t_count[2]),str(local_ip),str(local_port),str(remote_ip),\
                                          str(remote_port),str(p_id),str(t_count[14]),str(t_count[13]),\
                                          str(p_name),str(loc_name))

            db_conn.commit()

            time.sleep(float(time_interval))

        

if __name__=='__main__':     
    main()







