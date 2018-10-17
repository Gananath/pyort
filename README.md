# pyort
Command line tool for monitoring all foreign network connections

# Installation (python 2.7)
`pip install pyort` 
   or 
`pip install git+https://github.com/Gananath/pyort.git`

# Usage
Help: `pyort -h`

Start: `pyort --start`

Custom: `pyort -s --kind tcp6`

Silent: `pyort -s -x`

# Configuration
`config.ini` and database files exsists in the direcotry `$HOME/.config/pyort`. 
```
db_path = database path
db_name = database name
interval = time interval for updating ip's
kind = kind of connections all,tcp,udp etc
project_honey_pot_key = projecthoneypot.org's api key
threat_update_count = interval for updating the threat score from projecthoneypot.org
```
# Optional
If wanted you can also get [project honey pot's](https://www.projecthoneypot.org/) threat score for foregin ip's but needs porject honey pot's api and `pip install httpbl`. Add the api key to `config.ini` without quotes.


