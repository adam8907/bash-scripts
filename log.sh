#!/bin/bash
# Author: Adamski Molina <adamski.molina@f5.com>

log_word="Cookie building failed"
log_found=0
first_found=0
previous_date=""
debug_bd="MODULE=IO_PLUGIN;\nLOG_LEVEL=TS_INFO | TS_DEBUG;\nFILE = 2;\n\nMODULE=BEM;\nLOG_LEVEL=TS_INFO | TS_DEBUG;\nFILE = 2;\n\
\nMODULE=COOKIE_MGR;\nLOG_LEVEL=TS_INFO | TS_DEBUG;\nFILE = 2;\nMODULE=ECARD_POLICY;\nLOG_LEVEL=TS_INFO | TS_DEBUG;\nFILE = 2;\n\
\nMODULE=LIBDATASYNC;\nLOG_LEVEL=TS_INFO | TS_DEBUG;\nFILE = 2;\n\nMODULE=CLIENT_SIDE;\nLOG_LEVEL=TS_INFO | TS_DEBUG;\nFILE = 2;\n"

function usage()
{
    echo "Usage"
    echo "bash simple_args_parsing.sh -v=<vs_name> -r=<irule_name> -t=<time min> [optional -c=<client_ip> -log=y -log_string=\"<string>\"]"
    echo "e.g."
    echo -e "bash simple_args_parsing.sh -v=vs_https -r=test_irule -t=10"
    echo ""
}


if [ $# -le 2 ]
  then
    echo "No arguments supplied"
    #echo "Usage: asm_log.sh <virtual_server> <time_capture_min> <irule_name> [-c <client_ip>]"
    usage
    exit 2
fi

while [ "$1" != "" ]; do
    PARAM=$(echo $1 | awk -F= '{print $1}')
    VALUE=$(echo $1 | awk -F= '{print $2}')
    echo $PARAM
    echo $VALUE
    case $PARAM in
        -v)
            virtual=$VALUE
            ;;
        -r)
            irule_name=$VALUE
            ;;
         -t)
            timer=$VALUE
            ;;
         -c)
            client_ip=$VALUE
            ;;
          *)
            echo "ERROR: unknown parameter \"$PARAM\""
            usage
            exit 1
            ;;
    esac
    shift
done

# Add iRule function

function add_irule() {
#Capture existing iRule configuration
tmsh list ltm virtual ${virtual} one-line | grep -q " rules { "

if [ $? -eq 1 ];
then
  echo "$0: ${virtual} currently contains no rules; adding new rule"
  irule_current=""
else
  irule_current=$(tmsh list ltm virtual ${virtual} one-line | sed -e 's/.* rules { //' -e 's/ }.*//')
#Check if rule already exists
  exists=0
  for rule in ${irule_current}
  do
    if [ ${rule} == ${irule_name} ];
    then
      exists=1
    fi
   done
   if [ ${exists} -eq 1 ];
   then
     echo "$0: ${irule_add} already exists in virtual ${virtual}" >&2
   fi
fi

#Modify iRule list
if [ ${exists} -eq 0 ];
then
  tmsh modify ltm virtual ${virtual} rules \{ ${irule_current} ${irule_name} \}
  status=$?
  if [ ${status} -ne 0 ]; then
    echo "tmsh returned error status ${status}" >&2
    exit ${status}
  fi
fi
}

function delete_irule {

tmsh list ltm virtual $virtual one-line | grep -q " rules { "

if [ $? -eq 1 ];
then
  echo "$0: ${virtual} currently contains no rules; exiting"
else
  irule_current=$(tmsh list ltm virtual ${virtual} one-line | sed -e 's/.* rules { //' -e 's/ }.*//')
  #Check if rule already exists
  exists=0
  for rule in ${irule_current}
  do
    if [ ${rule} == ${irule_name} ]; then
    exists=1
  fi
  done
  if [ ${exists} -eq 0 ]; then
    echo "$0: ${irule_del} does not exist in virtual ${virtual}" >&2
  else
    irule_current=`echo " ${irule_current} " | sed -e "s/ ${irule_name} / /"`
  fi
fi

#Modify iRule list
tmsh modify ltm virtual ${virtual} rules { ${irule_current} }
status=$?
if [ ${status} -ne 0 ];
then
  echo "tmsh returned error status ${status}" >&2
  exit ${status}
fi

}

function last_log() {
   #Getting the date for the last log
   log_date=$(grep "$log_word" /var/log/asm | tail -1 | awk -F" " '{print$1" "$2" "$3}')

   #Converting string to date
   orig_date=$(date -d "$log_date")
   date_now=$(date -d '-10 seconds')
   orig_date=$(date -d "${orig_date}" +"%s")
   date_now=$(date -d "${date_now}" +"%s")

   if [ "$orig_date" -lt "$date_now" ]
   then
     log_found=0
     return $log_found
   fi
   #Adding the time the script ran plus 1 min
   #new_timer=$(($timer + 1))
   #date_value_timer=$(date -d "$date_value $new_timer minutes")

   if [ "$log_date" != "" ] && [ -z "$previous_log" ]
   then
      log_found=1
      previous_log="$log_date"
      #Converting string to date
      date_value=$(date -d "$previous_log")
      #Adding the time the script ran plus 1 min
      new_timer=$(($timer + 1))
      date_value_timer=$(date -d "$date_value $new_timer minutes")

   else
      if [ "$previous_date" = "$log_date" ]
      then
        log_found=0
        previous_log="$log_date"
        #Converting string to date
        date_value=$(date -d "$previous_log")
        #Adding the time the script ran plus 1 min
        new_timer=$(($timer + 1))
        date_value_timer=$(date -d "$date_value $new_timer minutes")
      else
        #Converting to epoch time
        #orig_date=$(date -d "${orig_date}" +"%s")
        new_date=$(date -d "${date_value_timer}" +"%s")
        if [ "$orig_date" -gt "$new_date" ]
        then
          #echo "$log_date"
          log_found=1
          previous_log="$log_date"
          #Converting string to date
          date_value=$(date -d "$previous_log")
          #Adding the time the script ran plus 1 min
          new_timer=$(($timer + 1))
          date_value_timer=$(date -d "$date_value $new_timer minutes")
        else
          log_found=0
        fi
      fi
    fi
   #echo "Return value $log_found"
   return $log_found
}


###########################################################################################################33

while [ true ]
do
last_log
if [ $? -eq 1 ]
then
  echo "Log found"
  echo "--------------------------------"
  echo $client_ip
  if [ ! -z "$client_ip" ]
  then
     echo "Adding iRule to VS $virtual"
     add_irule
     echo "------------------------------"
     echo "Adding debug mode bd"
     cp /etc/ts/bd/logger.cfg /etc/ts/bd/logger.cfg.backup
     echo -e $debug_bd >> /etc/ts/bd/logger.cfg
     perl /usr/share/ts/bin/set_active.pl -g
     echo "-----------------------------"
     echo "Starting tcpdump command"
     timer_1=$(($timer*60))
     NOW=$(date +"%m-%d-%Y-%H-%M-%S")
     timeout $timer_1 tcpdump -ni 0.0:nnnp -s0 -v -w /var/tmp/cookie_$NOW.pcap host $client_ip &
     timer_1=$(($timer_1+5))
     echo "Stoping tcpdump command"
     sleep $timer_1
     echo "-----------------------------"
     echo "Generating PMS file"
     sed -e 's/^.*\(RSA Session-ID\)/\1/;tx;d;:x' /var/log/ltm > /var/tmp/sessionsecrets_$NOW.pms
     echo "PMS saved in /var/tmp/sessionsecrets.pms"
     echo "-----------------------------"
     echo "Removing iRule from VS"
     delete_irule
     echo "-----------------------------"
     echo "Removing debug from BD"
     cp /etc/ts/bd/logger.cfg.backup /etc/ts/bd/logger.cfg
     perl /usr/share/ts/bin/set_active.pl -g

  else
     echo "iRule without IP"
     echo "Adding iRule to VS $virtual"
     add_irule
     echo "------------------------------"
     echo "Adding debug mode bd"
     cp /etc/ts/bd/logger.cfg /etc/ts/bd/logger.cfg.backup
     echo -e $debug_bd >> /etc/ts/bd/logger.cfg
     perl /usr/share/ts/bin/set_active.pl -g
     echo "-----------------------------"
     echo "Starting tcpdump command"
     timer_1=$(($timer*60))
     NOW=$(date +"%m-%d-%Y-%H-%M-%S")
     virtual_ip=$(tmsh list ltm virtual vs_https | grep destination | sed -e 's/[ \t]*//' | cut -d " " -f2 | cut -d ":" -f1)
     timeout $timer_1 tcpdump -ni 0.0:nnnp -s0 -v -w /var/tmp/cookie_$NOW.pcap host $virtual_ip &
     timer_1=$(($timer_1+5))
     sleep $timer_1
     echo "Stoping tcpdump command"
     echo "-----------------------------"
     echo "Generating PMS file"
     sed -e 's/^.*\(RSA Session-ID\)/\1/;tx;d;:x' /var/log/ltm > /var/tmp/sessionsecrets_$NOW.pms
     echo "PMS saved in /var/tmp/sessionsecrets.pms"
     echo "-----------------------------"
     echo "Removing iRule from VS"
     delete_irule
     echo "-----------------------------"
     echo "Removing debug from BD"
     cp /etc/ts/bd/logger.cfg.backup /etc/ts/bd/logger.cfg
     perl /usr/share/ts/bin/set_active.pl -g

  fi
fi
done
