#!/bin/bash
EXEC=ecnDetector
DATASET=../datasets/flight.ip4.dataset
CONF="runs.conf"

if pgrep ecnDetector >> /dev/null; then
    echo "already running" >> cron.log
    exit 0
fi

# change directory to where the script is being called from
cd "$(dirname "$0")"


#conf shouldnt exist if we are running for the first time
if [ ! -f $CONF ]; then
    echo "RUNS=0" >> $CONF
fi

source $CONF

mkdir -p "trace${RUNS}/keystore"
sudo chown -R ecnDetector_psuedo trace${RUNS}



# we should be able to use sudo from scipts from installer.user.sh
sudo ./setup.sh

echo "### Start run $RUNS ###" >> experiment.log
./$EXEC -f $DATASET -d trace${RUNS} >> experiment.log

RUNS=$((RUNS+1))

sed -i "s~^\(RUNS=\).*~\1$RUNS~" $CONF
