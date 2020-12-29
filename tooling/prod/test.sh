#!/bin/bash
EXEC=ecnDetector
DATASET=../datasets/pre-flight.dataset
CONF="runs.conf"

if `pgrep ecnDetector`; then
    echo "already running" >> cron.log
fi

# change directory to where the script is being called from
cd "$(dirname "$0")"

mkdir keystore
chmod o+rwx keystore

if [ ! -f $CONF ]; then
    echo "RUNS=0" >> $CONF
fi

source $CONF

sudo ./setup.sh

echo "### Start run $RUNS ###" >> experiment.log
./$EXEC -f $DATASET -d trace${RUNS} >> experiment.log

RUNS=$((RUNS+1))

sed -i "s~^\(RUNS=\).*~\1$RUNS~" $CONF
