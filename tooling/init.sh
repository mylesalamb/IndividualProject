#!/bin/bash
# init script as a start time for the experiment
# should be set to run at midnight via a cron job, will dynamically remove the previous job
# and add in the proper schedule

cd "$(dirname "$0")"

# remove init job to start at midnight (ie. this job)
crontab -u pi -l | grep -v "init.sh" | crontab -u pi -
#add job to run on n hour schedule
(crontab -u pi -l; echo "0 0 */2 * * $(pwd)/prod/run_experiment.sh") | crontab -u pi -

./prod/run_experiment.sh
