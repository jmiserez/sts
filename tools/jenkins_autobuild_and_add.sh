#!/bin/bash
if [ "$#" -ne 1 ]
then
  echo "Usage: ./jenkins-autobuild.sh <sdnracer-traces folder path>"
  exit 1
fi

SCRIPT=$(readlink -f $0)
SCRIPTPATH=`dirname $SCRIPT`
cd "$SCRIPTPATH"

WORKSPACE=$1
echo "WORKSPACE: $WORKSPACE"

for i in "$WORKSPACE"/trace_*; do
echo "./gen.sh $i"
./gen.sh "$i"
pushd "$i"
# add results
git add \results_*.dat
git add \*summary.csv
# add timings
git add \timings_*.dat
git add \*summary_timings.csv
git status
popd
done;

