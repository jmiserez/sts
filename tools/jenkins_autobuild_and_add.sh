#!/bin/bash
if [ "$#" -ne 1 ]
then
  echo "Usage: ./jenkins-autobuild.sh <sdnracer-traces folder path>"
  exit 1
fi

SCRIPT=$(readlink -f $0)
SCRIPTPATH=`dirname $SCRIPT`
cd "$SCRIPTPATH/.."

WORKSPACE=$1
echo "WORKSPACE: $WORKSPACE"

process_traces() {
#  echo "Process trace in $1"
  echo "./gen.sh $1"
  ./gen.sh "$1"
}
export -f process_traces

add_results_to_git(){
  echo "Add to git in $1"
  pushd "$1" > /dev/null
  # add results
  git add \results_*.dat
  git add \*summary.csv
  # add timings
  git add \timings_*.dat
  git add \*summary_timings.csv
  popd > /dev/null
}
export -f add_results_to_git

# get trace directories
trace_dirs_array=()
while IFS=  read -r -d $'\0'; do
    trace_dirs_array+=("$REPLY")
done < <(find "$WORKSPACE" -maxdepth 1 -type d -name "trace_*" -print0 | sort -nz)

# Using GNU Parallel, uses N jobs (N=number of cores) by default
# -k: keep order of input to output
parallel -k process_traces ::: "${trace_dirs_array[@]}"
parallel -k --jobs 1 add_results_to_git ::: "${trace_dirs_array[@]}"

cd "$WORKSPACE"
git status
