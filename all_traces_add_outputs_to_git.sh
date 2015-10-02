#!/bin/bash
if [ "$#" -ne 1 ]
then
  echo "Usage: ./all_traces_generate_results.sh <sdnracer-traces folder path>"
  exit 1
fi

SCRIPT=$(readlink -f $0)
SCRIPTPATH=`dirname $SCRIPT`

WORKSPACE=$1
echo "WORKSPACE: $WORKSPACE"

add_results_to_git(){
  echo "Add to git in $1"
  pushd "$1" > /dev/null
  # add results
  git add results_\*.dat
  git add \*summary.csv
  # add timings
  git add timings_\*.dat
  git add \*summary_timings.csv
  # add plots
  git add num\*.pdf
  git add \*_pkt_consist.pdf
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
parallel -k --jobs 1 add_results_to_git ::: "${trace_dirs_array[@]}"

