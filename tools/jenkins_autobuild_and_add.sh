#!/bin/bash
if [ "$#" -lt 1 ]
then
  echo "Usage: ./all_traces_generate_results.sh <sdnracer-traces folder path> [<pattern for matching directories, default is \"trace_*\">]"
  exit 1
fi

# set default value if not set
MATCHPATTERN=${2:-"trace_*"}

SCRIPT=$(readlink -f $0)
SCRIPTPATH=`dirname $SCRIPT`

WORKSPACE=$1
echo "WORKSPACE: $WORKSPACE"

# get trace directories
trace_dirs_array=()
while IFS=  read -r -d $'\0'; do
    trace_dirs_array+=("$REPLY")
done < <(find "$WORKSPACE" -maxdepth 1 -type d -name "$MATCHPATTERN" -print0 | sort -nz)

echo "List of directories to be processed:"
for i in "${trace_dirs_array[@]}"; do
  echo "  " "$i"
done;

generate_results() {
#  echo "Generating results for trace $1"
  pushd "$SCRIPTPATH" > /dev/null
  echo "./gen.sh $1"
  ./gen.sh "$1"
  popd > /dev/null
}
export -f generate_results

generate_plots() {
#  echo "Generating plots for trace $1"
  pushd "$SCRIPTPATH" > /dev/null
  echo "./plots.sh $1"
  ./plots.sh "$1"
  popd > /dev/null
}
export -f generate_plots

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
parallel -k generate_results ::: "${trace_dirs_array[@]}"
parallel -k generate_plots ::: "${trace_dirs_array[@]}"
parallel -k --jobs 1 add_results_to_git ::: "${trace_dirs_array[@]}"

