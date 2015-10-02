#!/bin/bash
SCRIPT=$(readlink -f $0)
SCRIPTPATH=`dirname $SCRIPT`
SCRIPTNAME=$(basename "$SCRIPT")

if [ "$#" -lt 1 ]
then
  echo "Usage: ./$SCRIPTNAME <sdnracer-traces folder path> [<pattern for matching directories, default is \"trace_*\">]"
  echo "or     ./$SCRIPTNAME -i <single trace folder path>"
  exit 1
fi

trace_dirs_array=()
ADDITIONAL_PARALLEL_OPTS=""
case "$1" in
  -i)
    if [ "$#" -eq 2 ]
    then
      trace_dirs_array+=("$2")
      ADDITIONAL_PARALLEL_OPTS="--ungroup"
    else
      echo "No trace directory specified for option -i"
      exit 1
    fi
    ;;
  *)
    WORKSPACE=$1
    # set default value if not set
    MATCHPATTERN=${2:-"trace_*"}
    # get trace directories
    while IFS=  read -r -d $'\0'; do
      trace_dirs_array+=("$REPLY")
    done < <(find "$WORKSPACE" -maxdepth 1 -type d -name "$MATCHPATTERN" -print0 | sort -nz)
    ;;
esac

echo "Directories to be processed:"
for i in "${trace_dirs_array[@]}"; do
  echo "  " "$i"
done;

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

# Using GNU Parallel, uses N jobs (N=number of cores) by default
# -k: keep order of input to output
# --jobs: number of jobs (here we want to disable parallelism)
parallel -k --jobs 1 $ADDITIONAL_PARALLEL_OPTS add_results_to_git ::: "${trace_dirs_array[@]}"

