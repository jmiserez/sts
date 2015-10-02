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

generate_plots() {
#  echo "Generating plots for trace $1"
  pushd "$SCRIPTPATH" > /dev/null
  echo "./plot.py $1"
  ./plot.py "$1"
  popd > /dev/null
}
export -f generate_plots

# Using GNU Parallel, uses N jobs (N=number of cores) by default
# -k: keep order of input to output
parallel -k $ADDITIONAL_PARALLEL_OPTS generate_plots ::: "${trace_dirs_array[@]}"
