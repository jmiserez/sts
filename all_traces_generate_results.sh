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

generate_results() {
#  echo "Generating results for trace $1"
  pushd "$SCRIPTPATH" > /dev/null
  echo "./gen.sh $1"
  ./gen.sh "$1"
  popd > /dev/null
}
export -f generate_results

# get trace directories
trace_dirs_array=()
while IFS=  read -r -d $'\0'; do
    trace_dirs_array+=("$REPLY")
done < <(find "$WORKSPACE" -maxdepth 1 -type d -name "trace_*" -print0 | sort -nz)

# Using GNU Parallel, uses N jobs (N=number of cores) by default
# -k: keep order of input to output
parallel -k generate_results ::: "${trace_dirs_array[@]}"

