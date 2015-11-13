#!/bin/bash
# reliable way to get the directory where this file is stored
SCRIPT=$(readlink -f $0)
export SCRIPTPATH=`dirname $SCRIPT`
SCRIPTNAME=$(basename "$SCRIPT")

export STS_DIR=$SCRIPTPATH

if [ "$#" -lt 1 ]
then
  echo "Usage: ./$SCRIPTNAME <sdnracer-traces folder path> [<pattern for matching directories, default is \"trace_*\">]"
  echo "or     ./$SCRIPTNAME -i <single trace folder path>"
  exit 1
fi

# Note variables used here must have been exported before
run_per_trace_dir(){
  echo "Add to git in $1"
  pushd "$1" > /dev/null
  # add results
  git add gen_sh_format_results.out
  git add gen_sh_generate_results.out
  git add results_\*.dat
  git add \*summary.csv
  git add \*summary_tbl.csv
  popd > /dev/null
}
export -f run_per_trace_dir

trace_dirs_array=()
export IS_SINGLE_JOB=false
IS_OVERRIDE_NUM_THREADS=false
case "$1" in
  -i)
    if [ "$#" -eq 2 ]
    then
      trace_dirs_array+=("$2")
      export IS_SINGLE_JOB=true
    else
      echo "No trace directory specified for option -i"
      exit 1
    fi
    ;;
  -t)
    if [ "$#" -eq 4 ]
    then
      echo "-t Argument ignored"
      shift # shift arguments to the left
      shift
    else
      echo "Wrong number of arguments."
      exit 1
    fi
    ;& #fallthrough
  *)
    WORKSPACE=$1
    # set default value if not set
    MATCHPATTERN=${2:-"trace_*"}
    # get trace directories, reads NUL-terminated strings of filenames into an array. This is the only way to do it safely.
    # sort -z preserves NULs, -n sorts by name
    while IFS=  read -r -d $'\0'; do
      trace_dirs_array+=("$REPLY")
    done < <(find "$WORKSPACE" -maxdepth 1 -type d -name "$MATCHPATTERN" -print0 | sort -nz)
    ;;
esac

echo "${#trace_dirs_array[@]} directories to be processed:"
for i in "${trace_dirs_array[@]}"; do
  echo "  " "$i"
done;

func_call_by_name(){
  # no redirection, no tmpfile
  # call function $1 with all remaining arguments
  $1 "${@:2}"
}
export -f func_call_by_name

# How this works:
# (Equivalent to: parallel generate_plots ::: "${trace_dirs_array[@]}")
# 1. print each entry in the array followed by a NUL char (\x00)
# 2. xargs:
#    -0 handle NUL chars as delimiter
#    -i use {}
#    -n 1 pass at most 1 entry from the array to each process
#    -P N run N processes in parallel

if [ "${#trace_dirs_array[@]}" -gt 0 ]
then
  printf "%s\x00" "${trace_dirs_array[@]}" | xargs -0 -I{} -n 1 -P 1 bash -c 'func_call_by_name run_per_trace_dir {}'
fi
echo "Done."


