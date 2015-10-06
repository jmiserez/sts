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
run_per_trace_dir() {
#  echo "Generating plots for trace $1"
  pushd "$STS_DIR" > /dev/null
  echo "./plot.py $1"
  ./plot.py "$1"
  popd > /dev/null
}
export -f run_per_trace_dir

trace_dirs_array=()
export IS_SINGLE_JOB=false
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

echo "Directories to be processed:"
for i in "${trace_dirs_array[@]}"; do
  echo "  " "$i"
done;

pidtree(){
  pids_for_ppid=(); while read pid ppid; do pids_for_ppid[$ppid]+=" $pid"; done < <(ps -e -o pid,ppid --no-headers)
  print_children(){ for i in ${pids_for_ppid[$1]}; do ( (print_children $i) ); echo $i; done }
  ( (print_children $1) ); echo $1
}
export -f pidtree

# create tmp directory
export CURRENT_TMP_DIR=`mktemp -d`
# set trap to cleanup upon exit/CTRL-C. Note: not triggered when using kill -9.
trap 'for i in $CURRENT_TMP_DIR/*.pid; do kill $(pidtree $(basename "${i%.pid}")) >> /dev/null 2>&1; rm -f "$i"; done; rm -rf "$CURRENT_TMP_DIR"' EXIT

func_call_by_name(){
  if [ "$IS_SINGLE_JOB" = true ]
  then
    # no redirection, no tmpfile
    # call function $1 with all remaining arguments
    $1 "${@:2}" & FUNC_PID=$!; touch "$CURRENT_TMP_DIR/$FUNC_PID.pid"; wait $FUNC_PID; rm -f "$CURRENT_TMP_DIR/$FUNC_PID.pid"
  else
    # redirect output to tmpfile, then print out once done
    FUNC_CALL_OUTPUT_TMPFILE=$(mktemp --tmpdir="$CURRENT_TMP_DIR")
#    echo "Storing output temporarily in $FUNC_CALL_OUTPUT_TMPFILE"
    $1 "${@:2}" >> "$FUNC_CALL_OUTPUT_TMPFILE" 2>&1 & FUNC_PID=$!; touch "$CURRENT_TMP_DIR/$FUNC_PID.pid"; wait $FUNC_PID; rm -f "$CURRENT_TMP_DIR/$FUNC_PID.pid"
    # print output once done, if file still exists
    [[ -f "$FUNC_CALL_OUTPUT_TMPFILE" ]] && cat "$FUNC_CALL_OUTPUT_TMPFILE"
    # remove temp file
    rm -f "$FUNC_CALL_OUTPUT_TMPFILE"
  fi
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

NUM_CPU_CORES=$(cat /proc/cpuinfo | egrep ^processor | wc -l)
case $NUM_CPU_CORES in
    ''|*[!0-9]*)
      # not a number, let's set it to 1
      NUM_CPU_CORES=1
      ;;
    *)
      if [ "$NUM_CPU_CORES" -lt 1 ]
      then
        NUM_CPU_CORES=1
      fi
      ;;
esac
echo "NUM_CPU_CORES=$NUM_CPU_CORES"

printf "%s\x00" "${trace_dirs_array[@]}" | xargs -0 -I{} -n 1 -P $NUM_CPU_CORES bash -c 'func_call_by_name run_per_trace_dir {}'

if [ "$IS_SINGLE_JOB" = true ]
  then
    :
  else
    rm -rf "$CURRENT_TMP_DIR"
fi
