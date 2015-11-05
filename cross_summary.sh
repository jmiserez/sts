#!/bin/bash


TRACES="$@"
SUMMARY_FILE=summary_tbl.csv
TIMINGS_FILE=summary_timings_tbl.csv
CROSS_FILE=cross_summary.csv
CROSS_TIMINGS_FILE=cross_summary_timings.csv

# Clear previous files
rm ${CROSS_FILE}
rm ${CROSS_TIMINGS_FILE}
touch ${CROSS_FILE}
touch ${CROSS_TIMINGS_FILE}


function read_files {
 folder=$1
 file=$2
 outfile=$3
 HEADER=

 >&2 echo "Reading ${folder}/${file}"
 >&2 echo "Saving to ${outfile}"

  header=`head -n1 "${folder}/${file}"`
  if [ $HEADER ];
  then
    if [ $HEADER != $header ];
    then
      >&2 echo "Found unexpected HEADER: ${header}"
      >&2 echo "While expecting: ${HEADER}"
      exit -1
    fi
  else
    HEADER=$header
    echo "app,controller,${header}" > ${outfile}
  fi

  app=$(basename "${folder}")
  app="${app/trace_/}"
  controller="UNKNOWN"
  case $app in
   *"pox_eel"*)
    controller='POX_EEL'
    app="${app/pox_eel_/}"
   ;;
   *"pox"*)
    controller='POX'
    app="${app/pox_/}"
   ;;
   *"floodlight"*)
    controller='floodlight'
    app="${app/floodlight_/}"
   ;;
  esac
 # Actually read the file
  while read -r line
  do
    if [ $line == $HEADER ]; then
      # Skip header
      continue;
    fi
    echo "${app},${controller},${line}" >> ${outfile}
  done < ${folder}/${file}
}


for trace in $TRACES;
do
  if [ ! -e ${trace}/${SUMMARY_FILE} ];
  then
    >&2 echo "no summary in ${trace}"
    continue
  fi

  read_files $trace $SUMMARY_FILE $CROSS_FILE
  read_files $trace $TIMINGS_FILE $CROSS_TIMINGS_FILE
done;
