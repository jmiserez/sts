#!/bin/bash


TRACES="$@"
SUMMARY_FILE=summary_tbl.csv
TIMINGS_FILE=summary_timings_tbl.csv
CROSS_FILE=cross_summary.csv
CROSS_TIMINGS_FILE=cross_summary_timings.csv
HEADER=

# Clear previous files
rm ${CROSS_FILE}
rm ${CROSS_TIMINGS_FILE}
touch ${CROSS_FILE}
touch ${CROSS_TIMINGS_FILE}


function read_files {
 folder=$1
 file=$2
 outfile=$3

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
    echo "app,controller,topology,steps,${header}" > ${outfile}
  fi

  app=$(basename "${folder}")
  app="${app/trace_/}"
  controller="UNKNOWN"
  topology="UNKOWN"
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
   *"onos"*)
    controller='onos'
    app="${app/onos_/}"
   ;;
  esac

  case $app in
   *"StarTopology2"*)
    topology="Star2"
    app="${app/StarTopology2-/}"
    ;;
   *"MeshTopology2"*)
    topology="Mesh2"
    app="${app/MeshTopology2-/}"
    ;;
   *"BinaryLeafTreeTopology1"*)
    topology="BinTree1"
    app="${app/BinaryLeafTreeTopology1-/}"
    ;;
   *"BinaryLeafTreeTopology2"*)
    topology="BinTree2"
    app="${app/BinaryLeafTreeTopology2-/}"
    ;;
   esac

 steps="${app/*-steps/}"
 app="${app/-steps[[:digit:]]*/}"
 app="${app/l2_multi/forwarding}"

 # Actually read the file
  while read -r line
  do
    if [ $line == $HEADER ]; then
      # Skip header
      continue;
    fi
    echo "${app},${controller},${topology},${steps},${line}" >> ${outfile}
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
done;

HEADER=

for trace in $TRACES;
do
  if [ ! -e ${trace}/${TIMINGS_FILE} ];
  then
    >&2 echo "no timing summary in ${trace}"
    continue
  fi

  read_files $trace $TIMINGS_FILE $CROSS_TIMINGS_FILE
done;
