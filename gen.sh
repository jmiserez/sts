#!/bin/bash

generate_results(){
  if [ -z "$result_dir" ]; then exit 1; fi

  rm -f "${result_dir}"/*.dat


#  echo "==============================================="
#  echo "Running HB Graph with alt-barr and delta=inf"
#  echo "==============================================="
#  ./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --no-dot-files --pkt --alt-barr --data-deps
#  for x in {0..10};
#  do
#    echo "=============================================="
#    echo "Running HB Graph with alt-barr and delta=$x"
#    echo "=============================================="
#    ./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --no-dot-files --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
#  done

  echo "==============================================="
  echo "Running HB Graph WITHOUT alt-barr and delta=inf"
  echo "==============================================="
  ./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --no-dot-files --pkt --data-deps
  for x in {0..10};
  do
    echo "=============================================="
    echo "Running HB Graph WITHOUT alt-barr and delta=$x"
    echo "=============================================="
    ./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --no-dot-files --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
  done

}

format_results(){
  if [ -z "$result_dir" ]; then exit 1; fi
  echo "Formatting results"

  rm -f "${result_dir}/summary.csv"
  rm -f "${result_dir}/summary_timings.csv"
  rm -f "${result_dir}/summary_tbl.csv"
  rm -f "${result_dir}/summary_timings_tbl.csv"

  ./format_results.py ${result_dir}

  if [[ ${INRUN} ]];
  then
    echo "Backing up"
    mv "${result_dir}/summary_timings_tbl.csv" "${result_dir}/summary_timings_tbl_run_${INRUN}.csv"
  fi
}

case "$1" in
  -n)
    if [ "$#" -eq 2 ]
    then
      result_dir=$2
      format_results
    else
      echo "No trace directory specified for option -n"
      exit 1
    fi
    ;;
  *)
    result_dir=$1
    generate_results
    format_results
    ;;
esac

#for i in traces/* ; do
#    if [ -d "$i" ]; then
#	echo "Happens before for ${i}"
#	dot -Tpdf ${i}/hb.dot -o ${i}/hb.pdf
#	./sts/happensbefore/hb_graph.py ${i}/hb.json > ${i}/hb.out
#    fi
#done
