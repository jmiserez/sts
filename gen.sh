#!/bin/bash

result_dir=$1

rm -f "${result_dir}/*.dat"

x=10000;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --data-deps
x=10;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
x=9;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
x=8;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
x=7;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
x=6;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
x=5;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
x=4;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
x=3;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
x=2;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
x=1;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps
x=0;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr --hbt --data-deps

x=10000;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --data-deps
x=10;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
x=9;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
x=8;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
x=7;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
x=6;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
x=5;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
x=4;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
x=3;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
x=2;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
x=1;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps
x=0;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --hbt --data-deps

echo "Formatting results"

rm -f "${result_dir}/summary_results.csv"
rm -f "${result_dir}/summary_timings.csv"

./format_results.py ${result_dir}

#for i in traces/* ; do
#    if [ -d "$i" ]; then
#	echo "Happens before for ${i}"
#	dot -Tpdf ${i}/hb.dot -o ${i}/hb.pdf
#	./sts/happensbefore/hb_graph.py ${i}/hb.json > ${i}/hb.out
#    fi
#done
