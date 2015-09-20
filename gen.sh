#!/bin/bash



result_dir=$1


x=10000;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr 
x=10;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt
x=9;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt
x=8;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt
x=7;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt
x=6;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt
x=5;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt
x=4;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt
x=3;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt
x=2;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt
x=1;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt
x=0;./sts/happensbefore/hb_graph.py ${result_dir}/hb.json  --pkt --rw_delta=$x --ww_delta=$x --alt-barr  --hbt

echo "Formatting results"

./format_results.py ${result_dir}

#for i in traces/* ; do
#    if [ -d "$i" ]; then
#	echo "Happens before for ${i}"
#	dot -Tpdf ${i}/hb.dot -o ${i}/hb.pdf
#	./sts/happensbefore/hb_graph.py ${i}/hb.json > ${i}/hb.out
#    fi
#done
