#!/bin/bash
SCRIPT=$(readlink -f $0)
SCRIPTPATH=`dirname $SCRIPT`
(
	pushd "$1";
	(
		"$SCRIPTPATH/../sts/happensbefore/hb_graph.py" hb.json | tee hb.out && dot -Tpdf hb.dot -o hb.pdf && xdot hb.dot
	);
	popd
)
