#!/bin/bash

for i in {1..100}
do
	cargo test "$1"
	if [ $? -ne 0 ]
	then
		break
	fi
done

