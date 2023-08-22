#make -j
for file in $(ls test/bench/*.scm)
do
    echo $file
    ./boom --heap-sz=1000000 $file |grep Traces
    echo
done
