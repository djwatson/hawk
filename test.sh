make -j
for file in $(ls test/bench/*.scm)
do
    echo $file
    time ./boom $file 
    echo
done
