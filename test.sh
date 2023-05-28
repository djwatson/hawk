#make -j
for file in $(ls test/bench/*.scm)
do
    echo $file
    ./boom $file 
    echo
done
