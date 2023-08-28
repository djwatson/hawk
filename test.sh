#make -j
for file in $(ls test/bench/*.scm)
do
    echo $file
    ./boom -v --heap-sz=1000000 $file |grep -F  -e "Non-const make-vector" -e NYI -e Traces|sort|uniq -c|sort -n
    echo
done
