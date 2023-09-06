#make -j
for file in $(ls test/bench2/*.scm)
do
    echo $file
    #./boom -v --heap-sz=1000000 $file |grep -F -e abort  -e NYI -e Traces|sort|uniq -c|sort -n
    ./boom $file -p|grep -i -e trace -e gc -e VM
    echo
done
