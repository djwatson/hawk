#make -j
for file in $(ls test/bench2/*.scm)
do
    echo $file
    ./boom -p -v --heap-sz=1000000 $file |grep -F -e abort  -e NYI -e Traces -e gc -e VM|sort|uniq -c|sort -n
    #./boom $file -p|grep -i -e trace -e gc -e VM
    echo
done
