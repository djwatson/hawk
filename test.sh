for file in $(ls test/bench/*.scm)
do
    echo $file
    ./boomc < $file > /dev/null
    make 2>&1 > /dev/null
    ./boom
done
