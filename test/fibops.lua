function lt(m, n)
	 return m < n
 end
    
function add(m, n)
	 return m + n
 end

function sub(m, n)
	 return m - n
 end

function fib(m)
    if lt(m,2) then
      return m
    end
    return add(fib(sub(m,1)), fib(sub(m, 2)))
end

print(fib(40))
