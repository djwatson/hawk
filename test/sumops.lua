function lt(m, n)
	 return m < n
 end
    
function add(m, n)
	 return m + n
 end

function sub(m, n)
	 return m - n
 end


function sum(m, suma)
if lt(m,0) then
    return suma
    else
      return sum(sub(m,1), add(suma,m))
    end
end

print(sum(1000000000, 0))
