	  function c3(v3, args)
	    return tak(args[1], args[2], v3, args[3], args[4])
	  end

function c2(v2, args)
        return tak(args[3] - 1, args[1], args[2], c3, {args[4], v2, args[5], args[6]})
	end


function c1(v1, args)
      return tak(args[2]-1, args[3], args[1], c2, {args[1], args[2], args[3], v1, args[4], args[5]})
    end

function tak(x, y, z, kptr, kargs)
    if(y >= x) then
      return kptr(z, kargs)
    else
         return tak(x-1, y, z, c1, {x, y, z, kptr, kargs})
     end
      
  end

function c(a, args) return a end

function cpstak(x, y, z)
  return  tak(x, y, z, c, {})
end

print(cpstak(32, 16, 8))