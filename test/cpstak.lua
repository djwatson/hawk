function cpstak(x, y, z)
 function tak(x, y, z, k)
    if(y >= x) then
      return k(z)
    else
      
      local c1 = function(v1)
        local c2 = function(v2)
	  local c3 = function(v3)
	    return tak(v1, v2, v3, k)
	  end
	  return tak(z-1, x, y, c3)
	end
        return tak(y-1, z, x, c2)
      end
      return tak(x-1, y, z, c1)
    end
  end
  local c = function(a) return a end
  return  tak(x, y, z, c)
end

print(cpstak(32, 16, 8))