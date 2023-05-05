function do_append(x, g)
	 if (nil == x) then
	    return g
	 end
	 return {x[1], do_append(x[2], g)}
end

	 function one_to_n(n)
	    ret = nil
	    for i=n,1,-1 do
	       ret = {i, ret}
	    end
	    return ret
	 end
	 function my_try(x, y, z)
	 	  if (nil == x) then
		     if (nil == y) then
			return 1
		     else
		        return 0
	             end
		  else
		     rest = 0
		     if (ok(x[1], 1, z)) then
		        rest = my_try(do_append(x[2], y), nil, {x[1], z})
		     end
		     return rest + my_try(x[2], {x[1], y}, z)
		  end
	 end
	 function ok(row, dist, placed)
	 	  if (placed == nil) then
		     return true
		  end
		  return (not (placed[1] == (row + dist))) and
		      (not (placed[1] == (row - dist))) and
		      ok(row, dist + 1, placed[2])
	 end
function nqueens(n)
	 		        collectgarbage("setpause",500000)
	 return my_try(one_to_n(n), nil, nil)
end

print(nqueens(13))