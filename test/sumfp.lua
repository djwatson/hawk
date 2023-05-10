function sum(m, suma)
if m < 0.0 then
    return suma
    else
      return sum(m-1.0, suma+m)
    end
end

print(sum(1000000000.0, 0.0))
