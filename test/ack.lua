function ack(m, n)
    if m == 0 then
      return(n + 1)
    elseif n == 0 then
      return(ack(m-1, 1))
    else
      return ack(m-1, ack(m, n-1))
    end
end

print(ack(3, 13))
