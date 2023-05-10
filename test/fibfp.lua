function fib(m)
    if m < 2.0 then
      return m
    end
    return fib(m-1.0) + fib(m-2.0)
end

fib(40.0)
