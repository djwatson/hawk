function(add_hawk_test name file regex)
  add_test(
    NAME ${name}
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/${file}
  )
  if(NOT "${regex}" STREQUAL "")
    set_tests_properties(${name} PROPERTIES PASS_REGULAR_EXPRESSION "${regex}")
  endif()
endfunction()

add_hawk_test(hawk_sum sum.scm "500000000500000000")
add_hawk_test(hawk_sumfp sumfp.scm "2.5000025e14")
add_hawk_test(hawk_summix summix.scm "50000000500000005.00000005e155000000050000000")
add_hawk_test(hawk_sum1 sum1.scm "500001500001")
add_hawk_test(hawk_sumloop sumloop.scm "1000000000")
add_hawk_test(hawk_tak tak.scm "12")
add_hawk_test(
  hawk_takl
  takl.scm
  "\\(6 5 4 3 2 1\\).*\n\\(7 6 5 4 3 2 1\\).*\n\\(10 9 8 7 6 5 4 3 2 1\\).*\n\\(13 12 11 10 9 8 7 6 5 4 3 2 1\\)"
)
add_hawk_test(hawk_cpstak cpstak.scm "RESULT: 9")
add_hawk_test(hawk_ack ack.scm "32765")
add_hawk_test(hawk_fib fib.scm "102334155")
add_hawk_test(hawk_fibfp fibfp.scm "9227465.0")
add_hawk_test(hawk_diviter diviter.scm "500")
add_hawk_test(hawk_divrec divrec.scm "500")
add_hawk_test(hawk_nqueens nqueens.scm "73712")
add_hawk_test(hawk_primes primes.scm "\\(2 3 5 7 11 13.*983 991 997\\)")
add_hawk_test(hawk_array2 array2.scm "1000000")
add_hawk_test(hawk_loopcheck loopcheck.scm "")
add_hawk_test(hawk_deriv deriv.scm "\\(\\+ \\(\\* \\(\\* 3 x x\\)")
add_hawk_test(hawk_quicksort quicksort.scm "")
add_hawk_test(hawk_pnpoly pnpoly.scm "6")
add_hawk_test(hawk_triangl triangl.scm "\\(22 34 31 15 7 1 20 17 25 6 5 13 32\\)")
add_hawk_test(hawk_simplex simplex.scm "\\(#\\(4 1 3 2\\) #\\(0 5 7 6\\)\\)")
add_hawk_test(hawk_perm9 perm9.scm "16329600")
add_hawk_test(hawk_fft fft.scm "0\\.0")
add_hawk_test(hawk_mbrot mbrot.scm "5")
add_hawk_test(
  hawk_r5rs_pitfall
  r5rs_pitfall.scm
  "Map is call/cc safe, but probably not tail recursive or inefficient\\."
)
set_tests_properties(hawk_r5rs_pitfall PROPERTIES FAIL_REGULAR_EXPRESSION "Failure")

add_hawk_test(
  hawk_r5rs_tests
  r5rs-tests.scm
  "188 out of 188 passed \\(100%\\)"
)
set_tests_properties(hawk_r5rs_tests PROPERTIES FAIL_REGULAR_EXPRESSION "Failure")

add_hawk_test(hawk_r7rs_tests r7rs-tests.scm "")
set_tests_properties(hawk_r7rs_tests PROPERTIES FAIL_REGULAR_EXPRESSION "FAIL")

add_hawk_test(hawk_r7rs_tests2 r7rs-tests2.scm "")
set_tests_properties(hawk_r7rs_tests2 PROPERTIES FAIL_REGULAR_EXPRESSION "FAIL")

add_hawk_test(hawk_ports ports.scm "")
set_tests_properties(hawk_ports PROPERTIES FAIL_REGULAR_EXPRESSION "FAIL")
