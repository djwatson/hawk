# Cool stuff found in luajit:

* The IR implicitly(and a bit explicitly) lists which registers are 'dead'. DCE is pretty easy.  
  * Since snapshots hold open slots, this is important.
  
* Loops: reifying loops is important not for any bytecode or IR reason, but for Tracing to trace loops, and ignore loops called only once.

* 'closures' are never Jited in luajit.  Important to do register allocatoin load/store/load/store vs. loadloadloadstorestorestore, for better register usage.

* non-tail-recursion is hard
* register usage at trace entry/exit
* polymorphic vs. monomorphic closures - detect as runtime feedback in VM.   No particular need for strong closure analysis up front?
* same with global/toplevel vars.
   
