#define LIBRARY_FUNC_BC(name) ABI void INS_##name(PARAMS) {	\
  DEBUG(#name);						    \
  unsigned char rb = instr & 0xff;			    \
  unsigned char rc = (instr >> 8) & 0xff;		    
#define LIBRARY_FUNC_BC_LOAD(name) LIBRARY_FUNC_BC(name) \
  long fb = frame[rb];					    \
  long fc = frame[rc];
#define LIBRARY_FUNC_B(name) ABI void INS_##name(PARAMS) {	\
  DEBUG(#name);						    \
  unsigned char rb = instr & 0xff;			    
#define LIBRARY_FUNC_B_LOAD(name) LIBRARY_FUNC_B(name) \
  long fb = frame[rb];					    
  

#define LIBRARY_FUNC_END pc++;NEXT_INSTR; }

LIBRARY_FUNC_BC_LOAD(EQ) 
  if (fb == fc) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }
LIBRARY_FUNC_END

LIBRARY_FUNC_BC(CONS)
  auto c = (cons_s *)GC_malloc(sizeof(cons_s));

  c->type = CONS_TAG;
  c->a = frame[rb];
  c->b = frame[rc];

  frame[ra] = (long)c|CONS_TAG;
LIBRARY_FUNC_END

#define CONS_OP(name, field)			\
  LIBRARY_FUNC_B_LOAD(name)			\
  if(unlikely((fb&TAG_MASK) != CONS_TAG)) {	\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);	\
  }						\
  auto c = (cons_s*)(fb-CONS_TAG);		\
  frame[ra] = c->field;				\
LIBRARY_FUNC_END

CONS_OP(CAR,a);
CONS_OP(CDR,b);

LIBRARY_FUNC_BC(MAKE_VECTOR)
  long fb = frame[rb];
  if(unlikely((fb&TAG_MASK) != FIXNUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto len = fb>>3;
  auto vec = (vector_s*)GC_malloc( sizeof(long) * (len + 2));
  // Load frame[rc] *after* GC
  long fc = frame[rc];
  vec->type = VECTOR_TAG;
  vec->len = len;
  for(long i = 0; i < len; i++) {
    vec->v[i] = fc;
  }
  
  frame[ra] = (long)vec | PTR_TAG;
LIBRARY_FUNC_END

LIBRARY_FUNC_BC(MAKE_STRING)
  long fb = frame[rb];
  if(unlikely((fb&TAG_MASK) != FIXNUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto len = fb>>3;
  auto str = (string_s*)GC_malloc( (sizeof(long) * 2) + len + 1);
  
  long fc = frame[rc]; // Load fc after GC
  if(unlikely((fc&IMMEDIATE_MASK) != CHAR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  
  str->type = STRING_TAG;
  str->len = len;
  for(long i = 0; i < len; i++) {
    str->str[i] = (fc >> 8)&0xff;
  }
  str->str[len] = '\0';
  
  frame[ra] = (long)str | PTR_TAG;
LIBRARY_FUNC_END
