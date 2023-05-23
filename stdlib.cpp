#define LIBRARY_FUNC_BC(name) ABI void INS_##name(PARAMS) { \
  DEBUG(#name);						    \
  unsigned char rb = instr & 0xff;			    \
  unsigned char rc = (instr >> 8) & 0xff;		    
#define LIBRARY_FUNC_BC_LOAD(name) LIBRARY_FUNC_BC(name) \
  long fb = frame[rb];					    \
  long fc = frame[rc];
#define LIBRARY_FUNC_B(name) ABI void INS_##name(PARAMS) {	\
  DEBUG(#name);						    \
  unsigned char rb = instr & 0xff;			    
#define LIBRARY_FUNC_D(name) ABI void INS_##name(PARAMS) {	\
  DEBUG(#name);						    \
  auto rd = (int16_t)instr;
#define LIBRARY_FUNC(name) ABI void INS_##name(PARAMS) {	\
  DEBUG(#name);						    
#define LIBRARY_FUNC_B_LOAD(name) LIBRARY_FUNC_B(name) \
  long fb = frame[rb];					    
#define LIBRARY_FUNC_B_LOAD_NAME(str, name) LIBRARY_FUNC_B_LOAD(name)
#define LIBRARY_FUNC_BC_LOAD_NAME(str, name) LIBRARY_FUNC_BC_LOAD(name)
#define LIBRARY_FUNC_BC_NAME(str, name) LIBRARY_FUNC_BC(name)
#define END_LIBRARY_FUNC pc++;NEXT_INSTR; }

#define TYPECHECK_TAG(val,tag)			\
  if(unlikely((val&TAG_MASK) != tag)) {		\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);	\
  }
#define TYPECHECK_FIXNUM(val) TYPECHECK_TAG(val, FIXNUM_TAG)

LIBRARY_FUNC_B(FUNC)
  // vararg
  //printf("FUNC vararg %i args %i argcnt %i\n", rb, ra, argcnt);
  if (rb) {
    if (argcnt < ra) {
      MUSTTAIL return FAIL_SLOWPATH_ARGCNT(ARGS);
    }
    frame[ra] = build_list(ra, argcnt -ra, frame);
  } else {
    if (argcnt != ra) {
      MUSTTAIL return FAIL_SLOWPATH_ARGCNT(ARGS);
    }
  }
END_LIBRARY_FUNC

LIBRARY_FUNC_D(KSHORT)
  frame[ra] = rd << 3;
END_LIBRARY_FUNC

LIBRARY_FUNC_D(JMP)
  pc += rd;
  NEXT_INSTR;
}

LIBRARY_FUNC(RET1)
  pc = (unsigned int *)frame[-1];
  frame[-1] = frame[ra];
  frame -= (INS_A(*(pc - 1)) + 1);

  NEXT_INSTR;
}

LIBRARY_FUNC(HALT)
  return;
}

// Note signed-ness of rc.
#define LIBRARY_FUNC_MATH_VN(name, op)		\
  LIBRARY_FUNC_B(name)				\
   char rc = (instr >> 8) & 0xff;		\
   long fb = frame[rb];				\
   if (unlikely(7 & fb)) {			\
     MUSTTAIL return FAIL_SLOWPATH(ARGS);	\
   }									\
   if (unlikely(__builtin_##op##_overflow(fb, (rc << 3), &frame[ra]))) {	\
     MUSTTAIL return FAIL_SLOWPATH(ARGS);				\
   }									\
END_LIBRARY_FUNC

LIBRARY_FUNC_MATH_VN(SUBVN, sub);
LIBRARY_FUNC_MATH_VN(ADDVN, add);

// Shift is necessary for adjusting the tag for mul.
#define LIBRARY_FUNC_MATH_VV(name, op, op2, shift)			\
ABI __attribute__((noinline)) void INS_##name##_SLOWPATH(PARAMS) {	\
  DEBUG(#name);								\
  unsigned char rb = instr & 0xff;					\
  unsigned char rc = (instr >> 8) & 0xff;				\
									\
  auto fb = frame[rb];							\
  auto fc = frame[rc];							\
  double x_b;								\
  double x_c;								\
  if ((fb&TAG_MASK) == FLONUM_TAG) {					\
    x_b = ((flonum_s*)(fb-FLONUM_TAG))->x;				\
  } else if ((fb&TAG_MASK) == FIXNUM_TAG) {				\
    x_b = fb >> 3;							\
  } else {								\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);				\
  }									\
  if ((fc&TAG_MASK) == FLONUM_TAG) {					\
    x_c = ((flonum_s*)(fc-FLONUM_TAG))->x;				\
  } else if ((fc&TAG_MASK) == FIXNUM_TAG) {				\
    x_c = fc >> 3;							\
  } else {								\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);				\
  }									\
									\
  auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));			\
  r->x = x_b op2 x_c;							\
  r->type = FLONUM_TAG;							\
  frame[ra] = (long)r|FLONUM_TAG;					\
  pc++;									\
									\
  NEXT_INSTR;								\
}									\
									\
 LIBRARY_FUNC_BC_LOAD(name)						\
  if (likely((7 & (fb | fc)) == 0)) {					\
    if (unlikely(__builtin_##op##_overflow(fb, fc >> shift, &frame[ra]))) { \
      MUSTTAIL return INS_##name##_SLOWPATH(ARGS);			\
    }									\
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {		\
    auto f1 = ((flonum_s*)(fb-FLONUM_TAG))->x;				\
    auto f2 = ((flonum_s*)(fc-FLONUM_TAG))->x;				\
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));			\
    r->x = f1 op2 f2;							\
    r->type = FLONUM_TAG;						\
    frame[ra] = (long)r|FLONUM_TAG;					\
  } else {								\
    MUSTTAIL return INS_##name##_SLOWPATH(ARGS);			\
  }									\
END_LIBRARY_FUNC							
 

LIBRARY_FUNC_MATH_VV(ADDVV,add,+, 0);
LIBRARY_FUNC_MATH_VV(SUBVV,sub,-, 0);
LIBRARY_FUNC_MATH_VV(MULVV,mul,*, 3);

LIBRARY_FUNC_D(GGET)
  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);
  if (unlikely(gp->val == UNDEFINED_TAG)) {
    MUSTTAIL return UNDEFINED_SYMBOL_SLOWPATH(ARGS);
  }
  frame[ra] = gp->val;
END_LIBRARY_FUNC

LIBRARY_FUNC_D(GSET)
  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);
  gp->val = frame[ra];
END_LIBRARY_FUNC

LIBRARY_FUNC_D(KFUNC)
  frame[ra] = (long)funcs[rd];
END_LIBRARY_FUNC

LIBRARY_FUNC_D(KONST)
  frame[ra] = const_table[rd];
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(MOV)
  frame[ra] = fb;
END_LIBRARY_FUNC

LIBRARY_FUNC_B(CALL)
  if (unlikely((hotmap[(((long)pc) >> 2) & hotmap_mask] -= hotmap_tail_rec) ==
               0)) {
    MUSTTAIL return RECORD_START(ARGS);
  }
  auto v = frame[ra];
  bcfunc *func = (bcfunc *)v;
  auto old_pc = pc;
  pc = &func->code[0];
  frame[ra] = long(old_pc + 1);
  frame += ra + 1;
  argcnt = rb - 1;
  if (unlikely((frame + 256) > frame_top)) {
    MUSTTAIL return EXPAND_STACK_SLOWPATH(ARGS);
  }

  NEXT_INSTR;
}

LIBRARY_FUNC_B(CALLT)
  if (unlikely((hotmap[(((long)pc) >> 2) & hotmap_mask] -= hotmap_tail_rec) ==
               0)) {
    MUSTTAIL return RECORD_START(ARGS);
  }
  auto v = frame[ra];
  bcfunc *func = (bcfunc *)v;
  pc = &func->code[0];

  long start = ra + 1;
  argcnt = rb - 1;
  for (auto i = 0; i < argcnt; i++) {
    frame[i] = frame[start + i];
  }
  // No need to stack size check for tailcalls since we reuse the frame.

  NEXT_INSTR;
}

LIBRARY_FUNC_BC_LOAD(EQ) 
  if (fb == fc) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }
END_LIBRARY_FUNC

LIBRARY_FUNC_BC(CONS)
  auto c = (cons_s *)GC_malloc(sizeof(cons_s));

  c->type = CONS_TAG;
  c->a = frame[rb];
  c->b = frame[rc];

  frame[ra] = (long)c|CONS_TAG;
END_LIBRARY_FUNC

#define LIBRARY_FUNC_CONS_OP(name, field)			\
 LIBRARY_FUNC_B_LOAD(name)			\
  TYPECHECK_TAG(fb, CONS_TAG);			\
  auto c = (cons_s*)(fb-CONS_TAG);		\
  frame[ra] = c->field;				\
END_LIBRARY_FUNC

LIBRARY_FUNC_CONS_OP(CAR,a);
LIBRARY_FUNC_CONS_OP(CDR,b);

LIBRARY_FUNC_BC_NAME(MAKE-VECTOR, MAKE_VECTOR)
  long fb = frame[rb];
  TYPECHECK_FIXNUM(fb);

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
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_NAME(MAKE-STRING, MAKE_STRING)
  long fb = frame[rb];
  TYPECHECK_FIXNUM(fb);
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
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(VECTOR-REF, VECTOR_REF)
  TYPECHECK_FIXNUM(fc);
  TYPECHECK_TAG(fb, PTR_TAG);
  auto vec = (vector_s*)(fb-PTR_TAG);
  if (unlikely(vec->type != VECTOR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = vec->v[fc>>3];
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(STRING-REF, STRING_REF)
  TYPECHECK_FIXNUM(fc);
  TYPECHECK_TAG(fb, PTR_TAG);
  auto str = (string_s*)(fb-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = (str->str[fc>>3] << 8)|CHAR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(VECTOR-LENGTH, VECTOR_LENGTH)
  TYPECHECK_TAG(fb, PTR_TAG);
  auto vec = (vector_s*)(fb-PTR_TAG);
  if (unlikely(vec->type != VECTOR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = vec->len << 3;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(STRING-LENGTH, STRING_LENGTH)
  TYPECHECK_TAG(fb, PTR_TAG);
  auto str = (string_s*)(fb-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = str->len << 3;
END_LIBRARY_FUNC
  
LIBRARY_FUNC_BC_LOAD_NAME(VECTOR-SET!, VECTOR_SET)
  auto fa = frame[ra];
  TYPECHECK_FIXNUM(fb);
  TYPECHECK_TAG(fa, PTR_TAG);
  auto vec = (vector_s*)(fa-PTR_TAG);
  if (unlikely(vec->type != VECTOR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  vec->v[fb >> 3] = fc;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(STRING-SET!, STRING_SET)
  auto fa = frame[ra];
  if (unlikely((fa & 0x7) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  TYPECHECK_FIXNUM(fb);
  if (unlikely((fc&IMMEDIATE_MASK) != CHAR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto str = (string_s*)(fa-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  str->str[fb >> 3] = (fc >> 8)&0xff;
END_LIBRARY_FUNC

#define LIBRARY_FUNC_CONS_SET_OP(str, name, field)	\
  LIBRARY_FUNC_B_LOAD_NAME(str, name)			\
  auto fa = frame[ra];				\
  if (unlikely((fa & 0x7) != CONS_TAG)) {	\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);	\
  }						\
  auto cons = (cons_s*)(fa-CONS_TAG);		\
  cons->field = fb;				\
END_LIBRARY_FUNC

LIBRARY_FUNC_CONS_SET_OP(SET-CAR!, SET_CAR,a);
LIBRARY_FUNC_CONS_SET_OP(SET-CDR!, SET_CDR,b);

LIBRARY_FUNC_BC_LOAD(WRITE)
  if (unlikely((fc&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fc-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  print_obj(fb, port->file);
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(WRITE-U8, WRITE_U8)
  if (unlikely((fc&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fc-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  TYPECHECK_FIXNUM(fb);
  long byte = fb >> 3;
  unsigned char b = byte;
  if (unlikely(byte >= 256)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  
  fwrite(&b, 1, 1, port->file);
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(WRITE-DOUBLE, WRITE_DOUBLE)
  if (unlikely((fc&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fc-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (unlikely((fb&TAG_MASK) != FLONUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto flo = (flonum_s*)(fb - FLONUM_TAG);
  
  fwrite(&flo->x, sizeof(flo->x), 1, port->file);
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(SYMBOL->STRING, SYMBOL_STRING)
  if (unlikely((fb&TAG_MASK) != SYMBOL_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto sym = (symbol*)(fb - SYMBOL_TAG);
  frame[ra] = (long)sym->name + PTR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(STRING->SYMBOL, STRING_SYMBOL)
  if (unlikely((fb&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto str = (string_s*)(fb-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto res = symbol_table_find(str);
  if (!res) {
    // Build a new symbol.
    // Must dup the string, since strings are not immutable.
    auto strlen = str->len;
    auto sym = (symbol *)GC_malloc(sizeof(symbol));
    sym->type = SYMBOL_TAG;

    // Note re-load of str after allocation.
    sym->name = (string_s*)(frame[rb]-PTR_TAG);
    sym->val = UNDEFINED_TAG;

    // Save new symbol in frame[ra].
    frame[ra] = (long)sym + SYMBOL_TAG;
    
    // DUP the string, so that this one is immutable.
    // Note that original is in sym->name temporarily
    // since ra could be eq to rb.
    auto str2 = (string_s*)GC_malloc(16 + strlen + 1);
    // Re-load sym after GC
    sym = (symbol*)(frame[ra]-SYMBOL_TAG);
    
    // Re-load str after GC
    str = (string_s*)sym->name;
    
    str2->type = STRING_TAG;
    str2->len = strlen;
    memcpy(str2->str, str->str, strlen);
    
    sym->name = str2;
    symbol_table_insert(sym);
  } else {
    frame[ra] = (long)res + SYMBOL_TAG;
  }
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(CHAR->INTEGER, CHAR_INTEGER)
  if (unlikely((fb&IMMEDIATE_MASK) != CHAR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = fb >> 5;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(INTEGER->CHAR, INTEGER_CHAR)
  TYPECHECK_FIXNUM(fb);
  frame[ra] = (fb << 5) + CHAR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC(OPEN)
  auto fc = frame[rc];
  if (unlikely((fc&IMMEDIATE_MASK) != BOOL_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  auto port = (port_s*)GC_malloc(sizeof(port_s));
  // Load FB (potentially a ptr) after GC
  auto fb = frame[rb];
  
  port->type = PORT_TAG;
  port->input_port = fc;

  if ((fb&TAG_MASK) == FIXNUM_TAG) {
    port->fd = frame[rb] >>3; 
  } else if ((fb&TAG_MASK) == PTR_TAG) {
    auto str = (string_s*)(fb - PTR_TAG);
    if (unlikely(str->type != STRING_TAG)) {
      MUSTTAIL return FAIL_SLOWPATH(ARGS);
    }
    port->fd = open(str->str, fc == TRUE_REP? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (port->fd == -1) {
      printf("Could not open fd for file %s\n", str->str);
      exit(-1);
    }
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  port->file = fdopen(port->fd, fc == TRUE_REP ? "r" : "w");
  if (port->file == nullptr) {
    printf("FDopen fail\n");
    exit(-1);
  }
  port->peek = FALSE_REP;
  frame[ra] = (long)port + PTR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(CLOSE)
  if (unlikely((fb&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fb-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (port->file) {
    fclose(port->file);
    port->file = nullptr;
  }
  if (port->fd != -1) {
    close(port->fd);
    port->fd = -1;
  }
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(PEEK)
  if (unlikely((fb&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fb-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (port->peek != FALSE_REP) {
  } else {
    uint8_t b;
    long res = fread(&b, 1, 1, port->file);
    if (res == 0) {
      port->peek = EOF_TAG;
    } else {
      port->peek = (((long)b) << 8) + CHAR_TAG;
    }
  }
  frame[ra] = port->peek;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(READ)
  if (unlikely((fb&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fb-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (port->peek != FALSE_REP) {
    frame[ra] = port->peek;
    port->peek = FALSE_REP;
  } else {
    uint8_t b;
    long res = fread(&b, 1, 1, port->file);
    if (res == 0) {
      frame[ra] = EOF_TAG;
    } else {
      frame[ra] = (((long)b) << 8) + CHAR_TAG;
    }
  }
END_LIBRARY_FUNC
  
LIBRARY_FUNC_B_LOAD(INEXACT)
  if ((fb&TAG_MASK) == FIXNUM_TAG) {
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->type = FLONUM_TAG;
    r->x = fb>>3;
    frame[ra] = (long)r + FLONUM_TAG;
  } else if ((fb&TAG_MASK) == FLONUM_TAG) {
    frame[ra] = fb;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(EXACT)
  if ((fb&TAG_MASK) == FIXNUM_TAG) {
    frame[ra] = fb;
  } else if ((fb&TAG_MASK) == FLONUM_TAG) {
    auto flo = (flonum_s*)(fb - FLONUM_TAG);
    frame[ra] = ((long)flo->x) << 3;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(ROUND)
  if ((fb&TAG_MASK) == FIXNUM_TAG) {
    frame[ra]  =fb;
  } else if ((fb&TAG_MASK) == FLONUM_TAG) {
    auto flo = (flonum_s*)(fb - FLONUM_TAG);
    auto res = roundeven(flo->x);
    
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->type = FLONUM_TAG;
    r->x = res;
    frame[ra] = (long)r + FLONUM_TAG;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
END_LIBRARY_FUNC

#define LIBRARY_FUNC_FLONUM_MATH(name, func)	\
  LIBRARY_FUNC_B_LOAD(name)			\
  if ((fb&TAG_MASK) == FLONUM_TAG) {		\
    auto flo = (flonum_s*)(fb - FLONUM_TAG);	\
    auto res = func(flo->x);				\
							\
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));	\
    r->type = FLONUM_TAG;				\
    r->x = res;						\
    frame[ra] = (long)r + FLONUM_TAG;			\
  } else {						\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);		\
  }							\
END_LIBRARY_FUNC

LIBRARY_FUNC_FLONUM_MATH(SIN, sin);
LIBRARY_FUNC_FLONUM_MATH(SQRT, sqrt);
LIBRARY_FUNC_FLONUM_MATH(ATAN, atan);
LIBRARY_FUNC_FLONUM_MATH(COS, cos);

LIBRARY_FUNC(CALLCC)
  auto sz = frame-stack;
  auto cont = (vector_s*)GC_malloc(sz*sizeof(long) + 16);
  cont->type = CONT_TAG;
  cont->len = sz;
  memcpy(cont->v, stack, sz*sizeof(long));

  frame[ra] = (long)cont | PTR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(CALLCC-RESUME, CALLCC_RESUME)
  TYPECHECK_TAG(fb, PTR_TAG);
  auto cont = (vector_s*)(fb-PTR_TAG);
  if (unlikely(cont->type != CONT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  memcpy(stack, cont->v, cont->len*sizeof(long));
  frame = &stack[cont->len];
  
  frame[ra] = (long)cont | PTR_TAG;

  // DO A RET
  pc = (unsigned int *)frame[-1];
  frame[-1] = fc;
  frame -= (INS_A(*(pc - 1)) + 1);

  NEXT_INSTR;
}
