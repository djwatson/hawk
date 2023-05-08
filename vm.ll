; ModuleID = 'vm.cpp'
source_filename = "vm.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%"class.std::vector" = type { %"struct.std::_Vector_base" }
%"struct.std::_Vector_base" = type { %"struct.std::_Vector_base<bcfunc *, std::allocator<bcfunc *>>::_Vector_impl" }
%"struct.std::_Vector_base<bcfunc *, std::allocator<bcfunc *>>::_Vector_impl" = type { %"struct.std::_Vector_base<bcfunc *, std::allocator<bcfunc *>>::_Vector_impl_data" }
%"struct.std::_Vector_base<bcfunc *, std::allocator<bcfunc *>>::_Vector_impl_data" = type { %struct.bcfunc**, %struct.bcfunc**, %struct.bcfunc** }
%struct.bcfunc = type { %"class.std::vector.0", %"class.std::vector.5" }
%"class.std::vector.0" = type { %"struct.std::_Vector_base.1" }
%"struct.std::_Vector_base.1" = type { %"struct.std::_Vector_base<unsigned int, std::allocator<unsigned int>>::_Vector_impl" }
%"struct.std::_Vector_base<unsigned int, std::allocator<unsigned int>>::_Vector_impl" = type { %"struct.std::_Vector_base<unsigned int, std::allocator<unsigned int>>::_Vector_impl_data" }
%"struct.std::_Vector_base<unsigned int, std::allocator<unsigned int>>::_Vector_impl_data" = type { i32*, i32*, i32* }
%"class.std::vector.5" = type { %"struct.std::_Vector_base.6" }
%"struct.std::_Vector_base.6" = type { %"struct.std::_Vector_base<unsigned long, std::allocator<unsigned long>>::_Vector_impl" }
%"struct.std::_Vector_base<unsigned long, std::allocator<unsigned long>>::_Vector_impl" = type { %"struct.std::_Vector_base<unsigned long, std::allocator<unsigned long>>::_Vector_impl_data" }
%"struct.std::_Vector_base<unsigned long, std::allocator<unsigned long>>::_Vector_impl_data" = type { i64*, i64*, i64* }
%struct.symbol = type { %"class.std::__cxx11::basic_string", i64 }
%"class.std::__cxx11::basic_string" = type { %"struct.std::__cxx11::basic_string<char>::_Alloc_hider", i64, %union.anon }
%"struct.std::__cxx11::basic_string<char>::_Alloc_hider" = type { i8* }
%union.anon = type { i64, [8 x i8] }

$_ZNSt6vectorIP6bcfuncSaIS1_EED2Ev = comdat any

@joff = dso_local local_unnamed_addr global i32 0, align 4, !dbg !0
@funcs = dso_local global %"class.std::vector" zeroinitializer, align 8, !dbg !532
@__dso_handle = external hidden global i8
@.str.1 = private unnamed_addr constant [27 x i8] c"FAIL undefined symbol: %s\0A\00", align 1
@stacksz = dso_local local_unnamed_addr global i32 1000, align 4, !dbg !534
@stack = dso_local local_unnamed_addr global i64* null, align 8, !dbg !536
@.str.3 = private unnamed_addr constant [28 x i8] c"Expand stack from %i to %i\0A\00", align 1
@hotmap = dso_local local_unnamed_addr global [64 x i8] zeroinitializer, align 16, !dbg !538
@.str.4 = private unnamed_addr constant [12 x i8] c"Result:%li\0A\00", align 1
@_ZL9frame_top = internal unnamed_addr global i64* null, align 8, !dbg !556
@.str.5 = private unnamed_addr constant [30 x i8] c"UNIMPLEMENTED INSTRUCTION %s\0A\00", align 1
@ins_names = external local_unnamed_addr global [0 x i8*], align 8
@_ZL8op_table = internal global [25 x void (i8, i32, i32*, i64*, i8**)*] zeroinitializer, align 16, !dbg !558
@_ZL5frame = internal unnamed_addr global i64* null, align 8, !dbg !563
@llvm.global_ctors = appending global [1 x { i32, void ()*, i8* }] [{ i32, void ()*, i8* } { i32 65535, void ()* @_GLOBAL__sub_I_vm.cpp, i8* null }]
@str = private unnamed_addr constant [16 x i8] c"FAIL not an int\00", align 1

; Function Attrs: nounwind uwtable
define linkonce_odr dso_local void @_ZNSt6vectorIP6bcfuncSaIS1_EED2Ev(%"class.std::vector"* noundef nonnull align 8 dereferenceable(24) %0) unnamed_addr #0 comdat align 2 personality i8* bitcast (i32 (...)* @__gxx_personality_v0 to i8*) !dbg !1384 {
  call void @llvm.dbg.value(metadata %"class.std::vector"* %0, metadata !1386, metadata !DIExpression()), !dbg !1388
  call void @llvm.dbg.value(metadata %"class.std::vector"* %0, metadata !1389, metadata !DIExpression()) #17, !dbg !1393
  %2 = getelementptr inbounds %"class.std::vector", %"class.std::vector"* %0, i64 0, i32 0, i32 0, i32 0, i32 0, !dbg !1396
  %3 = load %struct.bcfunc**, %struct.bcfunc*** %2, align 8, !dbg !1396, !tbaa !1398
  call void @llvm.dbg.value(metadata %"class.std::vector"* %0, metadata !1403, metadata !DIExpression()) #17, !dbg !1408
  call void @llvm.dbg.value(metadata %struct.bcfunc** %3, metadata !1406, metadata !DIExpression()) #17, !dbg !1408
  call void @llvm.dbg.value(metadata !DIArgList(%struct.bcfunc** undef, %struct.bcfunc** %3), metadata !1407, metadata !DIExpression(DW_OP_LLVM_arg, 0, DW_OP_LLVM_arg, 1, DW_OP_minus, DW_OP_constu, 3, DW_OP_shra, DW_OP_stack_value)) #17, !dbg !1408
  %4 = icmp eq %struct.bcfunc** %3, null, !dbg !1410
  br i1 %4, label %7, label %5, !dbg !1412

5:                                                ; preds = %1
  call void @llvm.dbg.value(metadata %"class.std::vector"* %0, metadata !1413, metadata !DIExpression()) #17, !dbg !1418
  call void @llvm.dbg.value(metadata %struct.bcfunc** %3, metadata !1416, metadata !DIExpression()) #17, !dbg !1418
  call void @llvm.dbg.value(metadata !DIArgList(%struct.bcfunc** undef, %struct.bcfunc** %3), metadata !1417, metadata !DIExpression(DW_OP_LLVM_arg, 0, DW_OP_LLVM_arg, 1, DW_OP_minus, DW_OP_constu, 3, DW_OP_shra, DW_OP_stack_value)) #17, !dbg !1418
  call void @llvm.dbg.value(metadata %"class.std::vector"* %0, metadata !1420, metadata !DIExpression()) #17, !dbg !1426
  call void @llvm.dbg.value(metadata %struct.bcfunc** %3, metadata !1423, metadata !DIExpression()) #17, !dbg !1426
  call void @llvm.dbg.value(metadata !DIArgList(%struct.bcfunc** undef, %struct.bcfunc** %3), metadata !1424, metadata !DIExpression(DW_OP_LLVM_arg, 0, DW_OP_LLVM_arg, 1, DW_OP_minus, DW_OP_constu, 3, DW_OP_shra, DW_OP_stack_value)) #17, !dbg !1426
  %6 = bitcast %struct.bcfunc** %3 to i8*, !dbg !1428
  tail call void @_ZdlPv(i8* noundef %6) #18, !dbg !1429
  br label %7, !dbg !1430

7:                                                ; preds = %1, %5
  ret void, !dbg !1431
}

; Function Attrs: nofree nounwind
declare i32 @__cxa_atexit(void (i8*)*, i8*, i8*) local_unnamed_addr #1

; Function Attrs: mustprogress nofree noinline norecurse nosync nounwind readnone uwtable willreturn
define dso_local noundef i64 @_Z14ADDVV_SLOWPATHll(i64 noundef %0, i64 noundef %1) local_unnamed_addr #2 !dbg !1432 {
  call void @llvm.dbg.value(metadata i64 %0, metadata !1436, metadata !DIExpression()), !dbg !1439
  call void @llvm.dbg.value(metadata i64 %1, metadata !1437, metadata !DIExpression()), !dbg !1439
  %3 = sitofp i64 %0 to double, !dbg !1440
  %4 = sitofp i64 %1 to double, !dbg !1441
  %5 = fadd double %3, %4, !dbg !1442
  call void @llvm.dbg.value(metadata double %5, metadata !1438, metadata !DIExpression()), !dbg !1439
  %6 = fadd double %5, 1.100000e+00, !dbg !1443
  call void @llvm.dbg.value(metadata double %6, metadata !1438, metadata !DIExpression()), !dbg !1439
  %7 = fptosi double %6 to i64, !dbg !1444
  ret i64 %7, !dbg !1445
}

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #3

; Function Attrs: mustprogress noinline noreturn nounwind uwtable
define dso_local noundef i64 @_Z13FAIL_SLOWPATHll(i64 %0, i64 %1) local_unnamed_addr #4 !dbg !1446 {
  call void @llvm.dbg.value(metadata i64 undef, metadata !1448, metadata !DIExpression()), !dbg !1450
  call void @llvm.dbg.value(metadata i64 undef, metadata !1449, metadata !DIExpression()), !dbg !1450
  %3 = tail call i32 @puts(i8* nonnull dereferenceable(1) getelementptr inbounds ([16 x i8], [16 x i8]* @str, i64 0, i64 0)), !dbg !1451
  tail call void @exit(i32 noundef -1) #19, !dbg !1452
  unreachable, !dbg !1452
}

; Function Attrs: nofree nounwind
declare noundef i32 @printf(i8* nocapture noundef readonly, ...) local_unnamed_addr #5

; Function Attrs: noreturn nounwind
declare void @exit(i32 noundef) local_unnamed_addr #6

; Function Attrs: mustprogress noinline noreturn nounwind uwtable
define dso_local void @_Z25UNDEFINED_SYMBOL_SLOWPATHP6symbol(%struct.symbol* nocapture noundef readonly %0) local_unnamed_addr #4 personality i32 (...)* @__gxx_personality_v0 !dbg !1453 {
  call void @llvm.dbg.value(metadata %struct.symbol* %0, metadata !1457, metadata !DIExpression()), !dbg !1458
  call void @llvm.dbg.value(metadata %struct.symbol* %0, metadata !1459, metadata !DIExpression()), !dbg !1469
  call void @llvm.dbg.value(metadata %struct.symbol* %0, metadata !1471, metadata !DIExpression()), !dbg !1524
  %2 = getelementptr inbounds %struct.symbol, %struct.symbol* %0, i64 0, i32 0, i32 0, i32 0, !dbg !1526
  %3 = load i8*, i8** %2, align 8, !dbg !1526, !tbaa !1527
  %4 = tail call i32 (i8*, ...) @printf(i8* noundef nonnull dereferenceable(1) getelementptr inbounds ([27 x i8], [27 x i8]* @.str.1, i64 0, i64 0), i8* noundef %3), !dbg !1531
  tail call void @exit(i32 noundef -1) #19, !dbg !1532
  unreachable, !dbg !1532
}

; Function Attrs: inaccessiblememonly mustprogress nofree nounwind willreturn
declare noalias noundef i8* @malloc(i64 noundef) local_unnamed_addr #7

; Function Attrs: mustprogress noinline nounwind uwtable
define dso_local void @_Z21EXPAND_STACK_SLOWPATHv() local_unnamed_addr #8 !dbg !1533 {
  %1 = load i32, i32* @stacksz, align 4, !dbg !1534, !tbaa !1535
  %2 = shl i32 %1, 1, !dbg !1537
  %3 = tail call i32 (i8*, ...) @printf(i8* noundef nonnull dereferenceable(1) getelementptr inbounds ([28 x i8], [28 x i8]* @.str.3, i64 0, i64 0), i32 noundef %1, i32 noundef %2), !dbg !1538
  %4 = load i32, i32* @stacksz, align 4, !dbg !1539, !tbaa !1535
  %5 = shl i32 %4, 1, !dbg !1539
  store i32 %5, i32* @stacksz, align 4, !dbg !1539, !tbaa !1535
  %6 = load i8*, i8** bitcast (i64** @stack to i8**), align 8, !dbg !1540, !tbaa !1541
  %7 = zext i32 %5 to i64, !dbg !1542
  %8 = shl nuw nsw i64 %7, 3, !dbg !1543
  %9 = tail call i8* @realloc(i8* noundef %6, i64 noundef %8) #17, !dbg !1544
  store i8* %9, i8** bitcast (i64** @stack to i8**), align 8, !dbg !1545, !tbaa !1541
  ret void, !dbg !1546
}

; Function Attrs: inaccessiblemem_or_argmemonly mustprogress nounwind willreturn
declare noalias noundef i8* @realloc(i8* nocapture noundef, i64 noundef) local_unnamed_addr #9

; Function Attrs: mustprogress uwtable
define  dso_local cc 10 void  @INS_FUNC(i8 zeroext %0, i32 %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1547 {
  call void @llvm.dbg.value(metadata i8 undef, metadata !1549, metadata !DIExpression()), !dbg !1557
  call void @llvm.dbg.value(metadata i32 undef, metadata !1550, metadata !DIExpression()), !dbg !1557
  call void @llvm.dbg.value(metadata i32* %2, metadata !1551, metadata !DIExpression()), !dbg !1557
  call void @llvm.dbg.value(metadata i64* %3, metadata !1552, metadata !DIExpression()), !dbg !1557
  call void @llvm.dbg.value(metadata i8** %4, metadata !1553, metadata !DIExpression()), !dbg !1557
  %6 = getelementptr inbounds i32, i32* %2, i64 1, !dbg !1558
  call void @llvm.dbg.value(metadata i32* %6, metadata !1551, metadata !DIExpression()), !dbg !1557
  %7 = load i32, i32* %6, align 4, !dbg !1559, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %7, metadata !1550, metadata !DIExpression()), !dbg !1557
  call void @llvm.dbg.value(metadata i32 %7, metadata !1554, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1560
  %8 = lshr i32 %7, 8, !dbg !1559
  %9 = trunc i32 %8 to i8, !dbg !1559
  call void @llvm.dbg.value(metadata i8 %9, metadata !1549, metadata !DIExpression()), !dbg !1557
  %10 = lshr i32 %7, 16, !dbg !1559
  call void @llvm.dbg.value(metadata i32 %10, metadata !1550, metadata !DIExpression()), !dbg !1557
  call void @llvm.dbg.value(metadata i8** %4, metadata !1556, metadata !DIExpression()), !dbg !1560
  %11 = and i32 %7, 255, !dbg !1559
  %12 = zext i32 %11 to i64, !dbg !1559
  %13 = getelementptr inbounds i8*, i8** %4, i64 %12, !dbg !1559
  %14 = bitcast i8** %13 to void (i8, i32, i32*, i64*, i8**)**, !dbg !1559
  %15 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %14, align 8, !dbg !1559, !tbaa !1541
  musttail call cc 10 void %15(i8 noundef zeroext %9, i32 noundef %10, i32* noundef nonnull %6, i64* noundef %3, i8** noundef %4), !dbg !1559
  ret void, !dbg !1559
}

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_KSHORT(i8 noundef zeroext %0, i32 noundef %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1561 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1563, metadata !DIExpression()), !dbg !1572
  call void @llvm.dbg.value(metadata i32 %1, metadata !1564, metadata !DIExpression()), !dbg !1572
  call void @llvm.dbg.value(metadata i32* %2, metadata !1565, metadata !DIExpression()), !dbg !1572
  call void @llvm.dbg.value(metadata i64* %3, metadata !1566, metadata !DIExpression()), !dbg !1572
  call void @llvm.dbg.value(metadata i8** %4, metadata !1567, metadata !DIExpression()), !dbg !1572
  %6 = and i32 %1, 255, !dbg !1573
  %7 = zext i32 %6 to i64, !dbg !1573
  call void @llvm.dbg.value(metadata i32 %1, metadata !1568, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1572
  %8 = zext i8 %0 to i64, !dbg !1574
  %9 = getelementptr inbounds i64, i64* %3, i64 %8, !dbg !1574
  store i64 %7, i64* %9, align 8, !dbg !1575, !tbaa !1576
  %10 = getelementptr inbounds i32, i32* %2, i64 1, !dbg !1577
  call void @llvm.dbg.value(metadata i32* %10, metadata !1565, metadata !DIExpression()), !dbg !1572
  %11 = load i32, i32* %10, align 4, !dbg !1578, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %11, metadata !1564, metadata !DIExpression()), !dbg !1572
  call void @llvm.dbg.value(metadata i32 %11, metadata !1569, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1579
  %12 = lshr i32 %11, 8, !dbg !1578
  %13 = trunc i32 %12 to i8, !dbg !1578
  call void @llvm.dbg.value(metadata i8 %13, metadata !1563, metadata !DIExpression()), !dbg !1572
  %14 = lshr i32 %11, 16, !dbg !1578
  call void @llvm.dbg.value(metadata i32 %14, metadata !1564, metadata !DIExpression()), !dbg !1572
  call void @llvm.dbg.value(metadata i8** %4, metadata !1571, metadata !DIExpression()), !dbg !1579
  %15 = and i32 %11, 255, !dbg !1578
  %16 = zext i32 %15 to i64, !dbg !1578
  %17 = getelementptr inbounds i8*, i8** %4, i64 %16, !dbg !1578
  %18 = bitcast i8** %17 to void (i8, i32, i32*, i64*, i8**)**, !dbg !1578
  %19 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %18, align 8, !dbg !1578, !tbaa !1541
  musttail call cc 10 void %19(i8 noundef zeroext %13, i32 noundef %14, i32* noundef nonnull %10, i64* noundef %3, i8** noundef %4), !dbg !1578
  ret void, !dbg !1578
}

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_JMP(i8 noundef zeroext %0, i32 %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1580 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1582, metadata !DIExpression()), !dbg !1590
  call void @llvm.dbg.value(metadata i32 undef, metadata !1583, metadata !DIExpression()), !dbg !1590
  call void @llvm.dbg.value(metadata i32* %2, metadata !1584, metadata !DIExpression()), !dbg !1590
  call void @llvm.dbg.value(metadata i64* %3, metadata !1585, metadata !DIExpression()), !dbg !1590
  call void @llvm.dbg.value(metadata i8** %4, metadata !1586, metadata !DIExpression()), !dbg !1590
  %6 = zext i8 %0 to i64
  %7 = getelementptr inbounds i32, i32* %2, i64 %6, !dbg !1591
  call void @llvm.dbg.value(metadata i32* %7, metadata !1584, metadata !DIExpression()), !dbg !1590
  %8 = load i32, i32* %7, align 4, !dbg !1592, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %8, metadata !1583, metadata !DIExpression()), !dbg !1590
  call void @llvm.dbg.value(metadata i32 %8, metadata !1587, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1593
  %9 = lshr i32 %8, 8, !dbg !1592
  %10 = trunc i32 %9 to i8, !dbg !1592
  call void @llvm.dbg.value(metadata i8 %10, metadata !1582, metadata !DIExpression()), !dbg !1590
  %11 = lshr i32 %8, 16, !dbg !1592
  call void @llvm.dbg.value(metadata i32 %11, metadata !1583, metadata !DIExpression()), !dbg !1590
  call void @llvm.dbg.value(metadata i8** %4, metadata !1589, metadata !DIExpression()), !dbg !1593
  %12 = and i32 %8, 255, !dbg !1592
  %13 = zext i32 %12 to i64, !dbg !1592
  %14 = getelementptr inbounds i8*, i8** %4, i64 %13, !dbg !1592
  %15 = bitcast i8** %14 to void (i8, i32, i32*, i64*, i8**)**, !dbg !1592
  %16 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %15, align 8, !dbg !1592, !tbaa !1541
  musttail call cc 10 void %16(i8 noundef zeroext %10, i32 noundef %11, i32* noundef nonnull %7, i64* noundef %3, i8** noundef %4), !dbg !1592
  ret void, !dbg !1592
}

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_RET1(i8 noundef zeroext %0, i32 %1, i32* nocapture readnone %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1594 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1596, metadata !DIExpression()), !dbg !1604
  call void @llvm.dbg.value(metadata i32 undef, metadata !1597, metadata !DIExpression()), !dbg !1604
  call void @llvm.dbg.value(metadata i32* undef, metadata !1598, metadata !DIExpression()), !dbg !1604
  call void @llvm.dbg.value(metadata i64* %3, metadata !1599, metadata !DIExpression()), !dbg !1604
  call void @llvm.dbg.value(metadata i8** %4, metadata !1600, metadata !DIExpression()), !dbg !1604
  %6 = getelementptr inbounds i64, i64* %3, i64 -2, !dbg !1605
  %7 = load i64, i64* %6, align 8, !dbg !1605, !tbaa !1576
  %8 = inttoptr i64 %7 to i32*, !dbg !1606
  call void @llvm.dbg.value(metadata i32* %8, metadata !1598, metadata !DIExpression()), !dbg !1604
  %9 = zext i8 %0 to i64, !dbg !1607
  %10 = getelementptr inbounds i64, i64* %3, i64 %9, !dbg !1607
  %11 = load i64, i64* %10, align 8, !dbg !1607, !tbaa !1576
  store i64 %11, i64* %6, align 8, !dbg !1608, !tbaa !1576
  %12 = getelementptr inbounds i32, i32* %8, i64 -1, !dbg !1609
  %13 = load i32, i32* %12, align 4, !dbg !1609, !tbaa !1535
  %14 = lshr i32 %13, 8, !dbg !1609
  %15 = and i32 %14, 255, !dbg !1609
  %16 = add nuw nsw i32 %15, 2, !dbg !1610
  %17 = zext i32 %16 to i64, !dbg !1611
  %18 = sub nsw i64 0, %17, !dbg !1611
  %19 = getelementptr inbounds i64, i64* %3, i64 %18, !dbg !1611
  call void @llvm.dbg.value(metadata i64* %19, metadata !1599, metadata !DIExpression()), !dbg !1604
  %20 = load i32, i32* %8, align 4, !dbg !1612, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %20, metadata !1597, metadata !DIExpression()), !dbg !1604
  call void @llvm.dbg.value(metadata i32 %20, metadata !1601, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1613
  %21 = lshr i32 %20, 8, !dbg !1612
  %22 = trunc i32 %21 to i8, !dbg !1612
  call void @llvm.dbg.value(metadata i8 %22, metadata !1596, metadata !DIExpression()), !dbg !1604
  %23 = lshr i32 %20, 16, !dbg !1612
  call void @llvm.dbg.value(metadata i32 %23, metadata !1597, metadata !DIExpression()), !dbg !1604
  call void @llvm.dbg.value(metadata i8** %4, metadata !1603, metadata !DIExpression()), !dbg !1613
  %24 = and i32 %20, 255, !dbg !1612
  %25 = zext i32 %24 to i64, !dbg !1612
  %26 = getelementptr inbounds i8*, i8** %4, i64 %25, !dbg !1612
  %27 = bitcast i8** %26 to void (i8, i32, i32*, i64*, i8**)**, !dbg !1612
  %28 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %27, align 8, !dbg !1612, !tbaa !1541
  musttail call cc 10 void %28(i8 noundef zeroext %22, i32 noundef %23, i32* noundef nonnull %8, i64* noundef %19, i8** noundef %4), !dbg !1612
  ret void, !dbg !1612
}

; Function Attrs: mustprogress nofree nounwind uwtable
define dso_local cc 10 void @INS_HALT(i8 noundef zeroext %0, i32 %1, i32* nocapture readnone %2, i64* nocapture noundef readonly %3, i8** nocapture readnone %4) #11 !dbg !1614 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1616, metadata !DIExpression()), !dbg !1621
  call void @llvm.dbg.value(metadata i32 undef, metadata !1617, metadata !DIExpression()), !dbg !1621
  call void @llvm.dbg.value(metadata i32* undef, metadata !1618, metadata !DIExpression()), !dbg !1621
  call void @llvm.dbg.value(metadata i64* %3, metadata !1619, metadata !DIExpression()), !dbg !1621
  call void @llvm.dbg.value(metadata i8** undef, metadata !1620, metadata !DIExpression()), !dbg !1621
  %6 = zext i8 %0 to i64, !dbg !1622
  %7 = getelementptr inbounds i64, i64* %3, i64 %6, !dbg !1622
  %8 = load i64, i64* %7, align 8, !dbg !1622, !tbaa !1576
  %9 = ashr i64 %8, 3, !dbg !1623
  %10 = tail call i32 (i8*, ...) @printf(i8* noundef nonnull dereferenceable(1) getelementptr inbounds ([12 x i8], [12 x i8]* @.str.4, i64 0, i64 0), i64 noundef %9), !dbg !1624
  ret void, !dbg !1625
}

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_ISGE(i8 noundef zeroext %0, i32 noundef %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1626 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1628, metadata !DIExpression()), !dbg !1639
  call void @llvm.dbg.value(metadata i32 %1, metadata !1629, metadata !DIExpression()), !dbg !1639
  call void @llvm.dbg.value(metadata i32* %2, metadata !1630, metadata !DIExpression()), !dbg !1639
  call void @llvm.dbg.value(metadata i64* %3, metadata !1631, metadata !DIExpression()), !dbg !1639
  call void @llvm.dbg.value(metadata i8** %4, metadata !1632, metadata !DIExpression()), !dbg !1639
  call void @llvm.dbg.value(metadata i32 %1, metadata !1633, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1639
  %6 = zext i8 %0 to i64, !dbg !1640
  %7 = getelementptr inbounds i64, i64* %3, i64 %6, !dbg !1640
  %8 = load i64, i64* %7, align 8, !dbg !1640, !tbaa !1576
  call void @llvm.dbg.value(metadata i64 %8, metadata !1634, metadata !DIExpression()), !dbg !1639
  %9 = and i32 %1, 255, !dbg !1641
  %10 = zext i32 %9 to i64, !dbg !1641
  %11 = getelementptr inbounds i64, i64* %3, i64 %10, !dbg !1641
  %12 = load i64, i64* %11, align 8, !dbg !1641, !tbaa !1576
  call void @llvm.dbg.value(metadata i64 %12, metadata !1635, metadata !DIExpression()), !dbg !1639
  %13 = or i64 %12, %8, !dbg !1642
  %14 = and i64 %13, 1, !dbg !1642
  %15 = icmp eq i64 %14, 0, !dbg !1642
  br i1 %15, label %18, label %16, !dbg !1644, !prof !1645

16:                                               ; preds = %5
  %17 = tail call noundef i64 @_Z13FAIL_SLOWPATHll(i64 undef, i64 undef), !dbg !1646
  unreachable, !dbg !1648

18:                                               ; preds = %5
  %19 = icmp slt i64 %8, %12, !dbg !1649
  %20 = select i1 %19, i64 2, i64 1, !dbg !1651
  %21 = getelementptr inbounds i32, i32* %2, i64 %20, !dbg !1651
  call void @llvm.dbg.value(metadata i32* %21, metadata !1630, metadata !DIExpression()), !dbg !1639
  %22 = load i32, i32* %21, align 4, !dbg !1652, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %22, metadata !1629, metadata !DIExpression()), !dbg !1639
  call void @llvm.dbg.value(metadata i32 %22, metadata !1636, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1653
  %23 = lshr i32 %22, 8, !dbg !1652
  %24 = trunc i32 %23 to i8, !dbg !1652
  call void @llvm.dbg.value(metadata i8 %24, metadata !1628, metadata !DIExpression()), !dbg !1639
  %25 = lshr i32 %22, 16, !dbg !1652
  call void @llvm.dbg.value(metadata i32 %25, metadata !1629, metadata !DIExpression()), !dbg !1639
  call void @llvm.dbg.value(metadata i8** %4, metadata !1638, metadata !DIExpression()), !dbg !1653
  %26 = and i32 %22, 255, !dbg !1652
  %27 = zext i32 %26 to i64, !dbg !1652
  %28 = getelementptr inbounds i8*, i8** %4, i64 %27, !dbg !1652
  %29 = bitcast i8** %28 to void (i8, i32, i32*, i64*, i8**)**, !dbg !1652
  %30 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %29, align 8, !dbg !1652, !tbaa !1541
  musttail call cc 10 void %30(i8 noundef zeroext %24, i32 noundef %25, i32* noundef nonnull %21, i64* noundef nonnull %3, i8** noundef %4), !dbg !1652
  ret void, !dbg !1652
}

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_SUBVN(i8 noundef zeroext %0, i32 noundef %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1654 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1656, metadata !DIExpression()), !dbg !1667
  call void @llvm.dbg.value(metadata i32 %1, metadata !1657, metadata !DIExpression()), !dbg !1667
  call void @llvm.dbg.value(metadata i32* %2, metadata !1658, metadata !DIExpression()), !dbg !1667
  call void @llvm.dbg.value(metadata i64* %3, metadata !1659, metadata !DIExpression()), !dbg !1667
  call void @llvm.dbg.value(metadata i8** %4, metadata !1660, metadata !DIExpression()), !dbg !1667
  call void @llvm.dbg.value(metadata i32 %1, metadata !1661, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1667
  call void @llvm.dbg.value(metadata i32 %1, metadata !1662, metadata !DIExpression(DW_OP_constu, 8, DW_OP_shr, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1667
  %6 = and i32 %1, 255, !dbg !1668
  %7 = zext i32 %6 to i64, !dbg !1668
  %8 = getelementptr inbounds i64, i64* %3, i64 %7, !dbg !1668
  %9 = load i64, i64* %8, align 8, !dbg !1668, !tbaa !1576
  call void @llvm.dbg.value(metadata i64 %9, metadata !1663, metadata !DIExpression()), !dbg !1667
  %10 = and i64 %9, 1, !dbg !1669
  %11 = icmp eq i64 %10, 0, !dbg !1669
  br i1 %11, label %14, label %12, !dbg !1671, !prof !1645

12:                                               ; preds = %5
  %13 = tail call noundef i64 @_Z13FAIL_SLOWPATHll(i64 undef, i64 undef), !dbg !1672
  unreachable, !dbg !1674

14:                                               ; preds = %5
  %15 = lshr i32 %1, 5, !dbg !1675
  %16 = and i32 %15, 2040, !dbg !1675
  %17 = zext i8 %0 to i64, !dbg !1675
  %18 = getelementptr inbounds i64, i64* %3, i64 %17, !dbg !1675
  %19 = zext i32 %16 to i64
  %20 = tail call { i64, i1 } @llvm.ssub.with.overflow.i64(i64 %9, i64 %19), !dbg !1675
  %21 = extractvalue { i64, i1 } %20, 1, !dbg !1675
  %22 = extractvalue { i64, i1 } %20, 0, !dbg !1675
  store i64 %22, i64* %18, align 8, !dbg !1675
  br i1 %21, label %23, label %25, !dbg !1677, !prof !1678

23:                                               ; preds = %14
  %24 = tail call noundef i64 @_Z13FAIL_SLOWPATHll(i64 undef, i64 undef), !dbg !1679
  unreachable, !dbg !1681

25:                                               ; preds = %14
  %26 = getelementptr inbounds i32, i32* %2, i64 1, !dbg !1682
  call void @llvm.dbg.value(metadata i32* %26, metadata !1658, metadata !DIExpression()), !dbg !1667
  %27 = load i32, i32* %26, align 4, !dbg !1683, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %27, metadata !1657, metadata !DIExpression()), !dbg !1667
  call void @llvm.dbg.value(metadata i32 %27, metadata !1664, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1684
  %28 = lshr i32 %27, 8, !dbg !1683
  %29 = trunc i32 %28 to i8, !dbg !1683
  call void @llvm.dbg.value(metadata i8 %29, metadata !1656, metadata !DIExpression()), !dbg !1667
  %30 = lshr i32 %27, 16, !dbg !1683
  call void @llvm.dbg.value(metadata i32 %30, metadata !1657, metadata !DIExpression()), !dbg !1667
  call void @llvm.dbg.value(metadata i8** %4, metadata !1666, metadata !DIExpression()), !dbg !1684
  %31 = and i32 %27, 255, !dbg !1683
  %32 = zext i32 %31 to i64, !dbg !1683
  %33 = getelementptr inbounds i8*, i8** %4, i64 %32, !dbg !1683
  %34 = bitcast i8** %33 to void (i8, i32, i32*, i64*, i8**)**, !dbg !1683
  %35 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %34, align 8, !dbg !1683, !tbaa !1541
  musttail call cc 10 void %35(i8 noundef zeroext %29, i32 noundef %30, i32* noundef nonnull %26, i64* noundef nonnull %3, i8** noundef %4), !dbg !1683
  ret void, !dbg !1683
}

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare { i64, i1 } @llvm.ssub.with.overflow.i64(i64, i64) #3

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_ADDVV(i8 noundef zeroext %0, i32 noundef %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1685 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1687, metadata !DIExpression()), !dbg !1699
  call void @llvm.dbg.value(metadata i32 %1, metadata !1688, metadata !DIExpression()), !dbg !1699
  call void @llvm.dbg.value(metadata i32* %2, metadata !1689, metadata !DIExpression()), !dbg !1699
  call void @llvm.dbg.value(metadata i64* %3, metadata !1690, metadata !DIExpression()), !dbg !1699
  call void @llvm.dbg.value(metadata i8** %4, metadata !1691, metadata !DIExpression()), !dbg !1699
  call void @llvm.dbg.value(metadata i32 %1, metadata !1692, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1699
  %6 = lshr i32 %1, 8, !dbg !1700
  call void @llvm.dbg.value(metadata i32 %6, metadata !1693, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1699
  %7 = and i32 %1, 255, !dbg !1701
  %8 = zext i32 %7 to i64, !dbg !1701
  %9 = getelementptr inbounds i64, i64* %3, i64 %8, !dbg !1701
  %10 = load i64, i64* %9, align 8, !dbg !1701, !tbaa !1576
  call void @llvm.dbg.value(metadata i64 %10, metadata !1694, metadata !DIExpression()), !dbg !1699
  %11 = and i32 %6, 255, !dbg !1702
  %12 = zext i32 %11 to i64, !dbg !1702
  %13 = getelementptr inbounds i64, i64* %3, i64 %12, !dbg !1702
  %14 = load i64, i64* %13, align 8, !dbg !1702, !tbaa !1576
  call void @llvm.dbg.value(metadata i64 %14, metadata !1695, metadata !DIExpression()), !dbg !1699
  %15 = or i64 %14, %10, !dbg !1703
  %16 = and i64 %15, 1, !dbg !1703
  %17 = icmp eq i64 %16, 0, !dbg !1703
  br i1 %17, label %22, label %18, !dbg !1705, !prof !1645

18:                                               ; preds = %5
  %19 = tail call noundef i64 @_Z14ADDVV_SLOWPATHll(i64 noundef %10, i64 noundef %14), !dbg !1706
  %20 = zext i8 %0 to i64, !dbg !1708
  %21 = getelementptr inbounds i64, i64* %3, i64 %20, !dbg !1708
  store i64 %19, i64* %21, align 8, !dbg !1709, !tbaa !1576
  br label %30, !dbg !1710

22:                                               ; preds = %5
  %23 = zext i8 %0 to i64, !dbg !1711
  %24 = getelementptr inbounds i64, i64* %3, i64 %23, !dbg !1711
  %25 = tail call { i64, i1 } @llvm.sadd.with.overflow.i64(i64 %10, i64 %14), !dbg !1711
  %26 = extractvalue { i64, i1 } %25, 1, !dbg !1711
  %27 = extractvalue { i64, i1 } %25, 0, !dbg !1711
  store i64 %27, i64* %24, align 8, !dbg !1711
  br i1 %26, label %28, label %30, !dbg !1714, !prof !1678

28:                                               ; preds = %22
  %29 = tail call noundef i64 @_Z14ADDVV_SLOWPATHll(i64 noundef %10, i64 noundef %14), !dbg !1715
  store i64 %29, i64* %24, align 8, !dbg !1717, !tbaa !1576
  br label %30, !dbg !1718

30:                                               ; preds = %22, %28, %18
  %31 = getelementptr inbounds i32, i32* %2, i64 1, !dbg !1719
  call void @llvm.dbg.value(metadata i32* %31, metadata !1689, metadata !DIExpression()), !dbg !1699
  %32 = load i32, i32* %31, align 4, !dbg !1720, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %32, metadata !1688, metadata !DIExpression()), !dbg !1699
  call void @llvm.dbg.value(metadata i32 %32, metadata !1696, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1721
  %33 = lshr i32 %32, 8, !dbg !1720
  %34 = trunc i32 %33 to i8, !dbg !1720
  call void @llvm.dbg.value(metadata i8 %34, metadata !1687, metadata !DIExpression()), !dbg !1699
  %35 = lshr i32 %32, 16, !dbg !1720
  call void @llvm.dbg.value(metadata i32 %35, metadata !1688, metadata !DIExpression()), !dbg !1699
  call void @llvm.dbg.value(metadata i8** %4, metadata !1698, metadata !DIExpression()), !dbg !1721
  %36 = and i32 %32, 255, !dbg !1720
  %37 = zext i32 %36 to i64, !dbg !1720
  %38 = getelementptr inbounds i8*, i8** %4, i64 %37, !dbg !1720
  %39 = bitcast i8** %38 to void (i8, i32, i32*, i64*, i8**)**, !dbg !1720
  %40 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %39, align 8, !dbg !1720, !tbaa !1541
  musttail call cc 10 void %40(i8 noundef zeroext %34, i32 noundef %35, i32* noundef nonnull %31, i64* noundef nonnull %3, i8** noundef %4), !dbg !1720
  ret void, !dbg !1720
}

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare { i64, i1 } @llvm.sadd.with.overflow.i64(i64, i64) #3

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_GGET(i8 noundef zeroext %0, i32 noundef %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1722 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1724, metadata !DIExpression()), !dbg !1735
  call void @llvm.dbg.value(metadata i32 %1, metadata !1725, metadata !DIExpression()), !dbg !1735
  call void @llvm.dbg.value(metadata i32* %2, metadata !1726, metadata !DIExpression()), !dbg !1735
  call void @llvm.dbg.value(metadata i64* %3, metadata !1727, metadata !DIExpression()), !dbg !1735
  call void @llvm.dbg.value(metadata i8** %4, metadata !1728, metadata !DIExpression()), !dbg !1735
  call void @llvm.dbg.value(metadata i32 %1, metadata !1729, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1735
  %6 = getelementptr inbounds i64, i64* %3, i64 -1, !dbg !1736
  %7 = load i64, i64* %6, align 8, !dbg !1736, !tbaa !1576
  %8 = add nsw i64 %7, -5, !dbg !1737
  %9 = inttoptr i64 %8 to %struct.bcfunc*, !dbg !1738
  call void @llvm.dbg.value(metadata %struct.bcfunc* %9, metadata !1730, metadata !DIExpression()), !dbg !1735
  %10 = and i32 %1, 255, !dbg !1739
  %11 = zext i32 %10 to i64, !dbg !1739
  call void @llvm.dbg.value(metadata %struct.bcfunc* %9, metadata !1740, metadata !DIExpression(DW_OP_plus_uconst, 24, DW_OP_stack_value)), !dbg !1800
  call void @llvm.dbg.value(metadata i64 %11, metadata !1798, metadata !DIExpression()), !dbg !1800
  %12 = getelementptr inbounds %struct.bcfunc, %struct.bcfunc* %9, i64 0, i32 1, i32 0, i32 0, i32 0, i32 0, !dbg !1802
  %13 = load i64*, i64** %12, align 8, !dbg !1802, !tbaa !1803
  %14 = getelementptr inbounds i64, i64* %13, i64 %11, !dbg !1805
  %15 = load i64, i64* %14, align 8, !dbg !1806, !tbaa !1576
  %16 = inttoptr i64 %15 to %struct.symbol*, !dbg !1807
  call void @llvm.dbg.value(metadata %struct.symbol* %16, metadata !1731, metadata !DIExpression()), !dbg !1735
  %17 = getelementptr inbounds %struct.symbol, %struct.symbol* %16, i64 0, i32 1, !dbg !1808
  %18 = load i64, i64* %17, align 8, !dbg !1808, !tbaa !1810
  %19 = icmp eq i64 %18, 27, !dbg !1808
  br i1 %19, label %20, label %21, !dbg !1812, !prof !1678

20:                                               ; preds = %5
  tail call void @_Z25UNDEFINED_SYMBOL_SLOWPATHP6symbol(%struct.symbol* noundef nonnull %16), !dbg !1813
  unreachable, !dbg !1815

21:                                               ; preds = %5
  %22 = zext i8 %0 to i64, !dbg !1816
  %23 = getelementptr inbounds i64, i64* %3, i64 %22, !dbg !1816
  store i64 %18, i64* %23, align 8, !dbg !1817, !tbaa !1576
  %24 = getelementptr inbounds i32, i32* %2, i64 1, !dbg !1818
  call void @llvm.dbg.value(metadata i32* %24, metadata !1726, metadata !DIExpression()), !dbg !1735
  %25 = load i32, i32* %24, align 4, !dbg !1819, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %25, metadata !1725, metadata !DIExpression()), !dbg !1735
  call void @llvm.dbg.value(metadata i32 %25, metadata !1732, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1820
  %26 = lshr i32 %25, 8, !dbg !1819
  %27 = trunc i32 %26 to i8, !dbg !1819
  call void @llvm.dbg.value(metadata i8 %27, metadata !1724, metadata !DIExpression()), !dbg !1735
  %28 = lshr i32 %25, 16, !dbg !1819
  call void @llvm.dbg.value(metadata i32 %28, metadata !1725, metadata !DIExpression()), !dbg !1735
  call void @llvm.dbg.value(metadata i8** %4, metadata !1734, metadata !DIExpression()), !dbg !1820
  %29 = and i32 %25, 255, !dbg !1819
  %30 = zext i32 %29 to i64, !dbg !1819
  %31 = getelementptr inbounds i8*, i8** %4, i64 %30, !dbg !1819
  %32 = bitcast i8** %31 to void (i8, i32, i32*, i64*, i8**)**, !dbg !1819
  %33 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %32, align 8, !dbg !1819, !tbaa !1541
  musttail call cc 10 void %33(i8 noundef zeroext %27, i32 noundef %28, i32* noundef nonnull %24, i64* noundef nonnull %3, i8** noundef %4), !dbg !1819
  ret void, !dbg !1819
}

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_GSET(i8 noundef zeroext %0, i32 noundef %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1821 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1823, metadata !DIExpression()), !dbg !1834
  call void @llvm.dbg.value(metadata i32 %1, metadata !1824, metadata !DIExpression()), !dbg !1834
  call void @llvm.dbg.value(metadata i32* %2, metadata !1825, metadata !DIExpression()), !dbg !1834
  call void @llvm.dbg.value(metadata i64* %3, metadata !1826, metadata !DIExpression()), !dbg !1834
  call void @llvm.dbg.value(metadata i8** %4, metadata !1827, metadata !DIExpression()), !dbg !1834
  call void @llvm.dbg.value(metadata i32 %1, metadata !1828, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1834
  %6 = getelementptr inbounds i64, i64* %3, i64 -1, !dbg !1835
  %7 = load i64, i64* %6, align 8, !dbg !1835, !tbaa !1576
  %8 = add nsw i64 %7, -5, !dbg !1836
  %9 = inttoptr i64 %8 to %struct.bcfunc*, !dbg !1837
  call void @llvm.dbg.value(metadata %struct.bcfunc* %9, metadata !1829, metadata !DIExpression()), !dbg !1834
  %10 = zext i8 %0 to i64, !dbg !1838
  call void @llvm.dbg.value(metadata %struct.bcfunc* %9, metadata !1740, metadata !DIExpression(DW_OP_plus_uconst, 24, DW_OP_stack_value)), !dbg !1839
  call void @llvm.dbg.value(metadata i64 %10, metadata !1798, metadata !DIExpression()), !dbg !1839
  %11 = getelementptr inbounds %struct.bcfunc, %struct.bcfunc* %9, i64 0, i32 1, i32 0, i32 0, i32 0, i32 0, !dbg !1841
  %12 = load i64*, i64** %11, align 8, !dbg !1841, !tbaa !1803
  %13 = getelementptr inbounds i64, i64* %12, i64 %10, !dbg !1842
  %14 = load i64, i64* %13, align 8, !dbg !1843, !tbaa !1576
  %15 = inttoptr i64 %14 to %struct.symbol*, !dbg !1844
  call void @llvm.dbg.value(metadata %struct.symbol* %15, metadata !1830, metadata !DIExpression()), !dbg !1834
  %16 = and i32 %1, 255, !dbg !1845
  %17 = zext i32 %16 to i64, !dbg !1845
  %18 = getelementptr inbounds i64, i64* %3, i64 %17, !dbg !1845
  %19 = load i64, i64* %18, align 8, !dbg !1845, !tbaa !1576
  %20 = getelementptr inbounds %struct.symbol, %struct.symbol* %15, i64 0, i32 1, !dbg !1846
  store i64 %19, i64* %20, align 8, !dbg !1847, !tbaa !1810
  %21 = getelementptr inbounds i32, i32* %2, i64 1, !dbg !1848
  call void @llvm.dbg.value(metadata i32* %21, metadata !1825, metadata !DIExpression()), !dbg !1834
  %22 = load i32, i32* %21, align 4, !dbg !1849, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %22, metadata !1824, metadata !DIExpression()), !dbg !1834
  call void @llvm.dbg.value(metadata i32 %22, metadata !1831, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1850
  %23 = lshr i32 %22, 8, !dbg !1849
  %24 = trunc i32 %23 to i8, !dbg !1849
  call void @llvm.dbg.value(metadata i8 %24, metadata !1823, metadata !DIExpression()), !dbg !1834
  %25 = lshr i32 %22, 16, !dbg !1849
  call void @llvm.dbg.value(metadata i32 %25, metadata !1824, metadata !DIExpression()), !dbg !1834
  call void @llvm.dbg.value(metadata i8** %4, metadata !1833, metadata !DIExpression()), !dbg !1850
  %26 = and i32 %22, 255, !dbg !1849
  %27 = zext i32 %26 to i64, !dbg !1849
  %28 = getelementptr inbounds i8*, i8** %4, i64 %27, !dbg !1849
  %29 = bitcast i8** %28 to void (i8, i32, i32*, i64*, i8**)**, !dbg !1849
  %30 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %29, align 8, !dbg !1849, !tbaa !1541
  musttail call cc 10 void %30(i8 noundef zeroext %24, i32 noundef %25, i32* noundef nonnull %21, i64* noundef %3, i8** noundef %4), !dbg !1849
  ret void, !dbg !1849
}

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_KFUNC(i8 noundef zeroext %0, i32 noundef %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1851 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1853, metadata !DIExpression()), !dbg !1862
  call void @llvm.dbg.value(metadata i32 %1, metadata !1854, metadata !DIExpression()), !dbg !1862
  call void @llvm.dbg.value(metadata i32* %2, metadata !1855, metadata !DIExpression()), !dbg !1862
  call void @llvm.dbg.value(metadata i64* %3, metadata !1856, metadata !DIExpression()), !dbg !1862
  call void @llvm.dbg.value(metadata i8** %4, metadata !1857, metadata !DIExpression()), !dbg !1862
  %6 = and i32 %1, 255, !dbg !1863
  %7 = zext i32 %6 to i64, !dbg !1863
  call void @llvm.dbg.value(metadata i32 %1, metadata !1858, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1862
  call void @llvm.dbg.value(metadata %"class.std::vector"* @funcs, metadata !1864, metadata !DIExpression()), !dbg !1868
  call void @llvm.dbg.value(metadata i64 %7, metadata !1867, metadata !DIExpression()), !dbg !1868
  %8 = load %struct.bcfunc**, %struct.bcfunc*** getelementptr inbounds (%"class.std::vector", %"class.std::vector"* @funcs, i64 0, i32 0, i32 0, i32 0, i32 0), align 8, !dbg !1870, !tbaa !1398
  %9 = getelementptr inbounds %struct.bcfunc*, %struct.bcfunc** %8, i64 %7, !dbg !1871
  %10 = load %struct.bcfunc*, %struct.bcfunc** %9, align 8, !dbg !1872, !tbaa !1541
  %11 = ptrtoint %struct.bcfunc* %10 to i64, !dbg !1873
  %12 = add nsw i64 %11, 5, !dbg !1874
  %13 = zext i8 %0 to i64, !dbg !1875
  %14 = getelementptr inbounds i64, i64* %3, i64 %13, !dbg !1875
  store i64 %12, i64* %14, align 8, !dbg !1876, !tbaa !1576
  %15 = getelementptr inbounds i32, i32* %2, i64 1, !dbg !1877
  call void @llvm.dbg.value(metadata i32* %15, metadata !1855, metadata !DIExpression()), !dbg !1862
  %16 = load i32, i32* %15, align 4, !dbg !1878, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %16, metadata !1854, metadata !DIExpression()), !dbg !1862
  call void @llvm.dbg.value(metadata i32 %16, metadata !1859, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1879
  %17 = lshr i32 %16, 8, !dbg !1878
  %18 = trunc i32 %17 to i8, !dbg !1878
  call void @llvm.dbg.value(metadata i8 %18, metadata !1853, metadata !DIExpression()), !dbg !1862
  %19 = lshr i32 %16, 16, !dbg !1878
  call void @llvm.dbg.value(metadata i32 %19, metadata !1854, metadata !DIExpression()), !dbg !1862
  call void @llvm.dbg.value(metadata i8** %4, metadata !1861, metadata !DIExpression()), !dbg !1879
  %20 = and i32 %16, 255, !dbg !1878
  %21 = zext i32 %20 to i64, !dbg !1878
  %22 = getelementptr inbounds i8*, i8** %4, i64 %21, !dbg !1878
  %23 = bitcast i8** %22 to void (i8, i32, i32*, i64*, i8**)**, !dbg !1878
  %24 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %23, align 8, !dbg !1878, !tbaa !1541
  musttail call cc 10 void %24(i8 noundef zeroext %18, i32 noundef %19, i32* noundef nonnull %15, i64* noundef %3, i8** noundef %4), !dbg !1878
  ret void, !dbg !1878
}

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_CALLT(i8 noundef zeroext %0, i32 noundef %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !1880 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !1882, metadata !DIExpression()), !dbg !1900
  call void @llvm.dbg.value(metadata i32 %1, metadata !1883, metadata !DIExpression()), !dbg !1900
  call void @llvm.dbg.value(metadata i32* %2, metadata !1884, metadata !DIExpression()), !dbg !1900
  call void @llvm.dbg.value(metadata i64* %3, metadata !1885, metadata !DIExpression()), !dbg !1900
  call void @llvm.dbg.value(metadata i8** %4, metadata !1886, metadata !DIExpression()), !dbg !1900
  call void @llvm.dbg.value(metadata i32 %1, metadata !1887, metadata !DIExpression()), !dbg !1900
  %6 = ptrtoint i32* %2 to i64, !dbg !1901
  %7 = lshr i64 %6, 2, !dbg !1901
  %8 = and i64 %7, 63, !dbg !1901
  %9 = getelementptr inbounds [64 x i8], [64 x i8]* @hotmap, i64 0, i64 %8, !dbg !1901
  %10 = load i8, i8* %9, align 1, !dbg !1901, !tbaa !1903
  %11 = add i8 %10, -1, !dbg !1901
  %12 = icmp eq i8 %11, 0, !dbg !1901
  br i1 %12, label %13, label %14, !dbg !1904, !prof !1678

13:                                               ; preds = %5
  br label %14, !dbg !1905

14:                                               ; preds = %13, %5
  %15 = phi i8 [ -56, %13 ], [ %11, %5 ], !dbg !1907
  store i8 %15, i8* %9, align 1, !dbg !1907, !tbaa !1903
  %16 = zext i8 %0 to i64, !dbg !1908
  %17 = getelementptr inbounds i64, i64* %3, i64 %16, !dbg !1908
  %18 = load i64, i64* %17, align 8, !dbg !1908, !tbaa !1576
  call void @llvm.dbg.value(metadata i64 %18, metadata !1888, metadata !DIExpression()), !dbg !1900
  %19 = and i64 %18, 7, !dbg !1909
  %20 = icmp eq i64 %19, 5, !dbg !1909
  br i1 %20, label %23, label %21, !dbg !1911, !prof !1645

21:                                               ; preds = %14
  %22 = tail call noundef i64 @_Z13FAIL_SLOWPATHll(i64 undef, i64 undef), !dbg !1912
  unreachable, !dbg !1914

23:                                               ; preds = %14
  %24 = add nsw i64 %18, -5, !dbg !1915
  %25 = inttoptr i64 %24 to %struct.bcfunc*, !dbg !1916
  call void @llvm.dbg.value(metadata %struct.bcfunc* %25, metadata !1889, metadata !DIExpression()), !dbg !1900
  call void @llvm.dbg.value(metadata %struct.bcfunc* %25, metadata !1917, metadata !DIExpression()), !dbg !1976
  call void @llvm.dbg.value(metadata i64 0, metadata !1974, metadata !DIExpression()), !dbg !1976
  %26 = getelementptr inbounds %struct.bcfunc, %struct.bcfunc* %25, i64 0, i32 0, i32 0, i32 0, i32 0, i32 0, !dbg !1978
  %27 = load i32*, i32** %26, align 8, !dbg !1978, !tbaa !1979
  call void @llvm.dbg.value(metadata i32* %27, metadata !1884, metadata !DIExpression()), !dbg !1900
  %28 = getelementptr inbounds i64, i64* %3, i64 -1, !dbg !1981
  store i64 %18, i64* %28, align 8, !dbg !1982, !tbaa !1576
  %29 = add nuw nsw i64 %16, 1, !dbg !1983
  call void @llvm.dbg.value(metadata i64 %29, metadata !1890, metadata !DIExpression()), !dbg !1900
  %30 = and i32 %1, 255, !dbg !1984
  call void @llvm.dbg.value(metadata i32 %30, metadata !1891, metadata !DIExpression(DW_OP_constu, 1, DW_OP_minus, DW_OP_stack_value)), !dbg !1900
  call void @llvm.dbg.value(metadata i32 0, metadata !1892, metadata !DIExpression()), !dbg !1985
  %31 = icmp ugt i32 %30, 1, !dbg !1986
  br i1 %31, label %32, label %148, !dbg !1988

32:                                               ; preds = %23
  %33 = add nsw i32 %30, -1, !dbg !1989
  call void @llvm.dbg.value(metadata i32 %33, metadata !1891, metadata !DIExpression()), !dbg !1900
  %34 = zext i32 %33 to i64, !dbg !1986
  %35 = icmp ult i32 %33, 4, !dbg !1988
  br i1 %35, label %129, label %36, !dbg !1988

36:                                               ; preds = %32
  %37 = getelementptr i64, i64* %3, i64 %34, !dbg !1988
  %38 = getelementptr i64, i64* %3, i64 %29, !dbg !1988
  %39 = add nuw nsw i64 %16, %34, !dbg !1988
  %40 = add nuw nsw i64 %39, 1, !dbg !1988
  %41 = getelementptr i64, i64* %3, i64 %40, !dbg !1988
  %42 = icmp ugt i64* %41, %3, !dbg !1988
  %43 = icmp ult i64* %38, %37, !dbg !1988
  %44 = and i1 %42, %43, !dbg !1988
  br i1 %44, label %129, label %45, !dbg !1988

45:                                               ; preds = %36
  %46 = and i64 %34, 4294967292, !dbg !1988
  %47 = add nsw i64 %46, -4, !dbg !1988
  %48 = lshr exact i64 %47, 2, !dbg !1988
  %49 = add nuw nsw i64 %48, 1, !dbg !1988
  %50 = and i64 %49, 3, !dbg !1988
  %51 = icmp ult i64 %47, 12, !dbg !1988
  br i1 %51, label %107, label %52, !dbg !1988

52:                                               ; preds = %45
  %53 = and i64 %49, 9223372036854775804, !dbg !1988
  br label %54, !dbg !1988

54:                                               ; preds = %54, %52
  %55 = phi i64 [ 0, %52 ], [ %104, %54 ], !dbg !1990
  %56 = phi i64 [ 0, %52 ], [ %105, %54 ]
  %57 = add nuw nsw i64 %29, %55, !dbg !1990
  %58 = getelementptr inbounds i64, i64* %3, i64 %57, !dbg !1990
  %59 = bitcast i64* %58 to <2 x i64>*, !dbg !1991
  %60 = load <2 x i64>, <2 x i64>* %59, align 8, !dbg !1991, !tbaa !1576, !alias.scope !1993
  %61 = getelementptr inbounds i64, i64* %58, i64 2, !dbg !1991
  %62 = bitcast i64* %61 to <2 x i64>*, !dbg !1991
  %63 = load <2 x i64>, <2 x i64>* %62, align 8, !dbg !1991, !tbaa !1576, !alias.scope !1993
  %64 = getelementptr inbounds i64, i64* %3, i64 %55, !dbg !1990
  %65 = bitcast i64* %64 to <2 x i64>*, !dbg !1996
  store <2 x i64> %60, <2 x i64>* %65, align 8, !dbg !1996, !tbaa !1576, !alias.scope !1997, !noalias !1993
  %66 = getelementptr inbounds i64, i64* %64, i64 2, !dbg !1996
  %67 = bitcast i64* %66 to <2 x i64>*, !dbg !1996
  store <2 x i64> %63, <2 x i64>* %67, align 8, !dbg !1996, !tbaa !1576, !alias.scope !1997, !noalias !1993
  %68 = or i64 %55, 4, !dbg !1990
  %69 = add nuw nsw i64 %29, %68, !dbg !1990
  %70 = getelementptr inbounds i64, i64* %3, i64 %69, !dbg !1990
  %71 = bitcast i64* %70 to <2 x i64>*, !dbg !1991
  %72 = load <2 x i64>, <2 x i64>* %71, align 8, !dbg !1991, !tbaa !1576, !alias.scope !1993
  %73 = getelementptr inbounds i64, i64* %70, i64 2, !dbg !1991
  %74 = bitcast i64* %73 to <2 x i64>*, !dbg !1991
  %75 = load <2 x i64>, <2 x i64>* %74, align 8, !dbg !1991, !tbaa !1576, !alias.scope !1993
  %76 = getelementptr inbounds i64, i64* %3, i64 %68, !dbg !1990
  %77 = bitcast i64* %76 to <2 x i64>*, !dbg !1996
  store <2 x i64> %72, <2 x i64>* %77, align 8, !dbg !1996, !tbaa !1576, !alias.scope !1997, !noalias !1993
  %78 = getelementptr inbounds i64, i64* %76, i64 2, !dbg !1996
  %79 = bitcast i64* %78 to <2 x i64>*, !dbg !1996
  store <2 x i64> %75, <2 x i64>* %79, align 8, !dbg !1996, !tbaa !1576, !alias.scope !1997, !noalias !1993
  %80 = or i64 %55, 8, !dbg !1990
  %81 = add nuw nsw i64 %29, %80, !dbg !1990
  %82 = getelementptr inbounds i64, i64* %3, i64 %81, !dbg !1990
  %83 = bitcast i64* %82 to <2 x i64>*, !dbg !1991
  %84 = load <2 x i64>, <2 x i64>* %83, align 8, !dbg !1991, !tbaa !1576, !alias.scope !1993
  %85 = getelementptr inbounds i64, i64* %82, i64 2, !dbg !1991
  %86 = bitcast i64* %85 to <2 x i64>*, !dbg !1991
  %87 = load <2 x i64>, <2 x i64>* %86, align 8, !dbg !1991, !tbaa !1576, !alias.scope !1993
  %88 = getelementptr inbounds i64, i64* %3, i64 %80, !dbg !1990
  %89 = bitcast i64* %88 to <2 x i64>*, !dbg !1996
  store <2 x i64> %84, <2 x i64>* %89, align 8, !dbg !1996, !tbaa !1576, !alias.scope !1997, !noalias !1993
  %90 = getelementptr inbounds i64, i64* %88, i64 2, !dbg !1996
  %91 = bitcast i64* %90 to <2 x i64>*, !dbg !1996
  store <2 x i64> %87, <2 x i64>* %91, align 8, !dbg !1996, !tbaa !1576, !alias.scope !1997, !noalias !1993
  %92 = or i64 %55, 12, !dbg !1990
  %93 = add nuw nsw i64 %29, %92, !dbg !1990
  %94 = getelementptr inbounds i64, i64* %3, i64 %93, !dbg !1990
  %95 = bitcast i64* %94 to <2 x i64>*, !dbg !1991
  %96 = load <2 x i64>, <2 x i64>* %95, align 8, !dbg !1991, !tbaa !1576, !alias.scope !1993
  %97 = getelementptr inbounds i64, i64* %94, i64 2, !dbg !1991
  %98 = bitcast i64* %97 to <2 x i64>*, !dbg !1991
  %99 = load <2 x i64>, <2 x i64>* %98, align 8, !dbg !1991, !tbaa !1576, !alias.scope !1993
  %100 = getelementptr inbounds i64, i64* %3, i64 %92, !dbg !1990
  %101 = bitcast i64* %100 to <2 x i64>*, !dbg !1996
  store <2 x i64> %96, <2 x i64>* %101, align 8, !dbg !1996, !tbaa !1576, !alias.scope !1997, !noalias !1993
  %102 = getelementptr inbounds i64, i64* %100, i64 2, !dbg !1996
  %103 = bitcast i64* %102 to <2 x i64>*, !dbg !1996
  store <2 x i64> %99, <2 x i64>* %103, align 8, !dbg !1996, !tbaa !1576, !alias.scope !1997, !noalias !1993
  %104 = add nuw i64 %55, 16, !dbg !1990
  %105 = add nuw i64 %56, 4, !dbg !1990
  %106 = icmp eq i64 %105, %53, !dbg !1990
  br i1 %106, label %107, label %54, !dbg !1990, !llvm.loop !1999

107:                                              ; preds = %54, %45
  %108 = phi i64 [ 0, %45 ], [ %104, %54 ]
  %109 = icmp eq i64 %50, 0, !dbg !1990
  br i1 %109, label %127, label %110, !dbg !1990

110:                                              ; preds = %107, %110
  %111 = phi i64 [ %124, %110 ], [ %108, %107 ], !dbg !1990
  %112 = phi i64 [ %125, %110 ], [ 0, %107 ]
  %113 = add nuw nsw i64 %29, %111, !dbg !1990
  %114 = getelementptr inbounds i64, i64* %3, i64 %113, !dbg !1990
  %115 = bitcast i64* %114 to <2 x i64>*, !dbg !1991
  %116 = load <2 x i64>, <2 x i64>* %115, align 8, !dbg !1991, !tbaa !1576, !alias.scope !1993
  %117 = getelementptr inbounds i64, i64* %114, i64 2, !dbg !1991
  %118 = bitcast i64* %117 to <2 x i64>*, !dbg !1991
  %119 = load <2 x i64>, <2 x i64>* %118, align 8, !dbg !1991, !tbaa !1576, !alias.scope !1993
  %120 = getelementptr inbounds i64, i64* %3, i64 %111, !dbg !1990
  %121 = bitcast i64* %120 to <2 x i64>*, !dbg !1996
  store <2 x i64> %116, <2 x i64>* %121, align 8, !dbg !1996, !tbaa !1576, !alias.scope !1997, !noalias !1993
  %122 = getelementptr inbounds i64, i64* %120, i64 2, !dbg !1996
  %123 = bitcast i64* %122 to <2 x i64>*, !dbg !1996
  store <2 x i64> %119, <2 x i64>* %123, align 8, !dbg !1996, !tbaa !1576, !alias.scope !1997, !noalias !1993
  %124 = add nuw i64 %111, 4, !dbg !1990
  %125 = add i64 %112, 1, !dbg !1990
  %126 = icmp eq i64 %125, %50, !dbg !1990
  br i1 %126, label %127, label %110, !dbg !1990, !llvm.loop !2003

127:                                              ; preds = %110, %107
  %128 = icmp eq i64 %46, %34, !dbg !1988
  br i1 %128, label %148, label %129, !dbg !1988

129:                                              ; preds = %36, %32, %127
  %130 = phi i64 [ 0, %36 ], [ 0, %32 ], [ %46, %127 ]
  %131 = xor i64 %130, -1, !dbg !1988
  %132 = add nsw i64 %131, %34, !dbg !1988
  %133 = and i64 %34, 3, !dbg !1988
  %134 = icmp eq i64 %133, 0, !dbg !1988
  br i1 %134, label %145, label %135, !dbg !1988

135:                                              ; preds = %129, %135
  %136 = phi i64 [ %142, %135 ], [ %130, %129 ]
  %137 = phi i64 [ %143, %135 ], [ 0, %129 ]
  call void @llvm.dbg.value(metadata i64 %136, metadata !1892, metadata !DIExpression()), !dbg !1985
  %138 = add nuw nsw i64 %29, %136, !dbg !2005
  %139 = getelementptr inbounds i64, i64* %3, i64 %138, !dbg !1991
  %140 = load i64, i64* %139, align 8, !dbg !1991, !tbaa !1576
  %141 = getelementptr inbounds i64, i64* %3, i64 %136, !dbg !2006
  store i64 %140, i64* %141, align 8, !dbg !1996, !tbaa !1576
  %142 = add nuw nsw i64 %136, 1, !dbg !1990
  call void @llvm.dbg.value(metadata i64 %142, metadata !1892, metadata !DIExpression()), !dbg !1985
  %143 = add i64 %137, 1, !dbg !1988
  %144 = icmp eq i64 %143, %133, !dbg !1988
  br i1 %144, label %145, label %135, !dbg !1988, !llvm.loop !2007

145:                                              ; preds = %135, %129
  %146 = phi i64 [ %130, %129 ], [ %142, %135 ]
  %147 = icmp ult i64 %132, 3, !dbg !1988
  br i1 %147, label %148, label %152, !dbg !1988

148:                                              ; preds = %145, %152, %127, %23
  %149 = getelementptr inbounds i64, i64* %3, i64 256, !dbg !2008
  %150 = load i64*, i64** @_ZL9frame_top, align 8, !dbg !2008, !tbaa !1541
  %151 = icmp ugt i64* %149, %150, !dbg !2008
  br i1 %151, label %175, label %186, !dbg !2009, !prof !1678

152:                                              ; preds = %145, %152
  %153 = phi i64 [ %173, %152 ], [ %146, %145 ]
  call void @llvm.dbg.value(metadata i64 %153, metadata !1892, metadata !DIExpression()), !dbg !1985
  %154 = add nuw nsw i64 %29, %153, !dbg !2005
  %155 = getelementptr inbounds i64, i64* %3, i64 %154, !dbg !1991
  %156 = load i64, i64* %155, align 8, !dbg !1991, !tbaa !1576
  %157 = getelementptr inbounds i64, i64* %3, i64 %153, !dbg !2006
  store i64 %156, i64* %157, align 8, !dbg !1996, !tbaa !1576
  %158 = add nuw nsw i64 %153, 1, !dbg !1990
  call void @llvm.dbg.value(metadata i64 %158, metadata !1892, metadata !DIExpression()), !dbg !1985
  call void @llvm.dbg.value(metadata i64 %158, metadata !1892, metadata !DIExpression()), !dbg !1985
  %159 = add nuw nsw i64 %29, %158, !dbg !2005
  %160 = getelementptr inbounds i64, i64* %3, i64 %159, !dbg !1991
  %161 = load i64, i64* %160, align 8, !dbg !1991, !tbaa !1576
  %162 = getelementptr inbounds i64, i64* %3, i64 %158, !dbg !2006
  store i64 %161, i64* %162, align 8, !dbg !1996, !tbaa !1576
  %163 = add nuw nsw i64 %153, 2, !dbg !1990
  call void @llvm.dbg.value(metadata i64 %163, metadata !1892, metadata !DIExpression()), !dbg !1985
  call void @llvm.dbg.value(metadata i64 %163, metadata !1892, metadata !DIExpression()), !dbg !1985
  %164 = add nuw nsw i64 %29, %163, !dbg !2005
  %165 = getelementptr inbounds i64, i64* %3, i64 %164, !dbg !1991
  %166 = load i64, i64* %165, align 8, !dbg !1991, !tbaa !1576
  %167 = getelementptr inbounds i64, i64* %3, i64 %163, !dbg !2006
  store i64 %166, i64* %167, align 8, !dbg !1996, !tbaa !1576
  %168 = add nuw nsw i64 %153, 3, !dbg !1990
  call void @llvm.dbg.value(metadata i64 %168, metadata !1892, metadata !DIExpression()), !dbg !1985
  call void @llvm.dbg.value(metadata i64 %168, metadata !1892, metadata !DIExpression()), !dbg !1985
  %169 = add nuw nsw i64 %29, %168, !dbg !2005
  %170 = getelementptr inbounds i64, i64* %3, i64 %169, !dbg !1991
  %171 = load i64, i64* %170, align 8, !dbg !1991, !tbaa !1576
  %172 = getelementptr inbounds i64, i64* %3, i64 %168, !dbg !2006
  store i64 %171, i64* %172, align 8, !dbg !1996, !tbaa !1576
  %173 = add nuw nsw i64 %153, 4, !dbg !1990
  call void @llvm.dbg.value(metadata i64 %173, metadata !1892, metadata !DIExpression()), !dbg !1985
  %174 = icmp eq i64 %173, %34, !dbg !1986
  br i1 %174, label %148, label %152, !dbg !1988, !llvm.loop !2010

175:                                              ; preds = %148
  %176 = load i64*, i64** @stack, align 8, !dbg !2011, !tbaa !1541
  %177 = ptrtoint i64* %3 to i64, !dbg !2012
  %178 = ptrtoint i64* %176 to i64, !dbg !2012
  %179 = sub i64 %177, %178, !dbg !2012
  %180 = ashr exact i64 %179, 3, !dbg !2012
  call void @llvm.dbg.value(metadata i64 %180, metadata !1894, metadata !DIExpression()), !dbg !2013
  tail call void @_Z21EXPAND_STACK_SLOWPATHv(), !dbg !2014
  %181 = load i64*, i64** @stack, align 8, !dbg !2015, !tbaa !1541
  %182 = getelementptr inbounds i64, i64* %181, i64 %180, !dbg !2016
  call void @llvm.dbg.value(metadata i64* %182, metadata !1885, metadata !DIExpression()), !dbg !1900
  %183 = load i32, i32* @stacksz, align 4, !dbg !2017, !tbaa !1535
  %184 = zext i32 %183 to i64, !dbg !2018
  %185 = getelementptr inbounds i64, i64* %181, i64 %184, !dbg !2018
  store i64* %185, i64** @_ZL9frame_top, align 8, !dbg !2019, !tbaa !1541
  br label %186, !dbg !2020

186:                                              ; preds = %175, %148
  %187 = phi i64* [ %182, %175 ], [ %3, %148 ]
  call void @llvm.dbg.value(metadata i64* %187, metadata !1885, metadata !DIExpression()), !dbg !1900
  %188 = load i32, i32* %27, align 4, !dbg !2021, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %188, metadata !1883, metadata !DIExpression()), !dbg !1900
  call void @llvm.dbg.value(metadata i32 %188, metadata !1897, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !2022
  %189 = lshr i32 %188, 8, !dbg !2021
  %190 = trunc i32 %189 to i8, !dbg !2021
  call void @llvm.dbg.value(metadata i8 %190, metadata !1882, metadata !DIExpression()), !dbg !1900
  %191 = lshr i32 %188, 16, !dbg !2021
  call void @llvm.dbg.value(metadata i32 %191, metadata !1883, metadata !DIExpression()), !dbg !1900
  call void @llvm.dbg.value(metadata i8** %4, metadata !1899, metadata !DIExpression()), !dbg !2022
  %192 = and i32 %188, 255, !dbg !2021
  %193 = zext i32 %192 to i64, !dbg !2021
  %194 = getelementptr inbounds i8*, i8** %4, i64 %193, !dbg !2021
  %195 = bitcast i8** %194 to void (i8, i32, i32*, i64*, i8**)**, !dbg !2021
  %196 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %195, align 8, !dbg !2021, !tbaa !1541
  musttail call cc 10 void %196(i8 noundef zeroext %190, i32 noundef %191, i32* noundef nonnull %27, i64* noundef %187, i8** noundef %4), !dbg !2021
  ret void, !dbg !2021
}

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_KONST(i8 noundef zeroext %0, i32 noundef %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !2023 {
  call void @llvm.dbg.value(metadata i8 %0, metadata !2025, metadata !DIExpression()), !dbg !2035
  call void @llvm.dbg.value(metadata i32 %1, metadata !2026, metadata !DIExpression()), !dbg !2035
  call void @llvm.dbg.value(metadata i32* %2, metadata !2027, metadata !DIExpression()), !dbg !2035
  call void @llvm.dbg.value(metadata i64* %3, metadata !2028, metadata !DIExpression()), !dbg !2035
  call void @llvm.dbg.value(metadata i8** %4, metadata !2029, metadata !DIExpression()), !dbg !2035
  call void @llvm.dbg.value(metadata i32 %1, metadata !2030, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !2035
  %6 = getelementptr inbounds i64, i64* %3, i64 -1, !dbg !2036
  %7 = load i64, i64* %6, align 8, !dbg !2036, !tbaa !1576
  %8 = add nsw i64 %7, -5, !dbg !2037
  %9 = inttoptr i64 %8 to %struct.bcfunc*, !dbg !2038
  call void @llvm.dbg.value(metadata %struct.bcfunc* %9, metadata !2031, metadata !DIExpression()), !dbg !2035
  %10 = and i32 %1, 255, !dbg !2039
  %11 = zext i32 %10 to i64, !dbg !2039
  call void @llvm.dbg.value(metadata %struct.bcfunc* %9, metadata !1740, metadata !DIExpression(DW_OP_plus_uconst, 24, DW_OP_stack_value)), !dbg !2040
  call void @llvm.dbg.value(metadata i64 %11, metadata !1798, metadata !DIExpression()), !dbg !2040
  %12 = getelementptr inbounds %struct.bcfunc, %struct.bcfunc* %9, i64 0, i32 1, i32 0, i32 0, i32 0, i32 0, !dbg !2042
  %13 = load i64*, i64** %12, align 8, !dbg !2042, !tbaa !1803
  %14 = getelementptr inbounds i64, i64* %13, i64 %11, !dbg !2043
  %15 = load i64, i64* %14, align 8, !dbg !2044, !tbaa !1576
  %16 = zext i8 %0 to i64, !dbg !2045
  %17 = getelementptr inbounds i64, i64* %3, i64 %16, !dbg !2045
  store i64 %15, i64* %17, align 8, !dbg !2046, !tbaa !1576
  %18 = getelementptr inbounds i32, i32* %2, i64 1, !dbg !2047
  call void @llvm.dbg.value(metadata i32* %18, metadata !2027, metadata !DIExpression()), !dbg !2035
  %19 = load i32, i32* %18, align 4, !dbg !2048, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %19, metadata !2026, metadata !DIExpression()), !dbg !2035
  call void @llvm.dbg.value(metadata i32 %19, metadata !2032, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !2049
  %20 = lshr i32 %19, 8, !dbg !2048
  %21 = trunc i32 %20 to i8, !dbg !2048
  call void @llvm.dbg.value(metadata i8 %21, metadata !2025, metadata !DIExpression()), !dbg !2035
  %22 = lshr i32 %19, 16, !dbg !2048
  call void @llvm.dbg.value(metadata i32 %22, metadata !2026, metadata !DIExpression()), !dbg !2035
  call void @llvm.dbg.value(metadata i8** %4, metadata !2034, metadata !DIExpression()), !dbg !2049
  %23 = and i32 %19, 255, !dbg !2048
  %24 = zext i32 %23 to i64, !dbg !2048
  %25 = getelementptr inbounds i8*, i8** %4, i64 %24, !dbg !2048
  %26 = bitcast i8** %25 to void (i8, i32, i32*, i64*, i8**)**, !dbg !2048
  %27 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %26, align 8, !dbg !2048, !tbaa !1541
  musttail call cc 10 void %27(i8 noundef zeroext %21, i32 noundef %22, i32* noundef nonnull %18, i64* noundef %3, i8** noundef %4), !dbg !2048
  ret void, !dbg !2048
}

; Function Attrs: mustprogress uwtable
define dso_local cc 10 void @INS_JISLT(i8 zeroext %0, i32 noundef %1, i32* noundef %2, i64* noundef %3, i8** noundef %4) #10 !dbg !2050 {
  call void @llvm.dbg.value(metadata i8 undef, metadata !2052, metadata !DIExpression()), !dbg !2064
  call void @llvm.dbg.value(metadata i32 %1, metadata !2053, metadata !DIExpression()), !dbg !2064
  call void @llvm.dbg.value(metadata i32* %2, metadata !2054, metadata !DIExpression()), !dbg !2064
  call void @llvm.dbg.value(metadata i64* %3, metadata !2055, metadata !DIExpression()), !dbg !2064
  call void @llvm.dbg.value(metadata i8** %4, metadata !2056, metadata !DIExpression()), !dbg !2064
  call void @llvm.dbg.value(metadata i32 %1, metadata !2057, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !2064
  %6 = lshr i32 %1, 8, !dbg !2065
  call void @llvm.dbg.value(metadata i32 %6, metadata !2058, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !2064
  %7 = and i32 %1, 255, !dbg !2066
  %8 = zext i32 %7 to i64, !dbg !2066
  %9 = getelementptr inbounds i64, i64* %3, i64 %8, !dbg !2066
  %10 = load i64, i64* %9, align 8, !dbg !2066, !tbaa !1576
  call void @llvm.dbg.value(metadata i64 %10, metadata !2059, metadata !DIExpression()), !dbg !2064
  %11 = and i32 %6, 255, !dbg !2067
  %12 = zext i32 %11 to i64, !dbg !2067
  %13 = getelementptr inbounds i64, i64* %3, i64 %12, !dbg !2067
  %14 = load i64, i64* %13, align 8, !dbg !2067, !tbaa !1576
  call void @llvm.dbg.value(metadata i64 %14, metadata !2060, metadata !DIExpression()), !dbg !2064
  %15 = or i64 %14, %10, !dbg !2068
  %16 = and i64 %15, 1, !dbg !2068
  %17 = icmp eq i64 %16, 0, !dbg !2068
  br i1 %17, label %20, label %18, !dbg !2070, !prof !1645

18:                                               ; preds = %5
  %19 = tail call noundef i64 @_Z13FAIL_SLOWPATHll(i64 undef, i64 undef), !dbg !2071
  unreachable, !dbg !2073

20:                                               ; preds = %5
  %21 = icmp slt i64 %10, %14, !dbg !2074
  %22 = select i1 %21, i64 2, i64 1, !dbg !2076
  %23 = getelementptr inbounds i32, i32* %2, i64 %22, !dbg !2076
  call void @llvm.dbg.value(metadata i32* %23, metadata !2054, metadata !DIExpression()), !dbg !2064
  %24 = load i32, i32* %23, align 4, !dbg !2077, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %24, metadata !2053, metadata !DIExpression()), !dbg !2064
  call void @llvm.dbg.value(metadata i32 %24, metadata !2061, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !2078
  %25 = lshr i32 %24, 8, !dbg !2077
  %26 = trunc i32 %25 to i8, !dbg !2077
  call void @llvm.dbg.value(metadata i8 %26, metadata !2052, metadata !DIExpression()), !dbg !2064
  %27 = lshr i32 %24, 16, !dbg !2077
  call void @llvm.dbg.value(metadata i32 %27, metadata !2053, metadata !DIExpression()), !dbg !2064
  call void @llvm.dbg.value(metadata i8** %4, metadata !2063, metadata !DIExpression()), !dbg !2078
  %28 = and i32 %24, 255, !dbg !2077
  %29 = zext i32 %28 to i64, !dbg !2077
  %30 = getelementptr inbounds i8*, i8** %4, i64 %29, !dbg !2077
  %31 = bitcast i8** %30 to void (i8, i32, i32*, i64*, i8**)**, !dbg !2077
  %32 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %31, align 8, !dbg !2077, !tbaa !1541
  musttail call cc 10 void %32(i8 noundef zeroext %26, i32 noundef %27, i32* noundef nonnull %23, i64* noundef nonnull %3, i8** noundef %4), !dbg !2077
  ret void, !dbg !2077
}

; Function Attrs: mustprogress noreturn nounwind uwtable
define dso_local cc 10 void @INS_UNKNOWN(i8 zeroext %0, i32 %1, i32* nocapture noundef readonly %2, i64* nocapture readnone %3, i8** nocapture readnone %4) #12 !dbg !2079 {
  call void @llvm.dbg.value(metadata i8 undef, metadata !2081, metadata !DIExpression()), !dbg !2086
  call void @llvm.dbg.value(metadata i32 undef, metadata !2082, metadata !DIExpression()), !dbg !2086
  call void @llvm.dbg.value(metadata i32* %2, metadata !2083, metadata !DIExpression()), !dbg !2086
  call void @llvm.dbg.value(metadata i64* undef, metadata !2084, metadata !DIExpression()), !dbg !2086
  call void @llvm.dbg.value(metadata i8** undef, metadata !2085, metadata !DIExpression()), !dbg !2086
  %6 = load i32, i32* %2, align 4, !dbg !2087, !tbaa !1535
  %7 = and i32 %6, 255, !dbg !2087
  %8 = zext i32 %7 to i64, !dbg !2088
  %9 = getelementptr inbounds [0 x i8*], [0 x i8*]* @ins_names, i64 0, i64 %8, !dbg !2088
  %10 = load i8*, i8** %9, align 8, !dbg !2088, !tbaa !1541
  %11 = tail call i32 (i8*, ...) @printf(i8* noundef nonnull dereferenceable(1) getelementptr inbounds ([30 x i8], [30 x i8]* @.str.5, i64 0, i64 0), i8* noundef %10), !dbg !2089
  tail call void @exit(i32 noundef -1) #19, !dbg !2090
  unreachable, !dbg !2090
}

; Function Attrs: mustprogress uwtable
define dso_local void @_Z3runv() local_unnamed_addr #10 !dbg !2091 {
  %1 = alloca i64, align 8
  %2 = bitcast i64* %1 to [2 x i32]*
  store void (i8, i32, i32*, i64*, i8**)* @INS_KSHORT, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 1), align 8, !dbg !2207, !tbaa !1541
  call void @llvm.dbg.declare(metadata [2 x i32]* %2, metadata !2093, metadata !DIExpression()), !dbg !2208
  store i64 34359803910, i64* %1, align 8, !dbg !2208
  call void @llvm.dbg.value(metadata %"class.std::vector"* @funcs, metadata !1864, metadata !DIExpression()), !dbg !2209
  call void @llvm.dbg.value(metadata i64 0, metadata !1867, metadata !DIExpression()), !dbg !2209
  %3 = load %struct.bcfunc**, %struct.bcfunc*** getelementptr inbounds (%"class.std::vector", %"class.std::vector"* @funcs, i64 0, i32 0, i32 0, i32 0, i32 0), align 8, !dbg !2211, !tbaa !1398
  %4 = load %struct.bcfunc*, %struct.bcfunc** %3, align 8, !dbg !2212, !tbaa !1541
  call void @llvm.dbg.value(metadata %struct.bcfunc* %4, metadata !1917, metadata !DIExpression()), !dbg !2213
  call void @llvm.dbg.value(metadata i64 0, metadata !1974, metadata !DIExpression()), !dbg !2213
  %5 = getelementptr inbounds %struct.bcfunc, %struct.bcfunc* %4, i64 0, i32 0, i32 0, i32 0, i32 0, i32 0, !dbg !2215
  %6 = load i32*, i32** %5, align 8, !dbg !2215, !tbaa !1979
  call void @llvm.dbg.value(metadata i32* %6, metadata !2097, metadata !DIExpression()), !dbg !2216
  %7 = getelementptr inbounds [2 x i32], [2 x i32]* %2, i64 0, i64 1, !dbg !2217
  %8 = ptrtoint i32* %7 to i64, !dbg !2218
  %9 = load i64*, i64** @stack, align 8, !dbg !2219, !tbaa !1541
  store i64 %8, i64* %9, align 8, !dbg !2220, !tbaa !1576
  call void @llvm.dbg.value(metadata %"class.std::vector"* @funcs, metadata !1864, metadata !DIExpression()), !dbg !2221
  call void @llvm.dbg.value(metadata i64 0, metadata !1867, metadata !DIExpression()), !dbg !2221
  %10 = ptrtoint %struct.bcfunc* %4 to i64, !dbg !2223
  %11 = add i64 %10, 5, !dbg !2224
  %12 = getelementptr inbounds i64, i64* %9, i64 1, !dbg !2225
  store i64 %11, i64* %12, align 8, !dbg !2226, !tbaa !1576
  %13 = getelementptr inbounds i64, i64* %9, i64 2, !dbg !2227
  store i64* %13, i64** @_ZL5frame, align 8, !dbg !2228, !tbaa !1541
  %14 = load i32, i32* @stacksz, align 4, !dbg !2229, !tbaa !1535
  %15 = zext i32 %14 to i64, !dbg !2230
  %16 = getelementptr inbounds i64, i64* %9, i64 %15, !dbg !2230
  store i64* %16, i64** @_ZL9frame_top, align 8, !dbg !2231, !tbaa !1541
  call void @llvm.dbg.value(metadata i32* %6, metadata !2098, metadata !DIExpression()), !dbg !2216
  call void @llvm.dbg.value(metadata i32 0, metadata !2099, metadata !DIExpression()), !dbg !2232
  call void @llvm.memset.p0i8.i64(i8* noundef nonnull align 16 dereferenceable(64) getelementptr inbounds ([64 x i8], [64 x i8]* @hotmap, i64 0, i64 0), i8 -56, i64 64, i1 false), !dbg !2233, !tbaa !1903
  call void @llvm.dbg.value(metadata i32 undef, metadata !2099, metadata !DIExpression()), !dbg !2232
  call void @llvm.dbg.value(metadata i32 undef, metadata !2099, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !2232
  call void @llvm.dbg.value(metadata i32 undef, metadata !2104, metadata !DIExpression()), !dbg !2216
  call void @llvm.dbg.value(metadata i64 0, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 1, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 1, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 2, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 2, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 3, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 3, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 4, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 4, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 5, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 5, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 6, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 6, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 6), align 16, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 7, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 7, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 8, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 8, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 9, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 9, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 9), align 8, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 10, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 10, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 10), align 16, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 11, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 11, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 11), align 8, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 12, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 12, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 12), align 16, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 13, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 13, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 14, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 14, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 15, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 15, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 16, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 16, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 17, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 17, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 18, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 18, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 18), align 16, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 19, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 19, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 19), align 8, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 20, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 20, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 20), align 16, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 21, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 21, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 21), align 8, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 22, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 22, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 23, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 23, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 23), align 8, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 24, metadata !2107, metadata !DIExpression()), !dbg !2236
  call void @llvm.dbg.value(metadata i64 24, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_UNKNOWN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 24), align 16, !dbg !2237, !tbaa !1541
  call void @llvm.dbg.value(metadata i64 25, metadata !2107, metadata !DIExpression()), !dbg !2236
  store void (i8, i32, i32*, i64*, i8**)* @INS_FUNC, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 0), align 16, !dbg !2240, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_KSHORT, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 1), align 8, !dbg !2241, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_ISGE, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 2), align 16, !dbg !2242, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_JMP, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 3), align 8, !dbg !2243, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_RET1, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 4), align 16, !dbg !2244, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_SUBVN, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 5), align 8, !dbg !2245, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_ADDVV, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 7), align 8, !dbg !2246, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_HALT, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 8), align 16, !dbg !2247, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_GGET, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 13), align 8, !dbg !2248, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_GSET, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 14), align 16, !dbg !2249, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_KFUNC, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 15), align 8, !dbg !2250, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_CALLT, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 16), align 16, !dbg !2251, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_KONST, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 17), align 8, !dbg !2252, !tbaa !1541
  store void (i8, i32, i32*, i64*, i8**)* @INS_JISLT, void (i8, i32, i32*, i64*, i8**)** getelementptr inbounds ([25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 22), align 16, !dbg !2253, !tbaa !1541
  %17 = load i32, i32* %6, align 4, !dbg !2254, !tbaa !1535
  call void @llvm.dbg.value(metadata i32 %17, metadata !2109, metadata !DIExpression()), !dbg !2255
  call void @llvm.dbg.value(metadata i32 %17, metadata !2112, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !2255
  %18 = lshr i32 %17, 8, !dbg !2256
  %19 = trunc i32 %18 to i8, !dbg !2257
  call void @llvm.dbg.value(metadata i8 %19, metadata !2113, metadata !DIExpression()), !dbg !2255
  %20 = lshr i32 %17, 16, !dbg !2258
  call void @llvm.dbg.value(metadata i32 %20, metadata !2109, metadata !DIExpression()), !dbg !2255
  call void @llvm.dbg.value(metadata i8** bitcast ([25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table to i8**), metadata !2114, metadata !DIExpression()), !dbg !2255
  %21 = and i32 %17, 255, !dbg !2259
  %22 = zext i32 %21 to i64, !dbg !2259
  %23 = getelementptr inbounds [25 x void (i8, i32, i32*, i64*, i8**)*], [25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table, i64 0, i64 %22, !dbg !2259
  %24 = load void (i8, i32, i32*, i64*, i8**)*, void (i8, i32, i32*, i64*, i8**)** %23, align 8, !dbg !2259, !tbaa !1541
  call cc 10 void %24(i8 noundef zeroext %19, i32 noundef %20, i32* noundef nonnull %6, i64* noundef nonnull %13, i8** noundef bitcast ([25 x void (i8, i32, i32*, i64*, i8**)*]* @_ZL8op_table to i8**)), !dbg !2259
  %25 = load i8*, i8** bitcast (i64** @stack to i8**), align 8, !dbg !2260, !tbaa !1541
  call void @free(i8* noundef %25) #17, !dbg !2261
  ret void, !dbg !2262
}

; Function Attrs: inaccessiblemem_or_argmemonly mustprogress nounwind willreturn
declare void @free(i8* nocapture noundef) local_unnamed_addr #9

declare i32 @__gxx_personality_v0(...)

; Function Attrs: nobuiltin nounwind
declare void @_ZdlPv(i8* noundef) local_unnamed_addr #13

; Function Attrs: nofree nounwind uwtable
define internal void @_GLOBAL__sub_I_vm.cpp() #14 section ".text.startup" !dbg !2263 {
  call void @llvm.dbg.value(metadata %"class.std::vector"* @funcs, metadata !2265, metadata !DIExpression()) #17, !dbg !2268
  call void @llvm.dbg.value(metadata %"class.std::vector"* @funcs, metadata !2272, metadata !DIExpression()) #17, !dbg !2275
  call void @llvm.dbg.value(metadata %"class.std::vector"* @funcs, metadata !2277, metadata !DIExpression()) #17, !dbg !2281
  call void @llvm.dbg.value(metadata %"class.std::vector"* @funcs, metadata !2283, metadata !DIExpression()) #17, !dbg !2287
  tail call void @llvm.memset.p0i8.i64(i8* noundef nonnull align 8 dereferenceable(24) bitcast (%"class.std::vector"* @funcs to i8*), i8 0, i64 24, i1 false) #17, !dbg !2289
  %1 = tail call i32 @__cxa_atexit(void (i8*)* bitcast (void (%"class.std::vector"*)* @_ZNSt6vectorIP6bcfuncSaIS1_EED2Ev to void (i8*)*), i8* bitcast (%"class.std::vector"* @funcs to i8*), i8* nonnull @__dso_handle) #17, !dbg !2290
  %2 = load i32, i32* @stacksz, align 4, !dbg !2291, !tbaa !1535
  %3 = zext i32 %2 to i64, !dbg !2291
  %4 = mul nuw nsw i64 %3, 8000000, !dbg !2294
  %5 = tail call noalias i8* @malloc(i64 noundef %4) #17, !dbg !2295
  store i8* %5, i8** bitcast (i64** @stack to i8**), align 8, !dbg !2296, !tbaa !1541
  ret void
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #15

; Function Attrs: nofree nounwind
declare noundef i32 @puts(i8* nocapture noundef readonly) local_unnamed_addr #1

; Function Attrs: argmemonly nofree nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #16

attributes #0 = { nounwind uwtable "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nounwind }
attributes #2 = { mustprogress nofree noinline norecurse nosync nounwind readnone uwtable willreturn "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { mustprogress nofree nosync nounwind readnone speculatable willreturn }
attributes #4 = { mustprogress noinline noreturn nounwind uwtable "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #5 = { nofree nounwind "frame-pointer"="none" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #6 = { noreturn nounwind "frame-pointer"="none" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #7 = { inaccessiblememonly mustprogress nofree nounwind willreturn "frame-pointer"="none" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #8 = { mustprogress noinline nounwind uwtable "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #9 = { inaccessiblemem_or_argmemonly mustprogress nounwind willreturn "frame-pointer"="none" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #10 = { mustprogress uwtable "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #11 = { mustprogress nofree nounwind uwtable "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #12 = { mustprogress noreturn nounwind uwtable "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #13 = { nobuiltin nounwind "frame-pointer"="none" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #14 = { nofree nounwind uwtable "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #15 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #16 = { argmemonly nofree nounwind willreturn writeonly }
attributes #17 = { nounwind }
attributes #18 = { builtin nounwind }
attributes #19 = { noreturn nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!1377, !1378, !1379, !1380, !1381, !1382}
!llvm.ident = !{!1383}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "joff", scope: !2, file: !3, line: 10, type: !547, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus_14, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !4, globals: !531, imports: !565, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "vm.cpp", directory: "/home/davejwatson/myprojects/boom")
!4 = !{!5, !6, !8, !15, !18, !28, !7, !38, !16, !39, !40, !43, !46, !67, !73, !169}
!5 = !DIBasicType(name: "double", size: 64, encoding: DW_ATE_float)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIDerivedType(tag: DW_TAG_typedef, name: "op_func", file: !3, line: 48, baseType: !10)
!10 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !11, size: 64)
!11 = !DISubroutineType(types: !12)
!12 = !{null, !13, !14, !15, !6, !16}
!13 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!14 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !14, size: 64)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bcfunc", file: !20, line: 48, size: 384, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !21, identifier: "_ZTS6bcfunc")
!20 = !DIFile(filename: "./bytecode.h", directory: "/home/davejwatson/myprojects/boom")
!21 = !{!22, !26}
!22 = !DIDerivedType(tag: DW_TAG_member, name: "code", scope: !19, file: !20, line: 49, baseType: !23, size: 192)
!23 = !DICompositeType(tag: DW_TAG_class_type, name: "vector<unsigned int, std::allocator<unsigned int> >", scope: !25, file: !24, line: 423, size: 192, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSSt6vectorIjSaIjEE")
!24 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h", directory: "")
!25 = !DINamespace(name: "std", scope: null)
!26 = !DIDerivedType(tag: DW_TAG_member, name: "consts", scope: !19, file: !20, line: 50, baseType: !27, size: 192, offset: 192)
!27 = !DICompositeType(tag: DW_TAG_class_type, name: "vector<unsigned long, std::allocator<unsigned long> >", scope: !25, file: !24, line: 423, size: 192, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSSt6vectorImSaImEE")
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "symbol", file: !20, line: 53, size: 320, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !30, identifier: "_ZTS6symbol")
!30 = !{!31, !37}
!31 = !DIDerivedType(tag: DW_TAG_member, name: "name", scope: !29, file: !20, line: 54, baseType: !32, size: 256)
!32 = !DIDerivedType(tag: DW_TAG_typedef, name: "string", scope: !25, file: !33, line: 77, baseType: !34)
!33 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stringfwd.h", directory: "")
!34 = !DICompositeType(tag: DW_TAG_class_type, name: "basic_string<char, std::char_traits<char>, std::allocator<char> >", scope: !36, file: !35, line: 1082, size: 256, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE")
!35 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/basic_string.tcc", directory: "")
!36 = !DINamespace(name: "__cxx11", scope: !25, exportSymbols: true)
!37 = !DIDerivedType(tag: DW_TAG_member, name: "val", scope: !29, file: !20, line: 55, baseType: !38, size: 64, offset: 256)
!38 = !DIBasicType(name: "unsigned long", size: 64, encoding: DW_ATE_unsigned)
!39 = !DIBasicType(name: "bool", size: 8, encoding: DW_ATE_boolean)
!40 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "vector<bcfunc *, std::allocator<bcfunc *> >", scope: !25, file: !24, line: 423, size: 192, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !41, templateParams: !262, identifier: "_ZTSSt6vectorIP6bcfuncSaIS1_EE")
!41 = !{!42, !263, !282, !298, !299, !305, !308, !311, !315, !321, !325, !331, !336, !340, !350, !353, !356, !359, !364, !365, !369, !372, !375, !378, !381, !387, !393, !394, !395, !400, !405, !406, !407, !408, !409, !410, !411, !414, !415, !418, !419, !420, !421, !424, !425, !433, !440, !443, !444, !445, !448, !451, !452, !453, !456, !459, !462, !466, !467, !470, !473, !476, !479, !482, !485, !488, !489, !490, !491, !492, !495, !496, !499, !500, !501, !508, !511, !516, !519, !522, !525, !528}
!42 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !40, baseType: !43, flags: DIFlagProtected, extraData: i32 0)
!43 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "_Vector_base<bcfunc *, std::allocator<bcfunc *> >", scope: !25, file: !24, line: 85, size: 192, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !44, templateParams: !262, identifier: "_ZTSSt12_Vector_baseIP6bcfuncSaIS1_EE")
!44 = !{!45, !213, !218, !223, !227, !230, !235, !238, !241, !245, !248, !251, !254, !255, !258, !261}
!45 = !DIDerivedType(tag: DW_TAG_member, name: "_M_impl", scope: !43, file: !24, line: 371, baseType: !46, size: 192)
!46 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "_Vector_impl", scope: !43, file: !24, line: 133, size: 192, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !47, identifier: "_ZTSNSt12_Vector_baseIP6bcfuncSaIS1_EE12_Vector_implE")
!47 = !{!48, !168, !193, !197, !202, !206, !210}
!48 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !46, baseType: !49, extraData: i32 0)
!49 = !DIDerivedType(tag: DW_TAG_typedef, name: "_Tp_alloc_type", scope: !43, file: !24, line: 88, baseType: !50)
!50 = !DIDerivedType(tag: DW_TAG_typedef, name: "other", scope: !52, file: !51, line: 120, baseType: !167)
!51 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/ext/alloc_traits.h", directory: "")
!52 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "rebind<bcfunc *>", scope: !53, file: !51, line: 119, size: 8, flags: DIFlagTypePassByValue, elements: !166, templateParams: !116, identifier: "_ZTSN9__gnu_cxx14__alloc_traitsISaIP6bcfuncES2_E6rebindIS2_EE")
!53 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "__alloc_traits<std::allocator<bcfunc *>, bcfunc *>", scope: !54, file: !51, line: 48, size: 8, flags: DIFlagTypePassByValue, elements: !55, templateParams: !164, identifier: "_ZTSN9__gnu_cxx14__alloc_traitsISaIP6bcfuncES2_EE")
!54 = !DINamespace(name: "__gnu_cxx", scope: null)
!55 = !{!56, !151, !154, !157, !160, !161, !162, !163}
!56 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !53, baseType: !57, extraData: i32 0)
!57 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "allocator_traits<std::allocator<bcfunc *> >", scope: !25, file: !58, line: 411, size: 8, flags: DIFlagTypePassByValue, elements: !59, templateParams: !149, identifier: "_ZTSSt16allocator_traitsISaIP6bcfuncEE")
!58 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/alloc_traits.h", directory: "")
!59 = !{!60, !133, !137, !140, !146}
!60 = !DISubprogram(name: "allocate", linkageName: "_ZNSt16allocator_traitsISaIP6bcfuncEE8allocateERS2_m", scope: !57, file: !58, line: 463, type: !61, scopeLine: 463, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!61 = !DISubroutineType(types: !62)
!62 = !{!63, !65, !132}
!63 = !DIDerivedType(tag: DW_TAG_typedef, name: "pointer", scope: !57, file: !58, line: 420, baseType: !64)
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!65 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !66, size: 64)
!66 = !DIDerivedType(tag: DW_TAG_typedef, name: "allocator_type", scope: !57, file: !58, line: 414, baseType: !67)
!67 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "allocator<bcfunc *>", scope: !25, file: !68, line: 124, size: 8, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !69, templateParams: !116, identifier: "_ZTSSaIP6bcfuncE")
!68 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/allocator.h", directory: "")
!69 = !{!70, !118, !122, !127, !131}
!70 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !67, baseType: !71, flags: DIFlagPublic, extraData: i32 0)
!71 = !DIDerivedType(tag: DW_TAG_typedef, name: "__allocator_base<bcfunc *>", scope: !25, file: !72, line: 47, baseType: !73)
!72 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/x86_64-linux-gnu/c++/12/bits/c++allocator.h", directory: "")
!73 = distinct !DICompositeType(tag: DW_TAG_class_type, name: "__new_allocator<bcfunc *>", scope: !25, file: !74, line: 56, size: 8, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !75, templateParams: !116, identifier: "_ZTSSt15__new_allocatorIP6bcfuncE")
!74 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/new_allocator.h", directory: "")
!75 = !{!76, !80, !85, !86, !93, !101, !109, !112, !115}
!76 = !DISubprogram(name: "__new_allocator", scope: !73, file: !74, line: 80, type: !77, scopeLine: 80, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!77 = !DISubroutineType(types: !78)
!78 = !{null, !79}
!79 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !73, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!80 = !DISubprogram(name: "__new_allocator", scope: !73, file: !74, line: 83, type: !81, scopeLine: 83, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!81 = !DISubroutineType(types: !82)
!82 = !{null, !79, !83}
!83 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !84, size: 64)
!84 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !73)
!85 = !DISubprogram(name: "~__new_allocator", scope: !73, file: !74, line: 90, type: !77, scopeLine: 90, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!86 = !DISubprogram(name: "address", linkageName: "_ZNKSt15__new_allocatorIP6bcfuncE7addressERS1_", scope: !73, file: !74, line: 93, type: !87, scopeLine: 93, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!87 = !DISubroutineType(types: !88)
!88 = !{!89, !90, !91}
!89 = !DIDerivedType(tag: DW_TAG_typedef, name: "pointer", scope: !73, file: !74, line: 63, baseType: !64)
!90 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !84, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!91 = !DIDerivedType(tag: DW_TAG_typedef, name: "reference", scope: !73, file: !74, line: 65, baseType: !92)
!92 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !18, size: 64)
!93 = !DISubprogram(name: "address", linkageName: "_ZNKSt15__new_allocatorIP6bcfuncE7addressERKS1_", scope: !73, file: !74, line: 97, type: !94, scopeLine: 97, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!94 = !DISubroutineType(types: !95)
!95 = !{!96, !90, !99}
!96 = !DIDerivedType(tag: DW_TAG_typedef, name: "const_pointer", scope: !73, file: !74, line: 64, baseType: !97)
!97 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !98, size: 64)
!98 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !18)
!99 = !DIDerivedType(tag: DW_TAG_typedef, name: "const_reference", scope: !73, file: !74, line: 66, baseType: !100)
!100 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !98, size: 64)
!101 = !DISubprogram(name: "allocate", linkageName: "_ZNSt15__new_allocatorIP6bcfuncE8allocateEmPKv", scope: !73, file: !74, line: 112, type: !102, scopeLine: 112, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!102 = !DISubroutineType(types: !103)
!103 = !{!64, !79, !104, !107}
!104 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_type", file: !74, line: 60, baseType: !105)
!105 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_t", scope: !25, file: !106, line: 298, baseType: !38)
!106 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/x86_64-linux-gnu/c++/12/bits/c++config.h", directory: "")
!107 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !108, size: 64)
!108 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!109 = !DISubprogram(name: "deallocate", linkageName: "_ZNSt15__new_allocatorIP6bcfuncE10deallocateEPS1_m", scope: !73, file: !74, line: 142, type: !110, scopeLine: 142, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!110 = !DISubroutineType(types: !111)
!111 = !{null, !79, !64, !104}
!112 = !DISubprogram(name: "max_size", linkageName: "_ZNKSt15__new_allocatorIP6bcfuncE8max_sizeEv", scope: !73, file: !74, line: 167, type: !113, scopeLine: 167, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!113 = !DISubroutineType(types: !114)
!114 = !{!104, !90}
!115 = !DISubprogram(name: "_M_max_size", linkageName: "_ZNKSt15__new_allocatorIP6bcfuncE11_M_max_sizeEv", scope: !73, file: !74, line: 210, type: !113, scopeLine: 210, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!116 = !{!117}
!117 = !DITemplateTypeParameter(name: "_Tp", type: !18)
!118 = !DISubprogram(name: "allocator", scope: !67, file: !68, line: 156, type: !119, scopeLine: 156, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!119 = !DISubroutineType(types: !120)
!120 = !{null, !121}
!121 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !67, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!122 = !DISubprogram(name: "allocator", scope: !67, file: !68, line: 159, type: !123, scopeLine: 159, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!123 = !DISubroutineType(types: !124)
!124 = !{null, !121, !125}
!125 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !126, size: 64)
!126 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !67)
!127 = !DISubprogram(name: "operator=", linkageName: "_ZNSaIP6bcfuncEaSERKS1_", scope: !67, file: !68, line: 164, type: !128, scopeLine: 164, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!128 = !DISubroutineType(types: !129)
!129 = !{!130, !121, !125}
!130 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !67, size: 64)
!131 = !DISubprogram(name: "~allocator", scope: !67, file: !68, line: 174, type: !119, scopeLine: 174, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!132 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_type", file: !58, line: 435, baseType: !105)
!133 = !DISubprogram(name: "allocate", linkageName: "_ZNSt16allocator_traitsISaIP6bcfuncEE8allocateERS2_mPKv", scope: !57, file: !58, line: 477, type: !134, scopeLine: 477, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!134 = !DISubroutineType(types: !135)
!135 = !{!63, !65, !132, !136}
!136 = !DIDerivedType(tag: DW_TAG_typedef, name: "const_void_pointer", file: !58, line: 429, baseType: !107)
!137 = !DISubprogram(name: "deallocate", linkageName: "_ZNSt16allocator_traitsISaIP6bcfuncEE10deallocateERS2_PS1_m", scope: !57, file: !58, line: 495, type: !138, scopeLine: 495, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!138 = !DISubroutineType(types: !139)
!139 = !{null, !65, !63, !132}
!140 = !DISubprogram(name: "max_size", linkageName: "_ZNSt16allocator_traitsISaIP6bcfuncEE8max_sizeERKS2_", scope: !57, file: !58, line: 547, type: !141, scopeLine: 547, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!141 = !DISubroutineType(types: !142)
!142 = !{!143, !144}
!143 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_type", scope: !57, file: !58, line: 435, baseType: !105)
!144 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !145, size: 64)
!145 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !66)
!146 = !DISubprogram(name: "select_on_container_copy_construction", linkageName: "_ZNSt16allocator_traitsISaIP6bcfuncEE37select_on_container_copy_constructionERKS2_", scope: !57, file: !58, line: 562, type: !147, scopeLine: 562, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!147 = !DISubroutineType(types: !148)
!148 = !{!66, !144}
!149 = !{!150}
!150 = !DITemplateTypeParameter(name: "_Alloc", type: !67)
!151 = !DISubprogram(name: "_S_select_on_copy", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIP6bcfuncES2_E17_S_select_on_copyERKS3_", scope: !53, file: !51, line: 97, type: !152, scopeLine: 97, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!152 = !DISubroutineType(types: !153)
!153 = !{!67, !125}
!154 = !DISubprogram(name: "_S_on_swap", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIP6bcfuncES2_E10_S_on_swapERS3_S5_", scope: !53, file: !51, line: 100, type: !155, scopeLine: 100, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!155 = !DISubroutineType(types: !156)
!156 = !{null, !130, !130}
!157 = !DISubprogram(name: "_S_propagate_on_copy_assign", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIP6bcfuncES2_E27_S_propagate_on_copy_assignEv", scope: !53, file: !51, line: 103, type: !158, scopeLine: 103, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!158 = !DISubroutineType(types: !159)
!159 = !{!39}
!160 = !DISubprogram(name: "_S_propagate_on_move_assign", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIP6bcfuncES2_E27_S_propagate_on_move_assignEv", scope: !53, file: !51, line: 106, type: !158, scopeLine: 106, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!161 = !DISubprogram(name: "_S_propagate_on_swap", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIP6bcfuncES2_E20_S_propagate_on_swapEv", scope: !53, file: !51, line: 109, type: !158, scopeLine: 109, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!162 = !DISubprogram(name: "_S_always_equal", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIP6bcfuncES2_E15_S_always_equalEv", scope: !53, file: !51, line: 112, type: !158, scopeLine: 112, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!163 = !DISubprogram(name: "_S_nothrow_move", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIP6bcfuncES2_E15_S_nothrow_moveEv", scope: !53, file: !51, line: 115, type: !158, scopeLine: 115, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!164 = !{!150, !165}
!165 = !DITemplateTypeParameter(type: !18)
!166 = !{}
!167 = !DIDerivedType(tag: DW_TAG_typedef, name: "rebind_alloc<bcfunc *>", scope: !57, file: !58, line: 450, baseType: !67)
!168 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !46, baseType: !169, extraData: i32 0)
!169 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "_Vector_impl_data", scope: !43, file: !24, line: 92, size: 192, flags: DIFlagTypePassByReference | DIFlagNonTrivial, elements: !170, identifier: "_ZTSNSt12_Vector_baseIP6bcfuncSaIS1_EE17_Vector_impl_dataE")
!170 = !{!171, !174, !175, !176, !180, !184, !189}
!171 = !DIDerivedType(tag: DW_TAG_member, name: "_M_start", scope: !169, file: !24, line: 94, baseType: !172, size: 64)
!172 = !DIDerivedType(tag: DW_TAG_typedef, name: "pointer", scope: !43, file: !24, line: 90, baseType: !173)
!173 = !DIDerivedType(tag: DW_TAG_typedef, name: "pointer", scope: !53, file: !51, line: 57, baseType: !63)
!174 = !DIDerivedType(tag: DW_TAG_member, name: "_M_finish", scope: !169, file: !24, line: 95, baseType: !172, size: 64, offset: 64)
!175 = !DIDerivedType(tag: DW_TAG_member, name: "_M_end_of_storage", scope: !169, file: !24, line: 96, baseType: !172, size: 64, offset: 128)
!176 = !DISubprogram(name: "_Vector_impl_data", scope: !169, file: !24, line: 99, type: !177, scopeLine: 99, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!177 = !DISubroutineType(types: !178)
!178 = !{null, !179}
!179 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !169, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!180 = !DISubprogram(name: "_Vector_impl_data", scope: !169, file: !24, line: 105, type: !181, scopeLine: 105, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!181 = !DISubroutineType(types: !182)
!182 = !{null, !179, !183}
!183 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !169, size: 64)
!184 = !DISubprogram(name: "_M_copy_data", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EE17_Vector_impl_data12_M_copy_dataERKS4_", scope: !169, file: !24, line: 113, type: !185, scopeLine: 113, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!185 = !DISubroutineType(types: !186)
!186 = !{null, !179, !187}
!187 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !188, size: 64)
!188 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !169)
!189 = !DISubprogram(name: "_M_swap_data", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EE17_Vector_impl_data12_M_swap_dataERS4_", scope: !169, file: !24, line: 122, type: !190, scopeLine: 122, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!190 = !DISubroutineType(types: !191)
!191 = !{null, !179, !192}
!192 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !169, size: 64)
!193 = !DISubprogram(name: "_Vector_impl", scope: !46, file: !24, line: 137, type: !194, scopeLine: 137, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!194 = !DISubroutineType(types: !195)
!195 = !{null, !196}
!196 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!197 = !DISubprogram(name: "_Vector_impl", scope: !46, file: !24, line: 143, type: !198, scopeLine: 143, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!198 = !DISubroutineType(types: !199)
!199 = !{null, !196, !200}
!200 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !201, size: 64)
!201 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !49)
!202 = !DISubprogram(name: "_Vector_impl", scope: !46, file: !24, line: 151, type: !203, scopeLine: 151, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!203 = !DISubroutineType(types: !204)
!204 = !{null, !196, !205}
!205 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !46, size: 64)
!206 = !DISubprogram(name: "_Vector_impl", scope: !46, file: !24, line: 156, type: !207, scopeLine: 156, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!207 = !DISubroutineType(types: !208)
!208 = !{null, !196, !209}
!209 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !49, size: 64)
!210 = !DISubprogram(name: "_Vector_impl", scope: !46, file: !24, line: 161, type: !211, scopeLine: 161, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!211 = !DISubroutineType(types: !212)
!212 = !{null, !196, !209, !205}
!213 = !DISubprogram(name: "_M_get_Tp_allocator", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EE19_M_get_Tp_allocatorEv", scope: !43, file: !24, line: 298, type: !214, scopeLine: 298, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!214 = !DISubroutineType(types: !215)
!215 = !{!216, !217}
!216 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !49, size: 64)
!217 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!218 = !DISubprogram(name: "_M_get_Tp_allocator", linkageName: "_ZNKSt12_Vector_baseIP6bcfuncSaIS1_EE19_M_get_Tp_allocatorEv", scope: !43, file: !24, line: 303, type: !219, scopeLine: 303, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!219 = !DISubroutineType(types: !220)
!220 = !{!200, !221}
!221 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !222, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!222 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !43)
!223 = !DISubprogram(name: "get_allocator", linkageName: "_ZNKSt12_Vector_baseIP6bcfuncSaIS1_EE13get_allocatorEv", scope: !43, file: !24, line: 308, type: !224, scopeLine: 308, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!224 = !DISubroutineType(types: !225)
!225 = !{!226, !221}
!226 = !DIDerivedType(tag: DW_TAG_typedef, name: "allocator_type", scope: !43, file: !24, line: 294, baseType: !67)
!227 = !DISubprogram(name: "_Vector_base", scope: !43, file: !24, line: 312, type: !228, scopeLine: 312, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!228 = !DISubroutineType(types: !229)
!229 = !{null, !217}
!230 = !DISubprogram(name: "_Vector_base", scope: !43, file: !24, line: 318, type: !231, scopeLine: 318, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!231 = !DISubroutineType(types: !232)
!232 = !{null, !217, !233}
!233 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !234, size: 64)
!234 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !226)
!235 = !DISubprogram(name: "_Vector_base", scope: !43, file: !24, line: 324, type: !236, scopeLine: 324, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!236 = !DISubroutineType(types: !237)
!237 = !{null, !217, !105}
!238 = !DISubprogram(name: "_Vector_base", scope: !43, file: !24, line: 330, type: !239, scopeLine: 330, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!239 = !DISubroutineType(types: !240)
!240 = !{null, !217, !105, !233}
!241 = !DISubprogram(name: "_Vector_base", scope: !43, file: !24, line: 335, type: !242, scopeLine: 335, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!242 = !DISubroutineType(types: !243)
!243 = !{null, !217, !244}
!244 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !43, size: 64)
!245 = !DISubprogram(name: "_Vector_base", scope: !43, file: !24, line: 340, type: !246, scopeLine: 340, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!246 = !DISubroutineType(types: !247)
!247 = !{null, !217, !209}
!248 = !DISubprogram(name: "_Vector_base", scope: !43, file: !24, line: 344, type: !249, scopeLine: 344, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!249 = !DISubroutineType(types: !250)
!250 = !{null, !217, !244, !233}
!251 = !DISubprogram(name: "_Vector_base", scope: !43, file: !24, line: 358, type: !252, scopeLine: 358, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!252 = !DISubroutineType(types: !253)
!253 = !{null, !217, !233, !244}
!254 = !DISubprogram(name: "~_Vector_base", scope: !43, file: !24, line: 364, type: !228, scopeLine: 364, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!255 = !DISubprogram(name: "_M_allocate", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EE11_M_allocateEm", scope: !43, file: !24, line: 375, type: !256, scopeLine: 375, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!256 = !DISubroutineType(types: !257)
!257 = !{!172, !217, !105}
!258 = !DISubprogram(name: "_M_deallocate", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EE13_M_deallocateEPS1_m", scope: !43, file: !24, line: 383, type: !259, scopeLine: 383, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!259 = !DISubroutineType(types: !260)
!260 = !{null, !217, !172, !105}
!261 = !DISubprogram(name: "_M_create_storage", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EE17_M_create_storageEm", scope: !43, file: !24, line: 393, type: !236, scopeLine: 393, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!262 = !{!117, !150}
!263 = !DISubprogram(name: "_S_nothrow_relocate", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE19_S_nothrow_relocateESt17integral_constantIbLb1EE", scope: !40, file: !24, line: 465, type: !264, scopeLine: 465, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!264 = !DISubroutineType(types: !265)
!265 = !{!39, !266}
!266 = !DIDerivedType(tag: DW_TAG_typedef, name: "true_type", scope: !25, file: !267, line: 82, baseType: !268)
!267 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/type_traits", directory: "")
!268 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "integral_constant<bool, true>", scope: !25, file: !267, line: 62, size: 8, flags: DIFlagTypePassByValue, elements: !269, templateParams: !279, identifier: "_ZTSSt17integral_constantIbLb1EE")
!269 = !{!270, !272, !278}
!270 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !268, file: !267, line: 64, baseType: !271, flags: DIFlagStaticMember, extraData: i1 true)
!271 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !39)
!272 = !DISubprogram(name: "operator bool", linkageName: "_ZNKSt17integral_constantIbLb1EEcvbEv", scope: !268, file: !267, line: 67, type: !273, scopeLine: 67, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!273 = !DISubroutineType(types: !274)
!274 = !{!275, !276}
!275 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_type", scope: !268, file: !267, line: 65, baseType: !39)
!276 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !277, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!277 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !268)
!278 = !DISubprogram(name: "operator()", linkageName: "_ZNKSt17integral_constantIbLb1EEclEv", scope: !268, file: !267, line: 72, type: !273, scopeLine: 72, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!279 = !{!280, !281}
!280 = !DITemplateTypeParameter(name: "_Tp", type: !39)
!281 = !DITemplateValueParameter(name: "__v", type: !39, value: i8 1)
!282 = !DISubprogram(name: "_S_nothrow_relocate", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE19_S_nothrow_relocateESt17integral_constantIbLb0EE", scope: !40, file: !24, line: 474, type: !283, scopeLine: 474, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!283 = !DISubroutineType(types: !284)
!284 = !{!39, !285}
!285 = !DIDerivedType(tag: DW_TAG_typedef, name: "false_type", scope: !25, file: !267, line: 85, baseType: !286)
!286 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "integral_constant<bool, false>", scope: !25, file: !267, line: 62, size: 8, flags: DIFlagTypePassByValue, elements: !287, templateParams: !296, identifier: "_ZTSSt17integral_constantIbLb0EE")
!287 = !{!288, !289, !295}
!288 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !286, file: !267, line: 64, baseType: !271, flags: DIFlagStaticMember, extraData: i1 false)
!289 = !DISubprogram(name: "operator bool", linkageName: "_ZNKSt17integral_constantIbLb0EEcvbEv", scope: !286, file: !267, line: 67, type: !290, scopeLine: 67, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!290 = !DISubroutineType(types: !291)
!291 = !{!292, !293}
!292 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_type", scope: !286, file: !267, line: 65, baseType: !39)
!293 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !294, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!294 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !286)
!295 = !DISubprogram(name: "operator()", linkageName: "_ZNKSt17integral_constantIbLb0EEclEv", scope: !286, file: !267, line: 72, type: !290, scopeLine: 72, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!296 = !{!280, !297}
!297 = !DITemplateValueParameter(name: "__v", type: !39, value: i8 0)
!298 = !DISubprogram(name: "_S_use_relocate", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE15_S_use_relocateEv", scope: !40, file: !24, line: 478, type: !158, scopeLine: 478, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!299 = !DISubprogram(name: "_S_do_relocate", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE14_S_do_relocateEPS1_S4_S4_RS2_St17integral_constantIbLb1EE", scope: !40, file: !24, line: 487, type: !300, scopeLine: 487, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!300 = !DISubroutineType(types: !301)
!301 = !{!302, !302, !302, !302, !303, !266}
!302 = !DIDerivedType(tag: DW_TAG_typedef, name: "pointer", scope: !40, file: !24, line: 449, baseType: !172)
!303 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !304, size: 64)
!304 = !DIDerivedType(tag: DW_TAG_typedef, name: "_Tp_alloc_type", scope: !40, file: !24, line: 444, baseType: !49)
!305 = !DISubprogram(name: "_S_do_relocate", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE14_S_do_relocateEPS1_S4_S4_RS2_St17integral_constantIbLb0EE", scope: !40, file: !24, line: 494, type: !306, scopeLine: 494, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!306 = !DISubroutineType(types: !307)
!307 = !{!302, !302, !302, !302, !303, !285}
!308 = !DISubprogram(name: "_S_relocate", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE11_S_relocateEPS1_S4_S4_RS2_", scope: !40, file: !24, line: 499, type: !309, scopeLine: 499, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!309 = !DISubroutineType(types: !310)
!310 = !{!302, !302, !302, !302, !303}
!311 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 526, type: !312, scopeLine: 526, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!312 = !DISubroutineType(types: !313)
!313 = !{null, !314}
!314 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!315 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 537, type: !316, scopeLine: 537, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!316 = !DISubroutineType(types: !317)
!317 = !{null, !314, !318}
!318 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !319, size: 64)
!319 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !320)
!320 = !DIDerivedType(tag: DW_TAG_typedef, name: "allocator_type", scope: !40, file: !24, line: 460, baseType: !67)
!321 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 551, type: !322, scopeLine: 551, flags: DIFlagPublic | DIFlagExplicit | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!322 = !DISubroutineType(types: !323)
!323 = !{null, !314, !324, !318}
!324 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_type", file: !24, line: 458, baseType: !105)
!325 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 564, type: !326, scopeLine: 564, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!326 = !DISubroutineType(types: !327)
!327 = !{null, !314, !324, !328, !318}
!328 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !329, size: 64)
!329 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !330)
!330 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_type", scope: !40, file: !24, line: 448, baseType: !18)
!331 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 596, type: !332, scopeLine: 596, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!332 = !DISubroutineType(types: !333)
!333 = !{null, !314, !334}
!334 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !335, size: 64)
!335 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !40)
!336 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 615, type: !337, scopeLine: 615, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!337 = !DISubroutineType(types: !338)
!338 = !{null, !314, !339}
!339 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !40, size: 64)
!340 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 619, type: !341, scopeLine: 619, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!341 = !DISubroutineType(types: !342)
!342 = !{null, !314, !334, !343}
!343 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !344, size: 64)
!344 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !345)
!345 = !DIDerivedType(tag: DW_TAG_typedef, name: "__type_identity_t<std::allocator<bcfunc *> >", scope: !25, file: !267, line: 128, baseType: !346)
!346 = !DIDerivedType(tag: DW_TAG_typedef, name: "type", scope: !347, file: !267, line: 125, baseType: !67)
!347 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "__type_identity<std::allocator<bcfunc *> >", scope: !25, file: !267, line: 124, size: 8, flags: DIFlagTypePassByValue, elements: !166, templateParams: !348, identifier: "_ZTSSt15__type_identityISaIP6bcfuncEE")
!348 = !{!349}
!349 = !DITemplateTypeParameter(name: "_Type", type: !67)
!350 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 630, type: !351, scopeLine: 630, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!351 = !DISubroutineType(types: !352)
!352 = !{null, !314, !339, !318, !266}
!353 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 635, type: !354, scopeLine: 635, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!354 = !DISubroutineType(types: !355)
!355 = !{null, !314, !339, !318, !285}
!356 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 654, type: !357, scopeLine: 654, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!357 = !DISubroutineType(types: !358)
!358 = !{null, !314, !339, !343}
!359 = !DISubprogram(name: "vector", scope: !40, file: !24, line: 673, type: !360, scopeLine: 673, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!360 = !DISubroutineType(types: !361)
!361 = !{null, !314, !362, !318}
!362 = !DICompositeType(tag: DW_TAG_class_type, name: "initializer_list<bcfunc *>", scope: !25, file: !363, line: 47, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSSt16initializer_listIP6bcfuncE")
!363 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/initializer_list", directory: "")
!364 = !DISubprogram(name: "~vector", scope: !40, file: !24, line: 728, type: !312, scopeLine: 728, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!365 = !DISubprogram(name: "operator=", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EEaSERKS3_", scope: !40, file: !24, line: 746, type: !366, scopeLine: 746, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!366 = !DISubroutineType(types: !367)
!367 = !{!368, !314, !334}
!368 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !40, size: 64)
!369 = !DISubprogram(name: "operator=", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EEaSEOS3_", scope: !40, file: !24, line: 761, type: !370, scopeLine: 761, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!370 = !DISubroutineType(types: !371)
!371 = !{!368, !314, !339}
!372 = !DISubprogram(name: "operator=", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EEaSESt16initializer_listIS1_E", scope: !40, file: !24, line: 783, type: !373, scopeLine: 783, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!373 = !DISubroutineType(types: !374)
!374 = !{!368, !314, !362}
!375 = !DISubprogram(name: "assign", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE6assignEmRKS1_", scope: !40, file: !24, line: 803, type: !376, scopeLine: 803, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!376 = !DISubroutineType(types: !377)
!377 = !{null, !314, !324, !328}
!378 = !DISubprogram(name: "assign", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE6assignESt16initializer_listIS1_E", scope: !40, file: !24, line: 850, type: !379, scopeLine: 850, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!379 = !DISubroutineType(types: !380)
!380 = !{null, !314, !362}
!381 = !DISubprogram(name: "begin", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE5beginEv", scope: !40, file: !24, line: 868, type: !382, scopeLine: 868, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!382 = !DISubroutineType(types: !383)
!383 = !{!384, !314}
!384 = !DIDerivedType(tag: DW_TAG_typedef, name: "iterator", scope: !40, file: !24, line: 453, baseType: !385)
!385 = !DICompositeType(tag: DW_TAG_class_type, name: "__normal_iterator<bcfunc **, std::vector<bcfunc *, std::allocator<bcfunc *> > >", scope: !54, file: !386, line: 1043, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSN9__gnu_cxx17__normal_iteratorIPP6bcfuncSt6vectorIS2_SaIS2_EEEE")
!386 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_iterator.h", directory: "")
!387 = !DISubprogram(name: "begin", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE5beginEv", scope: !40, file: !24, line: 878, type: !388, scopeLine: 878, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!388 = !DISubroutineType(types: !389)
!389 = !{!390, !392}
!390 = !DIDerivedType(tag: DW_TAG_typedef, name: "const_iterator", scope: !40, file: !24, line: 455, baseType: !391)
!391 = !DICompositeType(tag: DW_TAG_class_type, name: "__normal_iterator<bcfunc *const *, std::vector<bcfunc *, std::allocator<bcfunc *> > >", scope: !54, file: !386, line: 1043, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSN9__gnu_cxx17__normal_iteratorIPKP6bcfuncSt6vectorIS2_SaIS2_EEEE")
!392 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !335, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!393 = !DISubprogram(name: "end", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE3endEv", scope: !40, file: !24, line: 888, type: !382, scopeLine: 888, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!394 = !DISubprogram(name: "end", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE3endEv", scope: !40, file: !24, line: 898, type: !388, scopeLine: 898, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!395 = !DISubprogram(name: "rbegin", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE6rbeginEv", scope: !40, file: !24, line: 908, type: !396, scopeLine: 908, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!396 = !DISubroutineType(types: !397)
!397 = !{!398, !314}
!398 = !DIDerivedType(tag: DW_TAG_typedef, name: "reverse_iterator", scope: !40, file: !24, line: 457, baseType: !399)
!399 = !DICompositeType(tag: DW_TAG_class_type, name: "reverse_iterator<__gnu_cxx::__normal_iterator<bcfunc **, std::vector<bcfunc *, std::allocator<bcfunc *> > > >", scope: !25, file: !386, line: 132, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSSt16reverse_iteratorIN9__gnu_cxx17__normal_iteratorIPP6bcfuncSt6vectorIS3_SaIS3_EEEEE")
!400 = !DISubprogram(name: "rbegin", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE6rbeginEv", scope: !40, file: !24, line: 918, type: !401, scopeLine: 918, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!401 = !DISubroutineType(types: !402)
!402 = !{!403, !392}
!403 = !DIDerivedType(tag: DW_TAG_typedef, name: "const_reverse_iterator", scope: !40, file: !24, line: 456, baseType: !404)
!404 = !DICompositeType(tag: DW_TAG_class_type, name: "reverse_iterator<__gnu_cxx::__normal_iterator<bcfunc *const *, std::vector<bcfunc *, std::allocator<bcfunc *> > > >", scope: !25, file: !386, line: 132, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSSt16reverse_iteratorIN9__gnu_cxx17__normal_iteratorIPKP6bcfuncSt6vectorIS3_SaIS3_EEEEE")
!405 = !DISubprogram(name: "rend", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE4rendEv", scope: !40, file: !24, line: 928, type: !396, scopeLine: 928, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!406 = !DISubprogram(name: "rend", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE4rendEv", scope: !40, file: !24, line: 938, type: !401, scopeLine: 938, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!407 = !DISubprogram(name: "cbegin", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE6cbeginEv", scope: !40, file: !24, line: 949, type: !388, scopeLine: 949, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!408 = !DISubprogram(name: "cend", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE4cendEv", scope: !40, file: !24, line: 959, type: !388, scopeLine: 959, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!409 = !DISubprogram(name: "crbegin", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE7crbeginEv", scope: !40, file: !24, line: 969, type: !401, scopeLine: 969, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!410 = !DISubprogram(name: "crend", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE5crendEv", scope: !40, file: !24, line: 979, type: !401, scopeLine: 979, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!411 = !DISubprogram(name: "size", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE4sizeEv", scope: !40, file: !24, line: 987, type: !412, scopeLine: 987, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!412 = !DISubroutineType(types: !413)
!413 = !{!324, !392}
!414 = !DISubprogram(name: "max_size", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE8max_sizeEv", scope: !40, file: !24, line: 993, type: !412, scopeLine: 993, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!415 = !DISubprogram(name: "resize", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE6resizeEm", scope: !40, file: !24, line: 1008, type: !416, scopeLine: 1008, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!416 = !DISubroutineType(types: !417)
!417 = !{null, !314, !324}
!418 = !DISubprogram(name: "resize", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE6resizeEmRKS1_", scope: !40, file: !24, line: 1029, type: !376, scopeLine: 1029, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!419 = !DISubprogram(name: "shrink_to_fit", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE13shrink_to_fitEv", scope: !40, file: !24, line: 1063, type: !312, scopeLine: 1063, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!420 = !DISubprogram(name: "capacity", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE8capacityEv", scope: !40, file: !24, line: 1073, type: !412, scopeLine: 1073, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!421 = !DISubprogram(name: "empty", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE5emptyEv", scope: !40, file: !24, line: 1083, type: !422, scopeLine: 1083, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!422 = !DISubroutineType(types: !423)
!423 = !{!39, !392}
!424 = !DISubprogram(name: "reserve", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE7reserveEm", scope: !40, file: !24, line: 1105, type: !416, scopeLine: 1105, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!425 = !DISubprogram(name: "operator[]", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EEixEm", scope: !40, file: !24, line: 1121, type: !426, scopeLine: 1121, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!426 = !DISubroutineType(types: !427)
!427 = !{!428, !314, !324}
!428 = !DIDerivedType(tag: DW_TAG_typedef, name: "reference", scope: !40, file: !24, line: 451, baseType: !429)
!429 = !DIDerivedType(tag: DW_TAG_typedef, name: "reference", scope: !53, file: !51, line: 62, baseType: !430)
!430 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !431, size: 64)
!431 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_type", scope: !53, file: !51, line: 56, baseType: !432)
!432 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_type", scope: !57, file: !58, line: 417, baseType: !18)
!433 = !DISubprogram(name: "operator[]", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EEixEm", scope: !40, file: !24, line: 1140, type: !434, scopeLine: 1140, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!434 = !DISubroutineType(types: !435)
!435 = !{!436, !392, !324}
!436 = !DIDerivedType(tag: DW_TAG_typedef, name: "const_reference", scope: !40, file: !24, line: 452, baseType: !437)
!437 = !DIDerivedType(tag: DW_TAG_typedef, name: "const_reference", scope: !53, file: !51, line: 63, baseType: !438)
!438 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !439, size: 64)
!439 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !431)
!440 = !DISubprogram(name: "_M_range_check", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE14_M_range_checkEm", scope: !40, file: !24, line: 1150, type: !441, scopeLine: 1150, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!441 = !DISubroutineType(types: !442)
!442 = !{null, !392, !324}
!443 = !DISubprogram(name: "at", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE2atEm", scope: !40, file: !24, line: 1173, type: !426, scopeLine: 1173, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!444 = !DISubprogram(name: "at", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE2atEm", scope: !40, file: !24, line: 1192, type: !434, scopeLine: 1192, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!445 = !DISubprogram(name: "front", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE5frontEv", scope: !40, file: !24, line: 1204, type: !446, scopeLine: 1204, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!446 = !DISubroutineType(types: !447)
!447 = !{!428, !314}
!448 = !DISubprogram(name: "front", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE5frontEv", scope: !40, file: !24, line: 1216, type: !449, scopeLine: 1216, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!449 = !DISubroutineType(types: !450)
!450 = !{!436, !392}
!451 = !DISubprogram(name: "back", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE4backEv", scope: !40, file: !24, line: 1228, type: !446, scopeLine: 1228, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!452 = !DISubprogram(name: "back", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE4backEv", scope: !40, file: !24, line: 1240, type: !449, scopeLine: 1240, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!453 = !DISubprogram(name: "data", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE4dataEv", scope: !40, file: !24, line: 1255, type: !454, scopeLine: 1255, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!454 = !DISubroutineType(types: !455)
!455 = !{!64, !314}
!456 = !DISubprogram(name: "data", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE4dataEv", scope: !40, file: !24, line: 1260, type: !457, scopeLine: 1260, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!457 = !DISubroutineType(types: !458)
!458 = !{!97, !392}
!459 = !DISubprogram(name: "push_back", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE9push_backERKS1_", scope: !40, file: !24, line: 1276, type: !460, scopeLine: 1276, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!460 = !DISubroutineType(types: !461)
!461 = !{null, !314, !328}
!462 = !DISubprogram(name: "push_back", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE9push_backEOS1_", scope: !40, file: !24, line: 1293, type: !463, scopeLine: 1293, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!463 = !DISubroutineType(types: !464)
!464 = !{null, !314, !465}
!465 = !DIDerivedType(tag: DW_TAG_rvalue_reference_type, baseType: !330, size: 64)
!466 = !DISubprogram(name: "pop_back", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE8pop_backEv", scope: !40, file: !24, line: 1317, type: !312, scopeLine: 1317, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!467 = !DISubprogram(name: "insert", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE6insertEN9__gnu_cxx17__normal_iteratorIPKS1_S3_EERS6_", scope: !40, file: !24, line: 1357, type: !468, scopeLine: 1357, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!468 = !DISubroutineType(types: !469)
!469 = !{!384, !314, !390, !328}
!470 = !DISubprogram(name: "insert", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE6insertEN9__gnu_cxx17__normal_iteratorIPKS1_S3_EEOS1_", scope: !40, file: !24, line: 1388, type: !471, scopeLine: 1388, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!471 = !DISubroutineType(types: !472)
!472 = !{!384, !314, !390, !465}
!473 = !DISubprogram(name: "insert", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE6insertEN9__gnu_cxx17__normal_iteratorIPKS1_S3_EESt16initializer_listIS1_E", scope: !40, file: !24, line: 1406, type: !474, scopeLine: 1406, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!474 = !DISubroutineType(types: !475)
!475 = !{!384, !314, !390, !362}
!476 = !DISubprogram(name: "insert", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE6insertEN9__gnu_cxx17__normal_iteratorIPKS1_S3_EEmRS6_", scope: !40, file: !24, line: 1432, type: !477, scopeLine: 1432, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!477 = !DISubroutineType(types: !478)
!478 = !{!384, !314, !390, !324, !328}
!479 = !DISubprogram(name: "erase", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE5eraseEN9__gnu_cxx17__normal_iteratorIPKS1_S3_EE", scope: !40, file: !24, line: 1529, type: !480, scopeLine: 1529, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!480 = !DISubroutineType(types: !481)
!481 = !{!384, !314, !390}
!482 = !DISubprogram(name: "erase", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE5eraseEN9__gnu_cxx17__normal_iteratorIPKS1_S3_EES8_", scope: !40, file: !24, line: 1557, type: !483, scopeLine: 1557, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!483 = !DISubroutineType(types: !484)
!484 = !{!384, !314, !390, !390}
!485 = !DISubprogram(name: "swap", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE4swapERS3_", scope: !40, file: !24, line: 1581, type: !486, scopeLine: 1581, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!486 = !DISubroutineType(types: !487)
!487 = !{null, !314, !368}
!488 = !DISubprogram(name: "clear", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE5clearEv", scope: !40, file: !24, line: 1600, type: !312, scopeLine: 1600, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!489 = !DISubprogram(name: "_M_fill_initialize", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE18_M_fill_initializeEmRKS1_", scope: !40, file: !24, line: 1699, type: !376, scopeLine: 1699, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!490 = !DISubprogram(name: "_M_default_initialize", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE21_M_default_initializeEm", scope: !40, file: !24, line: 1710, type: !416, scopeLine: 1710, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!491 = !DISubprogram(name: "_M_fill_assign", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE14_M_fill_assignEmRKS1_", scope: !40, file: !24, line: 1757, type: !376, scopeLine: 1757, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!492 = !DISubprogram(name: "_M_fill_insert", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE14_M_fill_insertEN9__gnu_cxx17__normal_iteratorIPS1_S3_EEmRKS1_", scope: !40, file: !24, line: 1801, type: !493, scopeLine: 1801, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!493 = !DISubroutineType(types: !494)
!494 = !{null, !314, !384, !324, !328}
!495 = !DISubprogram(name: "_M_default_append", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE17_M_default_appendEm", scope: !40, file: !24, line: 1807, type: !416, scopeLine: 1807, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!496 = !DISubprogram(name: "_M_shrink_to_fit", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE16_M_shrink_to_fitEv", scope: !40, file: !24, line: 1811, type: !497, scopeLine: 1811, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!497 = !DISubroutineType(types: !498)
!498 = !{!39, !314}
!499 = !DISubprogram(name: "_M_insert_rval", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE14_M_insert_rvalEN9__gnu_cxx17__normal_iteratorIPKS1_S3_EEOS1_", scope: !40, file: !24, line: 1873, type: !471, scopeLine: 1873, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!500 = !DISubprogram(name: "_M_emplace_aux", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE14_M_emplace_auxEN9__gnu_cxx17__normal_iteratorIPKS1_S3_EEOS1_", scope: !40, file: !24, line: 1884, type: !471, scopeLine: 1884, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!501 = !DISubprogram(name: "_M_check_len", linkageName: "_ZNKSt6vectorIP6bcfuncSaIS1_EE12_M_check_lenEmPKc", scope: !40, file: !24, line: 1891, type: !502, scopeLine: 1891, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!502 = !DISubroutineType(types: !503)
!503 = !{!504, !392, !324, !505}
!504 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_type", scope: !40, file: !24, line: 458, baseType: !105)
!505 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !506, size: 64)
!506 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !507)
!507 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!508 = !DISubprogram(name: "_S_check_init_len", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE17_S_check_init_lenEmRKS2_", scope: !40, file: !24, line: 1902, type: !509, scopeLine: 1902, flags: DIFlagProtected | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!509 = !DISubroutineType(types: !510)
!510 = !{!504, !324, !318}
!511 = !DISubprogram(name: "_S_max_size", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE11_S_max_sizeERKS2_", scope: !40, file: !24, line: 1911, type: !512, scopeLine: 1911, flags: DIFlagProtected | DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!512 = !DISubroutineType(types: !513)
!513 = !{!504, !514}
!514 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !515, size: 64)
!515 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !304)
!516 = !DISubprogram(name: "_M_erase_at_end", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE15_M_erase_at_endEPS1_", scope: !40, file: !24, line: 1928, type: !517, scopeLine: 1928, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!517 = !DISubroutineType(types: !518)
!518 = !{null, !314, !302}
!519 = !DISubprogram(name: "_M_erase", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE8_M_eraseEN9__gnu_cxx17__normal_iteratorIPS1_S3_EE", scope: !40, file: !24, line: 1941, type: !520, scopeLine: 1941, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!520 = !DISubroutineType(types: !521)
!521 = !{!384, !314, !384}
!522 = !DISubprogram(name: "_M_erase", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE8_M_eraseEN9__gnu_cxx17__normal_iteratorIPS1_S3_EES7_", scope: !40, file: !24, line: 1945, type: !523, scopeLine: 1945, flags: DIFlagProtected | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!523 = !DISubroutineType(types: !524)
!524 = !{!384, !314, !384, !384}
!525 = !DISubprogram(name: "_M_move_assign", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE14_M_move_assignEOS3_St17integral_constantIbLb1EE", scope: !40, file: !24, line: 1954, type: !526, scopeLine: 1954, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!526 = !DISubroutineType(types: !527)
!527 = !{null, !314, !339, !266}
!528 = !DISubprogram(name: "_M_move_assign", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EE14_M_move_assignEOS3_St17integral_constantIbLb0EE", scope: !40, file: !24, line: 1966, type: !529, scopeLine: 1966, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!529 = !DISubroutineType(types: !530)
!530 = !{null, !314, !339, !285}
!531 = !{!0, !532, !534, !536, !538, !543, !548, !550, !552, !554, !556, !558, !563}
!532 = !DIGlobalVariableExpression(var: !533, expr: !DIExpression())
!533 = distinct !DIGlobalVariable(name: "funcs", scope: !2, file: !3, line: 12, type: !40, isLocal: false, isDefinition: true)
!534 = !DIGlobalVariableExpression(var: !535, expr: !DIExpression())
!535 = distinct !DIGlobalVariable(name: "stacksz", scope: !2, file: !3, line: 30, type: !14, isLocal: false, isDefinition: true)
!536 = !DIGlobalVariableExpression(var: !537, expr: !DIExpression())
!537 = distinct !DIGlobalVariable(name: "stack", scope: !2, file: !3, line: 33, type: !6, isLocal: false, isDefinition: true)
!538 = !DIGlobalVariableExpression(var: !539, expr: !DIExpression())
!539 = distinct !DIGlobalVariable(name: "hotmap", scope: !2, file: !3, line: 40, type: !540, isLocal: false, isDefinition: true)
!540 = !DICompositeType(tag: DW_TAG_array_type, baseType: !13, size: 512, elements: !541)
!541 = !{!542}
!542 = !DISubrange(count: 64)
!543 = !DIGlobalVariableExpression(var: !544, expr: !DIExpression(DW_OP_constu, 1, DW_OP_stack_value))
!544 = distinct !DIGlobalVariable(name: "hotmap_tail_rec", scope: !2, file: !545, line: 12, type: !546, isLocal: true, isDefinition: true)
!545 = !DIFile(filename: "./vm.h", directory: "/home/davejwatson/myprojects/boom")
!546 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !547)
!547 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!548 = !DIGlobalVariableExpression(var: !549, expr: !DIExpression(DW_OP_constu, 63, DW_OP_stack_value))
!549 = distinct !DIGlobalVariable(name: "hotmap_mask", scope: !2, file: !545, line: 13, type: !546, isLocal: true, isDefinition: true)
!550 = !DIGlobalVariableExpression(var: !551, expr: !DIExpression(DW_OP_constu, 200, DW_OP_stack_value))
!551 = distinct !DIGlobalVariable(name: "hotmap_cnt", scope: !2, file: !545, line: 10, type: !546, isLocal: true, isDefinition: true)
!552 = !DIGlobalVariableExpression(var: !553, expr: !DIExpression(DW_OP_constu, 64, DW_OP_stack_value))
!553 = distinct !DIGlobalVariable(name: "hotmap_sz", scope: !2, file: !545, line: 9, type: !546, isLocal: true, isDefinition: true)
!554 = !DIGlobalVariableExpression(var: !555, expr: !DIExpression(DW_OP_constu, 1, DW_OP_stack_value))
!555 = distinct !DIGlobalVariable(name: "hotmap_rec", scope: !2, file: !545, line: 11, type: !546, isLocal: true, isDefinition: true)
!556 = !DIGlobalVariableExpression(var: !557, expr: !DIExpression())
!557 = distinct !DIGlobalVariable(name: "frame_top", linkageName: "_ZL9frame_top", scope: !2, file: !3, line: 32, type: !6, isLocal: true, isDefinition: true)
!558 = !DIGlobalVariableExpression(var: !559, expr: !DIExpression())
!559 = distinct !DIGlobalVariable(name: "op_table", linkageName: "_ZL8op_table", scope: !2, file: !3, line: 49, type: !560, isLocal: true, isDefinition: true)
!560 = !DICompositeType(tag: DW_TAG_array_type, baseType: !9, size: 1600, elements: !561)
!561 = !{!562}
!562 = !DISubrange(count: 25)
!563 = !DIGlobalVariableExpression(var: !564, expr: !DIExpression())
!564 = distinct !DIGlobalVariable(name: "frame", linkageName: "_ZL5frame", scope: !2, file: !3, line: 31, type: !6, isLocal: true, isDefinition: true)
!565 = !{!566, !583, !586, !591, !653, !661, !665, !672, !676, !680, !682, !684, !688, !695, !699, !705, !711, !713, !717, !721, !725, !729, !740, !742, !746, !750, !754, !756, !761, !765, !769, !771, !773, !777, !785, !789, !793, !797, !799, !805, !807, !813, !818, !822, !826, !830, !834, !838, !840, !842, !846, !850, !854, !856, !860, !864, !866, !868, !872, !877, !882, !887, !888, !889, !890, !891, !892, !893, !894, !895, !896, !897, !902, !906, !909, !912, !915, !917, !919, !921, !924, !927, !930, !933, !936, !938, !942, !945, !948, !951, !953, !955, !957, !959, !962, !965, !968, !971, !974, !976, !980, !984, !989, !995, !997, !999, !1001, !1003, !1005, !1007, !1009, !1011, !1013, !1015, !1017, !1019, !1021, !1025, !1029, !1033, !1039, !1043, !1048, !1050, !1055, !1059, !1063, !1072, !1076, !1080, !1084, !1088, !1092, !1096, !1100, !1104, !1108, !1112, !1116, !1120, !1122, !1126, !1130, !1134, !1140, !1144, !1148, !1150, !1154, !1158, !1164, !1166, !1170, !1174, !1178, !1182, !1186, !1190, !1194, !1195, !1196, !1197, !1199, !1200, !1201, !1202, !1203, !1204, !1205, !1209, !1215, !1220, !1224, !1226, !1228, !1230, !1232, !1239, !1243, !1247, !1251, !1255, !1259, !1264, !1268, !1270, !1274, !1280, !1284, !1289, !1291, !1294, !1298, !1302, !1304, !1306, !1308, !1310, !1314, !1316, !1318, !1322, !1326, !1330, !1334, !1338, !1342, !1344, !1348, !1352, !1356, !1360, !1362, !1364, !1368, !1372, !1373, !1374, !1375, !1376}
!566 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !567, file: !582, line: 64)
!567 = !DIDerivedType(tag: DW_TAG_typedef, name: "mbstate_t", file: !568, line: 6, baseType: !569)
!568 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types/mbstate_t.h", directory: "")
!569 = !DIDerivedType(tag: DW_TAG_typedef, name: "__mbstate_t", file: !570, line: 21, baseType: !571)
!570 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types/__mbstate_t.h", directory: "")
!571 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !570, line: 13, size: 64, flags: DIFlagTypePassByValue, elements: !572, identifier: "_ZTS11__mbstate_t")
!572 = !{!573, !574}
!573 = !DIDerivedType(tag: DW_TAG_member, name: "__count", scope: !571, file: !570, line: 15, baseType: !547, size: 32)
!574 = !DIDerivedType(tag: DW_TAG_member, name: "__value", scope: !571, file: !570, line: 20, baseType: !575, size: 32, offset: 32)
!575 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !571, file: !570, line: 16, size: 32, flags: DIFlagTypePassByValue, elements: !576, identifier: "_ZTSN11__mbstate_tUt_E")
!576 = !{!577, !578}
!577 = !DIDerivedType(tag: DW_TAG_member, name: "__wch", scope: !575, file: !570, line: 18, baseType: !14, size: 32)
!578 = !DIDerivedType(tag: DW_TAG_member, name: "__wchb", scope: !575, file: !570, line: 19, baseType: !579, size: 32)
!579 = !DICompositeType(tag: DW_TAG_array_type, baseType: !507, size: 32, elements: !580)
!580 = !{!581}
!581 = !DISubrange(count: 4)
!582 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/cwchar", directory: "")
!583 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !584, file: !582, line: 141)
!584 = !DIDerivedType(tag: DW_TAG_typedef, name: "wint_t", file: !585, line: 20, baseType: !14)
!585 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types/wint_t.h", directory: "")
!586 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !587, file: !582, line: 143)
!587 = !DISubprogram(name: "btowc", scope: !588, file: !588, line: 319, type: !589, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!588 = !DIFile(filename: "/usr/include/wchar.h", directory: "")
!589 = !DISubroutineType(types: !590)
!590 = !{!584, !547}
!591 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !592, file: !582, line: 144)
!592 = !DISubprogram(name: "fgetwc", scope: !588, file: !588, line: 744, type: !593, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!593 = !DISubroutineType(types: !594)
!594 = !{!584, !595}
!595 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !596, size: 64)
!596 = !DIDerivedType(tag: DW_TAG_typedef, name: "__FILE", file: !597, line: 5, baseType: !598)
!597 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types/__FILE.h", directory: "")
!598 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "_IO_FILE", file: !599, line: 49, size: 1728, flags: DIFlagTypePassByValue, elements: !600, identifier: "_ZTS8_IO_FILE")
!599 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types/struct_FILE.h", directory: "")
!600 = !{!601, !602, !604, !605, !606, !607, !608, !609, !610, !611, !612, !613, !614, !617, !619, !620, !621, !624, !626, !628, !632, !635, !637, !640, !643, !644, !645, !648, !649}
!601 = !DIDerivedType(tag: DW_TAG_member, name: "_flags", scope: !598, file: !599, line: 51, baseType: !547, size: 32)
!602 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_read_ptr", scope: !598, file: !599, line: 54, baseType: !603, size: 64, offset: 64)
!603 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !507, size: 64)
!604 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_read_end", scope: !598, file: !599, line: 55, baseType: !603, size: 64, offset: 128)
!605 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_read_base", scope: !598, file: !599, line: 56, baseType: !603, size: 64, offset: 192)
!606 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_write_base", scope: !598, file: !599, line: 57, baseType: !603, size: 64, offset: 256)
!607 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_write_ptr", scope: !598, file: !599, line: 58, baseType: !603, size: 64, offset: 320)
!608 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_write_end", scope: !598, file: !599, line: 59, baseType: !603, size: 64, offset: 384)
!609 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_buf_base", scope: !598, file: !599, line: 60, baseType: !603, size: 64, offset: 448)
!610 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_buf_end", scope: !598, file: !599, line: 61, baseType: !603, size: 64, offset: 512)
!611 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_save_base", scope: !598, file: !599, line: 64, baseType: !603, size: 64, offset: 576)
!612 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_backup_base", scope: !598, file: !599, line: 65, baseType: !603, size: 64, offset: 640)
!613 = !DIDerivedType(tag: DW_TAG_member, name: "_IO_save_end", scope: !598, file: !599, line: 66, baseType: !603, size: 64, offset: 704)
!614 = !DIDerivedType(tag: DW_TAG_member, name: "_markers", scope: !598, file: !599, line: 68, baseType: !615, size: 64, offset: 768)
!615 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !616, size: 64)
!616 = !DICompositeType(tag: DW_TAG_structure_type, name: "_IO_marker", file: !599, line: 36, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTS10_IO_marker")
!617 = !DIDerivedType(tag: DW_TAG_member, name: "_chain", scope: !598, file: !599, line: 70, baseType: !618, size: 64, offset: 832)
!618 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !598, size: 64)
!619 = !DIDerivedType(tag: DW_TAG_member, name: "_fileno", scope: !598, file: !599, line: 72, baseType: !547, size: 32, offset: 896)
!620 = !DIDerivedType(tag: DW_TAG_member, name: "_flags2", scope: !598, file: !599, line: 73, baseType: !547, size: 32, offset: 928)
!621 = !DIDerivedType(tag: DW_TAG_member, name: "_old_offset", scope: !598, file: !599, line: 74, baseType: !622, size: 64, offset: 960)
!622 = !DIDerivedType(tag: DW_TAG_typedef, name: "__off_t", file: !623, line: 152, baseType: !7)
!623 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types.h", directory: "")
!624 = !DIDerivedType(tag: DW_TAG_member, name: "_cur_column", scope: !598, file: !599, line: 77, baseType: !625, size: 16, offset: 1024)
!625 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!626 = !DIDerivedType(tag: DW_TAG_member, name: "_vtable_offset", scope: !598, file: !599, line: 78, baseType: !627, size: 8, offset: 1040)
!627 = !DIBasicType(name: "signed char", size: 8, encoding: DW_ATE_signed_char)
!628 = !DIDerivedType(tag: DW_TAG_member, name: "_shortbuf", scope: !598, file: !599, line: 79, baseType: !629, size: 8, offset: 1048)
!629 = !DICompositeType(tag: DW_TAG_array_type, baseType: !507, size: 8, elements: !630)
!630 = !{!631}
!631 = !DISubrange(count: 1)
!632 = !DIDerivedType(tag: DW_TAG_member, name: "_lock", scope: !598, file: !599, line: 81, baseType: !633, size: 64, offset: 1088)
!633 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !634, size: 64)
!634 = !DIDerivedType(tag: DW_TAG_typedef, name: "_IO_lock_t", file: !599, line: 43, baseType: null)
!635 = !DIDerivedType(tag: DW_TAG_member, name: "_offset", scope: !598, file: !599, line: 89, baseType: !636, size: 64, offset: 1152)
!636 = !DIDerivedType(tag: DW_TAG_typedef, name: "__off64_t", file: !623, line: 153, baseType: !7)
!637 = !DIDerivedType(tag: DW_TAG_member, name: "_codecvt", scope: !598, file: !599, line: 91, baseType: !638, size: 64, offset: 1216)
!638 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !639, size: 64)
!639 = !DICompositeType(tag: DW_TAG_structure_type, name: "_IO_codecvt", file: !599, line: 37, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTS11_IO_codecvt")
!640 = !DIDerivedType(tag: DW_TAG_member, name: "_wide_data", scope: !598, file: !599, line: 92, baseType: !641, size: 64, offset: 1280)
!641 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !642, size: 64)
!642 = !DICompositeType(tag: DW_TAG_structure_type, name: "_IO_wide_data", file: !599, line: 38, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTS13_IO_wide_data")
!643 = !DIDerivedType(tag: DW_TAG_member, name: "_freeres_list", scope: !598, file: !599, line: 93, baseType: !618, size: 64, offset: 1344)
!644 = !DIDerivedType(tag: DW_TAG_member, name: "_freeres_buf", scope: !598, file: !599, line: 94, baseType: !17, size: 64, offset: 1408)
!645 = !DIDerivedType(tag: DW_TAG_member, name: "__pad5", scope: !598, file: !599, line: 95, baseType: !646, size: 64, offset: 1472)
!646 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_t", file: !647, line: 46, baseType: !38)
!647 = !DIFile(filename: "/usr/lib/llvm-14/lib/clang/14.0.0/include/stddef.h", directory: "")
!648 = !DIDerivedType(tag: DW_TAG_member, name: "_mode", scope: !598, file: !599, line: 96, baseType: !547, size: 32, offset: 1536)
!649 = !DIDerivedType(tag: DW_TAG_member, name: "_unused2", scope: !598, file: !599, line: 98, baseType: !650, size: 160, offset: 1568)
!650 = !DICompositeType(tag: DW_TAG_array_type, baseType: !507, size: 160, elements: !651)
!651 = !{!652}
!652 = !DISubrange(count: 20)
!653 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !654, file: !582, line: 145)
!654 = !DISubprogram(name: "fgetws", scope: !588, file: !588, line: 773, type: !655, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!655 = !DISubroutineType(types: !656)
!656 = !{!657, !659, !547, !660}
!657 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !658, size: 64)
!658 = !DIBasicType(name: "wchar_t", size: 32, encoding: DW_ATE_signed)
!659 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !657)
!660 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !595)
!661 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !662, file: !582, line: 146)
!662 = !DISubprogram(name: "fputwc", scope: !588, file: !588, line: 758, type: !663, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!663 = !DISubroutineType(types: !664)
!664 = !{!584, !658, !595}
!665 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !666, file: !582, line: 147)
!666 = !DISubprogram(name: "fputws", scope: !588, file: !588, line: 780, type: !667, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!667 = !DISubroutineType(types: !668)
!668 = !{!547, !669, !660}
!669 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !670)
!670 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !671, size: 64)
!671 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !658)
!672 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !673, file: !582, line: 148)
!673 = !DISubprogram(name: "fwide", scope: !588, file: !588, line: 588, type: !674, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!674 = !DISubroutineType(types: !675)
!675 = !{!547, !595, !547}
!676 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !677, file: !582, line: 149)
!677 = !DISubprogram(name: "fwprintf", scope: !588, file: !588, line: 595, type: !678, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!678 = !DISubroutineType(types: !679)
!679 = !{!547, !660, !669, null}
!680 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !681, file: !582, line: 150)
!681 = !DISubprogram(name: "fwscanf", linkageName: "__isoc99_fwscanf", scope: !588, file: !588, line: 657, type: !678, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!682 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !683, file: !582, line: 151)
!683 = !DISubprogram(name: "getwc", scope: !588, file: !588, line: 745, type: !593, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!684 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !685, file: !582, line: 152)
!685 = !DISubprogram(name: "getwchar", scope: !588, file: !588, line: 751, type: !686, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!686 = !DISubroutineType(types: !687)
!687 = !{!584}
!688 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !689, file: !582, line: 153)
!689 = !DISubprogram(name: "mbrlen", scope: !588, file: !588, line: 330, type: !690, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!690 = !DISubroutineType(types: !691)
!691 = !{!646, !692, !646, !693}
!692 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !505)
!693 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !694)
!694 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !567, size: 64)
!695 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !696, file: !582, line: 154)
!696 = !DISubprogram(name: "mbrtowc", scope: !588, file: !588, line: 297, type: !697, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!697 = !DISubroutineType(types: !698)
!698 = !{!646, !659, !692, !646, !693}
!699 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !700, file: !582, line: 155)
!700 = !DISubprogram(name: "mbsinit", scope: !588, file: !588, line: 293, type: !701, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!701 = !DISubroutineType(types: !702)
!702 = !{!547, !703}
!703 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !704, size: 64)
!704 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !567)
!705 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !706, file: !582, line: 156)
!706 = !DISubprogram(name: "mbsrtowcs", scope: !588, file: !588, line: 338, type: !707, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!707 = !DISubroutineType(types: !708)
!708 = !{!646, !659, !709, !646, !693}
!709 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !710)
!710 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !505, size: 64)
!711 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !712, file: !582, line: 157)
!712 = !DISubprogram(name: "putwc", scope: !588, file: !588, line: 759, type: !663, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!713 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !714, file: !582, line: 158)
!714 = !DISubprogram(name: "putwchar", scope: !588, file: !588, line: 765, type: !715, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!715 = !DISubroutineType(types: !716)
!716 = !{!584, !658}
!717 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !718, file: !582, line: 160)
!718 = !DISubprogram(name: "swprintf", scope: !588, file: !588, line: 605, type: !719, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!719 = !DISubroutineType(types: !720)
!720 = !{!547, !659, !646, !669, null}
!721 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !722, file: !582, line: 162)
!722 = !DISubprogram(name: "swscanf", linkageName: "__isoc99_swscanf", scope: !588, file: !588, line: 664, type: !723, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!723 = !DISubroutineType(types: !724)
!724 = !{!547, !669, !669, null}
!725 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !726, file: !582, line: 163)
!726 = !DISubprogram(name: "ungetwc", scope: !588, file: !588, line: 788, type: !727, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!727 = !DISubroutineType(types: !728)
!728 = !{!584, !584, !595}
!729 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !730, file: !582, line: 164)
!730 = !DISubprogram(name: "vfwprintf", scope: !588, file: !588, line: 613, type: !731, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!731 = !DISubroutineType(types: !732)
!732 = !{!547, !660, !669, !733}
!733 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !734, size: 64)
!734 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "__va_list_tag", size: 192, flags: DIFlagTypePassByValue, elements: !735, identifier: "_ZTS13__va_list_tag")
!735 = !{!736, !737, !738, !739}
!736 = !DIDerivedType(tag: DW_TAG_member, name: "gp_offset", scope: !734, file: !3, baseType: !14, size: 32)
!737 = !DIDerivedType(tag: DW_TAG_member, name: "fp_offset", scope: !734, file: !3, baseType: !14, size: 32, offset: 32)
!738 = !DIDerivedType(tag: DW_TAG_member, name: "overflow_arg_area", scope: !734, file: !3, baseType: !17, size: 64, offset: 64)
!739 = !DIDerivedType(tag: DW_TAG_member, name: "reg_save_area", scope: !734, file: !3, baseType: !17, size: 64, offset: 128)
!740 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !741, file: !582, line: 166)
!741 = !DISubprogram(name: "vfwscanf", linkageName: "__isoc99_vfwscanf", scope: !588, file: !588, line: 711, type: !731, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!742 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !743, file: !582, line: 169)
!743 = !DISubprogram(name: "vswprintf", scope: !588, file: !588, line: 626, type: !744, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!744 = !DISubroutineType(types: !745)
!745 = !{!547, !659, !646, !669, !733}
!746 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !747, file: !582, line: 172)
!747 = !DISubprogram(name: "vswscanf", linkageName: "__isoc99_vswscanf", scope: !588, file: !588, line: 718, type: !748, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!748 = !DISubroutineType(types: !749)
!749 = !{!547, !669, !669, !733}
!750 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !751, file: !582, line: 174)
!751 = !DISubprogram(name: "vwprintf", scope: !588, file: !588, line: 621, type: !752, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!752 = !DISubroutineType(types: !753)
!753 = !{!547, !669, !733}
!754 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !755, file: !582, line: 176)
!755 = !DISubprogram(name: "vwscanf", linkageName: "__isoc99_vwscanf", scope: !588, file: !588, line: 715, type: !752, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!756 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !757, file: !582, line: 178)
!757 = !DISubprogram(name: "wcrtomb", scope: !588, file: !588, line: 302, type: !758, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!758 = !DISubroutineType(types: !759)
!759 = !{!646, !760, !658, !693}
!760 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !603)
!761 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !762, file: !582, line: 179)
!762 = !DISubprogram(name: "wcscat", scope: !588, file: !588, line: 97, type: !763, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!763 = !DISubroutineType(types: !764)
!764 = !{!657, !659, !669}
!765 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !766, file: !582, line: 180)
!766 = !DISubprogram(name: "wcscmp", scope: !588, file: !588, line: 106, type: !767, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!767 = !DISubroutineType(types: !768)
!768 = !{!547, !670, !670}
!769 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !770, file: !582, line: 181)
!770 = !DISubprogram(name: "wcscoll", scope: !588, file: !588, line: 131, type: !767, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!771 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !772, file: !582, line: 182)
!772 = !DISubprogram(name: "wcscpy", scope: !588, file: !588, line: 87, type: !763, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!773 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !774, file: !582, line: 183)
!774 = !DISubprogram(name: "wcscspn", scope: !588, file: !588, line: 188, type: !775, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!775 = !DISubroutineType(types: !776)
!776 = !{!646, !670, !670}
!777 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !778, file: !582, line: 184)
!778 = !DISubprogram(name: "wcsftime", scope: !588, file: !588, line: 852, type: !779, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!779 = !DISubroutineType(types: !780)
!780 = !{!646, !659, !646, !669, !781}
!781 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !782)
!782 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !783, size: 64)
!783 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !784)
!784 = !DICompositeType(tag: DW_TAG_structure_type, name: "tm", file: !588, line: 83, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTS2tm")
!785 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !786, file: !582, line: 185)
!786 = !DISubprogram(name: "wcslen", scope: !588, file: !588, line: 223, type: !787, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!787 = !DISubroutineType(types: !788)
!788 = !{!646, !670}
!789 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !790, file: !582, line: 186)
!790 = !DISubprogram(name: "wcsncat", scope: !588, file: !588, line: 101, type: !791, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!791 = !DISubroutineType(types: !792)
!792 = !{!657, !659, !669, !646}
!793 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !794, file: !582, line: 187)
!794 = !DISubprogram(name: "wcsncmp", scope: !588, file: !588, line: 109, type: !795, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!795 = !DISubroutineType(types: !796)
!796 = !{!547, !670, !670, !646}
!797 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !798, file: !582, line: 188)
!798 = !DISubprogram(name: "wcsncpy", scope: !588, file: !588, line: 92, type: !791, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!799 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !800, file: !582, line: 189)
!800 = !DISubprogram(name: "wcsrtombs", scope: !588, file: !588, line: 344, type: !801, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!801 = !DISubroutineType(types: !802)
!802 = !{!646, !760, !803, !646, !693}
!803 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !804)
!804 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !670, size: 64)
!805 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !806, file: !582, line: 190)
!806 = !DISubprogram(name: "wcsspn", scope: !588, file: !588, line: 192, type: !775, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!807 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !808, file: !582, line: 191)
!808 = !DISubprogram(name: "wcstod", scope: !588, file: !588, line: 378, type: !809, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!809 = !DISubroutineType(types: !810)
!810 = !{!5, !669, !811}
!811 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !812)
!812 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !657, size: 64)
!813 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !814, file: !582, line: 193)
!814 = !DISubprogram(name: "wcstof", scope: !588, file: !588, line: 383, type: !815, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!815 = !DISubroutineType(types: !816)
!816 = !{!817, !669, !811}
!817 = !DIBasicType(name: "float", size: 32, encoding: DW_ATE_float)
!818 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !819, file: !582, line: 195)
!819 = !DISubprogram(name: "wcstok", scope: !588, file: !588, line: 218, type: !820, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!820 = !DISubroutineType(types: !821)
!821 = !{!657, !659, !669, !811}
!822 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !823, file: !582, line: 196)
!823 = !DISubprogram(name: "wcstol", scope: !588, file: !588, line: 429, type: !824, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!824 = !DISubroutineType(types: !825)
!825 = !{!7, !669, !811, !547}
!826 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !827, file: !582, line: 197)
!827 = !DISubprogram(name: "wcstoul", scope: !588, file: !588, line: 434, type: !828, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!828 = !DISubroutineType(types: !829)
!829 = !{!38, !669, !811, !547}
!830 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !831, file: !582, line: 198)
!831 = !DISubprogram(name: "wcsxfrm", scope: !588, file: !588, line: 135, type: !832, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!832 = !DISubroutineType(types: !833)
!833 = !{!646, !659, !669, !646}
!834 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !835, file: !582, line: 199)
!835 = !DISubprogram(name: "wctob", scope: !588, file: !588, line: 325, type: !836, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!836 = !DISubroutineType(types: !837)
!837 = !{!547, !584}
!838 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !839, file: !582, line: 200)
!839 = !DISubprogram(name: "wmemcmp", scope: !588, file: !588, line: 259, type: !795, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!840 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !841, file: !582, line: 201)
!841 = !DISubprogram(name: "wmemcpy", scope: !588, file: !588, line: 263, type: !791, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!842 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !843, file: !582, line: 202)
!843 = !DISubprogram(name: "wmemmove", scope: !588, file: !588, line: 268, type: !844, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!844 = !DISubroutineType(types: !845)
!845 = !{!657, !657, !670, !646}
!846 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !847, file: !582, line: 203)
!847 = !DISubprogram(name: "wmemset", scope: !588, file: !588, line: 272, type: !848, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!848 = !DISubroutineType(types: !849)
!849 = !{!657, !657, !658, !646}
!850 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !851, file: !582, line: 204)
!851 = !DISubprogram(name: "wprintf", scope: !588, file: !588, line: 602, type: !852, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!852 = !DISubroutineType(types: !853)
!853 = !{!547, !669, null}
!854 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !855, file: !582, line: 205)
!855 = !DISubprogram(name: "wscanf", linkageName: "__isoc99_wscanf", scope: !588, file: !588, line: 661, type: !852, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!856 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !857, file: !582, line: 206)
!857 = !DISubprogram(name: "wcschr", scope: !588, file: !588, line: 165, type: !858, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!858 = !DISubroutineType(types: !859)
!859 = !{!657, !670, !658}
!860 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !861, file: !582, line: 207)
!861 = !DISubprogram(name: "wcspbrk", scope: !588, file: !588, line: 202, type: !862, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!862 = !DISubroutineType(types: !863)
!863 = !{!657, !670, !670}
!864 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !865, file: !582, line: 208)
!865 = !DISubprogram(name: "wcsrchr", scope: !588, file: !588, line: 175, type: !858, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!866 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !867, file: !582, line: 209)
!867 = !DISubprogram(name: "wcsstr", scope: !588, file: !588, line: 213, type: !862, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!868 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !869, file: !582, line: 210)
!869 = !DISubprogram(name: "wmemchr", scope: !588, file: !588, line: 254, type: !870, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!870 = !DISubroutineType(types: !871)
!871 = !{!657, !670, !658, !646}
!872 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !873, file: !582, line: 251)
!873 = !DISubprogram(name: "wcstold", scope: !588, file: !588, line: 385, type: !874, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!874 = !DISubroutineType(types: !875)
!875 = !{!876, !669, !811}
!876 = !DIBasicType(name: "long double", size: 128, encoding: DW_ATE_float)
!877 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !878, file: !582, line: 260)
!878 = !DISubprogram(name: "wcstoll", scope: !588, file: !588, line: 442, type: !879, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!879 = !DISubroutineType(types: !880)
!880 = !{!881, !669, !811, !547}
!881 = !DIBasicType(name: "long long", size: 64, encoding: DW_ATE_signed)
!882 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !883, file: !582, line: 261)
!883 = !DISubprogram(name: "wcstoull", scope: !588, file: !588, line: 449, type: !884, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!884 = !DISubroutineType(types: !885)
!885 = !{!886, !669, !811, !547}
!886 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!887 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !873, file: !582, line: 267)
!888 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !878, file: !582, line: 268)
!889 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !883, file: !582, line: 269)
!890 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !814, file: !582, line: 283)
!891 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !741, file: !582, line: 286)
!892 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !747, file: !582, line: 289)
!893 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !755, file: !582, line: 292)
!894 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !873, file: !582, line: 296)
!895 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !878, file: !582, line: 297)
!896 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !883, file: !582, line: 298)
!897 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !898, file: !901, line: 47)
!898 = !DIDerivedType(tag: DW_TAG_typedef, name: "int8_t", file: !899, line: 24, baseType: !900)
!899 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/stdint-intn.h", directory: "")
!900 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int8_t", file: !623, line: 37, baseType: !627)
!901 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/cstdint", directory: "")
!902 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !903, file: !901, line: 48)
!903 = !DIDerivedType(tag: DW_TAG_typedef, name: "int16_t", file: !899, line: 25, baseType: !904)
!904 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int16_t", file: !623, line: 39, baseType: !905)
!905 = !DIBasicType(name: "short", size: 16, encoding: DW_ATE_signed)
!906 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !907, file: !901, line: 49)
!907 = !DIDerivedType(tag: DW_TAG_typedef, name: "int32_t", file: !899, line: 26, baseType: !908)
!908 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int32_t", file: !623, line: 41, baseType: !547)
!909 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !910, file: !901, line: 50)
!910 = !DIDerivedType(tag: DW_TAG_typedef, name: "int64_t", file: !899, line: 27, baseType: !911)
!911 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int64_t", file: !623, line: 44, baseType: !7)
!912 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !913, file: !901, line: 52)
!913 = !DIDerivedType(tag: DW_TAG_typedef, name: "int_fast8_t", file: !914, line: 58, baseType: !627)
!914 = !DIFile(filename: "/usr/include/stdint.h", directory: "")
!915 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !916, file: !901, line: 53)
!916 = !DIDerivedType(tag: DW_TAG_typedef, name: "int_fast16_t", file: !914, line: 60, baseType: !7)
!917 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !918, file: !901, line: 54)
!918 = !DIDerivedType(tag: DW_TAG_typedef, name: "int_fast32_t", file: !914, line: 61, baseType: !7)
!919 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !920, file: !901, line: 55)
!920 = !DIDerivedType(tag: DW_TAG_typedef, name: "int_fast64_t", file: !914, line: 62, baseType: !7)
!921 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !922, file: !901, line: 57)
!922 = !DIDerivedType(tag: DW_TAG_typedef, name: "int_least8_t", file: !914, line: 43, baseType: !923)
!923 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int_least8_t", file: !623, line: 52, baseType: !900)
!924 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !925, file: !901, line: 58)
!925 = !DIDerivedType(tag: DW_TAG_typedef, name: "int_least16_t", file: !914, line: 44, baseType: !926)
!926 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int_least16_t", file: !623, line: 54, baseType: !904)
!927 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !928, file: !901, line: 59)
!928 = !DIDerivedType(tag: DW_TAG_typedef, name: "int_least32_t", file: !914, line: 45, baseType: !929)
!929 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int_least32_t", file: !623, line: 56, baseType: !908)
!930 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !931, file: !901, line: 60)
!931 = !DIDerivedType(tag: DW_TAG_typedef, name: "int_least64_t", file: !914, line: 46, baseType: !932)
!932 = !DIDerivedType(tag: DW_TAG_typedef, name: "__int_least64_t", file: !623, line: 58, baseType: !911)
!933 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !934, file: !901, line: 62)
!934 = !DIDerivedType(tag: DW_TAG_typedef, name: "intmax_t", file: !914, line: 101, baseType: !935)
!935 = !DIDerivedType(tag: DW_TAG_typedef, name: "__intmax_t", file: !623, line: 72, baseType: !7)
!936 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !937, file: !901, line: 63)
!937 = !DIDerivedType(tag: DW_TAG_typedef, name: "intptr_t", file: !914, line: 87, baseType: !7)
!938 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !939, file: !901, line: 65)
!939 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint8_t", file: !940, line: 24, baseType: !941)
!940 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/stdint-uintn.h", directory: "")
!941 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint8_t", file: !623, line: 38, baseType: !13)
!942 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !943, file: !901, line: 66)
!943 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint16_t", file: !940, line: 25, baseType: !944)
!944 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint16_t", file: !623, line: 40, baseType: !625)
!945 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !946, file: !901, line: 67)
!946 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint32_t", file: !940, line: 26, baseType: !947)
!947 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint32_t", file: !623, line: 42, baseType: !14)
!948 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !949, file: !901, line: 68)
!949 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint64_t", file: !940, line: 27, baseType: !950)
!950 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint64_t", file: !623, line: 45, baseType: !38)
!951 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !952, file: !901, line: 70)
!952 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint_fast8_t", file: !914, line: 71, baseType: !13)
!953 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !954, file: !901, line: 71)
!954 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint_fast16_t", file: !914, line: 73, baseType: !38)
!955 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !956, file: !901, line: 72)
!956 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint_fast32_t", file: !914, line: 74, baseType: !38)
!957 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !958, file: !901, line: 73)
!958 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint_fast64_t", file: !914, line: 75, baseType: !38)
!959 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !960, file: !901, line: 75)
!960 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint_least8_t", file: !914, line: 49, baseType: !961)
!961 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint_least8_t", file: !623, line: 53, baseType: !941)
!962 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !963, file: !901, line: 76)
!963 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint_least16_t", file: !914, line: 50, baseType: !964)
!964 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint_least16_t", file: !623, line: 55, baseType: !944)
!965 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !966, file: !901, line: 77)
!966 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint_least32_t", file: !914, line: 51, baseType: !967)
!967 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint_least32_t", file: !623, line: 57, baseType: !947)
!968 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !969, file: !901, line: 78)
!969 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint_least64_t", file: !914, line: 52, baseType: !970)
!970 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint_least64_t", file: !623, line: 59, baseType: !950)
!971 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !972, file: !901, line: 80)
!972 = !DIDerivedType(tag: DW_TAG_typedef, name: "uintmax_t", file: !914, line: 102, baseType: !973)
!973 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uintmax_t", file: !623, line: 73, baseType: !38)
!974 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !975, file: !901, line: 81)
!975 = !DIDerivedType(tag: DW_TAG_typedef, name: "uintptr_t", file: !914, line: 90, baseType: !38)
!976 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !977, file: !979, line: 53)
!977 = !DICompositeType(tag: DW_TAG_structure_type, name: "lconv", file: !978, line: 51, size: 768, flags: DIFlagFwdDecl, identifier: "_ZTS5lconv")
!978 = !DIFile(filename: "/usr/include/locale.h", directory: "")
!979 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/clocale", directory: "")
!980 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !981, file: !979, line: 54)
!981 = !DISubprogram(name: "setlocale", scope: !978, file: !978, line: 122, type: !982, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!982 = !DISubroutineType(types: !983)
!983 = !{!603, !547, !505}
!984 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !985, file: !979, line: 55)
!985 = !DISubprogram(name: "localeconv", scope: !978, file: !978, line: 125, type: !986, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!986 = !DISubroutineType(types: !987)
!987 = !{!988}
!988 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !977, size: 64)
!989 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !990, file: !994, line: 64)
!990 = !DISubprogram(name: "isalnum", scope: !991, file: !991, line: 108, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!991 = !DIFile(filename: "/usr/include/ctype.h", directory: "")
!992 = !DISubroutineType(types: !993)
!993 = !{!547, !547}
!994 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/cctype", directory: "")
!995 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !996, file: !994, line: 65)
!996 = !DISubprogram(name: "isalpha", scope: !991, file: !991, line: 109, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!997 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !998, file: !994, line: 66)
!998 = !DISubprogram(name: "iscntrl", scope: !991, file: !991, line: 110, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!999 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1000, file: !994, line: 67)
!1000 = !DISubprogram(name: "isdigit", scope: !991, file: !991, line: 111, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1001 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1002, file: !994, line: 68)
!1002 = !DISubprogram(name: "isgraph", scope: !991, file: !991, line: 113, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1003 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1004, file: !994, line: 69)
!1004 = !DISubprogram(name: "islower", scope: !991, file: !991, line: 112, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1005 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1006, file: !994, line: 70)
!1006 = !DISubprogram(name: "isprint", scope: !991, file: !991, line: 114, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1007 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1008, file: !994, line: 71)
!1008 = !DISubprogram(name: "ispunct", scope: !991, file: !991, line: 115, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1009 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1010, file: !994, line: 72)
!1010 = !DISubprogram(name: "isspace", scope: !991, file: !991, line: 116, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1011 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1012, file: !994, line: 73)
!1012 = !DISubprogram(name: "isupper", scope: !991, file: !991, line: 117, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1013 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1014, file: !994, line: 74)
!1014 = !DISubprogram(name: "isxdigit", scope: !991, file: !991, line: 118, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1015 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1016, file: !994, line: 75)
!1016 = !DISubprogram(name: "tolower", scope: !991, file: !991, line: 122, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1017 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1018, file: !994, line: 76)
!1018 = !DISubprogram(name: "toupper", scope: !991, file: !991, line: 125, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1019 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1020, file: !994, line: 87)
!1020 = !DISubprogram(name: "isblank", scope: !991, file: !991, line: 130, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1021 = !DIImportedEntity(tag: DW_TAG_imported_module, scope: !1022, entity: !1023, file: !1024, line: 58)
!1022 = !DINamespace(name: "__gnu_debug", scope: null)
!1023 = !DINamespace(name: "__debug", scope: !25)
!1024 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/debug/debug.h", directory: "")
!1025 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1026, file: !1028, line: 52)
!1026 = !DISubprogram(name: "abs", scope: !1027, file: !1027, line: 848, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1027 = !DIFile(filename: "/usr/include/stdlib.h", directory: "")
!1028 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/std_abs.h", directory: "")
!1029 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1030, file: !1032, line: 127)
!1030 = !DIDerivedType(tag: DW_TAG_typedef, name: "div_t", file: !1027, line: 63, baseType: !1031)
!1031 = !DICompositeType(tag: DW_TAG_structure_type, file: !1027, line: 59, size: 64, flags: DIFlagFwdDecl, identifier: "_ZTS5div_t")
!1032 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/cstdlib", directory: "")
!1033 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1034, file: !1032, line: 128)
!1034 = !DIDerivedType(tag: DW_TAG_typedef, name: "ldiv_t", file: !1027, line: 71, baseType: !1035)
!1035 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !1027, line: 67, size: 128, flags: DIFlagTypePassByValue, elements: !1036, identifier: "_ZTS6ldiv_t")
!1036 = !{!1037, !1038}
!1037 = !DIDerivedType(tag: DW_TAG_member, name: "quot", scope: !1035, file: !1027, line: 69, baseType: !7, size: 64)
!1038 = !DIDerivedType(tag: DW_TAG_member, name: "rem", scope: !1035, file: !1027, line: 70, baseType: !7, size: 64, offset: 64)
!1039 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1040, file: !1032, line: 130)
!1040 = !DISubprogram(name: "abort", scope: !1027, file: !1027, line: 598, type: !1041, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!1041 = !DISubroutineType(types: !1042)
!1042 = !{null}
!1043 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1044, file: !1032, line: 134)
!1044 = !DISubprogram(name: "atexit", scope: !1027, file: !1027, line: 602, type: !1045, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1045 = !DISubroutineType(types: !1046)
!1046 = !{!547, !1047}
!1047 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1041, size: 64)
!1048 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1049, file: !1032, line: 137)
!1049 = !DISubprogram(name: "at_quick_exit", scope: !1027, file: !1027, line: 607, type: !1045, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1050 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1051, file: !1032, line: 140)
!1051 = !DISubprogram(name: "atof", scope: !1052, file: !1052, line: 25, type: !1053, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1052 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/stdlib-float.h", directory: "")
!1053 = !DISubroutineType(types: !1054)
!1054 = !{!5, !505}
!1055 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1056, file: !1032, line: 141)
!1056 = !DISubprogram(name: "atoi", scope: !1027, file: !1027, line: 362, type: !1057, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1057 = !DISubroutineType(types: !1058)
!1058 = !{!547, !505}
!1059 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1060, file: !1032, line: 142)
!1060 = !DISubprogram(name: "atol", scope: !1027, file: !1027, line: 367, type: !1061, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1061 = !DISubroutineType(types: !1062)
!1062 = !{!7, !505}
!1063 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1064, file: !1032, line: 143)
!1064 = !DISubprogram(name: "bsearch", scope: !1065, file: !1065, line: 20, type: !1066, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1065 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/stdlib-bsearch.h", directory: "")
!1066 = !DISubroutineType(types: !1067)
!1067 = !{!17, !107, !107, !646, !646, !1068}
!1068 = !DIDerivedType(tag: DW_TAG_typedef, name: "__compar_fn_t", file: !1027, line: 816, baseType: !1069)
!1069 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1070, size: 64)
!1070 = !DISubroutineType(types: !1071)
!1071 = !{!547, !107, !107}
!1072 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1073, file: !1032, line: 144)
!1073 = !DISubprogram(name: "calloc", scope: !1027, file: !1027, line: 543, type: !1074, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1074 = !DISubroutineType(types: !1075)
!1075 = !{!17, !646, !646}
!1076 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1077, file: !1032, line: 145)
!1077 = !DISubprogram(name: "div", scope: !1027, file: !1027, line: 860, type: !1078, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1078 = !DISubroutineType(types: !1079)
!1079 = !{!1030, !547, !547}
!1080 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1081, file: !1032, line: 146)
!1081 = !DISubprogram(name: "exit", scope: !1027, file: !1027, line: 624, type: !1082, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!1082 = !DISubroutineType(types: !1083)
!1083 = !{null, !547}
!1084 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1085, file: !1032, line: 147)
!1085 = !DISubprogram(name: "free", scope: !1027, file: !1027, line: 555, type: !1086, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1086 = !DISubroutineType(types: !1087)
!1087 = !{null, !17}
!1088 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1089, file: !1032, line: 148)
!1089 = !DISubprogram(name: "getenv", scope: !1027, file: !1027, line: 641, type: !1090, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1090 = !DISubroutineType(types: !1091)
!1091 = !{!603, !505}
!1092 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1093, file: !1032, line: 149)
!1093 = !DISubprogram(name: "labs", scope: !1027, file: !1027, line: 849, type: !1094, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1094 = !DISubroutineType(types: !1095)
!1095 = !{!7, !7}
!1096 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1097, file: !1032, line: 150)
!1097 = !DISubprogram(name: "ldiv", scope: !1027, file: !1027, line: 862, type: !1098, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1098 = !DISubroutineType(types: !1099)
!1099 = !{!1034, !7, !7}
!1100 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1101, file: !1032, line: 151)
!1101 = !DISubprogram(name: "malloc", scope: !1027, file: !1027, line: 540, type: !1102, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1102 = !DISubroutineType(types: !1103)
!1103 = !{!17, !646}
!1104 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1105, file: !1032, line: 153)
!1105 = !DISubprogram(name: "mblen", scope: !1027, file: !1027, line: 930, type: !1106, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1106 = !DISubroutineType(types: !1107)
!1107 = !{!547, !505, !646}
!1108 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1109, file: !1032, line: 154)
!1109 = !DISubprogram(name: "mbstowcs", scope: !1027, file: !1027, line: 941, type: !1110, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1110 = !DISubroutineType(types: !1111)
!1111 = !{!646, !659, !692, !646}
!1112 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1113, file: !1032, line: 155)
!1113 = !DISubprogram(name: "mbtowc", scope: !1027, file: !1027, line: 933, type: !1114, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1114 = !DISubroutineType(types: !1115)
!1115 = !{!547, !659, !692, !646}
!1116 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1117, file: !1032, line: 157)
!1117 = !DISubprogram(name: "qsort", scope: !1027, file: !1027, line: 838, type: !1118, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1118 = !DISubroutineType(types: !1119)
!1119 = !{null, !17, !646, !646, !1068}
!1120 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1121, file: !1032, line: 160)
!1121 = !DISubprogram(name: "quick_exit", scope: !1027, file: !1027, line: 630, type: !1082, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!1122 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1123, file: !1032, line: 163)
!1123 = !DISubprogram(name: "rand", scope: !1027, file: !1027, line: 454, type: !1124, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1124 = !DISubroutineType(types: !1125)
!1125 = !{!547}
!1126 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1127, file: !1032, line: 164)
!1127 = !DISubprogram(name: "realloc", scope: !1027, file: !1027, line: 551, type: !1128, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1128 = !DISubroutineType(types: !1129)
!1129 = !{!17, !17, !646}
!1130 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1131, file: !1032, line: 165)
!1131 = !DISubprogram(name: "srand", scope: !1027, file: !1027, line: 456, type: !1132, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1132 = !DISubroutineType(types: !1133)
!1133 = !{null, !14}
!1134 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1135, file: !1032, line: 166)
!1135 = !DISubprogram(name: "strtod", scope: !1027, file: !1027, line: 118, type: !1136, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1136 = !DISubroutineType(types: !1137)
!1137 = !{!5, !692, !1138}
!1138 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !1139)
!1139 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !603, size: 64)
!1140 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1141, file: !1032, line: 167)
!1141 = !DISubprogram(name: "strtol", scope: !1027, file: !1027, line: 177, type: !1142, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1142 = !DISubroutineType(types: !1143)
!1143 = !{!7, !692, !1138, !547}
!1144 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1145, file: !1032, line: 168)
!1145 = !DISubprogram(name: "strtoul", scope: !1027, file: !1027, line: 181, type: !1146, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1146 = !DISubroutineType(types: !1147)
!1147 = !{!38, !692, !1138, !547}
!1148 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1149, file: !1032, line: 169)
!1149 = !DISubprogram(name: "system", scope: !1027, file: !1027, line: 791, type: !1057, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1150 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1151, file: !1032, line: 171)
!1151 = !DISubprogram(name: "wcstombs", scope: !1027, file: !1027, line: 945, type: !1152, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1152 = !DISubroutineType(types: !1153)
!1153 = !{!646, !760, !669, !646}
!1154 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1155, file: !1032, line: 172)
!1155 = !DISubprogram(name: "wctomb", scope: !1027, file: !1027, line: 937, type: !1156, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1156 = !DISubroutineType(types: !1157)
!1157 = !{!547, !603, !658}
!1158 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1159, file: !1032, line: 200)
!1159 = !DIDerivedType(tag: DW_TAG_typedef, name: "lldiv_t", file: !1027, line: 81, baseType: !1160)
!1160 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !1027, line: 77, size: 128, flags: DIFlagTypePassByValue, elements: !1161, identifier: "_ZTS7lldiv_t")
!1161 = !{!1162, !1163}
!1162 = !DIDerivedType(tag: DW_TAG_member, name: "quot", scope: !1160, file: !1027, line: 79, baseType: !881, size: 64)
!1163 = !DIDerivedType(tag: DW_TAG_member, name: "rem", scope: !1160, file: !1027, line: 80, baseType: !881, size: 64, offset: 64)
!1164 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1165, file: !1032, line: 206)
!1165 = !DISubprogram(name: "_Exit", scope: !1027, file: !1027, line: 636, type: !1082, flags: DIFlagPrototyped | DIFlagNoReturn, spFlags: DISPFlagOptimized)
!1166 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1167, file: !1032, line: 210)
!1167 = !DISubprogram(name: "llabs", scope: !1027, file: !1027, line: 852, type: !1168, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1168 = !DISubroutineType(types: !1169)
!1169 = !{!881, !881}
!1170 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1171, file: !1032, line: 216)
!1171 = !DISubprogram(name: "lldiv", scope: !1027, file: !1027, line: 866, type: !1172, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1172 = !DISubroutineType(types: !1173)
!1173 = !{!1159, !881, !881}
!1174 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1175, file: !1032, line: 227)
!1175 = !DISubprogram(name: "atoll", scope: !1027, file: !1027, line: 374, type: !1176, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1176 = !DISubroutineType(types: !1177)
!1177 = !{!881, !505}
!1178 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1179, file: !1032, line: 228)
!1179 = !DISubprogram(name: "strtoll", scope: !1027, file: !1027, line: 201, type: !1180, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1180 = !DISubroutineType(types: !1181)
!1181 = !{!881, !692, !1138, !547}
!1182 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1183, file: !1032, line: 229)
!1183 = !DISubprogram(name: "strtoull", scope: !1027, file: !1027, line: 206, type: !1184, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1184 = !DISubroutineType(types: !1185)
!1185 = !{!886, !692, !1138, !547}
!1186 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1187, file: !1032, line: 231)
!1187 = !DISubprogram(name: "strtof", scope: !1027, file: !1027, line: 124, type: !1188, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1188 = !DISubroutineType(types: !1189)
!1189 = !{!817, !692, !1138}
!1190 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1191, file: !1032, line: 232)
!1191 = !DISubprogram(name: "strtold", scope: !1027, file: !1027, line: 127, type: !1192, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1192 = !DISubroutineType(types: !1193)
!1193 = !{!876, !692, !1138}
!1194 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1159, file: !1032, line: 240)
!1195 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1165, file: !1032, line: 242)
!1196 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1167, file: !1032, line: 244)
!1197 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1198, file: !1032, line: 245)
!1198 = !DISubprogram(name: "div", linkageName: "_ZN9__gnu_cxx3divExx", scope: !54, file: !1032, line: 213, type: !1172, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1199 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1171, file: !1032, line: 246)
!1200 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1175, file: !1032, line: 248)
!1201 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1187, file: !1032, line: 249)
!1202 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1179, file: !1032, line: 250)
!1203 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1183, file: !1032, line: 251)
!1204 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1191, file: !1032, line: 252)
!1205 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1206, file: !1208, line: 98)
!1206 = !DIDerivedType(tag: DW_TAG_typedef, name: "FILE", file: !1207, line: 7, baseType: !598)
!1207 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types/FILE.h", directory: "")
!1208 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/cstdio", directory: "")
!1209 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1210, file: !1208, line: 99)
!1210 = !DIDerivedType(tag: DW_TAG_typedef, name: "fpos_t", file: !1211, line: 84, baseType: !1212)
!1211 = !DIFile(filename: "/usr/include/stdio.h", directory: "")
!1212 = !DIDerivedType(tag: DW_TAG_typedef, name: "__fpos_t", file: !1213, line: 14, baseType: !1214)
!1213 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types/__fpos_t.h", directory: "")
!1214 = !DICompositeType(tag: DW_TAG_structure_type, name: "_G_fpos_t", file: !1213, line: 10, size: 128, flags: DIFlagFwdDecl, identifier: "_ZTS9_G_fpos_t")
!1215 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1216, file: !1208, line: 101)
!1216 = !DISubprogram(name: "clearerr", scope: !1211, file: !1211, line: 786, type: !1217, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1217 = !DISubroutineType(types: !1218)
!1218 = !{null, !1219}
!1219 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1206, size: 64)
!1220 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1221, file: !1208, line: 102)
!1221 = !DISubprogram(name: "fclose", scope: !1211, file: !1211, line: 178, type: !1222, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1222 = !DISubroutineType(types: !1223)
!1223 = !{!547, !1219}
!1224 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1225, file: !1208, line: 103)
!1225 = !DISubprogram(name: "feof", scope: !1211, file: !1211, line: 788, type: !1222, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1226 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1227, file: !1208, line: 104)
!1227 = !DISubprogram(name: "ferror", scope: !1211, file: !1211, line: 790, type: !1222, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1228 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1229, file: !1208, line: 105)
!1229 = !DISubprogram(name: "fflush", scope: !1211, file: !1211, line: 230, type: !1222, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1230 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1231, file: !1208, line: 106)
!1231 = !DISubprogram(name: "fgetc", scope: !1211, file: !1211, line: 513, type: !1222, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1232 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1233, file: !1208, line: 107)
!1233 = !DISubprogram(name: "fgetpos", scope: !1211, file: !1211, line: 760, type: !1234, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1234 = !DISubroutineType(types: !1235)
!1235 = !{!547, !1236, !1237}
!1236 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !1219)
!1237 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !1238)
!1238 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1210, size: 64)
!1239 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1240, file: !1208, line: 108)
!1240 = !DISubprogram(name: "fgets", scope: !1211, file: !1211, line: 592, type: !1241, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1241 = !DISubroutineType(types: !1242)
!1242 = !{!603, !760, !547, !1236}
!1243 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1244, file: !1208, line: 109)
!1244 = !DISubprogram(name: "fopen", scope: !1211, file: !1211, line: 258, type: !1245, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1245 = !DISubroutineType(types: !1246)
!1246 = !{!1219, !692, !692}
!1247 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1248, file: !1208, line: 110)
!1248 = !DISubprogram(name: "fprintf", scope: !1211, file: !1211, line: 350, type: !1249, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1249 = !DISubroutineType(types: !1250)
!1250 = !{!547, !1236, !692, null}
!1251 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1252, file: !1208, line: 111)
!1252 = !DISubprogram(name: "fputc", scope: !1211, file: !1211, line: 549, type: !1253, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1253 = !DISubroutineType(types: !1254)
!1254 = !{!547, !547, !1219}
!1255 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1256, file: !1208, line: 112)
!1256 = !DISubprogram(name: "fputs", scope: !1211, file: !1211, line: 655, type: !1257, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1257 = !DISubroutineType(types: !1258)
!1258 = !{!547, !692, !1236}
!1259 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1260, file: !1208, line: 113)
!1260 = !DISubprogram(name: "fread", scope: !1211, file: !1211, line: 675, type: !1261, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1261 = !DISubroutineType(types: !1262)
!1262 = !{!646, !1263, !646, !646, !1236}
!1263 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !17)
!1264 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1265, file: !1208, line: 114)
!1265 = !DISubprogram(name: "freopen", scope: !1211, file: !1211, line: 265, type: !1266, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1266 = !DISubroutineType(types: !1267)
!1267 = !{!1219, !692, !692, !1236}
!1268 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1269, file: !1208, line: 115)
!1269 = !DISubprogram(name: "fscanf", linkageName: "__isoc99_fscanf", scope: !1211, file: !1211, line: 434, type: !1249, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1270 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1271, file: !1208, line: 116)
!1271 = !DISubprogram(name: "fseek", scope: !1211, file: !1211, line: 713, type: !1272, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1272 = !DISubroutineType(types: !1273)
!1273 = !{!547, !1219, !7, !547}
!1274 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1275, file: !1208, line: 117)
!1275 = !DISubprogram(name: "fsetpos", scope: !1211, file: !1211, line: 765, type: !1276, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1276 = !DISubroutineType(types: !1277)
!1277 = !{!547, !1219, !1278}
!1278 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1279, size: 64)
!1279 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1210)
!1280 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1281, file: !1208, line: 118)
!1281 = !DISubprogram(name: "ftell", scope: !1211, file: !1211, line: 718, type: !1282, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1282 = !DISubroutineType(types: !1283)
!1283 = !{!7, !1219}
!1284 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1285, file: !1208, line: 119)
!1285 = !DISubprogram(name: "fwrite", scope: !1211, file: !1211, line: 681, type: !1286, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1286 = !DISubroutineType(types: !1287)
!1287 = !{!646, !1288, !646, !646, !1236}
!1288 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !107)
!1289 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1290, file: !1208, line: 120)
!1290 = !DISubprogram(name: "getc", scope: !1211, file: !1211, line: 514, type: !1222, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1291 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1292, file: !1208, line: 121)
!1292 = !DISubprogram(name: "getchar", scope: !1293, file: !1293, line: 47, type: !1124, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1293 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/stdio.h", directory: "")
!1294 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1295, file: !1208, line: 126)
!1295 = !DISubprogram(name: "perror", scope: !1211, file: !1211, line: 804, type: !1296, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1296 = !DISubroutineType(types: !1297)
!1297 = !{null, !505}
!1298 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1299, file: !1208, line: 127)
!1299 = !DISubprogram(name: "printf", scope: !1211, file: !1211, line: 356, type: !1300, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1300 = !DISubroutineType(types: !1301)
!1301 = !{!547, !692, null}
!1302 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1303, file: !1208, line: 128)
!1303 = !DISubprogram(name: "putc", scope: !1211, file: !1211, line: 550, type: !1253, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1304 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1305, file: !1208, line: 129)
!1305 = !DISubprogram(name: "putchar", scope: !1293, file: !1293, line: 82, type: !992, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1306 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1307, file: !1208, line: 130)
!1307 = !DISubprogram(name: "puts", scope: !1211, file: !1211, line: 661, type: !1057, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1308 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1309, file: !1208, line: 131)
!1309 = !DISubprogram(name: "remove", scope: !1211, file: !1211, line: 152, type: !1057, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1310 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1311, file: !1208, line: 132)
!1311 = !DISubprogram(name: "rename", scope: !1211, file: !1211, line: 154, type: !1312, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1312 = !DISubroutineType(types: !1313)
!1313 = !{!547, !505, !505}
!1314 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1315, file: !1208, line: 133)
!1315 = !DISubprogram(name: "rewind", scope: !1211, file: !1211, line: 723, type: !1217, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1316 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1317, file: !1208, line: 134)
!1317 = !DISubprogram(name: "scanf", linkageName: "__isoc99_scanf", scope: !1211, file: !1211, line: 437, type: !1300, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1318 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1319, file: !1208, line: 135)
!1319 = !DISubprogram(name: "setbuf", scope: !1211, file: !1211, line: 328, type: !1320, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1320 = !DISubroutineType(types: !1321)
!1321 = !{null, !1236, !760}
!1322 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1323, file: !1208, line: 136)
!1323 = !DISubprogram(name: "setvbuf", scope: !1211, file: !1211, line: 332, type: !1324, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1324 = !DISubroutineType(types: !1325)
!1325 = !{!547, !1236, !760, !547, !646}
!1326 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1327, file: !1208, line: 137)
!1327 = !DISubprogram(name: "sprintf", scope: !1211, file: !1211, line: 358, type: !1328, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1328 = !DISubroutineType(types: !1329)
!1329 = !{!547, !760, !692, null}
!1330 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1331, file: !1208, line: 138)
!1331 = !DISubprogram(name: "sscanf", linkageName: "__isoc99_sscanf", scope: !1211, file: !1211, line: 439, type: !1332, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1332 = !DISubroutineType(types: !1333)
!1333 = !{!547, !692, !692, null}
!1334 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1335, file: !1208, line: 139)
!1335 = !DISubprogram(name: "tmpfile", scope: !1211, file: !1211, line: 188, type: !1336, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1336 = !DISubroutineType(types: !1337)
!1337 = !{!1219}
!1338 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1339, file: !1208, line: 141)
!1339 = !DISubprogram(name: "tmpnam", scope: !1211, file: !1211, line: 205, type: !1340, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1340 = !DISubroutineType(types: !1341)
!1341 = !{!603, !603}
!1342 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1343, file: !1208, line: 143)
!1343 = !DISubprogram(name: "ungetc", scope: !1211, file: !1211, line: 668, type: !1253, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1344 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1345, file: !1208, line: 144)
!1345 = !DISubprogram(name: "vfprintf", scope: !1211, file: !1211, line: 365, type: !1346, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1346 = !DISubroutineType(types: !1347)
!1347 = !{!547, !1236, !692, !733}
!1348 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1349, file: !1208, line: 145)
!1349 = !DISubprogram(name: "vprintf", scope: !1293, file: !1293, line: 39, type: !1350, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1350 = !DISubroutineType(types: !1351)
!1351 = !{!547, !692, !733}
!1352 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1353, file: !1208, line: 146)
!1353 = !DISubprogram(name: "vsprintf", scope: !1211, file: !1211, line: 373, type: !1354, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1354 = !DISubroutineType(types: !1355)
!1355 = !{!547, !760, !692, !733}
!1356 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1357, file: !1208, line: 175)
!1357 = !DISubprogram(name: "snprintf", scope: !1211, file: !1211, line: 378, type: !1358, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1358 = !DISubroutineType(types: !1359)
!1359 = !{!547, !760, !646, !692, null}
!1360 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1361, file: !1208, line: 176)
!1361 = !DISubprogram(name: "vfscanf", linkageName: "__isoc99_vfscanf", scope: !1211, file: !1211, line: 479, type: !1346, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1362 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1363, file: !1208, line: 177)
!1363 = !DISubprogram(name: "vscanf", linkageName: "__isoc99_vscanf", scope: !1211, file: !1211, line: 484, type: !1350, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1364 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1365, file: !1208, line: 178)
!1365 = !DISubprogram(name: "vsnprintf", scope: !1211, file: !1211, line: 382, type: !1366, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1366 = !DISubroutineType(types: !1367)
!1367 = !{!547, !760, !646, !692, !733}
!1368 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !54, entity: !1369, file: !1208, line: 179)
!1369 = !DISubprogram(name: "vsscanf", linkageName: "__isoc99_vsscanf", scope: !1211, file: !1211, line: 487, type: !1370, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1370 = !DISubroutineType(types: !1371)
!1371 = !{!547, !692, !692, !733}
!1372 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1357, file: !1208, line: 185)
!1373 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1361, file: !1208, line: 186)
!1374 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1363, file: !1208, line: 187)
!1375 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1365, file: !1208, line: 188)
!1376 = !DIImportedEntity(tag: DW_TAG_imported_declaration, scope: !25, entity: !1369, file: !1208, line: 189)
!1377 = !{i32 7, !"Dwarf Version", i32 3}
!1378 = !{i32 2, !"Debug Info Version", i32 3}
!1379 = !{i32 1, !"wchar_size", i32 4}
!1380 = !{i32 7, !"PIC Level", i32 2}
!1381 = !{i32 7, !"PIE Level", i32 2}
!1382 = !{i32 7, !"uwtable", i32 1}
!1383 = !{!"Ubuntu clang version 14.0.0-1ubuntu1"}
!1384 = distinct !DISubprogram(name: "~vector", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EED2Ev", scope: !40, file: !24, line: 728, type: !312, scopeLine: 729, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !364, retainedNodes: !1385)
!1385 = !{!1386}
!1386 = !DILocalVariable(name: "this", arg: 1, scope: !1384, type: !1387, flags: DIFlagArtificial | DIFlagObjectPointer)
!1387 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !40, size: 64)
!1388 = !DILocation(line: 0, scope: !1384)
!1389 = !DILocalVariable(name: "this", arg: 1, scope: !1390, type: !1392, flags: DIFlagArtificial | DIFlagObjectPointer)
!1390 = distinct !DISubprogram(name: "~_Vector_base", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EED2Ev", scope: !43, file: !24, line: 364, type: !228, scopeLine: 365, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !254, retainedNodes: !1391)
!1391 = !{!1389}
!1392 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!1393 = !DILocation(line: 0, scope: !1390, inlinedAt: !1394)
!1394 = distinct !DILocation(line: 733, column: 7, scope: !1395)
!1395 = distinct !DILexicalBlock(scope: !1384, file: !24, line: 729, column: 7)
!1396 = !DILocation(line: 366, column: 24, scope: !1397, inlinedAt: !1394)
!1397 = distinct !DILexicalBlock(scope: !1390, file: !24, line: 365, column: 7)
!1398 = !{!1399, !1400, i64 0}
!1399 = !{!"_ZTSNSt12_Vector_baseIP6bcfuncSaIS1_EE17_Vector_impl_dataE", !1400, i64 0, !1400, i64 8, !1400, i64 16}
!1400 = !{!"any pointer", !1401, i64 0}
!1401 = !{!"omnipotent char", !1402, i64 0}
!1402 = !{!"Simple C++ TBAA"}
!1403 = !DILocalVariable(name: "this", arg: 1, scope: !1404, type: !1392, flags: DIFlagArtificial | DIFlagObjectPointer)
!1404 = distinct !DISubprogram(name: "_M_deallocate", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EE13_M_deallocateEPS1_m", scope: !43, file: !24, line: 383, type: !259, scopeLine: 384, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !258, retainedNodes: !1405)
!1405 = !{!1403, !1406, !1407}
!1406 = !DILocalVariable(name: "__p", arg: 2, scope: !1404, file: !24, line: 383, type: !172)
!1407 = !DILocalVariable(name: "__n", arg: 3, scope: !1404, file: !24, line: 383, type: !105)
!1408 = !DILocation(line: 0, scope: !1404, inlinedAt: !1409)
!1409 = distinct !DILocation(line: 366, column: 2, scope: !1397, inlinedAt: !1394)
!1410 = !DILocation(line: 386, column: 6, scope: !1411, inlinedAt: !1409)
!1411 = distinct !DILexicalBlock(scope: !1404, file: !24, line: 386, column: 6)
!1412 = !DILocation(line: 386, column: 6, scope: !1404, inlinedAt: !1409)
!1413 = !DILocalVariable(name: "__a", arg: 1, scope: !1414, file: !58, line: 495, type: !65)
!1414 = distinct !DISubprogram(name: "deallocate", linkageName: "_ZNSt16allocator_traitsISaIP6bcfuncEE10deallocateERS2_PS1_m", scope: !57, file: !58, line: 495, type: !138, scopeLine: 496, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !137, retainedNodes: !1415)
!1415 = !{!1413, !1416, !1417}
!1416 = !DILocalVariable(name: "__p", arg: 2, scope: !1414, file: !58, line: 495, type: !63)
!1417 = !DILocalVariable(name: "__n", arg: 3, scope: !1414, file: !58, line: 495, type: !132)
!1418 = !DILocation(line: 0, scope: !1414, inlinedAt: !1419)
!1419 = distinct !DILocation(line: 387, column: 4, scope: !1411, inlinedAt: !1409)
!1420 = !DILocalVariable(name: "this", arg: 1, scope: !1421, type: !1425, flags: DIFlagArtificial | DIFlagObjectPointer)
!1421 = distinct !DISubprogram(name: "deallocate", linkageName: "_ZNSt15__new_allocatorIP6bcfuncE10deallocateEPS1_m", scope: !73, file: !74, line: 142, type: !110, scopeLine: 143, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !109, retainedNodes: !1422)
!1422 = !{!1420, !1423, !1424}
!1423 = !DILocalVariable(name: "__p", arg: 2, scope: !1421, file: !74, line: 142, type: !64)
!1424 = !DILocalVariable(name: "__n", arg: 3, scope: !1421, file: !74, line: 142, type: !104)
!1425 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !73, size: 64)
!1426 = !DILocation(line: 0, scope: !1421, inlinedAt: !1427)
!1427 = distinct !DILocation(line: 496, column: 13, scope: !1414, inlinedAt: !1419)
!1428 = !DILocation(line: 158, column: 27, scope: !1421, inlinedAt: !1427)
!1429 = !DILocation(line: 158, column: 2, scope: !1421, inlinedAt: !1427)
!1430 = !DILocation(line: 387, column: 4, scope: !1411, inlinedAt: !1409)
!1431 = !DILocation(line: 733, column: 7, scope: !1384)
!1432 = distinct !DISubprogram(name: "ADDVV_SLOWPATH", linkageName: "_Z14ADDVV_SLOWPATHll", scope: !3, file: !3, line: 16, type: !1433, scopeLine: 16, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1435)
!1433 = !DISubroutineType(types: !1434)
!1434 = !{!7, !7, !7}
!1435 = !{!1436, !1437, !1438}
!1436 = !DILocalVariable(name: "a", arg: 1, scope: !1432, file: !3, line: 16, type: !7)
!1437 = !DILocalVariable(name: "b", arg: 2, scope: !1432, file: !3, line: 16, type: !7)
!1438 = !DILocalVariable(name: "c", scope: !1432, file: !3, line: 17, type: !5)
!1439 = !DILocation(line: 0, scope: !1432)
!1440 = !DILocation(line: 17, column: 22, scope: !1432)
!1441 = !DILocation(line: 17, column: 34, scope: !1432)
!1442 = !DILocation(line: 17, column: 24, scope: !1432)
!1443 = !DILocation(line: 18, column: 5, scope: !1432)
!1444 = !DILocation(line: 19, column: 10, scope: !1432)
!1445 = !DILocation(line: 19, column: 3, scope: !1432)
!1446 = distinct !DISubprogram(name: "FAIL_SLOWPATH", linkageName: "_Z13FAIL_SLOWPATHll", scope: !3, file: !3, line: 21, type: !1433, scopeLine: 21, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1447)
!1447 = !{!1448, !1449}
!1448 = !DILocalVariable(name: "a", arg: 1, scope: !1446, file: !3, line: 21, type: !7)
!1449 = !DILocalVariable(name: "b", arg: 2, scope: !1446, file: !3, line: 21, type: !7)
!1450 = !DILocation(line: 0, scope: !1446)
!1451 = !DILocation(line: 22, column: 3, scope: !1446)
!1452 = !DILocation(line: 23, column: 3, scope: !1446)
!1453 = distinct !DISubprogram(name: "UNDEFINED_SYMBOL_SLOWPATH", linkageName: "_Z25UNDEFINED_SYMBOL_SLOWPATHP6symbol", scope: !3, file: !3, line: 26, type: !1454, scopeLine: 26, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1456)
!1454 = !DISubroutineType(types: !1455)
!1455 = !{null, !28}
!1456 = !{!1457}
!1457 = !DILocalVariable(name: "s", arg: 1, scope: !1453, file: !3, line: 26, type: !28)
!1458 = !DILocation(line: 0, scope: !1453)
!1459 = !DILocalVariable(name: "this", arg: 1, scope: !1460, type: !1468, flags: DIFlagArtificial | DIFlagObjectPointer)
!1460 = distinct !DISubprogram(name: "c_str", linkageName: "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv", scope: !34, file: !1461, line: 2554, type: !1462, scopeLine: 2555, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !1466, retainedNodes: !1467)
!1461 = !DIFile(filename: "/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/basic_string.h", directory: "")
!1462 = !DISubroutineType(types: !1463)
!1463 = !{!505, !1464}
!1464 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1465, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1465 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !34)
!1466 = !DISubprogram(name: "c_str", linkageName: "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv", scope: !34, file: !1461, line: 2554, type: !1462, scopeLine: 2554, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1467 = !{!1459}
!1468 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1465, size: 64)
!1469 = !DILocation(line: 0, scope: !1460, inlinedAt: !1470)
!1470 = distinct !DILocation(line: 27, column: 49, scope: !1453)
!1471 = !DILocalVariable(name: "this", arg: 1, scope: !1472, type: !1468, flags: DIFlagArtificial | DIFlagObjectPointer)
!1472 = distinct !DISubprogram(name: "_M_data", linkageName: "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7_M_dataEv", scope: !34, file: !1461, line: 234, type: !1473, scopeLine: 235, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !1522, retainedNodes: !1523)
!1473 = !DISubroutineType(types: !1474)
!1474 = !{!1475, !1464}
!1475 = !DIDerivedType(tag: DW_TAG_typedef, name: "pointer", scope: !34, file: !1461, line: 131, baseType: !1476)
!1476 = !DIDerivedType(tag: DW_TAG_typedef, name: "pointer", scope: !1477, file: !51, line: 57, baseType: !1485)
!1477 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "__alloc_traits<std::allocator<char>, char>", scope: !54, file: !51, line: 48, size: 8, flags: DIFlagTypePassByValue, elements: !1478, templateParams: !1520, identifier: "_ZTSN9__gnu_cxx14__alloc_traitsISaIcEcEE")
!1478 = !{!1479, !1506, !1511, !1515, !1516, !1517, !1518, !1519}
!1479 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !1477, baseType: !1480, extraData: i32 0)
!1480 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "allocator_traits<std::allocator<char> >", scope: !25, file: !58, line: 411, size: 8, flags: DIFlagTypePassByValue, elements: !1481, templateParams: !1504, identifier: "_ZTSSt16allocator_traitsISaIcEE")
!1481 = !{!1482, !1489, !1492, !1495, !1501}
!1482 = !DISubprogram(name: "allocate", linkageName: "_ZNSt16allocator_traitsISaIcEE8allocateERS0_m", scope: !1480, file: !58, line: 463, type: !1483, scopeLine: 463, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1483 = !DISubroutineType(types: !1484)
!1484 = !{!1485, !1486, !132}
!1485 = !DIDerivedType(tag: DW_TAG_typedef, name: "pointer", scope: !1480, file: !58, line: 420, baseType: !603)
!1486 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1487, size: 64)
!1487 = !DIDerivedType(tag: DW_TAG_typedef, name: "allocator_type", scope: !1480, file: !58, line: 414, baseType: !1488)
!1488 = !DICompositeType(tag: DW_TAG_class_type, name: "allocator<char>", scope: !25, file: !68, line: 257, size: 8, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSSaIcE")
!1489 = !DISubprogram(name: "allocate", linkageName: "_ZNSt16allocator_traitsISaIcEE8allocateERS0_mPKv", scope: !1480, file: !58, line: 477, type: !1490, scopeLine: 477, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1490 = !DISubroutineType(types: !1491)
!1491 = !{!1485, !1486, !132, !136}
!1492 = !DISubprogram(name: "deallocate", linkageName: "_ZNSt16allocator_traitsISaIcEE10deallocateERS0_Pcm", scope: !1480, file: !58, line: 495, type: !1493, scopeLine: 495, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1493 = !DISubroutineType(types: !1494)
!1494 = !{null, !1486, !1485, !132}
!1495 = !DISubprogram(name: "max_size", linkageName: "_ZNSt16allocator_traitsISaIcEE8max_sizeERKS0_", scope: !1480, file: !58, line: 547, type: !1496, scopeLine: 547, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1496 = !DISubroutineType(types: !1497)
!1497 = !{!1498, !1499}
!1498 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_type", scope: !1480, file: !58, line: 435, baseType: !105)
!1499 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1500, size: 64)
!1500 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1487)
!1501 = !DISubprogram(name: "select_on_container_copy_construction", linkageName: "_ZNSt16allocator_traitsISaIcEE37select_on_container_copy_constructionERKS0_", scope: !1480, file: !58, line: 562, type: !1502, scopeLine: 562, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1502 = !DISubroutineType(types: !1503)
!1503 = !{!1487, !1499}
!1504 = !{!1505}
!1505 = !DITemplateTypeParameter(name: "_Alloc", type: !1488)
!1506 = !DISubprogram(name: "_S_select_on_copy", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIcEcE17_S_select_on_copyERKS1_", scope: !1477, file: !51, line: 97, type: !1507, scopeLine: 97, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1507 = !DISubroutineType(types: !1508)
!1508 = !{!1488, !1509}
!1509 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1510, size: 64)
!1510 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1488)
!1511 = !DISubprogram(name: "_S_on_swap", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIcEcE10_S_on_swapERS1_S3_", scope: !1477, file: !51, line: 100, type: !1512, scopeLine: 100, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1512 = !DISubroutineType(types: !1513)
!1513 = !{null, !1514, !1514}
!1514 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1488, size: 64)
!1515 = !DISubprogram(name: "_S_propagate_on_copy_assign", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIcEcE27_S_propagate_on_copy_assignEv", scope: !1477, file: !51, line: 103, type: !158, scopeLine: 103, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1516 = !DISubprogram(name: "_S_propagate_on_move_assign", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIcEcE27_S_propagate_on_move_assignEv", scope: !1477, file: !51, line: 106, type: !158, scopeLine: 106, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1517 = !DISubprogram(name: "_S_propagate_on_swap", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIcEcE20_S_propagate_on_swapEv", scope: !1477, file: !51, line: 109, type: !158, scopeLine: 109, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1518 = !DISubprogram(name: "_S_always_equal", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIcEcE15_S_always_equalEv", scope: !1477, file: !51, line: 112, type: !158, scopeLine: 112, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1519 = !DISubprogram(name: "_S_nothrow_move", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIcEcE15_S_nothrow_moveEv", scope: !1477, file: !51, line: 115, type: !158, scopeLine: 115, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1520 = !{!1505, !1521}
!1521 = !DITemplateTypeParameter(type: !507)
!1522 = !DISubprogram(name: "_M_data", linkageName: "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7_M_dataEv", scope: !34, file: !1461, line: 234, type: !1473, scopeLine: 234, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1523 = !{!1471}
!1524 = !DILocation(line: 0, scope: !1472, inlinedAt: !1525)
!1525 = distinct !DILocation(line: 2555, column: 16, scope: !1460, inlinedAt: !1470)
!1526 = !DILocation(line: 235, column: 28, scope: !1472, inlinedAt: !1525)
!1527 = !{!1528, !1400, i64 0}
!1528 = !{!"_ZTSNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE", !1529, i64 0, !1530, i64 8, !1401, i64 16}
!1529 = !{!"_ZTSNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_Alloc_hiderE", !1400, i64 0}
!1530 = !{!"long", !1401, i64 0}
!1531 = !DILocation(line: 27, column: 3, scope: !1453)
!1532 = !DILocation(line: 28, column: 3, scope: !1453)
!1533 = distinct !DISubprogram(name: "EXPAND_STACK_SLOWPATH", linkageName: "_Z21EXPAND_STACK_SLOWPATHv", scope: !3, file: !3, line: 34, type: !1041, scopeLine: 34, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !166)
!1534 = !DILocation(line: 35, column: 42, scope: !1533)
!1535 = !{!1536, !1536, i64 0}
!1536 = !{!"int", !1401, i64 0}
!1537 = !DILocation(line: 35, column: 59, scope: !1533)
!1538 = !DILocation(line: 35, column: 3, scope: !1533)
!1539 = !DILocation(line: 36, column: 11, scope: !1533)
!1540 = !DILocation(line: 37, column: 27, scope: !1533)
!1541 = !{!1400, !1400, i64 0}
!1542 = !DILocation(line: 37, column: 34, scope: !1533)
!1543 = !DILocation(line: 37, column: 42, scope: !1533)
!1544 = !DILocation(line: 37, column: 19, scope: !1533)
!1545 = !DILocation(line: 37, column: 9, scope: !1533)
!1546 = !DILocation(line: 38, column: 1, scope: !1533)
!1547 = distinct !DISubprogram(name: "INS_FUNC", scope: !3, file: !3, line: 60, type: !11, scopeLine: 60, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1548)
!1548 = !{!1549, !1550, !1551, !1552, !1553, !1554, !1556}
!1549 = !DILocalVariable(name: "ra", arg: 1, scope: !1547, file: !3, line: 60, type: !13)
!1550 = !DILocalVariable(name: "instr", arg: 2, scope: !1547, file: !3, line: 60, type: !14)
!1551 = !DILocalVariable(name: "pc", arg: 3, scope: !1547, file: !3, line: 60, type: !15)
!1552 = !DILocalVariable(name: "frame", arg: 4, scope: !1547, file: !3, line: 60, type: !6)
!1553 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1547, file: !3, line: 60, type: !16)
!1554 = !DILocalVariable(name: "op", scope: !1555, file: !3, line: 63, type: !13)
!1555 = distinct !DILexicalBlock(scope: !1547, file: !3, line: 63, column: 3)
!1556 = !DILocalVariable(name: "op_table_arg_c", scope: !1555, file: !3, line: 63, type: !8)
!1557 = !DILocation(line: 0, scope: !1547)
!1558 = !DILocation(line: 62, column: 5, scope: !1547)
!1559 = !DILocation(line: 63, column: 3, scope: !1555)
!1560 = !DILocation(line: 0, scope: !1555)
!1561 = distinct !DISubprogram(name: "INS_KSHORT", scope: !3, file: !3, line: 67, type: !11, scopeLine: 67, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1562)
!1562 = !{!1563, !1564, !1565, !1566, !1567, !1568, !1569, !1571}
!1563 = !DILocalVariable(name: "ra", arg: 1, scope: !1561, file: !3, line: 67, type: !13)
!1564 = !DILocalVariable(name: "instr", arg: 2, scope: !1561, file: !3, line: 67, type: !14)
!1565 = !DILocalVariable(name: "pc", arg: 3, scope: !1561, file: !3, line: 67, type: !15)
!1566 = !DILocalVariable(name: "frame", arg: 4, scope: !1561, file: !3, line: 67, type: !6)
!1567 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1561, file: !3, line: 67, type: !16)
!1568 = !DILocalVariable(name: "rb", scope: !1561, file: !3, line: 69, type: !13)
!1569 = !DILocalVariable(name: "op", scope: !1570, file: !3, line: 74, type: !13)
!1570 = distinct !DILexicalBlock(scope: !1561, file: !3, line: 74, column: 3)
!1571 = !DILocalVariable(name: "op_table_arg_c", scope: !1570, file: !3, line: 74, type: !8)
!1572 = !DILocation(line: 0, scope: !1561)
!1573 = !DILocation(line: 71, column: 15, scope: !1561)
!1574 = !DILocation(line: 71, column: 3, scope: !1561)
!1575 = !DILocation(line: 71, column: 13, scope: !1561)
!1576 = !{!1530, !1530, i64 0}
!1577 = !DILocation(line: 73, column: 5, scope: !1561)
!1578 = !DILocation(line: 74, column: 3, scope: !1570)
!1579 = !DILocation(line: 0, scope: !1570)
!1580 = distinct !DISubprogram(name: "INS_JMP", scope: !3, file: !3, line: 77, type: !11, scopeLine: 77, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1581)
!1581 = !{!1582, !1583, !1584, !1585, !1586, !1587, !1589}
!1582 = !DILocalVariable(name: "ra", arg: 1, scope: !1580, file: !3, line: 77, type: !13)
!1583 = !DILocalVariable(name: "instr", arg: 2, scope: !1580, file: !3, line: 77, type: !14)
!1584 = !DILocalVariable(name: "pc", arg: 3, scope: !1580, file: !3, line: 77, type: !15)
!1585 = !DILocalVariable(name: "frame", arg: 4, scope: !1580, file: !3, line: 77, type: !6)
!1586 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1580, file: !3, line: 77, type: !16)
!1587 = !DILocalVariable(name: "op", scope: !1588, file: !3, line: 81, type: !13)
!1588 = distinct !DILexicalBlock(scope: !1580, file: !3, line: 81, column: 3)
!1589 = !DILocalVariable(name: "op_table_arg_c", scope: !1588, file: !3, line: 81, type: !8)
!1590 = !DILocation(line: 0, scope: !1580)
!1591 = !DILocation(line: 80, column: 5, scope: !1580)
!1592 = !DILocation(line: 81, column: 3, scope: !1588)
!1593 = !DILocation(line: 0, scope: !1588)
!1594 = distinct !DISubprogram(name: "INS_RET1", scope: !3, file: !3, line: 84, type: !11, scopeLine: 84, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1595)
!1595 = !{!1596, !1597, !1598, !1599, !1600, !1601, !1603}
!1596 = !DILocalVariable(name: "ra", arg: 1, scope: !1594, file: !3, line: 84, type: !13)
!1597 = !DILocalVariable(name: "instr", arg: 2, scope: !1594, file: !3, line: 84, type: !14)
!1598 = !DILocalVariable(name: "pc", arg: 3, scope: !1594, file: !3, line: 84, type: !15)
!1599 = !DILocalVariable(name: "frame", arg: 4, scope: !1594, file: !3, line: 84, type: !6)
!1600 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1594, file: !3, line: 84, type: !16)
!1601 = !DILocalVariable(name: "op", scope: !1602, file: !3, line: 91, type: !13)
!1602 = distinct !DILexicalBlock(scope: !1594, file: !3, line: 91, column: 3)
!1603 = !DILocalVariable(name: "op_table_arg_c", scope: !1602, file: !3, line: 91, type: !8)
!1604 = !DILocation(line: 0, scope: !1594)
!1605 = !DILocation(line: 87, column: 24, scope: !1594)
!1606 = !DILocation(line: 87, column: 8, scope: !1594)
!1607 = !DILocation(line: 88, column: 15, scope: !1594)
!1608 = !DILocation(line: 88, column: 13, scope: !1594)
!1609 = !DILocation(line: 89, column: 13, scope: !1594)
!1610 = !DILocation(line: 89, column: 30, scope: !1594)
!1611 = !DILocation(line: 89, column: 9, scope: !1594)
!1612 = !DILocation(line: 91, column: 3, scope: !1602)
!1613 = !DILocation(line: 0, scope: !1602)
!1614 = distinct !DISubprogram(name: "INS_HALT", scope: !3, file: !3, line: 94, type: !11, scopeLine: 94, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1615)
!1615 = !{!1616, !1617, !1618, !1619, !1620}
!1616 = !DILocalVariable(name: "ra", arg: 1, scope: !1614, file: !3, line: 94, type: !13)
!1617 = !DILocalVariable(name: "instr", arg: 2, scope: !1614, file: !3, line: 94, type: !14)
!1618 = !DILocalVariable(name: "pc", arg: 3, scope: !1614, file: !3, line: 94, type: !15)
!1619 = !DILocalVariable(name: "frame", arg: 4, scope: !1614, file: !3, line: 94, type: !6)
!1620 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1614, file: !3, line: 94, type: !16)
!1621 = !DILocation(line: 0, scope: !1614)
!1622 = !DILocation(line: 97, column: 26, scope: !1614)
!1623 = !DILocation(line: 97, column: 36, scope: !1614)
!1624 = !DILocation(line: 97, column: 3, scope: !1614)
!1625 = !DILocation(line: 98, column: 3, scope: !1614)
!1626 = distinct !DISubprogram(name: "INS_ISGE", scope: !3, file: !3, line: 101, type: !11, scopeLine: 101, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1627)
!1627 = !{!1628, !1629, !1630, !1631, !1632, !1633, !1634, !1635, !1636, !1638}
!1628 = !DILocalVariable(name: "ra", arg: 1, scope: !1626, file: !3, line: 101, type: !13)
!1629 = !DILocalVariable(name: "instr", arg: 2, scope: !1626, file: !3, line: 101, type: !14)
!1630 = !DILocalVariable(name: "pc", arg: 3, scope: !1626, file: !3, line: 101, type: !15)
!1631 = !DILocalVariable(name: "frame", arg: 4, scope: !1626, file: !3, line: 101, type: !6)
!1632 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1626, file: !3, line: 101, type: !16)
!1633 = !DILocalVariable(name: "rb", scope: !1626, file: !3, line: 103, type: !13)
!1634 = !DILocalVariable(name: "fa", scope: !1626, file: !3, line: 105, type: !7)
!1635 = !DILocalVariable(name: "fb", scope: !1626, file: !3, line: 106, type: !7)
!1636 = !DILocalVariable(name: "op", scope: !1637, file: !3, line: 116, type: !13)
!1637 = distinct !DILexicalBlock(scope: !1626, file: !3, line: 116, column: 3)
!1638 = !DILocalVariable(name: "op_table_arg_c", scope: !1637, file: !3, line: 116, type: !8)
!1639 = !DILocation(line: 0, scope: !1626)
!1640 = !DILocation(line: 105, column: 13, scope: !1626)
!1641 = !DILocation(line: 106, column: 13, scope: !1626)
!1642 = !DILocation(line: 107, column: 7, scope: !1643)
!1643 = distinct !DILexicalBlock(scope: !1626, file: !3, line: 107, column: 7)
!1644 = !DILocation(line: 107, column: 7, scope: !1626)
!1645 = !{!"branch_weights", i32 2000, i32 1}
!1646 = !DILocation(line: 108, column: 5, scope: !1647)
!1647 = distinct !DILexicalBlock(scope: !1643, file: !3, line: 107, column: 32)
!1648 = !DILocation(line: 109, column: 3, scope: !1647)
!1649 = !DILocation(line: 110, column: 10, scope: !1650)
!1650 = distinct !DILexicalBlock(scope: !1626, file: !3, line: 110, column: 7)
!1651 = !DILocation(line: 110, column: 7, scope: !1626)
!1652 = !DILocation(line: 116, column: 3, scope: !1637)
!1653 = !DILocation(line: 0, scope: !1637)
!1654 = distinct !DISubprogram(name: "INS_SUBVN", scope: !3, file: !3, line: 119, type: !11, scopeLine: 119, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1655)
!1655 = !{!1656, !1657, !1658, !1659, !1660, !1661, !1662, !1663, !1664, !1666}
!1656 = !DILocalVariable(name: "ra", arg: 1, scope: !1654, file: !3, line: 119, type: !13)
!1657 = !DILocalVariable(name: "instr", arg: 2, scope: !1654, file: !3, line: 119, type: !14)
!1658 = !DILocalVariable(name: "pc", arg: 3, scope: !1654, file: !3, line: 119, type: !15)
!1659 = !DILocalVariable(name: "frame", arg: 4, scope: !1654, file: !3, line: 119, type: !6)
!1660 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1654, file: !3, line: 119, type: !16)
!1661 = !DILocalVariable(name: "rb", scope: !1654, file: !3, line: 121, type: !13)
!1662 = !DILocalVariable(name: "rc", scope: !1654, file: !3, line: 122, type: !13)
!1663 = !DILocalVariable(name: "fb", scope: !1654, file: !3, line: 124, type: !7)
!1664 = !DILocalVariable(name: "op", scope: !1665, file: !3, line: 134, type: !13)
!1665 = distinct !DILexicalBlock(scope: !1654, file: !3, line: 134, column: 3)
!1666 = !DILocalVariable(name: "op_table_arg_c", scope: !1665, file: !3, line: 134, type: !8)
!1667 = !DILocation(line: 0, scope: !1654)
!1668 = !DILocation(line: 124, column: 13, scope: !1654)
!1669 = !DILocation(line: 125, column: 7, scope: !1670)
!1670 = distinct !DILexicalBlock(scope: !1654, file: !3, line: 125, column: 7)
!1671 = !DILocation(line: 125, column: 7, scope: !1654)
!1672 = !DILocation(line: 126, column: 5, scope: !1673)
!1673 = distinct !DILexicalBlock(scope: !1670, file: !3, line: 125, column: 25)
!1674 = !DILocation(line: 127, column: 3, scope: !1673)
!1675 = !DILocation(line: 128, column: 7, scope: !1676)
!1676 = distinct !DILexicalBlock(scope: !1654, file: !3, line: 128, column: 7)
!1677 = !DILocation(line: 128, column: 7, scope: !1654)
!1678 = !{!"branch_weights", i32 1, i32 2000}
!1679 = !DILocation(line: 130, column: 5, scope: !1680)
!1680 = distinct !DILexicalBlock(scope: !1676, file: !3, line: 129, column: 61)
!1681 = !DILocation(line: 131, column: 3, scope: !1680)
!1682 = !DILocation(line: 132, column: 5, scope: !1654)
!1683 = !DILocation(line: 134, column: 3, scope: !1665)
!1684 = !DILocation(line: 0, scope: !1665)
!1685 = distinct !DISubprogram(name: "INS_ADDVV", scope: !3, file: !3, line: 137, type: !11, scopeLine: 137, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1686)
!1686 = !{!1687, !1688, !1689, !1690, !1691, !1692, !1693, !1694, !1695, !1696, !1698}
!1687 = !DILocalVariable(name: "ra", arg: 1, scope: !1685, file: !3, line: 137, type: !13)
!1688 = !DILocalVariable(name: "instr", arg: 2, scope: !1685, file: !3, line: 137, type: !14)
!1689 = !DILocalVariable(name: "pc", arg: 3, scope: !1685, file: !3, line: 137, type: !15)
!1690 = !DILocalVariable(name: "frame", arg: 4, scope: !1685, file: !3, line: 137, type: !6)
!1691 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1685, file: !3, line: 137, type: !16)
!1692 = !DILocalVariable(name: "rb", scope: !1685, file: !3, line: 139, type: !13)
!1693 = !DILocalVariable(name: "rc", scope: !1685, file: !3, line: 140, type: !13)
!1694 = !DILocalVariable(name: "fb", scope: !1685, file: !3, line: 142, type: !7)
!1695 = !DILocalVariable(name: "fc", scope: !1685, file: !3, line: 143, type: !7)
!1696 = !DILocalVariable(name: "op", scope: !1697, file: !3, line: 153, type: !13)
!1697 = distinct !DILexicalBlock(scope: !1685, file: !3, line: 153, column: 3)
!1698 = !DILocalVariable(name: "op_table_arg_c", scope: !1697, file: !3, line: 153, type: !8)
!1699 = !DILocation(line: 0, scope: !1685)
!1700 = !DILocation(line: 140, column: 29, scope: !1685)
!1701 = !DILocation(line: 142, column: 13, scope: !1685)
!1702 = !DILocation(line: 143, column: 13, scope: !1685)
!1703 = !DILocation(line: 144, column: 7, scope: !1704)
!1704 = distinct !DILexicalBlock(scope: !1685, file: !3, line: 144, column: 7)
!1705 = !DILocation(line: 144, column: 7, scope: !1685)
!1706 = !DILocation(line: 145, column: 17, scope: !1707)
!1707 = distinct !DILexicalBlock(scope: !1704, file: !3, line: 144, column: 32)
!1708 = !DILocation(line: 145, column: 5, scope: !1707)
!1709 = !DILocation(line: 145, column: 15, scope: !1707)
!1710 = !DILocation(line: 146, column: 3, scope: !1707)
!1711 = !DILocation(line: 147, column: 9, scope: !1712)
!1712 = distinct !DILexicalBlock(scope: !1713, file: !3, line: 147, column: 9)
!1713 = distinct !DILexicalBlock(scope: !1704, file: !3, line: 146, column: 10)
!1714 = !DILocation(line: 147, column: 9, scope: !1713)
!1715 = !DILocation(line: 148, column: 19, scope: !1716)
!1716 = distinct !DILexicalBlock(scope: !1712, file: !3, line: 147, column: 63)
!1717 = !DILocation(line: 148, column: 17, scope: !1716)
!1718 = !DILocation(line: 149, column: 5, scope: !1716)
!1719 = !DILocation(line: 151, column: 5, scope: !1685)
!1720 = !DILocation(line: 153, column: 3, scope: !1697)
!1721 = !DILocation(line: 0, scope: !1697)
!1722 = distinct !DISubprogram(name: "INS_GGET", scope: !3, file: !3, line: 156, type: !11, scopeLine: 156, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1723)
!1723 = !{!1724, !1725, !1726, !1727, !1728, !1729, !1730, !1731, !1732, !1734}
!1724 = !DILocalVariable(name: "ra", arg: 1, scope: !1722, file: !3, line: 156, type: !13)
!1725 = !DILocalVariable(name: "instr", arg: 2, scope: !1722, file: !3, line: 156, type: !14)
!1726 = !DILocalVariable(name: "pc", arg: 3, scope: !1722, file: !3, line: 156, type: !15)
!1727 = !DILocalVariable(name: "frame", arg: 4, scope: !1722, file: !3, line: 156, type: !6)
!1728 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1722, file: !3, line: 156, type: !16)
!1729 = !DILocalVariable(name: "rb", scope: !1722, file: !3, line: 158, type: !13)
!1730 = !DILocalVariable(name: "func", scope: !1722, file: !3, line: 160, type: !18)
!1731 = !DILocalVariable(name: "gp", scope: !1722, file: !3, line: 161, type: !28)
!1732 = !DILocalVariable(name: "op", scope: !1733, file: !3, line: 168, type: !13)
!1733 = distinct !DILexicalBlock(scope: !1722, file: !3, line: 168, column: 3)
!1734 = !DILocalVariable(name: "op_table_arg_c", scope: !1733, file: !3, line: 168, type: !8)
!1735 = !DILocation(line: 0, scope: !1722)
!1736 = !DILocation(line: 160, column: 29, scope: !1722)
!1737 = !DILocation(line: 160, column: 39, scope: !1722)
!1738 = !DILocation(line: 160, column: 18, scope: !1722)
!1739 = !DILocation(line: 161, column: 39, scope: !1722)
!1740 = !DILocalVariable(name: "this", arg: 1, scope: !1741, type: !1799, flags: DIFlagArtificial | DIFlagObjectPointer)
!1741 = distinct !DISubprogram(name: "operator[]", linkageName: "_ZNSt6vectorImSaImEEixEm", scope: !27, file: !24, line: 1121, type: !1742, scopeLine: 1122, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !1796, retainedNodes: !1797)
!1742 = !DISubroutineType(types: !1743)
!1743 = !{!1744, !1795, !324}
!1744 = !DIDerivedType(tag: DW_TAG_typedef, name: "reference", scope: !27, file: !24, line: 451, baseType: !1745)
!1745 = !DIDerivedType(tag: DW_TAG_typedef, name: "reference", scope: !1746, file: !51, line: 62, baseType: !1792)
!1746 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "__alloc_traits<std::allocator<unsigned long>, unsigned long>", scope: !54, file: !51, line: 48, size: 8, flags: DIFlagTypePassByValue, elements: !1747, templateParams: !1790, identifier: "_ZTSN9__gnu_cxx14__alloc_traitsISaImEmEE")
!1747 = !{!1748, !1776, !1781, !1785, !1786, !1787, !1788, !1789}
!1748 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !1746, baseType: !1749, extraData: i32 0)
!1749 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "allocator_traits<std::allocator<unsigned long> >", scope: !25, file: !58, line: 411, size: 8, flags: DIFlagTypePassByValue, elements: !1750, templateParams: !1774, identifier: "_ZTSSt16allocator_traitsISaImEE")
!1750 = !{!1751, !1759, !1762, !1765, !1771}
!1751 = !DISubprogram(name: "allocate", linkageName: "_ZNSt16allocator_traitsISaImEE8allocateERS0_m", scope: !1749, file: !58, line: 463, type: !1752, scopeLine: 463, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1752 = !DISubroutineType(types: !1753)
!1753 = !{!1754, !1756, !132}
!1754 = !DIDerivedType(tag: DW_TAG_typedef, name: "pointer", scope: !1749, file: !58, line: 420, baseType: !1755)
!1755 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !38, size: 64)
!1756 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1757, size: 64)
!1757 = !DIDerivedType(tag: DW_TAG_typedef, name: "allocator_type", scope: !1749, file: !58, line: 414, baseType: !1758)
!1758 = !DICompositeType(tag: DW_TAG_class_type, name: "allocator<unsigned long>", scope: !25, file: !68, line: 124, size: 8, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSSaImE")
!1759 = !DISubprogram(name: "allocate", linkageName: "_ZNSt16allocator_traitsISaImEE8allocateERS0_mPKv", scope: !1749, file: !58, line: 477, type: !1760, scopeLine: 477, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1760 = !DISubroutineType(types: !1761)
!1761 = !{!1754, !1756, !132, !136}
!1762 = !DISubprogram(name: "deallocate", linkageName: "_ZNSt16allocator_traitsISaImEE10deallocateERS0_Pmm", scope: !1749, file: !58, line: 495, type: !1763, scopeLine: 495, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1763 = !DISubroutineType(types: !1764)
!1764 = !{null, !1756, !1754, !132}
!1765 = !DISubprogram(name: "max_size", linkageName: "_ZNSt16allocator_traitsISaImEE8max_sizeERKS0_", scope: !1749, file: !58, line: 547, type: !1766, scopeLine: 547, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1766 = !DISubroutineType(types: !1767)
!1767 = !{!1768, !1769}
!1768 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_type", scope: !1749, file: !58, line: 435, baseType: !105)
!1769 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1770, size: 64)
!1770 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1757)
!1771 = !DISubprogram(name: "select_on_container_copy_construction", linkageName: "_ZNSt16allocator_traitsISaImEE37select_on_container_copy_constructionERKS0_", scope: !1749, file: !58, line: 562, type: !1772, scopeLine: 562, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1772 = !DISubroutineType(types: !1773)
!1773 = !{!1757, !1769}
!1774 = !{!1775}
!1775 = !DITemplateTypeParameter(name: "_Alloc", type: !1758)
!1776 = !DISubprogram(name: "_S_select_on_copy", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaImEmE17_S_select_on_copyERKS1_", scope: !1746, file: !51, line: 97, type: !1777, scopeLine: 97, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1777 = !DISubroutineType(types: !1778)
!1778 = !{!1758, !1779}
!1779 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1780, size: 64)
!1780 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1758)
!1781 = !DISubprogram(name: "_S_on_swap", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaImEmE10_S_on_swapERS1_S3_", scope: !1746, file: !51, line: 100, type: !1782, scopeLine: 100, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1782 = !DISubroutineType(types: !1783)
!1783 = !{null, !1784, !1784}
!1784 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1758, size: 64)
!1785 = !DISubprogram(name: "_S_propagate_on_copy_assign", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaImEmE27_S_propagate_on_copy_assignEv", scope: !1746, file: !51, line: 103, type: !158, scopeLine: 103, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1786 = !DISubprogram(name: "_S_propagate_on_move_assign", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaImEmE27_S_propagate_on_move_assignEv", scope: !1746, file: !51, line: 106, type: !158, scopeLine: 106, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1787 = !DISubprogram(name: "_S_propagate_on_swap", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaImEmE20_S_propagate_on_swapEv", scope: !1746, file: !51, line: 109, type: !158, scopeLine: 109, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1788 = !DISubprogram(name: "_S_always_equal", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaImEmE15_S_always_equalEv", scope: !1746, file: !51, line: 112, type: !158, scopeLine: 112, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1789 = !DISubprogram(name: "_S_nothrow_move", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaImEmE15_S_nothrow_moveEv", scope: !1746, file: !51, line: 115, type: !158, scopeLine: 115, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1790 = !{!1775, !1791}
!1791 = !DITemplateTypeParameter(type: !38)
!1792 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1793, size: 64)
!1793 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_type", scope: !1746, file: !51, line: 56, baseType: !1794)
!1794 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_type", scope: !1749, file: !58, line: 417, baseType: !38)
!1795 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1796 = !DISubprogram(name: "operator[]", linkageName: "_ZNSt6vectorImSaImEEixEm", scope: !27, file: !24, line: 1121, type: !1742, scopeLine: 1121, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1797 = !{!1740, !1798}
!1798 = !DILocalVariable(name: "__n", arg: 2, scope: !1741, file: !24, line: 1121, type: !324)
!1799 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 64)
!1800 = !DILocation(line: 0, scope: !1741, inlinedAt: !1801)
!1801 = distinct !DILocation(line: 161, column: 26, scope: !1722)
!1802 = !DILocation(line: 1124, column: 25, scope: !1741, inlinedAt: !1801)
!1803 = !{!1804, !1400, i64 0}
!1804 = !{!"_ZTSNSt12_Vector_baseImSaImEE17_Vector_impl_dataE", !1400, i64 0, !1400, i64 8, !1400, i64 16}
!1805 = !DILocation(line: 1124, column: 34, scope: !1741, inlinedAt: !1801)
!1806 = !DILocation(line: 161, column: 26, scope: !1722)
!1807 = !DILocation(line: 161, column: 16, scope: !1722)
!1808 = !DILocation(line: 162, column: 7, scope: !1809)
!1809 = distinct !DILexicalBlock(scope: !1722, file: !3, line: 162, column: 7)
!1810 = !{!1811, !1530, i64 32}
!1811 = !{!"_ZTS6symbol", !1528, i64 0, !1530, i64 32}
!1812 = !DILocation(line: 162, column: 7, scope: !1722)
!1813 = !DILocation(line: 163, column: 5, scope: !1814)
!1814 = distinct !DILexicalBlock(scope: !1809, file: !3, line: 162, column: 39)
!1815 = !DILocation(line: 164, column: 3, scope: !1814)
!1816 = !DILocation(line: 165, column: 3, scope: !1722)
!1817 = !DILocation(line: 165, column: 13, scope: !1722)
!1818 = !DILocation(line: 167, column: 5, scope: !1722)
!1819 = !DILocation(line: 168, column: 3, scope: !1733)
!1820 = !DILocation(line: 0, scope: !1733)
!1821 = distinct !DISubprogram(name: "INS_GSET", scope: !3, file: !3, line: 171, type: !11, scopeLine: 171, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1822)
!1822 = !{!1823, !1824, !1825, !1826, !1827, !1828, !1829, !1830, !1831, !1833}
!1823 = !DILocalVariable(name: "ra", arg: 1, scope: !1821, file: !3, line: 171, type: !13)
!1824 = !DILocalVariable(name: "instr", arg: 2, scope: !1821, file: !3, line: 171, type: !14)
!1825 = !DILocalVariable(name: "pc", arg: 3, scope: !1821, file: !3, line: 171, type: !15)
!1826 = !DILocalVariable(name: "frame", arg: 4, scope: !1821, file: !3, line: 171, type: !6)
!1827 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1821, file: !3, line: 171, type: !16)
!1828 = !DILocalVariable(name: "rb", scope: !1821, file: !3, line: 173, type: !13)
!1829 = !DILocalVariable(name: "func", scope: !1821, file: !3, line: 175, type: !18)
!1830 = !DILocalVariable(name: "gp", scope: !1821, file: !3, line: 176, type: !28)
!1831 = !DILocalVariable(name: "op", scope: !1832, file: !3, line: 180, type: !13)
!1832 = distinct !DILexicalBlock(scope: !1821, file: !3, line: 180, column: 3)
!1833 = !DILocalVariable(name: "op_table_arg_c", scope: !1832, file: !3, line: 180, type: !8)
!1834 = !DILocation(line: 0, scope: !1821)
!1835 = !DILocation(line: 175, column: 29, scope: !1821)
!1836 = !DILocation(line: 175, column: 39, scope: !1821)
!1837 = !DILocation(line: 175, column: 18, scope: !1821)
!1838 = !DILocation(line: 176, column: 39, scope: !1821)
!1839 = !DILocation(line: 0, scope: !1741, inlinedAt: !1840)
!1840 = distinct !DILocation(line: 176, column: 26, scope: !1821)
!1841 = !DILocation(line: 1124, column: 25, scope: !1741, inlinedAt: !1840)
!1842 = !DILocation(line: 1124, column: 34, scope: !1741, inlinedAt: !1840)
!1843 = !DILocation(line: 176, column: 26, scope: !1821)
!1844 = !DILocation(line: 176, column: 16, scope: !1821)
!1845 = !DILocation(line: 177, column: 13, scope: !1821)
!1846 = !DILocation(line: 177, column: 7, scope: !1821)
!1847 = !DILocation(line: 177, column: 11, scope: !1821)
!1848 = !DILocation(line: 179, column: 5, scope: !1821)
!1849 = !DILocation(line: 180, column: 3, scope: !1832)
!1850 = !DILocation(line: 0, scope: !1832)
!1851 = distinct !DISubprogram(name: "INS_KFUNC", scope: !3, file: !3, line: 183, type: !11, scopeLine: 183, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1852)
!1852 = !{!1853, !1854, !1855, !1856, !1857, !1858, !1859, !1861}
!1853 = !DILocalVariable(name: "ra", arg: 1, scope: !1851, file: !3, line: 183, type: !13)
!1854 = !DILocalVariable(name: "instr", arg: 2, scope: !1851, file: !3, line: 183, type: !14)
!1855 = !DILocalVariable(name: "pc", arg: 3, scope: !1851, file: !3, line: 183, type: !15)
!1856 = !DILocalVariable(name: "frame", arg: 4, scope: !1851, file: !3, line: 183, type: !6)
!1857 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1851, file: !3, line: 183, type: !16)
!1858 = !DILocalVariable(name: "rb", scope: !1851, file: !3, line: 185, type: !13)
!1859 = !DILocalVariable(name: "op", scope: !1860, file: !3, line: 190, type: !13)
!1860 = distinct !DILexicalBlock(scope: !1851, file: !3, line: 190, column: 3)
!1861 = !DILocalVariable(name: "op_table_arg_c", scope: !1860, file: !3, line: 190, type: !8)
!1862 = !DILocation(line: 0, scope: !1851)
!1863 = !DILocation(line: 187, column: 28, scope: !1851)
!1864 = !DILocalVariable(name: "this", arg: 1, scope: !1865, type: !1387, flags: DIFlagArtificial | DIFlagObjectPointer)
!1865 = distinct !DISubprogram(name: "operator[]", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EEixEm", scope: !40, file: !24, line: 1121, type: !426, scopeLine: 1122, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !425, retainedNodes: !1866)
!1866 = !{!1864, !1867}
!1867 = !DILocalVariable(name: "__n", arg: 2, scope: !1865, file: !24, line: 1121, type: !324)
!1868 = !DILocation(line: 0, scope: !1865, inlinedAt: !1869)
!1869 = distinct !DILocation(line: 187, column: 22, scope: !1851)
!1870 = !DILocation(line: 1124, column: 25, scope: !1865, inlinedAt: !1869)
!1871 = !DILocation(line: 1124, column: 34, scope: !1865, inlinedAt: !1869)
!1872 = !DILocation(line: 187, column: 22, scope: !1851)
!1873 = !DILocation(line: 187, column: 16, scope: !1851)
!1874 = !DILocation(line: 187, column: 33, scope: !1851)
!1875 = !DILocation(line: 187, column: 3, scope: !1851)
!1876 = !DILocation(line: 187, column: 13, scope: !1851)
!1877 = !DILocation(line: 189, column: 5, scope: !1851)
!1878 = !DILocation(line: 190, column: 3, scope: !1860)
!1879 = !DILocation(line: 0, scope: !1860)
!1880 = distinct !DISubprogram(name: "INS_CALLT", scope: !3, file: !3, line: 193, type: !11, scopeLine: 193, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1881)
!1881 = !{!1882, !1883, !1884, !1885, !1886, !1887, !1888, !1889, !1890, !1891, !1892, !1894, !1897, !1899}
!1882 = !DILocalVariable(name: "ra", arg: 1, scope: !1880, file: !3, line: 193, type: !13)
!1883 = !DILocalVariable(name: "instr", arg: 2, scope: !1880, file: !3, line: 193, type: !14)
!1884 = !DILocalVariable(name: "pc", arg: 3, scope: !1880, file: !3, line: 193, type: !15)
!1885 = !DILocalVariable(name: "frame", arg: 4, scope: !1880, file: !3, line: 193, type: !6)
!1886 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !1880, file: !3, line: 193, type: !16)
!1887 = !DILocalVariable(name: "rb", scope: !1880, file: !3, line: 195, type: !13)
!1888 = !DILocalVariable(name: "v", scope: !1880, file: !3, line: 203, type: !7)
!1889 = !DILocalVariable(name: "func", scope: !1880, file: !3, line: 207, type: !18)
!1890 = !DILocalVariable(name: "start", scope: !1880, file: !3, line: 210, type: !7)
!1891 = !DILocalVariable(name: "cnt", scope: !1880, file: !3, line: 211, type: !547)
!1892 = !DILocalVariable(name: "i", scope: !1893, file: !3, line: 212, type: !547)
!1893 = distinct !DILexicalBlock(scope: !1880, file: !3, line: 212, column: 3)
!1894 = !DILocalVariable(name: "pos", scope: !1895, file: !3, line: 216, type: !7)
!1895 = distinct !DILexicalBlock(scope: !1896, file: !3, line: 215, column: 44)
!1896 = distinct !DILexicalBlock(scope: !1880, file: !3, line: 215, column: 7)
!1897 = !DILocalVariable(name: "op", scope: !1898, file: !3, line: 222, type: !13)
!1898 = distinct !DILexicalBlock(scope: !1880, file: !3, line: 222, column: 3)
!1899 = !DILocalVariable(name: "op_table_arg_c", scope: !1898, file: !3, line: 222, type: !8)
!1900 = !DILocation(line: 0, scope: !1880)
!1901 = !DILocation(line: 197, column: 7, scope: !1902)
!1902 = distinct !DILexicalBlock(scope: !1880, file: !3, line: 197, column: 7)
!1903 = !{!1401, !1401, i64 0}
!1904 = !DILocation(line: 197, column: 7, scope: !1880)
!1905 = !DILocation(line: 202, column: 3, scope: !1906)
!1906 = distinct !DILexicalBlock(scope: !1902, file: !3, line: 198, column: 27)
!1907 = !DILocation(line: 0, scope: !1902)
!1908 = !DILocation(line: 203, column: 12, scope: !1880)
!1909 = !DILocation(line: 204, column: 7, scope: !1910)
!1910 = distinct !DILexicalBlock(scope: !1880, file: !3, line: 204, column: 7)
!1911 = !DILocation(line: 204, column: 7, scope: !1880)
!1912 = !DILocation(line: 205, column: 5, scope: !1913)
!1913 = distinct !DILexicalBlock(scope: !1910, file: !3, line: 204, column: 33)
!1914 = !DILocation(line: 206, column: 3, scope: !1913)
!1915 = !DILocation(line: 207, column: 31, scope: !1880)
!1916 = !DILocation(line: 207, column: 18, scope: !1880)
!1917 = !DILocalVariable(name: "this", arg: 1, scope: !1918, type: !1975, flags: DIFlagArtificial | DIFlagObjectPointer)
!1918 = distinct !DISubprogram(name: "operator[]", linkageName: "_ZNSt6vectorIjSaIjEEixEm", scope: !23, file: !24, line: 1121, type: !1919, scopeLine: 1122, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !1972, retainedNodes: !1973)
!1919 = !DISubroutineType(types: !1920)
!1920 = !{!1921, !1971, !324}
!1921 = !DIDerivedType(tag: DW_TAG_typedef, name: "reference", scope: !23, file: !24, line: 451, baseType: !1922)
!1922 = !DIDerivedType(tag: DW_TAG_typedef, name: "reference", scope: !1923, file: !51, line: 62, baseType: !1968)
!1923 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "__alloc_traits<std::allocator<unsigned int>, unsigned int>", scope: !54, file: !51, line: 48, size: 8, flags: DIFlagTypePassByValue, elements: !1924, templateParams: !1966, identifier: "_ZTSN9__gnu_cxx14__alloc_traitsISaIjEjEE")
!1924 = !{!1925, !1952, !1957, !1961, !1962, !1963, !1964, !1965}
!1925 = !DIDerivedType(tag: DW_TAG_inheritance, scope: !1923, baseType: !1926, extraData: i32 0)
!1926 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "allocator_traits<std::allocator<unsigned int> >", scope: !25, file: !58, line: 411, size: 8, flags: DIFlagTypePassByValue, elements: !1927, templateParams: !1950, identifier: "_ZTSSt16allocator_traitsISaIjEE")
!1927 = !{!1928, !1935, !1938, !1941, !1947}
!1928 = !DISubprogram(name: "allocate", linkageName: "_ZNSt16allocator_traitsISaIjEE8allocateERS0_m", scope: !1926, file: !58, line: 463, type: !1929, scopeLine: 463, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1929 = !DISubroutineType(types: !1930)
!1930 = !{!1931, !1932, !132}
!1931 = !DIDerivedType(tag: DW_TAG_typedef, name: "pointer", scope: !1926, file: !58, line: 420, baseType: !15)
!1932 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1933, size: 64)
!1933 = !DIDerivedType(tag: DW_TAG_typedef, name: "allocator_type", scope: !1926, file: !58, line: 414, baseType: !1934)
!1934 = !DICompositeType(tag: DW_TAG_class_type, name: "allocator<unsigned int>", scope: !25, file: !68, line: 124, size: 8, flags: DIFlagFwdDecl | DIFlagNonTrivial, identifier: "_ZTSSaIjE")
!1935 = !DISubprogram(name: "allocate", linkageName: "_ZNSt16allocator_traitsISaIjEE8allocateERS0_mPKv", scope: !1926, file: !58, line: 477, type: !1936, scopeLine: 477, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1936 = !DISubroutineType(types: !1937)
!1937 = !{!1931, !1932, !132, !136}
!1938 = !DISubprogram(name: "deallocate", linkageName: "_ZNSt16allocator_traitsISaIjEE10deallocateERS0_Pjm", scope: !1926, file: !58, line: 495, type: !1939, scopeLine: 495, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1939 = !DISubroutineType(types: !1940)
!1940 = !{null, !1932, !1931, !132}
!1941 = !DISubprogram(name: "max_size", linkageName: "_ZNSt16allocator_traitsISaIjEE8max_sizeERKS0_", scope: !1926, file: !58, line: 547, type: !1942, scopeLine: 547, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1942 = !DISubroutineType(types: !1943)
!1943 = !{!1944, !1945}
!1944 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_type", scope: !1926, file: !58, line: 435, baseType: !105)
!1945 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1946, size: 64)
!1946 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1933)
!1947 = !DISubprogram(name: "select_on_container_copy_construction", linkageName: "_ZNSt16allocator_traitsISaIjEE37select_on_container_copy_constructionERKS0_", scope: !1926, file: !58, line: 562, type: !1948, scopeLine: 562, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1948 = !DISubroutineType(types: !1949)
!1949 = !{!1933, !1945}
!1950 = !{!1951}
!1951 = !DITemplateTypeParameter(name: "_Alloc", type: !1934)
!1952 = !DISubprogram(name: "_S_select_on_copy", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIjEjE17_S_select_on_copyERKS1_", scope: !1923, file: !51, line: 97, type: !1953, scopeLine: 97, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1953 = !DISubroutineType(types: !1954)
!1954 = !{!1934, !1955}
!1955 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1956, size: 64)
!1956 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !1934)
!1957 = !DISubprogram(name: "_S_on_swap", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIjEjE10_S_on_swapERS1_S3_", scope: !1923, file: !51, line: 100, type: !1958, scopeLine: 100, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1958 = !DISubroutineType(types: !1959)
!1959 = !{null, !1960, !1960}
!1960 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1934, size: 64)
!1961 = !DISubprogram(name: "_S_propagate_on_copy_assign", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIjEjE27_S_propagate_on_copy_assignEv", scope: !1923, file: !51, line: 103, type: !158, scopeLine: 103, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1962 = !DISubprogram(name: "_S_propagate_on_move_assign", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIjEjE27_S_propagate_on_move_assignEv", scope: !1923, file: !51, line: 106, type: !158, scopeLine: 106, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1963 = !DISubprogram(name: "_S_propagate_on_swap", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIjEjE20_S_propagate_on_swapEv", scope: !1923, file: !51, line: 109, type: !158, scopeLine: 109, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1964 = !DISubprogram(name: "_S_always_equal", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIjEjE15_S_always_equalEv", scope: !1923, file: !51, line: 112, type: !158, scopeLine: 112, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1965 = !DISubprogram(name: "_S_nothrow_move", linkageName: "_ZN9__gnu_cxx14__alloc_traitsISaIjEjE15_S_nothrow_moveEv", scope: !1923, file: !51, line: 115, type: !158, scopeLine: 115, flags: DIFlagPrototyped | DIFlagStaticMember, spFlags: DISPFlagOptimized)
!1966 = !{!1951, !1967}
!1967 = !DITemplateTypeParameter(type: !14)
!1968 = !DIDerivedType(tag: DW_TAG_reference_type, baseType: !1969, size: 64)
!1969 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_type", scope: !1923, file: !51, line: 56, baseType: !1970)
!1970 = !DIDerivedType(tag: DW_TAG_typedef, name: "value_type", scope: !1926, file: !58, line: 417, baseType: !14)
!1971 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !23, size: 64, flags: DIFlagArtificial | DIFlagObjectPointer)
!1972 = !DISubprogram(name: "operator[]", linkageName: "_ZNSt6vectorIjSaIjEEixEm", scope: !23, file: !24, line: 1121, type: !1919, scopeLine: 1121, flags: DIFlagPublic | DIFlagPrototyped, spFlags: DISPFlagOptimized)
!1973 = !{!1917, !1974}
!1974 = !DILocalVariable(name: "__n", arg: 2, scope: !1918, file: !24, line: 1121, type: !324)
!1975 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !23, size: 64)
!1976 = !DILocation(line: 0, scope: !1918, inlinedAt: !1977)
!1977 = distinct !DILocation(line: 208, column: 9, scope: !1880)
!1978 = !DILocation(line: 1124, column: 25, scope: !1918, inlinedAt: !1977)
!1979 = !{!1980, !1400, i64 0}
!1980 = !{!"_ZTSNSt12_Vector_baseIjSaIjEE17_Vector_impl_dataE", !1400, i64 0, !1400, i64 8, !1400, i64 16}
!1981 = !DILocation(line: 209, column: 3, scope: !1880)
!1982 = !DILocation(line: 209, column: 13, scope: !1880)
!1983 = !DILocation(line: 210, column: 19, scope: !1880)
!1984 = !DILocation(line: 211, column: 14, scope: !1880)
!1985 = !DILocation(line: 0, scope: !1893)
!1986 = !DILocation(line: 212, column: 22, scope: !1987)
!1987 = distinct !DILexicalBlock(scope: !1893, file: !3, line: 212, column: 3)
!1988 = !DILocation(line: 212, column: 3, scope: !1893)
!1989 = !DILocation(line: 211, column: 17, scope: !1880)
!1990 = !DILocation(line: 212, column: 30, scope: !1987)
!1991 = !DILocation(line: 213, column: 16, scope: !1992)
!1992 = distinct !DILexicalBlock(scope: !1987, file: !3, line: 212, column: 34)
!1993 = !{!1994}
!1994 = distinct !{!1994, !1995}
!1995 = distinct !{!1995, !"LVerDomain"}
!1996 = !DILocation(line: 213, column: 14, scope: !1992)
!1997 = !{!1998}
!1998 = distinct !{!1998, !1995}
!1999 = distinct !{!1999, !1988, !2000, !2001, !2002}
!2000 = !DILocation(line: 214, column: 3, scope: !1893)
!2001 = !{!"llvm.loop.mustprogress"}
!2002 = !{!"llvm.loop.isvectorized", i32 1}
!2003 = distinct !{!2003, !2004}
!2004 = !{!"llvm.loop.unroll.disable"}
!2005 = !DILocation(line: 213, column: 28, scope: !1992)
!2006 = !DILocation(line: 213, column: 5, scope: !1992)
!2007 = distinct !{!2007, !2004}
!2008 = !DILocation(line: 215, column: 7, scope: !1896)
!2009 = !DILocation(line: 215, column: 7, scope: !1880)
!2010 = distinct !{!2010, !1988, !2000, !2001, !2002}
!2011 = !DILocation(line: 216, column: 24, scope: !1895)
!2012 = !DILocation(line: 216, column: 22, scope: !1895)
!2013 = !DILocation(line: 0, scope: !1895)
!2014 = !DILocation(line: 217, column: 5, scope: !1895)
!2015 = !DILocation(line: 218, column: 13, scope: !1895)
!2016 = !DILocation(line: 218, column: 19, scope: !1895)
!2017 = !DILocation(line: 219, column: 25, scope: !1895)
!2018 = !DILocation(line: 219, column: 23, scope: !1895)
!2019 = !DILocation(line: 219, column: 15, scope: !1895)
!2020 = !DILocation(line: 220, column: 3, scope: !1895)
!2021 = !DILocation(line: 222, column: 3, scope: !1898)
!2022 = !DILocation(line: 0, scope: !1898)
!2023 = distinct !DISubprogram(name: "INS_KONST", scope: !3, file: !3, line: 225, type: !11, scopeLine: 225, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !2024)
!2024 = !{!2025, !2026, !2027, !2028, !2029, !2030, !2031, !2032, !2034}
!2025 = !DILocalVariable(name: "ra", arg: 1, scope: !2023, file: !3, line: 225, type: !13)
!2026 = !DILocalVariable(name: "instr", arg: 2, scope: !2023, file: !3, line: 225, type: !14)
!2027 = !DILocalVariable(name: "pc", arg: 3, scope: !2023, file: !3, line: 225, type: !15)
!2028 = !DILocalVariable(name: "frame", arg: 4, scope: !2023, file: !3, line: 225, type: !6)
!2029 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !2023, file: !3, line: 225, type: !16)
!2030 = !DILocalVariable(name: "rb", scope: !2023, file: !3, line: 227, type: !13)
!2031 = !DILocalVariable(name: "func", scope: !2023, file: !3, line: 229, type: !18)
!2032 = !DILocalVariable(name: "op", scope: !2033, file: !3, line: 233, type: !13)
!2033 = distinct !DILexicalBlock(scope: !2023, file: !3, line: 233, column: 3)
!2034 = !DILocalVariable(name: "op_table_arg_c", scope: !2033, file: !3, line: 233, type: !8)
!2035 = !DILocation(line: 0, scope: !2023)
!2036 = !DILocation(line: 229, column: 29, scope: !2023)
!2037 = !DILocation(line: 229, column: 39, scope: !2023)
!2038 = !DILocation(line: 229, column: 18, scope: !2023)
!2039 = !DILocation(line: 230, column: 28, scope: !2023)
!2040 = !DILocation(line: 0, scope: !1741, inlinedAt: !2041)
!2041 = distinct !DILocation(line: 230, column: 15, scope: !2023)
!2042 = !DILocation(line: 1124, column: 25, scope: !1741, inlinedAt: !2041)
!2043 = !DILocation(line: 1124, column: 34, scope: !1741, inlinedAt: !2041)
!2044 = !DILocation(line: 230, column: 15, scope: !2023)
!2045 = !DILocation(line: 230, column: 3, scope: !2023)
!2046 = !DILocation(line: 230, column: 13, scope: !2023)
!2047 = !DILocation(line: 232, column: 5, scope: !2023)
!2048 = !DILocation(line: 233, column: 3, scope: !2033)
!2049 = !DILocation(line: 0, scope: !2033)
!2050 = distinct !DISubprogram(name: "INS_JISLT", scope: !3, file: !3, line: 236, type: !11, scopeLine: 236, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !2051)
!2051 = !{!2052, !2053, !2054, !2055, !2056, !2057, !2058, !2059, !2060, !2061, !2063}
!2052 = !DILocalVariable(name: "ra", arg: 1, scope: !2050, file: !3, line: 236, type: !13)
!2053 = !DILocalVariable(name: "instr", arg: 2, scope: !2050, file: !3, line: 236, type: !14)
!2054 = !DILocalVariable(name: "pc", arg: 3, scope: !2050, file: !3, line: 236, type: !15)
!2055 = !DILocalVariable(name: "frame", arg: 4, scope: !2050, file: !3, line: 236, type: !6)
!2056 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !2050, file: !3, line: 236, type: !16)
!2057 = !DILocalVariable(name: "rb", scope: !2050, file: !3, line: 238, type: !13)
!2058 = !DILocalVariable(name: "rc", scope: !2050, file: !3, line: 239, type: !13)
!2059 = !DILocalVariable(name: "fb", scope: !2050, file: !3, line: 241, type: !7)
!2060 = !DILocalVariable(name: "fc", scope: !2050, file: !3, line: 242, type: !7)
!2061 = !DILocalVariable(name: "op", scope: !2062, file: !3, line: 252, type: !13)
!2062 = distinct !DILexicalBlock(scope: !2050, file: !3, line: 252, column: 3)
!2063 = !DILocalVariable(name: "op_table_arg_c", scope: !2062, file: !3, line: 252, type: !8)
!2064 = !DILocation(line: 0, scope: !2050)
!2065 = !DILocation(line: 239, column: 29, scope: !2050)
!2066 = !DILocation(line: 241, column: 13, scope: !2050)
!2067 = !DILocation(line: 242, column: 13, scope: !2050)
!2068 = !DILocation(line: 243, column: 7, scope: !2069)
!2069 = distinct !DILexicalBlock(scope: !2050, file: !3, line: 243, column: 7)
!2070 = !DILocation(line: 243, column: 7, scope: !2050)
!2071 = !DILocation(line: 244, column: 5, scope: !2072)
!2072 = distinct !DILexicalBlock(scope: !2069, file: !3, line: 243, column: 32)
!2073 = !DILocation(line: 245, column: 3, scope: !2072)
!2074 = !DILocation(line: 246, column: 10, scope: !2075)
!2075 = distinct !DILexicalBlock(scope: !2050, file: !3, line: 246, column: 7)
!2076 = !DILocation(line: 246, column: 7, scope: !2050)
!2077 = !DILocation(line: 252, column: 3, scope: !2062)
!2078 = !DILocation(line: 0, scope: !2062)
!2079 = distinct !DISubprogram(name: "INS_UNKNOWN", scope: !3, file: !3, line: 255, type: !11, scopeLine: 255, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !2080)
!2080 = !{!2081, !2082, !2083, !2084, !2085}
!2081 = !DILocalVariable(name: "ra", arg: 1, scope: !2079, file: !3, line: 255, type: !13)
!2082 = !DILocalVariable(name: "instr", arg: 2, scope: !2079, file: !3, line: 255, type: !14)
!2083 = !DILocalVariable(name: "pc", arg: 3, scope: !2079, file: !3, line: 255, type: !15)
!2084 = !DILocalVariable(name: "frame", arg: 4, scope: !2079, file: !3, line: 255, type: !6)
!2085 = !DILocalVariable(name: "op_table_arg", arg: 5, scope: !2079, file: !3, line: 255, type: !16)
!2086 = !DILocation(line: 0, scope: !2079)
!2087 = !DILocation(line: 256, column: 54, scope: !2079)
!2088 = !DILocation(line: 256, column: 44, scope: !2079)
!2089 = !DILocation(line: 256, column: 3, scope: !2079)
!2090 = !DILocation(line: 257, column: 3, scope: !2079)
!2091 = distinct !DISubprogram(name: "run", linkageName: "_Z3runv", scope: !3, file: !3, line: 260, type: !1041, scopeLine: 260, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !2092)
!2092 = !{!2093, !2097, !2098, !2099, !2101, !2103, !2104, !2105, !2107, !2109, !2112, !2113, !2114, !2115, !2117, !2120, !2121, !2123, !2124, !2126, !2127, !2129, !2130, !2132, !2133, !2135, !2137, !2139, !2140, !2141, !2144, !2146, !2147, !2148, !2149, !2151, !2154, !2156, !2157, !2159, !2160, !2162, !2163, !2165, !2166, !2168, !2170, !2172, !2174, !2175, !2176, !2177, !2178, !2179, !2181, !2183, !2185, !2186, !2187, !2188, !2189, !2190, !2192, !2194, !2195, !2196, !2197, !2198, !2199, !2201, !2203, !2205}
!2093 = !DILocalVariable(name: "final_code", scope: !2091, file: !3, line: 265, type: !2094)
!2094 = !DICompositeType(tag: DW_TAG_array_type, baseType: !14, size: 64, elements: !2095)
!2095 = !{!2096}
!2096 = !DISubrange(count: 2)
!2097 = !DILocalVariable(name: "code", scope: !2091, file: !3, line: 266, type: !15)
!2098 = !DILocalVariable(name: "pc", scope: !2091, file: !3, line: 273, type: !15)
!2099 = !DILocalVariable(name: "i", scope: !2100, file: !3, line: 275, type: !547)
!2100 = distinct !DILexicalBlock(scope: !2091, file: !3, line: 275, column: 3)
!2101 = !DILocalVariable(name: "l_op_table", scope: !2091, file: !3, line: 279, type: !2102)
!2102 = !DICompositeType(tag: DW_TAG_array_type, baseType: !17, size: 1600, elements: !561)
!2103 = !DILocalVariable(name: "l_op_table_interpret", scope: !2091, file: !3, line: 281, type: !2102)
!2104 = !DILocalVariable(name: "l_op_table_record", scope: !2091, file: !3, line: 308, type: !2102)
!2105 = !DILocalVariable(name: "i", scope: !2106, file: !3, line: 309, type: !547)
!2106 = distinct !DILexicalBlock(scope: !2091, file: !3, line: 309, column: 3)
!2107 = !DILocalVariable(name: "i", scope: !2108, file: !3, line: 316, type: !547)
!2108 = distinct !DILexicalBlock(scope: !2091, file: !3, line: 316, column: 3)
!2109 = !DILocalVariable(name: "instr", scope: !2110, file: !3, line: 334, type: !14)
!2110 = distinct !DILexicalBlock(scope: !2111, file: !3, line: 333, column: 9)
!2111 = distinct !DILexicalBlock(scope: !2091, file: !3, line: 333, column: 6)
!2112 = !DILocalVariable(name: "op", scope: !2110, file: !3, line: 335, type: !13)
!2113 = !DILocalVariable(name: "ra", scope: !2110, file: !3, line: 336, type: !13)
!2114 = !DILocalVariable(name: "op_table_arg", scope: !2110, file: !3, line: 338, type: !16)
!2115 = !DILocalVariable(name: "i", scope: !2116, file: !3, line: 348, type: !14)
!2116 = distinct !DILexicalBlock(scope: !2091, file: !3, line: 347, column: 16)
!2117 = !DILocalVariable(name: "fa", scope: !2118, file: !3, line: 386, type: !7)
!2118 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 384, column: 13)
!2119 = distinct !DILexicalBlock(scope: !2116, file: !3, line: 370, column: 24)
!2120 = !DILocalVariable(name: "fb", scope: !2118, file: !3, line: 387, type: !7)
!2121 = !DILocalVariable(name: "fb", scope: !2122, file: !3, line: 401, type: !7)
!2122 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 399, column: 14)
!2123 = !DILocalVariable(name: "fc", scope: !2122, file: !3, line: 402, type: !7)
!2124 = !DILocalVariable(name: "fb", scope: !2125, file: !3, line: 416, type: !7)
!2125 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 414, column: 14)
!2126 = !DILocalVariable(name: "fc", scope: !2125, file: !3, line: 417, type: !7)
!2127 = !DILocalVariable(name: "fb", scope: !2128, file: !3, line: 431, type: !7)
!2128 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 429, column: 14)
!2129 = !DILocalVariable(name: "fc", scope: !2128, file: !3, line: 432, type: !7)
!2130 = !DILocalVariable(name: "fb", scope: !2131, file: !3, line: 448, type: !7)
!2131 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 446, column: 14)
!2132 = !DILocalVariable(name: "fc", scope: !2131, file: !3, line: 449, type: !7)
!2133 = !DILocalVariable(name: "fb", scope: !2134, file: !3, line: 490, type: !7)
!2134 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 488, column: 13)
!2135 = !DILocalVariable(name: "fb", scope: !2136, file: !3, line: 504, type: !7)
!2136 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 502, column: 14)
!2137 = !DILocalVariable(name: "v", scope: !2138, file: !3, line: 522, type: !7)
!2138 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 516, column: 13)
!2139 = !DILocalVariable(name: "func", scope: !2138, file: !3, line: 526, type: !18)
!2140 = !DILocalVariable(name: "old_pc", scope: !2138, file: !3, line: 527, type: !15)
!2141 = !DILocalVariable(name: "pos", scope: !2142, file: !3, line: 531, type: !7)
!2142 = distinct !DILexicalBlock(scope: !2143, file: !3, line: 530, column: 63)
!2143 = distinct !DILexicalBlock(scope: !2138, file: !3, line: 530, column: 11)
!2144 = !DILocalVariable(name: "v", scope: !2145, file: !3, line: 546, type: !7)
!2145 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 540, column: 14)
!2146 = !DILocalVariable(name: "func", scope: !2145, file: !3, line: 550, type: !18)
!2147 = !DILocalVariable(name: "start", scope: !2145, file: !3, line: 553, type: !7)
!2148 = !DILocalVariable(name: "cnt", scope: !2145, file: !3, line: 554, type: !14)
!2149 = !DILocalVariable(name: "i", scope: !2150, file: !3, line: 555, type: !547)
!2150 = distinct !DILexicalBlock(scope: !2145, file: !3, line: 555, column: 7)
!2151 = !DILocalVariable(name: "pos", scope: !2152, file: !3, line: 559, type: !7)
!2152 = distinct !DILexicalBlock(scope: !2153, file: !3, line: 558, column: 48)
!2153 = distinct !DILexicalBlock(scope: !2145, file: !3, line: 558, column: 11)
!2154 = !DILocalVariable(name: "rb", scope: !2155, file: !3, line: 570, type: !7)
!2155 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 568, column: 13)
!2156 = !DILocalVariable(name: "rc", scope: !2155, file: !3, line: 571, type: !7)
!2157 = !DILocalVariable(name: "rb", scope: !2158, file: !3, line: 596, type: !7)
!2158 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 594, column: 14)
!2159 = !DILocalVariable(name: "rc", scope: !2158, file: !3, line: 597, type: !7)
!2160 = !DILocalVariable(name: "func", scope: !2161, file: !3, line: 611, type: !18)
!2161 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 609, column: 14)
!2162 = !DILocalVariable(name: "gp", scope: !2161, file: !3, line: 612, type: !28)
!2163 = !DILocalVariable(name: "func", scope: !2164, file: !3, line: 623, type: !18)
!2164 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 621, column: 14)
!2165 = !DILocalVariable(name: "gp", scope: !2164, file: !3, line: 624, type: !28)
!2166 = !DILocalVariable(name: "f", scope: !2167, file: !3, line: 632, type: !18)
!2167 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 630, column: 14)
!2168 = !DILocalVariable(name: "func", scope: !2169, file: !3, line: 641, type: !18)
!2169 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 639, column: 14)
!2170 = !DILabel(scope: !2171, name: "L_INS_FUNC", file: !3, line: 372)
!2171 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 371, column: 16)
!2172 = !DILabel(scope: !2173, name: "L_INS_KSHORT", file: !3, line: 378)
!2173 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 377, column: 13)
!2174 = !DILabel(scope: !2118, name: "L_INS_ISGE", file: !3, line: 385)
!2175 = !DILabel(scope: !2122, name: "L_INS_JISEQ", file: !3, line: 400)
!2176 = !DILabel(scope: !2125, name: "L_INS_JISLT", file: !3, line: 415)
!2177 = !DILabel(scope: !2128, name: "L_INS_ISLT", file: !3, line: 430)
!2178 = !DILabel(scope: !2131, name: "L_INS_ISEQ", file: !3, line: 447)
!2179 = !DILabel(scope: !2180, name: "L_INS_ISF", file: !3, line: 464)
!2180 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 463, column: 14)
!2181 = !DILabel(scope: !2182, name: "L_INS_JMP", file: !3, line: 475)
!2182 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 474, column: 13)
!2183 = !DILabel(scope: !2184, name: "L_INS_RET1", file: !3, line: 481)
!2184 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 480, column: 13)
!2185 = !DILabel(scope: !2134, name: "L_INS_SUBVN", file: !3, line: 489)
!2186 = !DILabel(scope: !2136, name: "L_INS_ADDVN", file: !3, line: 503)
!2187 = !DILabel(scope: !2138, name: "L_INS_CALL", file: !3, line: 517)
!2188 = !DILabel(scope: !2145, name: "L_INS_CALLT", file: !3, line: 541)
!2189 = !DILabel(scope: !2155, name: "L_INS_ADDVV", file: !3, line: 569)
!2190 = !DILabel(scope: !2191, name: "L_INS_HALT", file: !3, line: 584)
!2191 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 583, column: 13)
!2192 = !DILabel(scope: !2193, name: "L_INS_ALLOC", file: !3, line: 589)
!2193 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 588, column: 13)
!2194 = !DILabel(scope: !2158, name: "L_INS_SUBVV", file: !3, line: 595)
!2195 = !DILabel(scope: !2161, name: "L_INS_GGET", file: !3, line: 610)
!2196 = !DILabel(scope: !2164, name: "L_INS_GSET", file: !3, line: 622)
!2197 = !DILabel(scope: !2167, name: "L_INS_KFUNC", file: !3, line: 631)
!2198 = !DILabel(scope: !2169, name: "L_INS_KONST", file: !3, line: 640)
!2199 = !DILabel(scope: !2200, name: "L_INS_MOV", file: !3, line: 648)
!2200 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 647, column: 14)
!2201 = !DILabel(scope: !2202, name: "L_INS_JFUNC", file: !3, line: 656)
!2202 = distinct !DILexicalBlock(scope: !2119, file: !3, line: 655, column: 14)
!2203 = !DILabel(scope: !2204, name: "L_INS_RECORD_START", file: !3, line: 678)
!2204 = distinct !DILexicalBlock(scope: !2116, file: !3, line: 677, column: 5)
!2205 = !DILabel(scope: !2206, name: "L_INS_RECORD", file: !3, line: 689)
!2206 = distinct !DILexicalBlock(scope: !2116, file: !3, line: 688, column: 5)
!2207 = !DILocation(line: 262, column: 15, scope: !2091)
!2208 = !DILocation(line: 265, column: 16, scope: !2091)
!2209 = !DILocation(line: 0, scope: !1865, inlinedAt: !2210)
!2210 = distinct !DILocation(line: 266, column: 25, scope: !2091)
!2211 = !DILocation(line: 1124, column: 25, scope: !1865, inlinedAt: !2210)
!2212 = !DILocation(line: 266, column: 25, scope: !2091)
!2213 = !DILocation(line: 0, scope: !1918, inlinedAt: !2214)
!2214 = distinct !DILocation(line: 266, column: 25, scope: !2091)
!2215 = !DILocation(line: 1124, column: 25, scope: !1918, inlinedAt: !2214)
!2216 = !DILocation(line: 0, scope: !2091)
!2217 = !DILocation(line: 268, column: 30, scope: !2091)
!2218 = !DILocation(line: 268, column: 14, scope: !2091)
!2219 = !DILocation(line: 268, column: 3, scope: !2091)
!2220 = !DILocation(line: 268, column: 12, scope: !2091)
!2221 = !DILocation(line: 0, scope: !1865, inlinedAt: !2222)
!2222 = distinct !DILocation(line: 269, column: 30, scope: !2091)
!2223 = !DILocation(line: 269, column: 15, scope: !2091)
!2224 = !DILocation(line: 269, column: 40, scope: !2091)
!2225 = !DILocation(line: 269, column: 3, scope: !2091)
!2226 = !DILocation(line: 269, column: 12, scope: !2091)
!2227 = !DILocation(line: 270, column: 12, scope: !2091)
!2228 = !DILocation(line: 270, column: 9, scope: !2091)
!2229 = !DILocation(line: 271, column: 23, scope: !2091)
!2230 = !DILocation(line: 271, column: 21, scope: !2091)
!2231 = !DILocation(line: 271, column: 13, scope: !2091)
!2232 = !DILocation(line: 0, scope: !2100)
!2233 = !DILocation(line: 276, column: 15, scope: !2234)
!2234 = distinct !DILexicalBlock(scope: !2235, file: !3, line: 275, column: 39)
!2235 = distinct !DILexicalBlock(scope: !2100, file: !3, line: 275, column: 3)
!2236 = !DILocation(line: 0, scope: !2108)
!2237 = !DILocation(line: 317, column: 17, scope: !2238)
!2238 = distinct !DILexicalBlock(scope: !2239, file: !3, line: 316, column: 31)
!2239 = distinct !DILexicalBlock(scope: !2108, file: !3, line: 316, column: 3)
!2240 = !DILocation(line: 319, column: 15, scope: !2091)
!2241 = !DILocation(line: 320, column: 15, scope: !2091)
!2242 = !DILocation(line: 321, column: 15, scope: !2091)
!2243 = !DILocation(line: 322, column: 15, scope: !2091)
!2244 = !DILocation(line: 323, column: 15, scope: !2091)
!2245 = !DILocation(line: 324, column: 15, scope: !2091)
!2246 = !DILocation(line: 325, column: 15, scope: !2091)
!2247 = !DILocation(line: 326, column: 15, scope: !2091)
!2248 = !DILocation(line: 327, column: 16, scope: !2091)
!2249 = !DILocation(line: 328, column: 16, scope: !2091)
!2250 = !DILocation(line: 329, column: 16, scope: !2091)
!2251 = !DILocation(line: 330, column: 16, scope: !2091)
!2252 = !DILocation(line: 331, column: 16, scope: !2091)
!2253 = !DILocation(line: 332, column: 16, scope: !2091)
!2254 = !DILocation(line: 334, column: 26, scope: !2110)
!2255 = !DILocation(line: 0, scope: !2110)
!2256 = !DILocation(line: 336, column: 31, scope: !2110)
!2257 = !DILocation(line: 336, column: 24, scope: !2110)
!2258 = !DILocation(line: 337, column: 11, scope: !2110)
!2259 = !DILocation(line: 339, column: 5, scope: !2110)
!2260 = !DILocation(line: 340, column: 10, scope: !2110)
!2261 = !DILocation(line: 340, column: 5, scope: !2110)
!2262 = !DILocation(line: 698, column: 1, scope: !2091)
!2263 = distinct !DISubprogram(linkageName: "_GLOBAL__sub_I_vm.cpp", scope: !3, file: !3, type: !2264, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !166)
!2264 = !DISubroutineType(types: !166)
!2265 = !DILocalVariable(name: "this", arg: 1, scope: !2266, type: !1387, flags: DIFlagArtificial | DIFlagObjectPointer)
!2266 = distinct !DISubprogram(name: "vector", linkageName: "_ZNSt6vectorIP6bcfuncSaIS1_EEC2Ev", scope: !40, file: !24, line: 526, type: !312, scopeLine: 526, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !311, retainedNodes: !2267)
!2267 = !{!2265}
!2268 = !DILocation(line: 0, scope: !2266, inlinedAt: !2269)
!2269 = distinct !DILocation(line: 12, column: 23, scope: !2270, inlinedAt: !2271)
!2270 = distinct !DISubprogram(name: "__cxx_global_var_init", scope: !3, file: !3, type: !1041, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !166)
!2271 = distinct !DILocation(line: 0, scope: !2263)
!2272 = !DILocalVariable(name: "this", arg: 1, scope: !2273, type: !1392, flags: DIFlagArtificial | DIFlagObjectPointer)
!2273 = distinct !DISubprogram(name: "_Vector_base", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EEC2Ev", scope: !43, file: !24, line: 312, type: !228, scopeLine: 312, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !227, retainedNodes: !2274)
!2274 = !{!2272}
!2275 = !DILocation(line: 0, scope: !2273, inlinedAt: !2276)
!2276 = distinct !DILocation(line: 526, column: 7, scope: !2266, inlinedAt: !2269)
!2277 = !DILocalVariable(name: "this", arg: 1, scope: !2278, type: !2280, flags: DIFlagArtificial | DIFlagObjectPointer)
!2278 = distinct !DISubprogram(name: "_Vector_impl", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EE12_Vector_implC2Ev", scope: !46, file: !24, line: 137, type: !194, scopeLine: 140, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !193, retainedNodes: !2279)
!2279 = !{!2277}
!2280 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !46, size: 64)
!2281 = !DILocation(line: 0, scope: !2278, inlinedAt: !2282)
!2282 = distinct !DILocation(line: 312, column: 7, scope: !2273, inlinedAt: !2276)
!2283 = !DILocalVariable(name: "this", arg: 1, scope: !2284, type: !2286, flags: DIFlagArtificial | DIFlagObjectPointer)
!2284 = distinct !DISubprogram(name: "_Vector_impl_data", linkageName: "_ZNSt12_Vector_baseIP6bcfuncSaIS1_EE17_Vector_impl_dataC2Ev", scope: !169, file: !24, line: 99, type: !177, scopeLine: 101, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, declaration: !176, retainedNodes: !2285)
!2285 = !{!2283}
!2286 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !169, size: 64)
!2287 = !DILocation(line: 0, scope: !2284, inlinedAt: !2288)
!2288 = distinct !DILocation(line: 137, column: 2, scope: !2278, inlinedAt: !2282)
!2289 = !DILocation(line: 100, column: 16, scope: !2284, inlinedAt: !2288)
!2290 = !DILocation(line: 0, scope: !2270, inlinedAt: !2271)
!2291 = !DILocation(line: 33, column: 45, scope: !2292, inlinedAt: !2293)
!2292 = distinct !DISubprogram(name: "__cxx_global_var_init.2", scope: !3, file: !3, type: !1041, flags: DIFlagArtificial, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !166)
!2293 = distinct !DILocation(line: 0, scope: !2263)
!2294 = !DILocation(line: 33, column: 53, scope: !2292, inlinedAt: !2293)
!2295 = !DILocation(line: 33, column: 23, scope: !2292, inlinedAt: !2293)
!2296 = !DILocation(line: 0, scope: !2292, inlinedAt: !2293)
