/**
 * @name Global function pointer near small buffer strcpy
 * @description Detects global function pointers accessed near strcpy calls into small buffers, indicating possible chained attack.
 * @kind problem
 * @problem.severity critical
 * @precision low
 * @tags security
 * @id cpp/custom-chained-global-funcptr
 */

import cpp

predicate isFunctionPointer(Type t) {
  exists(PointerType pt |
    pt = t and
    pt.getElementType() instanceof FunctionType
  )
}

from Field globalPtr, FunctionCall strcpyCall, Expr destBuffer
where
  isFunctionPointer(globalPtr.getType()) and
  strcpyCall.getTarget().hasName("strcpy") and
  destBuffer = strcpyCall.getArgument(0) and
  exists(ArrayType arrType | destBuffer.getType() = arrType and arrType.getSize() < 20) and
  globalPtr.getAnAccess() = strcpyCall.getEnclosingStmt().getAChild*()
select globalPtr, "Critical: Global function pointer accessed near strcpy call with small buffer — chained attack risk."
