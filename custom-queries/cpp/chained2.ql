/**
 * @name Global function pointer near overflowable buffer
 * @description Finds global function pointer fields accessed near strcpy calls with small buffers, indicating chained attack risk.
 * @kind problem
 * @problem.severity critical
 * @precision low
 * @tags security
 * @id cpp/custom-critical-global-funcptr-near-buffer
 */

import cpp

// Check for a global field which is a pointer to a function
predicate isGlobalFunctionPointer(Field f) {
  exists(PointerType pt |
    f.getType() = pt and
    exists(FunctionType ft | pt.getPointeeType() = ft)
  )
}

from Field globalPtr, FunctionCall strcpyCall, Expr buffer
where
  isGlobalFunctionPointer(globalPtr) and
  strcpyCall.getTarget().hasName("strcpy") and
  buffer = strcpyCall.getArgument(0) and
  exists(ArrayType arrType | buffer.getType() = arrType and arrType.getSize() < 20) and
  globalPtr.getAnAccess() = strcpyCall.getEnclosingStmt().getAChild*()
select globalPtr, "Critical: Global function pointer accessed near strcpy call with small buffer — chained attack risk."
