/**
 * @name strcpy into small buffer
 * @description Detects strcpy calls where the destination buffer size is less than 20, indicating possible buffer overflow.
 * @kind problem
 * @problem.severity critical
 * @precision medium
 * @tags security
 * @id cpp/custom-critical-strcpy-small-buffer
 */

import cpp

// Detect strcpy calls where the first argument is a buffer (array) smaller than 20 bytes
from FunctionCall strcpyCall, Expr destBuffer
where
  strcpyCall.getTarget().hasName("strcpy") and
  destBuffer = strcpyCall.getArgument(0) and
  exists(ArrayType arrType | destBuffer.getType() = arrType and arrType.getSize() < 20)
select strcpyCall, "Critical: Potential buffer overflow detected — strcpy into small buffer (<20 bytes)."


/**
 * @name Global function pointer near overflowable buffer
 * @description Finds global function pointer fields that are accessed in statements near strcpy calls with small buffers, indicating a chained attack risk.
 * @kind problem
 * @problem.severity critical
 * @precision low
 * @tags security
 * @id cpp/custom-critical-global-funcptr-near-buffer
 */

import cpp

from Field globalPtr, FunctionCall strcpyCall, Expr buffer
where
  globalPtr.getType().(PointerType).getPointeeType() instanceof FunctionType and
  strcpyCall.getTarget().hasName("strcpy") and
  buffer = strcpyCall.getArgument(0) and
  exists(ArrayType arrType | buffer.getType() = arrType and arrType.getSize() < 20) and
  // Check if globalPtr is accessed in the same statement or close by in the AST
  globalPtr.getAnAccess() = strcpyCall.getEnclosingStmt().getAChild*()
select globalPtr, "Critical: Global function pointer accessed near strcpy call with small buffer — chained attack risk."
