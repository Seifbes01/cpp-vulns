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

from FunctionCall strcpyCall, Expr destBuffer
where
  strcpyCall.getTarget().hasName("strcpy") and
  destBuffer = strcpyCall.getArgument(0) and
  exists(ArrayType arrType | destBuffer.getType() = arrType and arrType.getSize() < 20)
select strcpyCall, "Critical: Potential buffer overflow detected — strcpy into small buffer (<20 bytes)."
