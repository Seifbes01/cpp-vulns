/**
 * @name Custom strcpy buffer overflow
 * @description Detects unsafe strcpy usage.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 * @id cpp/custom-test-query
 */

import cpp

class UnsafeStrcpyCall extends FunctionCall {
  UnsafeStrcpyCall() {
    this.getTarget().getName() = "strcpy"
  }
}

from UnsafeStrcpyCall call
select call, "Potential buffer overflow using strcpy."