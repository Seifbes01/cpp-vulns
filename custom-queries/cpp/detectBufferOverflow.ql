/**
 * @name Custom strcpy buffer overflow
 * @description Detects unsafe strcpy usage.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @tags security
* @id cpp/custom-test-query
 */

import cpp
import semmle.code.cpp.security.TaintTracking

class UnsafeStrcpyCall extends Expr {
  UnsafeStrcpyCall() {
    this.getTarget().(Function).getName() = "strcpy"
  }

  override string toString() { result = "Potential buffer overflow via strcpy" }
}

from UnsafeStrcpyCall call
select call, "Potential buffer overflow using strcpy."
