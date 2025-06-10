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

from FunctionCall call
where call.getTarget().getName() = "strcpy"
select call, "Potential buffer overflow using strcpy."
