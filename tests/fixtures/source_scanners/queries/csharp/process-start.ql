/**
 * @name Synthetic process launch call
 * @description A synthetic source boundary, not proof of exploitability.
 * @kind problem
 * @problem.severity warning
 * @id aegis/csharp-process-start
 */
import csharp
from MethodCall call
where call.getTarget().getDeclaringType().getName() = "Process"
  and call.getTarget().getName() = "Start"
select call, "Synthetic process launch boundary."
