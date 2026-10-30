/**
 * @name Synthetic dynamic eval call
 * @description A synthetic source boundary, not proof of exploitability.
 * @kind problem
 * @problem.severity warning
 * @id aegis/js-dynamic-eval
 */
import javascript
from CallExpr call
where call.getCalleeName() = "eval"
select call, "Synthetic dynamic evaluation boundary."
