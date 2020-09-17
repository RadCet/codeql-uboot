import cpp

from FunctionCall fc
where fc.getTarget().getName().regexpMatch("memcpy")
select fc, "call to memcpy"