import cpp

from MacroInvocation mi
where mi.getMacro().getName().regexpMatch("ntoh(.*)")
select mi.getExpr()
