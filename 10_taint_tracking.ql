import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr{
    NetworkByteSwap(){
        exists(
            MacroInvocation mi | mi.getMacro().getName().regexpMatch("ntoh(.*)")
            and this = mi.getExpr()
        )
    }
}

class MemcpyCall extends FunctionCall{
    MemcpyCall(){
        exists(
            FunctionCall fc | fc.getTarget().getName().regexpMatch("memcpy")
            and this = fc
        )
    }
}

class Config extends TaintTracking::Configuration{
    Config(){
        this = "FromNetworkToMemFunLen"
    }
    override predicate isSource(DataFlow::Node source){
        source.asExpr() instanceof NetworkByteSwap
    }

    override predicate isSink(DataFlow::Node sink){
        exists(
            MemcpyCall c | sink.asExpr() = c.getArgument(2)
        )
    }
}

from Config c, DataFlow::PathNode source, DataFlow::PathNode sink
where c.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
