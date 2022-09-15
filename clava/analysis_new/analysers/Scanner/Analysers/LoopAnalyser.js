laraImport("lara.graphs.Graphs");
laraImport("clava.graphs.cfg.CfgBuilder");
laraImport("clava.analysis_new.analysers.Scanner.Tools.Getter");
laraImport("clava.analysis_new.analysers.Scanner.Analysers.IfAnalyser");
laraImport("clava.analysis_new.analysers.Scanner.Analysers.CallAnalyser");
laraImport("clava.analysis_new.analysers.Scanner.Analysers.LoopAnalyser");
laraImport("clava.analysis_new.analysers.VariablesManager.VariableAction");

class LoopAnalyser{


    constructor($jp,$condition ){
        VariableAction.addLoopToGraph($jp,$condition)
    }
    
    
    /*
    processing($jp){

		if($jp===undefined){
			return undefined
		}

        if(!$jp.instanceOf("loop")){
            return undefined
        }
        

        const cfg = CfgBuilder.buildGraph($jp);

        const graph = cfg.graph;
        
  
        var typeNode = " "
        var valueNode = " "

        for (const node of cfg.graph.nodes()) {
            typeNode = node.data().type.toString()
            

            
            if(typeNode==="LOOP"){
                var call = Query.searchFromInclusive(node.data().nodeStmt,"intLiteral").get()[0]
                
            }

            
            if(typeNode==="INIT"){
                var call = Query.searchFromInclusive(node.data().nodeStmt,"intLiteral").get()[0]
                
                var call = Query.searchFromInclusive(node.data().nodeStmt,"vardecl").get()[0]
                
            }

            if(typeNode==="COND"){
                var call = Query.searchFromInclusive(node.data().nodeStmt,"op").get()[0]
                
            }

            
        }

        println(Graphs.toDot(graph))

    } */

}