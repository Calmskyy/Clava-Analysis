/**
 * The IfAnalyser class allows to find from a "if jointpoint " the main information useful information to built variable graphs
 * 
 * 
 *  
*/



laraImport("clava.graphs.cfg.CfgBuilder");
laraImport("lara.graphs.Graphs");
laraImport("clava.analysis_new.analysers.Scanner.Tools.Getter");
laraImport("clava.analysis_new.analysers.Scanner.Analysers.IfAnalyser");
laraImport("clava.analysis_new.analysers.Scanner.Analysers.CallAnalyser");
laraImport("clava.analysis_new.analysers.Scanner.Analysers.LoopAnalyser");
laraImport("clava.analysis_new.analysers.VariablesManager.VariableAction");


class IfAnalyser {

  constructor($ifjp, $condition) {

    if ($ifjp !== undefined) {
      
      // println("+++if " + $ifjp)
      
      VariableAction.addActionToGraph($ifjp, $condition)
      
      this.processing($ifjp)
    
    } 
  }


  processing($jp) {

    if ($jp === undefined) {
      return undefined
    }
    // launch cfg view on the if stmt to analyse it 
    this.#cfgView($jp)

    println("  ---if")

    VariableAction.finish("NODE_IN_IF")
  }

  /*In the function #cfgView from "jp if" we use the cfg view to separate the analysis of the nodes that are located 
  *in the if condition and those that are located in the else condition. 
  * 
  */

  #cfgView($jp) {

    // initiate cfg with the jp if 

   // const cfg = CfgBuilder.buildGraph($jp);
   // const graph = cfg.graph;

    let builder = new CfgBuilder($jp)
    const cfg = builder.build();

    println(cfg[0])
    
    var positionInCfg = " ";

    var typeNode = " "

    // go through the cfg
    for (const node of cfg[0].nodes()) {

      typeNode = node.data().type.toString()

      if (positionInCfg === "ELSE") {
        if (typeNode === "THEN") {
          break
        }
      }

      if (typeNode === "THEN") {
        positionInCfg = "THEN"
      }

      if (typeNode === "ELSE") {
        positionInCfg = "ELSE"
      }

      if (typeNode === "INST_LIST") {
        continue;
      }

      if (positionInCfg.equals("THEN")) {

        this.#analyseInThen(node.data().nodeStmt)
      }

      if (positionInCfg.equals("ELSE")) {
        this.#analyseInElse(node.data().nodeStmt)
      }



    }

  }


  #analyseInThen($jp) {

    //analyse stmt in the "then condition" 

    for (const $stmt of Getter.getChildrenJoinPoints($jp)) {

      Getter.analyse($stmt,"NODE_IN_IF")
  
    }
  }



  #analyseInElse($jp) {
    
    //analyse stmt in the "else condition"
    for (const $stmt of Getter.getChildrenJoinPoints($jp)) {

      Getter.analyse($stmt,"NODE_IN_ELSE")
     
    }
  }

}