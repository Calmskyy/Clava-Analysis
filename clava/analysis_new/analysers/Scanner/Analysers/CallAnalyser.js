
/**
 * The CallAnalyser class allows to find from a "call joint point " the main information useful information to built variable graphs
 * 
 * 
 *  
*/



laraImport("clava.analysis_new.analysers.Scanner.Tools.Getter");
laraImport("clava.analysis_new.analysers.Scanner.Analysers.IfAnalyser");
laraImport("clava.analysis_new.analysers.Scanner.Analysers.CallAnalyser");
laraImport("clava.analysis_new.analysers.Scanner.Analysers.LoopAnalyser");
laraImport("clava.analysis_new.analysers.VariablesManager.VariableAction");


class CallAnalyser {

    constructor($call, $condition) {

        // If there is no jointpoint not processing the analyse the analyse
        if ($call === undefined) {
            
        }
        // in case there is called function
        else {

            

            // Initiate the variable in use as parametre            
            VariableAction.initParametres($call)

            // Update the graph  of the variable which are concerned by the called function
            if($call.definition!==undefined){
                VariableAction.addActionToGraph($call.definition, $condition)
                //processing analyse
                this.processing($call.definition)
            }else{
                VariableAction.addActionToGraph($call, $condition)
            }
            
            // Update the graph  of the variable which are concerned by the called function
            VariableAction.finish("NODE_IN_CALL")

            // Update the variables which are concerned by the called function
            VariableAction.updateVariable($call)

           
        }

    }

    processing($jp) {

        if ($jp === undefined) {
            return undefined
        }

        const followingNodes = Getter.getJoinPointsInBody($jp)

        if (followingNodes === undefined) {
            return undefined
        }

        for (const f of followingNodes) {
            Getter.analyse(f, "NODE_IN_CALL")


        }


    }

    

}