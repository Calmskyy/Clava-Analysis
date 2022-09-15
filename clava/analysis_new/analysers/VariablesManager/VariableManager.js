
/*
* This class enabe to manage  variables which are store in VariableStorage  
*
*/


laraImport("clava.analysis_new.analysers.VariablesManager.VariableStorage");
laraImport("clava.analysis_new.analysers.Scanner.Tools.Getter");
laraImport("clava.analysis_new.analysers.VariablesManager.Variable");


class VariablesManager{

    #currentVariable

    constructor(){

    }

    addVariable($jp) {

        if ($jp === undefined) {
            return undefined
        }

        if (!$jp.instanceOf("vardecl")) {
            return undefined
        }

        this.#currentVariable = new Variable($jp)

        const variableTab = VariableStorage.getTabOfvariable($jp)

        if (variableTab !== undefined) {
            variableTab.push(this.#currentVariable)
        }
    }
   
    isVariableInit($jp) {

        if ($jp === undefined) {
            return false
        }
                
        if ($jp.instanceOf("vardecl")) {

            if (this.#currentVariable !== undefined) {
                if ($jp.equals(this.#currentVariable.getDeclaration())) {
                    return true
                }

            }
            const variableTab = VariableStorage.getTabOfvariable($jp)
            
            if (variableTab === undefined) {
                return false
            }

            for (const variable of variableTab) {
                
                if ($jp.astId === variable.getId()) {
                    this.#currentVariable = variable
                    return true
                }
            }

            return false
        } 
    }

    getVariable($jp){
        if(this.isVariableInit($jp)){
            return this.#currentVariable
        }
        return undefined
    }

    initParametres($jp) {

        if ($jp === undefined) {
            return false
        }

        if (!$jp.instanceOf("call")) {
            return undefined
        }

        if ($jp.definition === undefined) {
            return undefined
        }

        for (let pas = 0; pas < $jp.args.length; pas++) {
            if (this.isVariableInit($jp.args[pas].decl)) {
                if($jp.definition.params[pas] === undefined)
                    continue;
                this.#currentVariable.setId($jp.definition.params[pas].astId)
            }
        }
    }

    updateVariable($jp) {

        if ($jp === undefined) {
            return false
        }

        if (!$jp.instanceOf("call")) {
            return undefined
        }

        if ($jp.definition === undefined) {
            return undefined
        }

        
        for (let pas = 0; pas < $jp.args.length; pas++) {
            if ($jp.definition.params[pas] === undefined)
                continue;
            if ($jp.definition.params[pas].decl === undefined) {
                
                if (this.isVariableInit($jp.definition.params[pas])) {
                  
                    this.#currentVariable.popId()
                }
            }
        }

    }

    finish($condition) {
        if (this.#currentVariable == undefined) {
            return undefined
        }
        this.#currentVariable.finishAction($condition)
    }



}