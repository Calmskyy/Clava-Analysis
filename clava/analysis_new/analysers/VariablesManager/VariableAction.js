/*
* This class enable to modifying a variable 
*
*/







laraImport("clava.analysis_new.analysers.VariablesManager.Variable");
laraImport("clava.analysis_new.analysers.Scanner.Tools.Getter");
laraImport("clava.analysis_new.analysers.VariablesManager.VariableManager");


class VariableAction {

    static #manager = new VariablesManager()

    // add a new node for variable which are concerne 
    static addNodeToGraph($jp, $condition) {

        if ($jp === undefined) {
            return false
        }


        const vardecl = Getter.lookingForVardecl($jp)

        if (vardecl !== undefined) {
            this.#manager.addVariable(vardecl)
            return true
        }

        const varref = Getter.lookingForVarref($jp)[0];

        if (varref !== undefined) {

            const variable = this.#manager.getVariable(varref.decl)

            if (variable !== undefined) {
                variable.addNewNode($jp, $condition)
                return true
            }
        }
        return false
    }
     // add a new node"loop" for variable which are concerne 
    static addLoopToGraph($jp, $condition) {

        if ($jp === undefined) {
            return false
        }



        const varref = Getter.lookingForVarref($jp);

        var usedVarref = undefined

        if (varref !== undefined) {
            for (var pas = 0; pas < varref.length; pas++) {

                const variable = this.#manager.getVariable(varref[pas].decl)
                if (variable !== undefined) {
                    if (usedVarref === undefined) {
                        usedVarref = varref[pas]
                        variable.addNewNode($jp, $condition)
                        continue
                    } else if (varref[pas].decl.equals(usedVarref.decl)) {
                        continue
                    }
                    else {
                        usedVarref = varref[pas]
                        variable.addNewNode($jp, $condition)
                    }
                }

            }
        }
        return false
    }
     // add a new node (if or call) for variable which are concerne 
    static addActionToGraph($jp, $condition) {

        if ($jp === undefined) {
            return false
        }


        const varref = Getter.lookingForVarref($jp);



        if (varref !== undefined) {
            for (const usingVariable of varref) {

                const variable = this.#manager.getVariable(usingVariable.decl)

                if (variable !== undefined) {

                    variable.addNewAction($jp, $condition)
                }
            }

            return false

        }
    }
    
    static initParametres($jp) {
        this.#manager.initParametres($jp)
    }
    //enable to finish a if or a call
    static finish($condition) {
        this.#manager.finish($condition)
    }

    static updateVariable($condition) {
        this.#manager.updateVariable($condition)
    }



}