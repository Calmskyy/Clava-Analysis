laraImport("lara.analysis.Analyser");
laraImport("lara.analysis.Checker");
laraImport("lara.analysis.CheckResult");
laraImport("lara.analysis.ResultFormatManager");
laraImport("clava.analysis.analysers.DoubleFreeResult");
laraImport("weaver.Query");

// Analyser that scan scopes to check double-freed or unfreed memory

class DoubleFreeAnalyserNew extends Analyser {

    constructor() {
        super();
        this.resultFormatManager = new ResultFormatManager();
    }

    isDynamicAlloc($node) {
        if ($node.code.match(/.*malloc|calloc|realloc.*/)) {
            return 1;
        }
        return 0;
    }

    /**
* Check file for pointers not being freed or being freed two times in the same scope
* @param {JoinPoint} $node
* @return fileResult
*/
    analyse($node) {
        var doubleFreeResultList = [];
        for (var $child of $node.descendants) {
            //Check for dynamic pointer declaration
            if ((($child.instanceOf("vardecl")) || ($child.instanceOf("binaryOp"))) && this.isDynamicAlloc($child)) {
                var ptrName = ($child.instanceOf("vardecl")) ? $child.name : $child.left.code;
                for (var $grandChild of $child.descendants) {
                    if (($grandChild.instanceOf("call")) && this.isDynamicAlloc($grandChild)) {
                        var message = " Unfreed pointer in this scope. This can lead to a memory leak and a potential vunerability (CWE-401)."
                            + " Make sure it is freed somewhere in your program.\n\n";
                        doubleFreeResultList.push(new DoubleFreeResult("Unfreed array", $child, message, ptrName, $node.name));
                    }
                }
            }
            if (($child.instanceOf("call")) && ($child.name === "free")) {
                for (var result of doubleFreeResultList) {
                    if (($child.args[0].code === result.ptrName) && ($node.name === result.scopeName)) {
                        if (result.freedFlag === 0) {
                            result.freedFlag = 1;
                            result.message = undefined;
                        } else if (result.freedFlag === 1) {
                            result.freedFlag = -1;
                            result.name = "Double-freed array";
                            result.message = " Double-freed pointer in this scope. This could lead to a security vulnerability (CWE-415). Remove one of the calls to free().\n\n";
                        }
                    }
                }
            }
        }
        // We have now a list of checker's name each leading to a list of CheckResult 
        for (var res of doubleFreeResultList) {
            if (res.freedFlag === 1) {
                delete res.name;
            }
        }

        this.resultFormatManager.setAnalyserResultList(doubleFreeResultList);
        var fileResult = this.resultFormatManager.formatResultList($node);
        if (fileResult === undefined) {
            return;
        }
        return fileResult;
    }
}
