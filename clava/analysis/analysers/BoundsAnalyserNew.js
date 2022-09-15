laraImport("lara.analysis.Analyser");
laraImport("lara.analysis.Checker");
laraImport("lara.analysis.ResultFormatManager");
laraImport("clava.analysis.analysers.BoundsResult");
laraImport("weaver.Query");

// Analyser that scan code to detect unsafe array accesses

class BoundsAnalyserNew extends Analyser {

    constructor() {
        super();
        this.resultFormatManager = new ResultFormatManager();
    }

    /**
    * Check file for illegal access of an array with an invalid index
    * @param {JoinPoint} $node
    * @return fileResult
    */
    analyse($node) {
        var boundsResultList = [];
        for (var $child of $node.descendants) {
            if (($child.instanceOf("vardecl")) && ($child.type.joinPointType === "arrayType")) {
                var lengths = $child.type.arrayDims;
                if ($child.hasInit) {
                    var message = " The index used to access the array is not valid (CWE-119). Please check the length of the array accessed.\n\n";
                    boundsResultList.push(new BoundsResult("Unsafe array access", $child, message, $node.name, 1, 0, lengths));
                    continue;
                }
                var message = " The array being accessed has not been initialized (CWE-457).\n\n";
                boundsResultList.push(new BoundsResult("Unsafe array access", $child, message, $node.name, 0, 0, lengths));
                continue;
            }
            if ($child.instanceOf("arrayAccess")) {
                var arrayName = $child.arrayVar.code;
                for (var result of boundsResultList) {
                    if (result.arrayName === arrayName) {
                        var indexes = $child.subscript.map(node => node.code);     // list of indexes in square brackets
                        for (var i = 0; i < indexes.length; i++) {
                            if (indexes[i].length > 1) {        // formats list of indexes
                                indexes[i] = indexes[i].substring(1, indexes[i].length - 1);
                            }
                            if (result.initializedFlag === 0) {
                                result.unsafeAccessFlag = 1;
                                result.line = $child.line;
                                continue;
                            }
                            if ((indexes[i] > result.lengths[i] - 1) || (indexes[i] < 0)) {     // access out of bounds
                                result.unsafeAccessFlag = 1;
                                result.line = $child.line;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        for (var res of boundsResultList) {      // disabling unharmful results
            if (res.unsafeAccessFlag === 0) {
                delete res.name;
            }
        }

        this.resultFormatManager.setAnalyserResultList(boundsResultList);
        var fileResult = this.resultFormatManager.formatResultList($node);
        if (fileResult === undefined) {
            return;
        }
        return fileResult;
    }
}
