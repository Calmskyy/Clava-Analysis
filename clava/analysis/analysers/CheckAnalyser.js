laraImport("lara.analysis.Analyser");
laraImport("lara.analysis.Checker");
laraImport("lara.analysis.CheckResult");
laraImport("clava.analysis.checkers.CompleteChecker");
laraImport("weaver.Query");

// Analyser that scans code to detect unsafe functions

class CheckAnalyser extends Analyser {

    constructor() {
        super();
        this.checkers = [];
        this.unsafeCounter = 0;
        this.warningCounter = 0;
        this.fixFlag = 0;
    }

    addChecker(checker) {
        this.checkers.push(checker);
    }

    addAllCheckers() {
        this.checkers.push(new CompleteChecker());
    }

    enableFixing() {
        this.fixFlag = 1;
    }

    disableFixing() {
        this.fixFlag = 0;
    }

    /**
    * Check file for unsafe functions, each one of them being specified by a checker
    * @param {JoinPoint} $node
    * @return fileResult
    */
    analyse($node) {
        // Analyser based on a list of checkers, each one of them is designed to spot one type of function.
        // The analysis is performed node by node.

        var checkResult;
        for (var checker of this.checkers) {
            var result = checker.check($node);
            if (result === undefined) {
                continue;
            }
            checkResult = result;
            break;
        }
        // We have now a list of checker's name each leading to a list of CheckResult

        if (this.fixFlag == 1 && checkResult !== undefined) {
            checkResult.performFix();
        }
        return checkResult;
    }
}