
laraImport("clava.analysis_new.analysers.CWE.Checker.CheckerString");
laraImport("clava.analysis_new.analysers.CWE.Checker.CheckerArray");
laraImport("clava.analysis_new.analysers.CWE.Report.MessageGenerator");
laraImport("clava.analysis_new.analysers.CWE.Report.Weakness");

class AnalyserCWE120 {

	variable

	isBuffer = false

	hasCopyFunction = false

	isSizeCheck = false

	tabChecker = [this.isBuffer, this.hasCopyFunction, this.isSizeCheck]

	size = 0

	tabInt = {}

	constructor() {
	}



	result() {
		if (this.tabChecker[2] !== this.tabChecker[1]) {
			println("Vulnerability detected: CWE120 " + true)
			MessageGenerator.append(new Weakness(this.variable, "CWE120"))
		} else {
			//println("weakness detected:120" + false)
		}
	}


	analyse($node) {

		if ($node === undefined) {
			return false
		}
		if ($node.instanceOf("vardecl")) {
			this.variable = $node
		}
		//  check if variable is a Buffer and get size
		if (this.tabChecker[0] === false) {
			this.tabChecker[0] = CheckerString.isBufferInput($node)
			if (this.tabChecker[0] === true) {
				this.size = CheckerArray.getSizeArray($node)
			}
			return this.tabChecker[0]
		}
		// check  a if condition which check size  
		else if (this.tabChecker[1] === false) {
			if (CheckerString.isSensibleFunction($node)) {
				this.tabChecker[1] = true
				this.tabChecker[2] = CheckerString.isVerifyingSize($node, this.size)
			}
		}

	}



}
