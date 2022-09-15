laraImport("clava.analysis_new.analysers.CWE.Checker.CheckerArray");
laraImport("clava.analysis_new.analysers.CWE.Report.MessageGenerator");
laraImport("clava.analysis_new.analysers.CWE.Report.Weakness");

class AnalyserCWE457 {


	variable
	isVariableDecl = false

	isVariableAlloc = false

	isTabInit = false

	tabChecker = [this.isVariableDecl, this.isVariableAlloc, this.isTabInit]

	size = 0

	tabInt = {}

	constructor() {

	}

	result() {
		if (this.tabChecker[0] === true) {
			if (this.tabChecker[2] !== this.tabChecker[1]) {
				println("Vulnerability detected: CWE457 " + true)
				MessageGenerator.append(new Weakness(this.variable, "CWE457"))
			}
		} else {
			// println("weakness detected:457 " + false)
		}
	}



	analyse($node) {
		if ($node === undefined) {
			return false
		}
		if ($node.instanceOf("vardecl")) {
			this.variable = $node
		}

		//declare
		if (this.tabChecker[0] === false) {
			this.tabChecker[0] = CheckerArray.isPointerDeclare($node)
			return this.tabChecker[0]
		}
		//allocate
		else if (this.tabChecker[1] === false) {
			if (CheckerArray.isAllocate($node)) {
				this.tabChecker[1] = true
				this.size = CheckerArray.getSizeAllocation($node)
				println("allocate size:" + this.size)
				return true
			}
			else if (CheckerArray.isDeclare($node)) {
				this.tabChecker[1] = true
				this.size = CheckerArray.getSizeDeclare($node)
				println("Declare size:" + this.size)
				return true
			}
			return false
		}
		//allocat
		else if (this.tabChecker[2] === false) {

			if ($node.instanceOf("loop")) {
				index = CheckerArray.loopAnalyserForInit($node)
				if (index !== undefined) {
					println("loop" + $node.line + "index--->" + index)
					for (var pas = index[0]; pas < index[1]; pas++) {
						this.tabInt[pas] = true
					}
				}
			} else if ($node.instanceOf("exprStmt")) {

				var index = CheckerArray.getIndexOfInit($node)
				if (index !== undefined) {
					this.tabInt[index] = true
				}
			}

			var cl = 0
			for (const f in this.tabInt) {
				cl++
			}
			println(cl + "-->")
			if (cl === this.size) {
				this.tabChecker[2] = true
			}

		}

	}



}
