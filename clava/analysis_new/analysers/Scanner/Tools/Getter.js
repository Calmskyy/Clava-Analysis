

class Getter{

	// return an array of joint point which are on the first layer after the body else return undefined
    static getJoinPointsInBody($jp){
        
		if($jp===undefined){
			return undefined
		}
		
		const body = Query.searchFromInclusive($jp,"body").get();
		
		return body[0].astChildren
	}

	static getChildrenJoinPoints($jp){
		
		if($jp===undefined){
			return undefined
		}
		
		const ExprStmtJoinPoints= $jp.astChildren
		
		return ExprStmtJoinPoints
	}

	// from a joinpoint return a call which is the first one following $jp in the tree else return undefined
		
    static lookingForCall($jp){
        
		if($jp===undefined){
			return undefined
		}
		
		const call = Query.searchFromInclusive($jp,"call").get();
		
		
		if(call[0]===undefined){
			return undefined
		}
		return call[0]
	}

	// from a joinpoint return an array of varref which are following $jp in the tree else return undefined
    static lookingForVarref($jp){
        
		if($jp===undefined){
			return undefined
		}
		
		const varref = Query.searchFromInclusive($jp,"varref").get();
		
		if(varref===undefined){
			return undefined
		}
		return varref
	
	}

	// from a joinpoint return a vardecl which is the first one following $jp in the tree else return undefined
    static lookingForVardecl($jp){
        
		if($jp===undefined){
			return undefined
		}
		
		const vardecl = Query.searchFromInclusive($jp,"vardecl").get();
		
		// return an array of joint point which are on the first layer after the body

		if(vardecl[0]===undefined){
			return undefined
		}
		return vardecl[0]
	
	}

	static analyse($jp,$condition){
		
		if ($jp === undefined) {
			return undefined
		  }
	
		  
		if ($jp.instanceOf("exprStmt")) {
			// case calling an other function traitement of it
			const callStmt = Getter.lookingForCall($jp)

			if (callStmt !== undefined) {
				new CallAnalyser(callStmt, $condition)
			}

			// case there is a operation on a variable traitement of it
			VariableAction.addNodeToGraph($jp, $condition)
		}

		if ($jp.instanceOf("call")) {

			new CallAnalyser($jp, $condition)
	
			return undefined
	
		  }

		//traitement of a new declaration variable
		if ($jp.instanceOf("declStmt")) {
			VariableAction.addNodeToGraph($jp, $condition)
			return undefined
		}
		// traitement of if condition 
		if ($jp.instanceOf("if")) {
			new IfAnalyser($jp, $condition)
			return undefined
		}

		 if ($jp.instanceOf("loop")) {
			  new LoopAnalyser($jp, $condition)
		 }


	}

}