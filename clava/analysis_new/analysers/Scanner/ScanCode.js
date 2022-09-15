
/**
 * The scancode class allows to find from a source code the head functions of the code and to launch the analyse
 * 
 * 
 *  
*/


laraImport("clava.analysis_new.analysers.Scanner.Analysers.CallAnalyser");



class ScanCode {

	#analyser 
	

	constructor() {
	}


	launch($file) {
		
		println("File: " + $file.name + "\n")
		
		// look for the head function of the file and launch a callAnalyser on it 
		for (const $node of this.getHeadFunctionIncallgraph($file)) {
			this.#analyser=new CallAnalyser()
			this.#analyser.processing($node)

		}

		
	}





	getHeadFunctionIncallgraph($jp) {
		// Utility object that counts tuples
		var callGraph = {};
		var functions= {}
		var functionCall={}
		// Collect information 
		for(var chain of Query.searchFromInclusive($jp,"function").search("call").chain()) {
			var $function = chain["function"];
			var $call = chain["call"];	
			
				// Test 1st key
				if(!($function.signature in callGraph)) {
					callGraph[$function.signature] = {} ;
					functions[$function.signature]=$function
				}
		
				// Test 2nd key
				if(!($call.signature in callGraph[$function.signature])){
					callGraph[$function.signature][$call.signature] = $call.function;
				}
		
				// Increment
				//callGraph[$function.signature][$call.signature]++;
			
		}
	
		
		
		var noHeadNode={}
		
		for (var f in callGraph) {
			for (var c in callGraph[f]) {		
				noHeadNode[c]=0;
			}
		
		}
		
		
		var HeadNode=[]

		for(var f in callGraph) {
			if (!(f in noHeadNode)) {
				HeadNode.push(functions[f])
			}
				  
		}

		/*for(var call in callGraph[HeadNode[0].signature]){
			println(callGraph[HeadNode[0].signature][call].hasDefinition)
		}*/
		
		return HeadNode
		  
	}

	
}
	








