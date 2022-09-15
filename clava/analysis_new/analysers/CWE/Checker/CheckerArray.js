

class CheckerArray{


    static isPointerDeclare($jp){
        if($jp===undefined){
            return false
        }
        if(!$jp.instanceOf("vardecl")){
            return false
        }

        if($jp.type.instanceOf("pointerType")){
            if(!$jp.isParam){
                return true
            }
        }
        return false
    }

    static getSizeArray($jp){
        if($jp===undefined){
            return false
        }

        if(!$jp.type.instanceOf("arrayType")){
            return false
        }

        return $jp.type.arraySize

    }

    static isAllocate($jp){

        if($jp===undefined){
            return false
        }

        
        if(!$jp.instanceOf("exprStmt")){
            return false
        }

		if ($jp.astChildren[0].instanceOf('binaryOp')){
            const call = Query.searchFromInclusive($jp.astChildren[0],"call").get()[0];
		
            if(call===undefined){
                return false
            }
            switch(call.name ){
                case "calloc":
                    return true
                case "__builtin_alloca":
                    return true
                case "malloc":
                    return true
                default :
                    return false
            }
            

        }
        return false
	}

    static isDeclare($jp){
        if($jp===undefined){
            return false
        }

        if(!$jp.instanceOf("exprStmt")){
            return false
        }

        const binaryOp = $jp.astChildren[0]
        
        if(binaryOp === undefined){
            return false
        }
		
        if (binaryOp.instanceOf('binaryOp')){
            if (binaryOp.lastChild.type.instanceOf("arrayType")) {
                return true
            }
        
        }
        return false
    }  
    
    static getSizeAllocation($jp){

        const intLiteral = Query.searchFromInclusive($jp,"intLiteral").get()[0];

        if(intLiteral!== undefined){
            
            return intLiteral.value
        }
        
        return undefined
    }

    static getSizeDeclare($jp){
        const varref = Query.searchFromInclusive($jp,"varref").get();
        
        if(varref[1]!== undefined){
            return varref[1].type.arraySize
        }

        return undefined
    }

    static getIndexOfInit($jp){
        if($jp===undefined){
            return undefined
        }

        if(!$jp.instanceOf("exprStmt")){
            return undefined
        }

        const binaryOp = $jp.astChildren[0]

        
        if(binaryOp=== undefined){
            return undefined
        }
        
        const arrayAccess = Query.searchFromInclusive(binaryOp.firstChild,"arrayAccess").get()[0];

        if(arrayAccess===undefined){
            return undefined
        }
        

        if(arrayAccess.lastChild===undefined){
            return undefined
        }

        if(arrayAccess.lastChild.instanceOf("intLiteral")){
            return arrayAccess.lastChild.value
        }
        else if (arrayAccess.lastChild.instanceOf("varref")){
            return arrayAccess.lastChild.name
        }
        return undefined
    }

    static loopAnalyserForInit($jp){
        var numIteration;
        var nameVariable;
        var initLoop;
        
        if($jp===undefined){
            return undefined
        }

        if(!$jp.instanceOf("loop")){
            return undefined
        }   
    
        
        var vardecl = Query.searchFromInclusive($jp,"vardecl").get()[0]
        
        nameVariable=vardecl.name

        initLoop = Query.searchFromInclusive(vardecl,"intLiteral").get()[0].value
        
        const exprStmt = Query.searchFromInclusive($jp,"exprStmt").get()[0]
        var intLiteral = Query.searchFromInclusive(exprStmt,"intLiteral").get()[0]

        numIteration = intLiteral.value - initLoop;
        

        var body = Query.searchFromInclusive($jp,"body").get()[0]

        for(const initInLoop of searchFromInclusive(body,"exprStmt")){
            var index = this.getIndexOfInit(initInLoop)
        }

        if(index===nameVariable){
            return [initLoop,numIteration]
            
        }else{
            return [index]
        }
        return undefined

    }

}

    


