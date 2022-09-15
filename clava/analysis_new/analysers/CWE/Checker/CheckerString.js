

class CheckerString{


    static isBufferInput($jp){
        if($jp===undefined){
            return false
        }

        if(!$jp.instanceOf("vardecl")){
            return false
        }


        if($jp.code[0]+$jp.code[1]+$jp.code[2]+$jp.code[3]==="char"){    
            if($jp.type.instanceOf("arrayType")){
                return true
            }
        }
        return false
    }

    static isSensibleFunction($jp){

        if(!$jp.instanceOf("call")){
            return false
        }

        
        
        const sensibleFunction = ["gets","strcpy","sprintf","scanf"]



        for(const funct of sensibleFunction ){
            if(funct.equals($jp.name)){
                return true
            }

        }

        return false
    }
    
    static isVerifyingSize($jp,$size){
        if($jp===undefined){
            return false
        }

        if(!$jp.instanceOf("call")){
            return false
        }

       const literal = Query.searchFromInclusive($jp,"literal").get()[0];

       if(literal===undefined){
           return false
       }

       const  code =literal.code.toString();

       if(code===undefined){
        return false
    }

       const indexStart = code.indexOf("%");
       
       const indexEnd = code.indexOf("s");
       
       if(indexEnd === undefined){
        const indexEnd = code.indexOf("c");
       }

        const number = code.slice(indexStart+1, indexEnd )
        println(number)
       if( parseInt(number) <= $size ){
           return true
       }
       return false

    }


}

    


