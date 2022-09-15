/**
 * keep in memory the variables and their graph
 */

class VariableStorage{
   
    static pointerType = []

    static builtinType = []
 
    static getTabOfvariable($jp) {
        if ($jp === undefined) {
            return undefined
        }

        if (!$jp.instanceOf("vardecl")) {
            return undefined
        }

        switch ("" + $jp.type.joinPointType) {
            case "pointerType":
                return this.pointerType


            case "builtinType":
                return this.builtinType


            case "arrayType":
                return this.pointerType

            default:
                return undefined
        }


    }

    static getTabOfPointer() {
        return this.pointerType
    }

    static getTabOfBuiltin() {
        return this.builtinType
    }

    static clear() {
        this.pointerType = [];
        this.builtinType = [];
    }

    static getTabOfArray() {
        const ArrayType = []
        for (const variable of this.pointerType){
            if(variable.getDeclaration().type.instanceOf("arrayType"))
            ArrayType.push(variable)
        }
        return ArrayType
    }

}