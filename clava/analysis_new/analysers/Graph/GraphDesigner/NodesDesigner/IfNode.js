class IfNode {

    //type of node
    #type = "IF_NODE"

    //the following node
    #nextNodeInIf

    #nextNodeInElse

    //the content of the node
    #content
    
    #desc


    constructor($jp, $nextNodeInIf, $nextNodeInElse) {
        this.#content = $jp;
        this.#desc= $jp
        this.#nextNodeInIf = $nextNodeInIf;
        this.#nextNodeInElse = $nextNodeInElse;
    }


    getdesc(){
        return this.#desc
    }

    getType() {
        return this.#type
    }

    getfollowingNodeInIf() {
        return this.#nextNodeInIf;
    }

    getfollowingNodeInElse() {
        return this.#nextNodeInElse;
    }

    getContent() {
        return this.#content;
    }

    setfollowingNodeInIf($node) {
        this.#nextNodeInIf = $node;
    }

    setfollowingNodeInElse($node) {
        this.#nextNodeInElse = $node;
    }



}