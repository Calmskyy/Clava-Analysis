class IfEndNode{
    
    //type of node
    #type="IF_END_NODE"
    
     //the following node
    #nextNode
    
    //the content of the node
    #content

    #desc
    
    constructor($nextNode,$ifNumber){
        this.#content=undefined
        this.#desc="end if"+$ifNumber
        this.#nextNode=$nextNode;
    }


    getdesc(){
        return this.#desc
    }
    getType(){
        return this.#type
    }
    
    getContent(){
        return this.#content;
    }

    setfollowingNode($node){
        this.#nextNode=$node;
    }

    getfollowingNode(){
        return this.#nextNode;
    }
}

   
   