class EndNode {

    //type of node
    #type = "END_NODE"

    //the content of the node
    #content = undefined

    #desc

    constructor() {
        this.#desc="end"
    }


    getdesc(){
        return this.#desc
    }
    getType() {
        return this.#type
    }

    getContent() {
        return this.#content;
    }
}