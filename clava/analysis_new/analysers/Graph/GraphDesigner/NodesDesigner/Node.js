class Node {

    //type of node
    #type = "NODE"

    //the following node
    #nextNode

    //the content of the node
    #content

    #desc


    constructor($jp, $nextNode) {
        this.#content = $jp;
        this.#desc=$jp
        this.#nextNode = $nextNode;
    }

    getdesc(){
        return this.#desc
    }

    getType() {
        return this.#type
    }

    getfollowingNode() {
        return this.#nextNode;
    }

    getContent() {
        return this.#content;
    }

    setfollowingNode($node) {
        this.#nextNode = $node;
    }


}