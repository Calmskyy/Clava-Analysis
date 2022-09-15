laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.NodesDesigner.Node");
laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.NodesDesigner.EndNode");

class GraphBuilder {

    //Starting node
    #startNode

    // The last node before the ending node
    #lastNode

    // the last node
    #endNode

    #typeGraphe="GRAPH"

    constructor($jp) {

        this.#endNode = new EndNode();

        this.#startNode = new Node($jp, this.#endNode);

        this.#lastNode = this.#startNode;

    }

    getGraphType(){
        return this.#typeGraphe
    }

    getStartNode() {

        return this.#startNode

    }

    getEndNode() {

        return this.#endNode

    }

    //enable to add a node in the graph

    addNode($jp) {

        if ($jp === undefined) {
            return false;
        }

        const newNode = new Node($jp, this.#endNode);

        this.#lastNode.setfollowingNode(newNode);

        this.#lastNode = newNode;

        return true;
    }

    //enable to connect an other graph to this one

    connect($startNode, $endNode) {

        this.#lastNode.setfollowingNode($startNode);

        this.#lastNode = $endNode

        $endNode.setfollowingNode(this.#endNode)

    }


}