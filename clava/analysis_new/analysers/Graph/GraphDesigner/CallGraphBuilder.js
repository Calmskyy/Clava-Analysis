laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.NodesDesigner.CallNode");
laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.NodesDesigner.CallEndNode");
laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.NodesDesigner.EndNode");

class CallGraphBuilder {

    //Starting node
    #startNode

    // The last node before the ending node
    #lastNode

    // the last node
    #endNode

    #typeGraphe="CALL_GRAPH"

    constructor($jp,$callNumber) {

        this.#endNode = new CallEndNode(new EndNode(), $callNumber);

        this.#startNode = new CallNode($jp, this.#endNode);

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