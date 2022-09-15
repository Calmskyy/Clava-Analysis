laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.NodesDesigner.Node");
laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.NodesDesigner.IfNode");
laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.NodesDesigner.EndNode");
laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.NodesDesigner.IfEndNode");

class IfGraphBuilder {

    #startNode

    #lastNodeInIf

    #lastNodeInElse

    #ifEndNode

    #typeGraphe="IF_GRAPH"

    #currentNodes

    constructor($jp, $ifNumber) {

        this.#ifEndNode = new IfEndNode(new EndNode(), $ifNumber);

        this.#startNode = new IfNode($jp, this.#ifEndNode, this.#ifEndNode);

        this.#lastNodeInIf = this.#startNode;

        this.#lastNodeInElse = this.#startNode;

        

    }

    getGraphType(){
        return this.#typeGraphe
    }

    getStartNode() {
        return this.#startNode
    }

    getEndNode() {
        return this.#ifEndNode
    }

    addNodeInIf($jp) {

        if ($jp === undefined) {
            return false;
        }
        const newNode = new Node($jp, this.#ifEndNode);


        if(this.#lastNodeInIf.getType().equals("IF_NODE")){
            this.#startNode.setfollowingNodeInIf(newNode)
        } else {
            this.#lastNodeInIf.setfollowingNode(newNode)
        }

        this.#lastNodeInIf = newNode;

        return true;
    }


    addNodeInElse($jp) {

        if ($jp === undefined) {
            return false;
        }
        const newNode = new Node($jp, this.#ifEndNode);


        if(this.#lastNodeInElse.getType().equals("IF_NODE")){
            this.#startNode.setfollowingNodeInElse(newNode)
        } else {
            this.#lastNodeInElse.setfollowingNode(newNode)
        }

        this.#lastNodeInElse = newNode;

        return true;
    }

    
    

    connectToIfBranch($startNode, $endNode){

        if(this.#lastNodeInIf.getType().equals("IF_NODE")){
            
            this.#lastNodeInIf.setfollowingNodeInIf($startNode);
            this.#lastNodeInIf = $endNode

            $endNode.setfollowingNode(this.#ifEndNode) 
        }

        else{

            this.#lastNodeInIf.setfollowingNode($startNode);

            this.#lastNodeInIf = $endNode

            $endNode.setfollowingNode(this.#ifEndNode)
        }
    

    }
    
    connectToElseBranch($startNode, $endNode){
        
        if(this.#lastNodeInElse.getType().equals("IF_NODE")){
            
            this.#lastNodeInElse.setfollowingNodeInElse($startNode);
            this.#lastNodeInElse = $endNode

            $endNode.setfollowingNode(this.#ifEndNode) 
        }

        else{
        this.#lastNodeInElse.setfollowingNode($startNode);

        this.#lastNodeInElse = $endNode

        $endNode.setfollowingNode(this.#ifEndNode)

    }


    }
}