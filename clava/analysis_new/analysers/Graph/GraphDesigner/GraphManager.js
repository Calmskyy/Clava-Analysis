laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.GraphBuilder");
laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.IfGraphBuilder");
laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.CallGraphBuilder");


class GraphManager {

    //the first node of the graph

    #startNode

    // the node where we were

    #currentNode

    
    //enable to build the graph

    #graphBuilder

    //enable to build a graph in case of if condition

    #ifGraphBuilder = null

    #callGraphBuilder = null

    #numberOfIf = 0

    #numberOfCall =0
    
    //table of graphbuilder

    #tabCurrentsGraphs=[]

    #indexOfLastGraphs=this.#tabCurrentsGraphs.length-1



    constructor($jp) {

        this.#graphBuilder = new GraphBuilder($jp);

        this.#tabCurrentsGraphs.push(this.#graphBuilder)

        this.#startNode = this.#graphBuilder.getStartNode();

        this.#currentNode = this.#startNode;
    }

    // action  in the simple graph 

    createNewNode($jp) {
        
        const currentGraph=this.#tabCurrentsGraphs[this.#tabCurrentsGraphs.length-1]
        
        if(!currentGraph.getGraphType().equals("IF_GRAPH")){
           
            currentGraph.addNode($jp);

            //this.#currentNode = this.#currentNode.getfollowingNode()
        }
    }

    createNewCallGraph($jp){
        const currentGraph=this.#tabCurrentsGraphs[this.#tabCurrentsGraphs.length-1]
        
        if(!currentGraph.getGraphType().equals("IF_GRAPH")){
           
            this.#numberOfCall++;

            this.#callGraphBuilder=new CallGraphBuilder($jp,this.#numberOfCall)

            currentGraph.connect(this.#callGraphBuilder.getStartNode(), this.#callGraphBuilder.getEndNode())

            this.#tabCurrentsGraphs.push(this.#callGraphBuilder)

            //this.#currentNode = this.#currentNode.getfollowingNode()
        }
    }
   
    createNewIfGraph($jp) {

        const currentGraph = this.#tabCurrentsGraphs[this.#tabCurrentsGraphs.length-1]

       
        if(!currentGraph.getGraphType().equals("IF_GRAPH")){
            
            // increment the number of if condition
            this.#numberOfIf++

            //build a ifgraph

            this.#ifGraphBuilder = new IfGraphBuilder($jp, this.#numberOfIf)

            //connect it with the actual graph

            currentGraph.connect(this.#ifGraphBuilder.getStartNode(), this.#ifGraphBuilder.getEndNode())

            this.#tabCurrentsGraphs.push(this.#ifGraphBuilder)
           
        }
    }


    //action in a if graph 
    createNewIfNode($jp,$branch) {

        const currentGraph = this.#tabCurrentsGraphs[this.#tabCurrentsGraphs.length-1]

       
        if(currentGraph.getGraphType().equals("IF_GRAPH")){
            
            // increment the number of if condition
            this.#numberOfIf++

            //build a ifgraph

            this.#ifGraphBuilder = new IfGraphBuilder($jp, this.#numberOfIf)

            //connect it with the actual graph
            if($branch.equals("NODE_IN_IF")){
                
                currentGraph.connectToIfBranch(this.#ifGraphBuilder.getStartNode(), this.#ifGraphBuilder.getEndNode())

                this.#tabCurrentsGraphs.push(this.#ifGraphBuilder)
            }
            
            if($branch.equals("NODE_IN_ELSE")){
                
                currentGraph.connectToElseBranch(this.#ifGraphBuilder.getStartNode(), this.#ifGraphBuilder.getEndNode())

                this.#tabCurrentsGraphs.push(this.#ifGraphBuilder)
            }
        }
    }

    createNewCallNode($jp,$branch) {

        const currentGraph = this.#tabCurrentsGraphs[this.#tabCurrentsGraphs.length-1]

       
        if(currentGraph.getGraphType().equals("IF_GRAPH")){
            
            // increment the number of if condition
            this.#numberOfCall++

            //build a ifgraph

            this.#callGraphBuilder = new CallGraphBuilder($jp, this.#numberOfCall)

            //connect it with the actual graph
            if($branch.equals("NODE_IN_IF")){
                
                currentGraph.connectToIfBranch(this.#callGraphBuilder.getStartNode(), this.#callGraphBuilder.getEndNode())

                this.#tabCurrentsGraphs.push(this.#callGraphBuilder)
            }
            
            if($branch.equals("NODE_IN_ELSE")){
                
                currentGraph.connectToElseBranch(this.#callGraphBuilder.getStartNode(), this.#callGraphBuilder.getEndNode())

                this.#tabCurrentsGraphs.push(this.#callGraphBuilder)
            }
        }
    }

    createNewNodeInIf($jp) {
    const currentGraph = this.#tabCurrentsGraphs[this.#tabCurrentsGraphs.length-1]
       
        if(currentGraph.getGraphType().equals("IF_GRAPH")){   
            if (currentGraph !== null) {
                
                currentGraph.addNodeInIf($jp)

            }
        }

    }

    createNewNodeInElse($jp) {
        const currentGraph = this.#tabCurrentsGraphs[this.#tabCurrentsGraphs.length-1]
       
        if(currentGraph.getGraphType().equals("IF_GRAPH")){   
            if (currentGraph !== null) {
                
                currentGraph.addNodeInElse($jp)

            }
        }

    }


    // ending a sub-graph
    endIfGraph(){
        const currentGraph = this.#tabCurrentsGraphs[this.#tabCurrentsGraphs.length-1]
       
        if(currentGraph.getGraphType().equals("IF_GRAPH")){
            this.#tabCurrentsGraphs.pop()
        } 
    }

    endCallGraph(){
        const currentGraph = this.#tabCurrentsGraphs[this.#tabCurrentsGraphs.length-1]
       
        if(currentGraph.getGraphType().equals("CALL_GRAPH")){
            this.#tabCurrentsGraphs.pop()
        } 
    }


    go(functionPar) {



        var node = this.#startNode

        while (!node.getType().equals("END_NODE")) {

            if (node.getType().equals("IF_NODE")) {

                node = this.Processing(node, functionPar)

            }

            functionPar.analyse(node.getContent())
            node = node.getfollowingNode()
        }

    }

    Processing(node, functionPar) {

        if (node.getType().equals("IF_NODE")) {

            var startNodeForIfGraph = node

            functionPar.analyse(startNodeForIfGraph.getContent())
            node = node.getfollowingNodeInIf()

            while (!node.getType().equals("IF_END_NODE")) {
                if (node.getType().equals("IF_NODE")) {
                    node = this.Processing(node, functionPar)
                }
                functionPar.analyse(node.getContent())
                node = node.getfollowingNode()
            }

            node = startNodeForIfGraph.getfollowingNodeInElse()

            while (!node.getType().equals("IF_END_NODE")) {
                if (node.getType().equals("IF_NODE")) {
                    node = this.Processing(node, functionPar)
                }
                functionPar.analyse(node.getContent());
                node = node.getfollowingNode()
            }

            return node

        }
    }


    display() {

        println('digraph static_call_graph {\n');

        var node = this.#startNode

        while (!node.getType().equals("END_NODE")) {

            if (node.getType().equals("IF_NODE")) {

                node = this.displayProcessing(node)

            }

            println('\t"' + node.getdesc() + node.getdesc().line + '"->"' + node.getfollowingNode().getdesc() + node.getfollowingNode().getdesc().line + '" [label="' + 1 + '"];');

            node = node.getfollowingNode()
        }
        println('}');
    }

    displayProcessing(node) {

        if (node.getType().equals("IF_NODE")) {

            var startNodeForIfGraph = node

            println('\t"' + startNodeForIfGraph.getdesc() + startNodeForIfGraph.getdesc().line + '"->"' + startNodeForIfGraph.getfollowingNodeInIf().getdesc() + startNodeForIfGraph.getfollowingNodeInIf().getdesc().line + '" [label="' + "If" + '"];');

            println('\t"' + startNodeForIfGraph.getdesc() + startNodeForIfGraph.getdesc().line + '"->"' + startNodeForIfGraph.getfollowingNodeInElse().getdesc() + startNodeForIfGraph.getfollowingNodeInElse().getdesc().line + '" [label="' + "else" + '"];');

            node = node.getfollowingNodeInIf()

            while (!node.getType().equals("IF_END_NODE")) {
                if (node.getType().equals("IF_NODE")) {
                    node = this.displayProcessing(node)
                }
                println('\t"' + node.getdesc() + node.getdesc().line + '"->"' + node.getfollowingNode().getdesc() + node.getfollowingNode().getdesc().line + '" [label="' + 1 + '"];');
                node = node.getfollowingNode()
            }

            node = startNodeForIfGraph.getfollowingNodeInElse()

            while (!node.getType().equals("IF_END_NODE")) {
                if (node.getType().equals("IF_NODE")) {
                    node = this.displayProcessing(node)
                }
                println('\t"' + node.getdesc() + node.getdesc().line + '"->"' + node.getfollowingNode().getdesc() + node.getfollowingNode().getdesc().line + '" [label="' + 1 + '"];');
                node = node.getfollowingNode()
            }

            return node

        }
    }


}