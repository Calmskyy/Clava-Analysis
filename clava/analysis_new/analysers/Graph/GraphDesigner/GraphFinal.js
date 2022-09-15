laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.GraphManager");
laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.IfGraphBuilder");
laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.CallGraphBuilder");

class GraphFinal {

    //the first node of the graph

    #startNode

    // the node where we were

    #currentNode


    //enable to build the graph

    #graphManager

    

    //table of graphbuilder


    constructor($jp) {

        this.#graphManager = new GraphManager($jp);

        this.#startNode =$jp

        this.#currentNode = this.#startNode;
    }


    //action sur le graph

    addNewNode($jp, $condition) {

        if ($jp === undefined) {
          return false
        }
    
        switch ($condition) {
          case "NODE_IN_CALL":
            
            this.#graphManager.createNewNode($jp)
    
            break;
          case "NODE_IN_IF":
            this.#graphManager.createNewNodeInIf($jp)
            break;
    
          case "NODE_IN_ELSE":
            this.#graphManager.createNewNodeInElse($jp)
            break;
    
          default:
            return false
        }
        return true
    }
    addNewAction($jp, $condition) {
    
        if ($jp === undefined) {
          return false
        }
    
        if ($jp.instanceOf("if")) {
    
          switch ($condition) {
            case "NODE_IN_CALL":
    
              this.#graphManager.createNewIfGraph($jp)
              break;
    
            case "NODE_IN_IF":
              this.#graphManager.createNewIfNode($jp, $condition)
              break;
    
            case "NODE_IN_ELSE":
              this.#graphManager.createNewIfNode($jp, $condition)
              break;
    
            default:
              return false
          }
    
    
        }
        else{
          switch ($condition) {
            case "NODE_IN_CALL":
              this.#graphManager.createNewCallGraph($jp)
              break;
    
            case "NODE_IN_IF":
              this.#graphManager.createNewCallNode($jp, $condition)
              break;
    
            case "NODE_IN_ELSE":
              this.#graphManager.createNewCallNode($jp, $condition)
              break;
    
            default:
              return false
          }
    
        }
        return true
    
    }
    finishAction($condition) {
    switch ($condition) {
      case "NODE_IN_CALL":
        this.#graphManager.endCallGraph()
        break;

      case "NODE_IN_IF":
        this.#graphManager.endIfGraph()
        break;

      default:
        return undefined
    }

    }
    
    // get information on the gobal graph
    getStartNode() {
        return this.#startNode;
    }
    getCurrentNode() {
        return this.#currentNode
    }
    initCurrentNodeTOStartNode() {
        this.#currentNode = this.#startNode
    }

    // parcourrir graph en executqnt fonctionPar sur chaque noeud 

    goThroughGraph(functionPar){
        this.#graphManager.go(functionPar)
    }


    // display graph
    display(){
        this.#graphManager.display()
    }





}