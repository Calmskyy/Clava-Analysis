/*
* This class describes a variable: 
* its name
* its declaration
* its identifier
* its graph 
*/


laraImport("clava.analysis_new.analysers.Graph.GraphDesigner.GraphFinal");


class Variable extends GraphFinal {

  #variableDecl

  #variableid = []

  #name


  constructor($jp) {

    if ($jp === undefined) {
      return undefined
    }

    if (!$jp.instanceOf("vardecl")) {
      return undefined
    }

    super($jp)

    this.#variableDecl = $jp

    this.#name = $jp.name

    this.#variableid.push($jp.astId)

  }


  getDeclaration() {
    return this.#variableDecl
  }

  getName() {
    return this.#name
  }

  getId() {
    return this.#variableid[this.#variableid.length - 1]
  }

  popId() {
    this.#variableid.pop()
  }

  setId($newId) {
    this.#variableid.push($newId)
  }


}