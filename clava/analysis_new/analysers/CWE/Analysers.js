

class Analysers{
  
    
    #analysers=[]

    constructor(){

    }

    addAnlayser($analyser){
        this.#analysers.push($analyser)
    }


    analyse($node){
        for(const analyser of this.#analysers){
            analyser.analyse($node)
        }
    }

    result(){
        for(const analyser of this.#analysers){
            analyser.result()
        }
        
    }
}