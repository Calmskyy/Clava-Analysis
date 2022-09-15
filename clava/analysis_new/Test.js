																																																				
laraImport("weaver.Query");
laraImport("weaver.Weaver");
laraImport("lara.Strings");
laraImport("clava.Clava");
laraImport("clava.analysis_new.analysers.Scanner.ScanCode");
laraImport("clava.analysis_new.analysers.VariablesManager.VariableStorage");
laraImport("clava.analysis_new.analysers.CWE.AnalyserCWE120");
laraImport("clava.analysis_new.analysers.CWE.AnalyserCWE457");
laraImport("clava.analysis_new.analysers.CWE.Analysers");


println(Query.root().dump)



//Analyse file by file
for(const $jp of Query.search("file")){
	
	//initialisation a new Scanner 
	let scanner = new ScanCode();

	//launch the scanner for one file 
	scanner.launch($jp);
	
	//After that Scanne succed , Variable Storage is full
	println(VariableStorage.getTabOfPointer())
	
	// for each variable which were found in the file ...
	for( const varia of VariableStorage.getTabOfPointer()){

		println(varia.getDeclaration().name)

		//... display the graph, 
		varia.display()

		// create and param a new analyser,
		analysers = new Analysers()
		analysers.addAnlayser( new AnalyserCWE457() )
		analysers.addAnlayser( new AnalyserCWE120() )

		//Launch the analyse through the graph of the variable,
		varia.goThroughGraph(analysers)

		// initate the result 
		analysers.result()
	}
	//generate a report
	MessageGenerator.generateReport($jp.name)
}

