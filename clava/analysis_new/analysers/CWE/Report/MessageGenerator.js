laraImport("lara.Io");
laraImport("clava.analysis_new.analysers.CWE.Report.Weakness");

class MessageGenerator {
    static messages = [];



    static append(checkpoint) {
        if (checkpoint === undefined) {
            return;
        }
        var message = ""
        message += "," + checkpoint.getDesc() + ",Line: " + checkpoint.getLine() + ",Data name: " + checkpoint.getName() + "\n";
        println(message)
        this.messages.push(message)
    }

    static generateReport(fileName) {
        var analysisFileName = Io.getPath(Clava.getData().getContextFolder(), "AnalysisReports/" + fileName + "_report.txt");
        var message = "" + fileName;
        for (const $message of this.messages) {
            message += $message

        }
        if (message != fileName) 
            Io.writeFile(analysisFileName, message);
        this.messages = []
    }
}
