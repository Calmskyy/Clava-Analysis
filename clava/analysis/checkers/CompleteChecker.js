laraImport("lara.analysis.Checker");
laraImport("clava.analysis.checkers.ChgrpChecker");
laraImport("clava.analysis.checkers.ChmodChecker");
laraImport("clava.analysis.checkers.ChownChecker");
laraImport("clava.analysis.checkers.CinChecker");
laraImport("clava.analysis.checkers.ExecChecker");
laraImport("clava.analysis.checkers.FprintfChecker");
laraImport("clava.analysis.checkers.FscanfChecker");
laraImport("clava.analysis.checkers.GetsChecker");
laraImport("clava.analysis.checkers.LambdaChecker");
laraImport("clava.analysis.checkers.MemcpyChecker");
laraImport("clava.analysis.checkers.PrintfChecker");
laraImport("clava.analysis.checkers.ScanfChecker");
laraImport("clava.analysis.checkers.SprintfChecker");
laraImport("clava.analysis.checkers.StrcatChecker");
laraImport("clava.analysis.checkers.StrcpyChecker");
laraImport("clava.analysis.checkers.SyslogChecker");
laraImport("clava.analysis.checkers.SystemChecker");

/*Check for the presence of unsafe functions*/

class CompleteChecker extends Checker {

    constructor() {
        super();
    }

    check($node) {
        var result;

        const chgrp = new ChgrpChecker();
        const chmod = new ChmodChecker();
        const chown = new ChownChecker();
        const cin = new CinChecker();
        const exec = new ExecChecker();
        const fprintf = new FprintfChecker();
        const fscanf = new FscanfChecker();
        const gets = new GetsChecker();
        const lambda = new LambdaChecker();
        const memcpy = new MemcpyChecker();
        const printf = new PrintfChecker();
        const scanf = new ScanfChecker();
        const sprintf = new SprintfChecker();
        const strcat = new StrcatChecker();
        const strcpy = new StrcpyChecker();
        const syslog = new SyslogChecker();
        const system = new SystemChecker();

        const checkers = [chgrp, chmod, chown, cin, exec, fprintf, fscanf, gets, lambda, memcpy, printf, scanf, sprintf, strcat, strcpy, syslog, system];

        for (const checker of checkers) {
            result = checker.check($node);
            if (result !== undefined) {
                return result;
            }
        }
    }
}   