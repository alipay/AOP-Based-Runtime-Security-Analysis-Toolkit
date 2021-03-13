// Log utils.

function getCurrentThreadId() {
    let threadClass = Java.use("java.lang.Thread");
    let currThread = threadClass.currentThread();
    let currId = currThread.getId();
    let currName = currThread.getName();
    return currId + "-" + currName;
}

function getStack(prefix: string = "") {
    let currThread = Java.use("java.lang.Thread").currentThread();
    let stackTrace = currThread.getStackTrace();
    let stack = "\n";
    for (const element of stackTrace) {
        stack += prefix + element.toString() + "\n";
    }
    return stack;
}

function log(msg: string, printStack: boolean = false) {
    if (printStack) {
        msg = msg + getStack("ARSAT:     ");
    }
    console.log("ARSAT: " + getCurrentThreadId() + ":" + msg);
}

export { log };