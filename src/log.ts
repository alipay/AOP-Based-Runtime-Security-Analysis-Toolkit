// Log utils.

var DEBUG = false;

function getCurrentThreadId() {
    let threadClass = Java.use("java.lang.Thread");
    let currThread = threadClass.currentThread();
    let currId = currThread.getId();
    let currName = currThread.getName();
    return `${currId}-${currName}-${currThread.hashCode()}`;
}

function getStack(prefix: string = "") {
    let currThread = Java.use("java.lang.Thread").currentThread();
    let stackTrace = currThread.getStackTrace();
    let stack = stackTrace.join("#");
    return stack;
}

function log(aspect: string, params: string, printStack: boolean = false, category: string = "-") {
    let stack = '-';
    if (printStack) {
        stack = getStack("");
    }

    send(`${getCurrentThreadId()},${aspect},${params},${stack},${category}`);
}

function debug(msg: string) {
    if (DEBUG) {
        console.log(msg);
    }
}

function print(msg: string) {
    console.log(msg);
}

export { log };
export { debug };
export { print };