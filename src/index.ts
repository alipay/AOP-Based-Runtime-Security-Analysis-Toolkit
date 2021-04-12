import * as ArsatLog from "./log"
import * as ThreadChain from "./thread_chain"
import * as Injector from "./injector"

// Entry point.
Java.perform(function () {
    console.log("Arsat 1.0.0.");
    ThreadChain.initThreadStackChain();

    Injector.injectAspects();

    // Tmp test.
    let fileClass = Java.use("java.io.File");
    fileClass.createNewFile.implementation = function () {
        ArsatLog.log("File.createNewFile()", "-", true);
        return this.createNewFile();
    }
});