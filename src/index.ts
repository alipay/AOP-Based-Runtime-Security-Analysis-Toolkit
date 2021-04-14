import * as ArsatLog from "./log";
import * as ThreadChain from "./thread_chain";
import * as Injector from "./injector";
import * as ComponentMonitor from "./component_monitor";

// Entry point.
Java.perform(function () {
    console.log("[*] Arsat 0.0.1");

    console.log("[*] Preparing cross-thread stack trace handler...");
    ThreadChain.initThreadStackChain();

    console.log("[*] Preparing Compontent monitor...");
    ComponentMonitor.initMonitor();

    console.log("[*] Generating proxy...");
    Injector.injectAspects();

    console.log("[*] Start monitor...");

    // Tmp test.
    /*
    let fileClass = Java.use("java.io.File");
    fileClass.createNewFile.implementation = function () {
        ArsatLog.log("File.createNewFile()", "-", true);
        return this.createNewFile();
    }
    */
});