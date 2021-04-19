import * as ArsatLog from "./log";
import * as ThreadChain from "./thread_chain";
import * as Injector from "./injector";
import * as ComponentMonitor from "./component_monitor";

// Entry point.
Java.perform(function () {
    ArsatLog.print("[*] Arsat 0.0.1");

    ArsatLog.print("[*] Preparing cross-thread stack trace handler...");
    ThreadChain.initThreadStackChain();

    ArsatLog.print("[*] Preparing Compontent monitor...");
    ComponentMonitor.initMonitor();

    ArsatLog.print("[*] Generating proxy...");
    Injector.injectAspects();

    ArsatLog.print("[*] Start monitor...");
});