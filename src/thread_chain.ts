// Thread stack chain utils.
// All functions in thie file **MUST** be called inside Java.perform().

import * as ArsatLog from "./log";

function hookThread() {
    ArsatLog.debug("Hook Thread");

    let threadClass = Java.use("java.lang.Thread");
    threadClass.start.implementation = function () {
        let id = this.getId();
        let name = this.getName();
        let threadId = id + "-" + name;
        let hash = this.hashCode();
        ArsatLog.log("Thread.start()", `${threadId}-${hash}`, true);
        this.start();
    }
}

function hookThreadPoolExecutor() {
    ArsatLog.debug("Hook ThreadPoolExecutor");

    let exectorClass = Java.use("java.util.concurrent.ThreadPoolExecutor");
    let objectClass = Java.use("java.lang.Object");
    exectorClass.execute.overload("java.lang.Runnable").implementation = function (runnable: any) {
        let obj = Java.cast(runnable, objectClass);
        let hashCode = obj.hashCode();
        ArsatLog.log("ThreadPoolExecutor.execute()", hashCode, true);
        this.execute(runnable);
    }
    exectorClass.getTask.implementation = function() {
        let runnable = this.getTask();
        let obj = Java.cast(runnable, objectClass);
        let hashCode = obj.hashCode();
        ArsatLog.log("ThreadPoolExecutor.getTask()", hashCode);
        return runnable;
    }
}

function hookHandler() {
    ArsatLog.debug("Hook handler");
    let handlerClass = Java.use("android.os.Handler");
    handlerClass.enqueueMessage.implementation = function (queue: any, msg: any, timeMills: any) {
        let result = this.enqueueMessage(queue, msg, timeMills);
        ArsatLog.log("Handler.enqueueMessage()", msg.hashCode(), true);
        return result;
    }
    handlerClass.dispatchMessage.implementation = function (msg: any) {
        ArsatLog.log("Handler.dispatchMessage()", msg.hashCode());
        this.dispatchMessage(msg);
    }
}

function initThreadStackChain() {
    try {
        hookThread();
        hookHandler();
        hookThreadPoolExecutor();
    } catch (err) {
        ArsatLog.debug(err);
    }
}

export { initThreadStackChain };
