// Thread stack chain utils.
// All functions in thie file **MUST** be called inside Java.perform().

import * as ArsatLog from "./log";

function hookThread() {
    console.log("Hook Thread.start");

    let threadClass = Java.use("java.lang.Thread");
    threadClass.start.implementation = function () {
        let id = this.getId();
        let name = this.getName();
        let threadId = id + "-" + name;
        let hash = this.hashCode();
        ArsatLog.log("Thread.start()", `${threadId}-${hash}`, true);
        this.start();
    }
    /*
    threadClass.run.implementation = function () {
        let hash = this.hashCode();
        ArsatLog.log("Thread.run()", hash);
        this.run();
    }
    */
}

function executorsFilter(name: string, candidateClass: any, candidateClazz: any) {
    let interfaces = candidateClazz.getInterfaces();
    for (const inter of interfaces) {
        if (inter.getCanonicalName() == "java.util.concurrent.Executor") {
            return true;
        }
        if (executorsFilter(name, candidateClass, candidateClazz)) {
            return true;
        }
    }
    return false;
}

function executorsHooker(name: string, executorClass: any) {
    console.log("Hook " + name);
    executorClass.execute.overload("java.lang.Runnable").implementation = function (runnable: any) {
        ArsatLog.log("Executor.execute(),", runnable.hashCode(), true);
        this.execute(runnable);
    }
}

function findAndHookMethod(pattern: string, filter: any, hooker: any) {
    const clazzClass = Java.use("java.lang.Class");
    const modifierClass = Java.use("java.lang.reflect.Modifier");
    const groups = Java.enumerateMethods(pattern);
    for (const group of groups) {
        let loader = group.loader;
        for (const cla of group.classes) {
            let factory = Java.ClassFactory.get(loader);
            let candidateClass = factory.use(cla.name);
            let candidateClazz = candidateClass.class;
            if (modifierClass.isAbstract(candidateClazz.getModifiers())) {
                console.log(cla.name + " is abstract");
                continue;
            }
            if (!filter(cla.name, candidateClass, candidateClazz)) {
                console.log(cla.name + " not match");
                continue;
            }
            hooker(cla.name, candidateClass);
        }
    }
}

function checkRunnable(runnableClazz: any): boolean {
    let interfaces = runnableClazz.getInterfaces();
    for (const inter of interfaces) {
        if (inter.getCanonicalName() === "java.lang.Runnable") {
            return true;
        }
        if (checkRunnable(inter)) {
            return true;
        }
    }
    return false;
}

var runnableBlackList = [
    "android.view.Choreographer$FrameDisplayEventReceiver",
    "android.view.ViewRootImpl$TraversalRunnable",
];
function runnableHooker(name: string, runnableClass: any) {
    console.log("hook " + name);
    runnableClass.run.overload().implementation = function () {
        ArsatLog.log("Runnable.begin()", this.hashCode());
        this.run();
        ArsatLog.log("Runnable.end()", this.hashCode());
    }
}
function runnableFilter(name: string, candidateClass: any, candidateClazz: any) {
    for (let black of runnableBlackList) {
        if (black === name) {
            return false;
        }
    }
    return checkRunnable(candidateClazz);
}

function hookThreadPoolExecutor() {
    let exectorClass = Java.use("java.util.concurrent.ThreadPoolExecutor");
    let objectClass = Java.use("java.lang.Object");
    exectorClass.execute.overload("java.lang.Runnable").implementation = function (runnable: any) {
        let obj = Java.cast(runnable, objectClass);
        let hashCode = obj.hashCode();
        ArsatLog.log("ThreadPoolExecutor.execute()", hashCode, true);
        this.execute(runnable);
        //ArsatLog.log("ThreadPoolExecutor.execute end.")
    }
}

function hookAllThreadSwitch() {
    /* Record all threads switch point. */
    // Thread
    hookThread();
    hookThreadPoolExecutor();
}

function hookAllRunnables() {
    console.log("Hook all runnable");
    findAndHookMethod("*!run", runnableFilter, runnableHooker);
}

function hookAllHandlers() {
    console.log("Hook all handlers");
    let handlerClass = Java.use("android.os.Handler");
    handlerClass.enqueueMessage.implementation = function (queue: any, msg: any, timeMills: any) {
        let result = this.enqueueMessage(queue, msg, timeMills);
        ArsatLog.log("Handler.enqueueMessage()", msg.hashCode(), true);
        return result;
    }
    handlerClass.dispatchMessage.implementation = function (msg: any) {
        ArsatLog.log("Handler.dispatchMessage()", msg.hashCode(), true);
        this.dispatchMessage(msg);
    }
}

function initThreadStackChain() {
    hookAllThreadSwitch();
    hookAllRunnables();
    hookAllHandlers();
}

export { initThreadStackChain };