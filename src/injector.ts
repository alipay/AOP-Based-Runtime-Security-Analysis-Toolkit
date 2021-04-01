import * as AspectProfile from "./default_aspects";

function injectAspects() {
    AspectProfile.gAspects.forEach(config => {
        injectAspect(config);
    });
}

function injectAspect(config: AspectProfile.AspectConfig) {
    let targetClass = undefined;
    try {
        targetClass = Java.use(config.class);
    } catch (e) {
        console.log(`Can't find ${config.class}`);
    }
    if (targetClass === undefined) {
        return;
    }
    if (!targetClass.hasOwnProperty(config.method)) {
        console.log(`Can't find ${config.method} in ${config.class}`);
        return;
    }

    let handler = config.handler;
    if (handler === undefined) {
        handler = AspectProfile.gDefaultAspectHandler;
    }
    let params = "";
    if (config.params !== undefined) {
        params = [...config.params].join(",");
    }

    console.log(`Start hooking ${config.class}.${config.method}(${params})`);
    if (config.params !== undefined) {
        let ov = targetClass[config.method].overload(...config.params);
        ov.implementation = function (...ps: any[]) {
            handler(config, ...ps);
            return this[config.method](...ps);
        };
    } else {
        if (config.method === "requestSingleUpdates") {
            for (let i of Object.getOwnPropertyNames(targetClass)) {
                console.log(i);
            }
        }
        let overloads = targetClass[config.method].overloads;
        for (let i in overloads) {
            if (overloads[i].hasOwnProperty('argumentTypes')) {
                var parameters = [];
                for (let j in overloads[i].argumentTypes) {
                    parameters.push(overloads[i].argumentTypes[j].className);
                }
                targetClass[config.method].overload.apply('this', parameters).implementation = function (...ps: any[]) {
                    handler(config, ...ps);
                    return this[config.method](...ps);
                };
            }
        }
    }
    console.log(`Hooked ${config.class}.${config.method}(${params})`);
}

export { injectAspects };