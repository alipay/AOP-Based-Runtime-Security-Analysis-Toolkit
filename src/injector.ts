import * as AspectProfile from "./default_aspects";
import * as ArsatLog from "./log";

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
        // ignore
        // console.log(`Can't find ${config.class}`);
    }
    if (targetClass === undefined) {
        return;
    }
    if (!targetClass.hasOwnProperty(config.method)) {
        // console.log(`Can't find ${config.method} in ${config.class}`);
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

    ArsatLog.debug(`Start hooking ${config.class}.${config.method}(${params})`);
    if (config.params !== undefined) {
        let ov = targetClass[config.method].overload(...config.params);
        ov.implementation = function (...ps: any[]) {
            handler(this, config, ...ps);
            return this[config.method](...ps);
        };
        ArsatLog.debug(`Hooked ${config.class}.${config.method}(${params})`);
    } else {
        let overloads = targetClass[config.method].overloads;
        let count = 0;
        for (let i of overloads) {
            i.implementation = function (...ps: any[]) {
                handler(this, config, ...ps);
                return this[config.method](...ps);
            }
            ++count;
        }
        ArsatLog.debug(`Hooked ${count} overloads of ${config.class}.${config.method}(${params})`);
    }
}

export { injectAspects };