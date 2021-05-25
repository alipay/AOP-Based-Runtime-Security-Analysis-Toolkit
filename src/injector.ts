import * as ArsatLog from "./log";
import {AspectConfig, gAspects, gDefaultAspectHandler} from "./default_aspects";

function injectAspects(rconfig: AspectConfig[] | null, aconfig: AspectConfig[] | null) {
    let configs : AspectConfig[] = gAspects;

    if (rconfig !== null && rconfig !== undefined) {
        configs = rconfig;
    } else {
        if (aconfig !== null && aconfig !== undefined) {
            configs = configs.concat(aconfig);
        }
    }
    configs.forEach(config => {
        injectAspect(config);
    });
}

function injectAspect(config: AspectConfig) {
    let targetClass = undefined;
    try {
        targetClass = Java.use(config.class);
    } catch (e) {
        return;
    }
    if (targetClass === undefined) {
        return;
    }
    if (!targetClass.hasOwnProperty(config.method)) {
        // console.log(`Can't find ${config.method} in ${config.class}`);
        return;
    }

    let handler = gDefaultAspectHandler;
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
