import * as AspectProfile from "./default_aspects";

function injectAspects() {
    AspectProfile.gAspects.forEach(config => {
        injectAspect(config);
    });
}

function injectAspect(config: AspectProfile.AspectConfig) {
    let targetClass = Java.use(config.class);
    if (targetClass === undefined) {
        return;
    }
    let handler = config.handler;
    if (handler === undefined) {
        handler = AspectProfile.gDefaultAspectHandler;
    }
    let params = [...config.params].join(",");
    console.log(`Hook ${config.class}.${config.method}(${params})`);
    let ov = targetClass[config.method].overload(...config.params);
    ov.implementation = function (...ps: any[]) {
        handler(config, ...ps);
        return this[config.method](...ps);
    };
}

export { injectAspects };