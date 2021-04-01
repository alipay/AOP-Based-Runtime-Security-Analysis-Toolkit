import * as ArsatLog from "./log";
import { AspectConfig } from "./default_aspects_config"

function gDefaultAspectHandler(config: AspectConfig, ...params: any[]) {
    let paramsStr = "";
    if (config.params !== undefined) {
        paramsStr = [...config.params].join(",");
    }
    let description = `${config.class}.${config.method}(${paramsStr})`;
    ArsatLog.log(description, true);
}

export { AspectConfig };
export { gDefaultAspectHandler };
export { gAspects } from "./default_aspects_config";