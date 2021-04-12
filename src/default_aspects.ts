import * as ArsatLog from "./log";
import { AspectConfig } from "./default_aspects_config"

function gDefaultAspectHandler(config: AspectConfig, ...params: any[]) {
    let paramsStr = "";
    if (config.params !== undefined) {
        paramsStr = [...config.params].join(" ");
    }
    let paramsLogStr = "";
    if (config.params_log !== undefined) {
        for (let pl of config.params_log) {
            if (paramsLogStr !== "") {
                paramsLogStr += " ";
            }
            paramsLogStr += params[pl.location][pl.method]();
        }
    }

    let aspect = `${config.class}.${config.method}(${paramsStr})`;
    if (paramsLogStr === "") {
        paramsLogStr = '-';
    }
    ArsatLog.log(aspect, paramsLogStr, true);
}

export { AspectConfig };
export { gDefaultAspectHandler };
export { gAspects } from "./default_aspects_config";