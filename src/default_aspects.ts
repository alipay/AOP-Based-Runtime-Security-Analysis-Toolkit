import * as ArsatLog from "./log";
import { AspectConfig } from "./default_aspects_config"

function gDefaultAspectHandler(caller_obj: any, config: AspectConfig, ...params: any[]) {
    let paramsStr = "";
    if (config.params !== undefined) {
        paramsStr = [...config.params].join(" ");
    }
    let category = `${config.category}`;
    let aspect = `${config.class}.${config.method}(${paramsStr})`;

    let paramsLogStr = "";
    if (config.params_log !== undefined) {
        for (let pl of config.params_log) {
            if (paramsLogStr !== "") {
                paramsLogStr += " ";
            }
            if (pl.location < 0) {
                paramsLogStr += caller_obj[pl.method]();
            } else {
                paramsLogStr += params[pl.location][pl.method]();
            }
        }
    }

    if (paramsLogStr === "") {
        paramsLogStr = "-";
    }
    ArsatLog.log(aspect, paramsLogStr, true, category);
}

export { AspectConfig };
export { gDefaultAspectHandler };
export { gAspects } from "./default_aspects_config";