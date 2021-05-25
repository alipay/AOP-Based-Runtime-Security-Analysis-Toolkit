import * as ArsatLog from "./log";
import * as ThreadChain from "./thread_chain";
import * as Injector from "./injector";
import * as ComponentMonitor from "./component_monitor";
import {AspectConfig, is_valid_config} from "./default_aspects";

// Entry point.
function arsat_init(chain: boolean, rconfig: AspectConfig[]|null, aconfig: AspectConfig[]|null) {
    Java.perform(function() {
        ArsatLog.print("[*] Arsat 0.0.1");

        if (chain) {
            ArsatLog.print("[*] Preparing cross-thread stack trace handler...");
            ThreadChain.initThreadStackChain();
        }

        ArsatLog.print("[*] Preparing Compontent monitor...");
        ComponentMonitor.initMonitor();

        ArsatLog.print("[*] Generating proxy...");
        Injector.injectAspects(rconfig, aconfig);

        ArsatLog.print("[*] Start the monitoring...(Press enter to quit.)");
    });
}

rpc.exports = {
    init(chain: boolean, rconfig: any, aconfig: any) {
        let replace_config: AspectConfig[] | null = null;
        let extra_config: AspectConfig[] | null = null;
        try {
            if (rconfig !== null && rconfig !== undefined) {
                replace_config = JSON.parse(rconfig);
                if (! is_valid_config(replace_config)) {
                    throw "unknown config";
                }
            }
            if (aconfig !== null && aconfig !== undefined) {
                extra_config = JSON.parse(aconfig);
                if (! is_valid_config(extra_config)) {
                    throw "unknown config";
                }
            }
        } catch (err) {
            ArsatLog.print("[*] Invalide config file: " + err);
            return false;
        }
        arsat_init(chain, replace_config, extra_config);
        return true;
    }
}
