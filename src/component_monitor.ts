import * as ArsatLog from "./log";

function initMonitor() {
    let activityClass = Java.use("android.app.Activity");
    activityClass.onResume.implementation = function () {
        ArsatLog.log("Activity.onResume()", this.getClass().getCanonicalName(), false);
        this.onResume();
    };
    activityClass.onPause.implementation = function () {
        ArsatLog.log("Activity.onPause()", this.getClass().getCanonicalName(), false);
        this.onPause();
    }
}

export { initMonitor };