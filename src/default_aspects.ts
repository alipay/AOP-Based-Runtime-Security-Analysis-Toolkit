import * as ArsatLog from "./log";

type AspectConfig = {
    class: string;
    method: string;
    params: string[];
    handler?: any;
};
const gAspects: AspectConfig[] = [
    // ClipboardManager
    {
        class: "android.content.ClipboardManager",
        method: "getPrimaryClip",
        params: [],
    },
    {
        class: "android.content.ClipboardManager",
        method: "getPrimaryClipDescription",
        params: [],
    },
    {
        class: "android.content.ClipboardManager",
        method: "getText",
        params: [],
    },
    {
        class: "android.text.ClipboardManager",
        method: "getText",
        params: [],
    },
    // PackageInstaller
    {
        class: "android.app.ApplicationPackageManager",
        method: "getInstalledApplications",
        params: ["int"],
    },
    {
        class: "android.app.ApplicationPackageManager",
        method: "getInstalledPackages",
        params: ["int"],
    },
];

function gDefaultAspectHandler(config: AspectConfig, ...params: any[]) {
    let paramsStr = [...config.params].join(",");
    let description = `${config.class}.${config.method}(${paramsStr})`;
    ArsatLog.log(description, true);
}

export { AspectConfig };
export { gAspects };
export { gDefaultAspectHandler };