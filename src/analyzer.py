#!/usr/bin/env python3

import argparse
import time
import frida
import os
import sqlite3
import sys


g_has_quit = False
g_curr_activity = "unknown"


class Context:
    def __init__(self):
        self.thread_stacktraces = {}
        self.runnables = {}
        self.messages = {}


def get_stack(stack, parent):
    while parent is not None:
        if len(stack) > 0 and stack[-1] == "\n":
            stack = stack[:-1]
        stack += "##"
        stack += parent[4]
        parent = parent[6]
    if len(stack) > 0 and stack[-1] == "\n":
        stack = stack[:-1]
    return stack


def analyze_line(line, context):
    ti, thread_id, aspect, params, stack, category = tuple(line.split(","))
    parent = None
    if thread_id in context.thread_stacktraces:
        parent = context.thread_stacktraces[thread_id]

    if aspect == "Activity.onResume()":
        global g_curr_activity
        g_curr_activity = params
        return None
    elif aspect == "Activity.onPause()":
        return None
    elif aspect == "Thread.start()":
        context.thread_stacktraces[params] = ti, thread_id, aspect, params, stack, category, parent
    elif aspect == "Runnable.begin()":
        if params in context.runnables:
            context.thread_stacktraces[thread_id] = context.runnables[params]
    elif aspect == "Runnable.end()":
        if params in context.runnables:
            del context.runnables[params]
    elif aspect == "ThreadPoolExecutor.execute()":
        context.runnables[params] = ti, thread_id, aspect, params, stack, category, parent
    elif aspect == "Handler.enqueueMessage()":
        handler_black_words = {
            "android.view.View.post(",
            "android.view.Choreographer$FrameDisplayEventReceiver.onVsync(",
        }
        found = False
        for word in handler_black_words:
            if word in stack:
                found = True
                break
        if not found:
            context.messages[params] = ti, thread_id, aspect, params, stack, category, parent
    elif aspect == "Handler.dispatchMessage()":
        if params in context.messages:
            context.thread_stacktraces[thread_id] = context.messages[params]
    else:
        stack = get_stack(stack, parent)
        return ti, aspect, params, stack, category
    return None


def analyze(package, log_filename, db_filename):
    conn = sqlite3.connect(db_filename)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS arsat (time text, aspect text, params text, stacktrace text, category text, entry text, foreground text)")

    context = Context()
    with open(log_filename, "r") as log_file:
        for line in log_file:
            if len(line) > 0 and line[-1] == "\n":
                line = line[:-1]
            data = analyze_line(line, context)
            if data is not None:
                insert_sql = "INSERT INTO arsat VALUES ('{}', '{}', '{}', '{}', '{}', '{entry}', '{foreground}')".format(
                    *data, entry=g_curr_activity, foreground=g_curr_activity)
                cur.execute(insert_sql)

    conn.commit()
    conn.close()


def write_to_file(message):
    now = time.localtime()
    now_str = time.strftime("%Y:%m:%d-%H:%M:%S", now)
    log_file.write(now_str + "," + message)
    log_file.write("\n")


def on_message(message, data):
    # print(message)
    if not g_has_quit and message["type"] == "send":
        write_to_file(message["payload"])


def on_session_off(reason, crash):
    print(reason + " Please stop the monitor by ^C")


def on_device_lost():
    # print("Device disconnected. Please stop the monitor by ^C")
    pass  # Do nothing


def arsat_monitor(arg):
    package = arg.package
    output_dir = os.getcwd() if arg.output is None else arg.output
    log_filename = output_dir + "/" + package + ".log"
    db_filename = output_dir + "/" + package + ".db"

    global log_file
    try:
        log_file = open(log_filename, "w")
    except:
        print("Can't create log file!")
        sys.exit(1)

    try:
        device = frida.get_usb_device()
        print("[*] Found device: {}".format(device.name))
        pid = device.spawn([package])
        session = device.attach(pid)
        device.on("lost", on_device_lost)
        session.on("detached", on_session_off)

        self_path = os.path.abspath(sys.argv[0])
        self_dir = self_path[:self_path.rfind("/")]
        script_path = self_dir + "/../dist/agent.js"
        script_content = open(script_path).read()
        script = session.create_script(script_content)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
    except Exception as e:
        print(e)
        sys.exit(1)

    try:
        while True:
            sys.stdin.read()
    except KeyboardInterrupt:
        print("[-] Quit monitor.")
    global g_has_quit
    g_has_quit = True

    print("[-] Start analyzing...")

    log_file.close()
    analyze(package, log_filename, db_filename)
    os.remove(log_filename)
    print("[-] Done. Output: {}".format(db_filename))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", help="application package name")
    parser.add_argument("-o", "--output", help="output path")
    args = parser.parse_args()

    arsat_monitor(args)


if __name__ == "__main__":
    main()
