#!/usr/bin/env python3

import argparse
import time
import frida
import sqlite3
import sys


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
        parent = parent[5]
    return stack


def analyze_line(line, context):
    ti, thread_id, aspect, params, stack = tuple(line.split(","))
    parent = None
    if thread_id in context.thread_stacktraces:
        parent = context.thread_stacktraces[thread_id]

    if aspect == "Thread.start()":
        context.thread_stacktraces[params] = ti, thread_id, aspect, params, stack, parent
    elif aspect == "Runnable.begin()":
        if params in context.runnables:
            context.thread_stacktraces[thread_id] = context.runnables[params]
    elif aspect == "Runnable.end()":
        if params in context.runnables:
            del context.runnables[params]
    elif aspect == "ThreadPoolExecutor.execute()":
        context.runnables[params] = ti, thread_id, aspect, params, stack, parent
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
            context.messages[params] = ti, thread_id, aspect, params, stack, parent
    elif aspect == "Handler.dispatchMessage()":
        if params in context.messages:
            context.thread_stacktraces[thread_id] = context.messages[params]
    else:
        stack = get_stack(stack, parent)
        print(ti, aspect, params)
        print("    " + stack)
        return ti, aspect, params, stack
    return None


def analyze(package, log_filename):
    conn = sqlite3.connect(package + ".db")
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS arsat (time text, aspect text, params text, stacktrace text)")

    context = Context()
    with open(log_filename, "r") as log_file:
        for line in log_file:
            data = analyze_line(line, context)
            if data is not None:
                insert_sql = "INSERT INTO arsat VALUES ('{}', '{}', '{}', '{}')".format(
                    *data)
                print(insert_sql)
                cur.execute(insert_sql)

    conn.commit()
    conn.close()


def write_to_file(message):
    now = time.localtime()
    now_str = time.strftime("%Y:%m:%d-%H:%M:%S", now)
    log_file.write(now_str + "," + message)
    log_file.write("\n")


def on_message(message, data):
    # print(message["payload"])
    # if message["payload"].startswith("ARSAT:"):
    if message["type"] == "send":
        write_to_file(message["payload"])


def arsat_monitor(package):
    global log_file
    filename = package + ".log"
    try:
        log_file = open(filename, "w")
    except:
        print("Can't create log file!")
        sys.exit(1)

    session = frida.get_usb_device().attach(package)
    script_content = open("dist/agent.js").read()
    script = session.create_script(script_content)
    script.on("message", on_message)
    script.load()
    try:
        while True:
            sys.stdin.read()
    except KeyboardInterrupt:
        print("Quit monitor.")

    print("Start analyzing...")

    log_file.close()
    analyze(package, filename)
    log_file.close()
    print("Done.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", help="application package name")
    args = parser.parse_args()

    arsat_monitor(args.package)


if __name__ == "__main__":
    main()
