#!/usr/bin/env python3

import re
import subprocess
import binascii
import bson
import sys
import pprint
import datetime

wt_path = "/usr/local/bin/wt"
ksdecode_path = ""
timestamp = None
time_now  = datetime.datetime.now().strftime('%m%d%Y%H%M%S') 

def prompt_timestamp():
    global timestamp

    new_timestamp = input("Timestamp to read data at (leave empty for latest): ")

    if not new_timestamp:
        timestamp = None
        return

    if new_timestamp.isnumeric():
        timestamp = int(new_timestamp)
        return

    found = re.compile("(\d+), ?(\d+)").findall(new_timestamp)
    if found:
        secs, inc = found[0]
        timestamp = (int(secs) << 32) + int(inc)
        return

    print("Unable to interpret timestamp", new_timestamp)


def timestamp_str():
    return (
        "Timestamp({}, {})".format(timestamp >> 32, timestamp % (1 << 32))
        if timestamp
        else ""
    )


def process_dump(
    proc,
    handle_key=lambda key: None,
    handle_value=lambda value: None,
    handle_key_value=lambda key, value: None,
):
    while True:
        line = proc.stdout.readline().decode("utf-8").strip()

        if not line:
            print("No data section")
            sys.exit(1)

        if line == "Data":
            break

    while True:
        key = proc.stdout.readline().strip()

        if not key:
            break

        value = proc.stdout.readline().strip()

        handle_key(key)
        handle_value(value)
        handle_key_value(key, value)


def dump(ident):
    dump_cmd = [
        wt_path,
        "-r",
        "-C",
        "log=(compressor=snappy,path=journal)",
        "-h",
        data_path,
        "dump",
        "-x",
    ]

    if timestamp:
        dump_cmd.append("-t")
        dump_cmd.append(str(timestamp))

    dump_cmd.append("table:" + ident)

    return subprocess.Popen(
        dump_cmd,
        stdout=subprocess.PIPE,
    )


def dump_write(
    ident,
    decode_key=lambda key: key,
    decode_value=lambda value: value,
    extra=lambda write, key, value: None,
    file=""
):
    dump_ident = dump(ident)

    def write_key(write, key):
        write("Key:\t%s\n" % (decode_key(key),))

    def write_value(write, value):
        write("Value:\t%s\n" % (decode_value(value),))

    def run_extra(write, key, value):
        extra(write, key, value)

    if file:
        with open(file, "w") as f:
            process_dump(
                dump_ident,
                lambda key: write_key(f.write, key),
                lambda value: write_value(f.write, value),
                lambda key, value: run_extra(f.write, key, value),
            )
    else:
        def print_without_newline(value):
            print(value, end="")  
        process_dump(
            dump_ident,
            lambda key: write_key(print_without_newline, key),
            lambda value: write_value(print_without_newline, value),
            lambda key, value: run_extra(print_without_newline, key, value),
        )


def decode_to_bson(data):
    return bson.decode(binascii.a2b_hex(data))


def format_to_bson(data):
    return "\n\t" + pprint.pformat(decode_to_bson(data)).replace("\n", "\n\t")


def get_string_width(text):
    return max(map(lambda line: len(line), text.splitlines()))


def explore_index(entry, index, position):
    collection_msg = "Collection " + entry["ns"]
    index_msg = "Index " + index
    timestamp_msg = timestamp_str()
    header_width = max(len(collection_msg), len(index_msg), len(timestamp_msg))


    def get_catalog_entry():
        return entry["md"]["indexes"][position]

    def write_decoded_key(write, key, value):
        if not ksdecode_path:
            return
        if index == "_id_":
            key += value[:4]
            value = value[-2:]
        ksdecode = subprocess.run(
            [
                ksdecode_path,
                "-o",
                "bson",
                "-p",
                pprint.pformat(get_catalog_entry()["spec"]["key"]),
                "-t",
                value,
                "-r",
                "string"
                if "clusteredIndex" in entry["md"]["options"]
                else "long",
                key,
            ],
            capture_output=True,
        )
        write("Decoded:\n\t" + ksdecode.stdout.decode("utf-8").strip() + "\n")

    index_file = "{}_{}.json".format(time_now,entry["idxIdent"][index])
    dump_write(entry["idxIdent"][index], extra=write_decoded_key,file=index_file)
    print(("->New output file created ({})").format(index_file))


def explore_collection(entry):
    collection_msg = "Collection " + entry["ns"]
    timestamp_msg = timestamp_str()
    header_width = max(len(collection_msg), len(timestamp_msg))

    indexes = []
    if "idxIdent" in entry:
        for index in entry["idxIdent"]:
            indexes.append(index)

    while True:
        print("*" * header_width)
        print(collection_msg)
        if timestamp_msg:
            print(timestamp_msg)
        print("*" * header_width)
        print("(b) back")
        print("(c) catalog entry")
        print("(d) dump collection")
        print("(i) ident")
        print("(q) quit")

        for i, index in enumerate(indexes):
            print("(" + str(i) + ") " + index)

        cmd = input("Choose something to do: ")

        if cmd == "b":
            return

        elif cmd == "c":
            print(pprint.pformat(entry))

        elif cmd == "d":
            dump_write(entry["ident"], decode_value=format_to_bson)

        elif cmd == "i":
            print(entry["ident"])

        elif cmd == "q":
            sys.exit(0)

        elif cmd.isnumeric() and int(cmd) < len(entries):
            explore_index(entry, indexes[int(cmd)], int(cmd))

        else:
            print("Unrecognized command " + cmd)


def load_catalog():
    entries = []

    dump_catalog = dump("_mdb_catalog")
    process_dump(
        dump_catalog, handle_value=lambda entry: entries.append(decode_to_bson(entry))
    )
    dump_catalog.wait()

    return entries

try:
    if(sys.argv[1]):
        data_path = sys.argv[1]
        print(("Data path : {}").format(data_path))
        entries = load_catalog()
    if(sys.argv[2]):
        myColl = sys.argv[2]
        for entry in entries:
            if entry["md"]["ns"] == myColl:
                print(("Read collection: {}").format(myColl))
                try:
                    if sys.argv[3]:
                        pass
                except IndexError: 
                        collection_file = "{}_{}.json".format(time_now,entry["ns"])
                        dump_write(entry["ident"], decode_value=format_to_bson,file=collection_file)
                        print(("->New output file created ({})").format(collection_file))
                break
        else:
            raise Exception("Collection is unknown")
    if(sys.argv[3]):
        myIndex = sys.argv[3]
        
        for k,v in enumerate(entry["md"]["indexes"]):
            if v["spec"]["name"] == myIndex:
                explore_index(entry, myIndex, k)
                break
        else:
            raise Exception("Index is unknown")
except IndexError:
    if not data_path:
        print("Path is missing")
        quit()
    if len(sys.argv) == 2:
        print("Collection list:")
        for index in entries: 
            for k,v in index["idxIdent"].items(): print(("    {} {} {} {}").format(index["md"]["ns"],index["ident"],k,v,))