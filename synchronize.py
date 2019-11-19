import copy
import base64
import json
from ast import literal_eval

from enum import Enum
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

with open("register.json", "r") as file:
    data_register = json.load(file)
    salt = data_register["salt"]
    email = data_register["email"]
    password = data_register["master_password"]

key = PBKDF2(email + password, salt.encode(), dkLen=16)  # 128-bit key
key = PBKDF2(b"verysecretaeskey", salt, 16, 100000)
cipher = AES.new(key, AES.MODE_ECB)
BLOCK_SIZE = 32

with open("passwords.txt", mode="rb") as passwords:
    data = unpad(cipher.decrypt(base64.b64decode(passwords.read())), BLOCK_SIZE)
    data = literal_eval(data.decode())


def write_data(new_data):
    with open("passwords.txt", "wb") as f:
        encrypted = cipher.encrypt(pad(str(new_data).encode(), BLOCK_SIZE))
        f.write(base64.b64encode(encrypted))


with open("old_state.json", "r") as file:
    old_state_ = json.load(file)[0]

with open("local_state.json", "r") as file:
    local_state_ = json.load(file)[0]

with open("server_state.json", "r") as file:
    server_state_ = json.load(file)[0]

with open("sync_out.json", "r") as file:
    enhanced_new_state_ = json.load(file)


# State synchronize(State old_state, Log[] local_logs,Log[] server_logs)
# 	EnhancedState local_state = new EnhancedState(old_state, local_logs)
# 	EnhancedState server_state = new EnhancedState(old_state, server_logs)
# 	EnhancedState enhanced_new_state = merge_states(old_state, local_state, server_state)
# 	update_server(server_state, enhanced_new_state)
# 	State new_state = clean_state(enhanced_new_state)
# 	save_as_current_state(new_state)
# 	save_as_old_state(new_state)
# 	clear_current_logs()


def synchronize():  # (old_state, local_logs, server_logs)
    """merge two states: old_state with logs from server and old_state with local logs"""
    pass
    # local_state = enhance_state(old_state, local_logs)
    # server_state = enhance_state(old_state, server_logs)
    # enhanced_new_state = merge_states(old_state, local_state, server_state) #todo for now from globals


def merge_states(old_state, local_state, server_state):  # ({},{},{}) -> {}
    if local_state["timestamp"] > server_state["timestamp"]:
        new_state = {"type": local_state["type"], "name": local_state["name"],
                     "data": [], "timestamp": local_state["timestamp"]}
    else:
        new_state = {"type": server_state["type"], "name": server_state["name"],
                     "data": [], "timestamp": server_state["timestamp"]}

    if new_state["type"] == "password":
        if local_state["timestamp"] > server_state["timestamp"]:
            return local_state
        else:
            return server_state

    old_dir = old_state["data"]
    local_dir = local_state["data"]
    server_dir = server_state["data"]

    for i in range(0, len(old_dir)):
        old_node = old_dir[i]
        local_node = local_dir[i]
        server_node = server_dir[i]

        new_node = merge_states(old_node, local_node, server_node)

        if "data" in new_state.keys():
            new_state["data"].append(new_node)
        else:
            new_state["data"] = [new_node]

    for i in range(len(old_dir), len(local_dir)):
        if "state" not in local_dir[i].keys():
            merge_node(new_state, local_dir[i])

    for i in range(len(old_dir), len(server_dir)):
        if "state" not in server_dir[i].keys():
            merge_node(new_state, server_dir[i])
    return new_state


def merge_node(new_state, new_node):
    added = False
    new_dir = new_state["data"]
    if new_node["type"] == "catalog":
        for i, node in enumerate(new_dir):
            if new_node["name"] == node["name"] and node["type"] == "catalog" and "state" not in node.keys():
                empty = {"type": "catalog", "data": []}
                new_dir[i] = merge_states(empty, node, new_node)
                added = True
        if not added:
            new_dir.append(new_node)
    elif new_node["type"] == "password":
        for i, node in enumerate(new_dir):
            if new_node["name"] == node["name"] and node["type"] == "password" and "state" not in node.keys():
                new_dir[i] = merge_states(None, node, new_node)
                added = True
        if not added:
            new_dir.append(new_node)
    return new_state


# def enhance_state(old_state, logs):
#     enhanced_old_state = copy.deepcopy(old_state)
#     for log in logs:
#         if LogType.create_directory.name == "create_directory":
#             create_directory(enhanced_old_state, log.path, log.modified_data)
#         if LogType.create_directory.name == "create_password":
#             create_password(enhanced_old_state, log.path, log.modified_data)
#         if LogType.create_directory.name == "delete":
#             delete_node(enhanced_old_state, log.path, log.modified_data)
#         if LogType.create_directory.name == "modify":
#             modify_node(enhanced_old_state, log.path, log.modified_data)
#         update_timestamp(enhanced_old_state, log.path, log.modified_data)

def create_update_logs(server_state, enhanced_new_state, path):
    update_logs = []
    return create_update_logs_helper(server_state, enhanced_new_state, path, update_logs)


def create_update_logs_helper(server_state, enhanced_new_state, path, update_logs):  # ({}, {}, "", [])
    server_dir = server_state["data"]
    enhanced_new_dir = enhanced_new_state["data"]
    for i in range(0, len(enhanced_new_dir)):
        log = {}
        node = enhanced_new_dir[i]

        if i >= len(server_dir) and "state" not in node.keys(): #jesli nowy
            # update_logs.append(new Log(path, create, enhanced_new_state[i], current_time))
            log["type"] = "create_" + node["type"]
            log["path"] = path
            log["data"] = node  # todo check this!!!
            update_logs.append(log)
        elif i < len(server_dir) and "state" in node.keys(): #jesli usuniety
            log["type"] = "delete_" + node["type"]
            log["path"] = path
            update_logs.append(log) #jesli zmodyfikowany
        elif i < len(server_dir) and (node["name"] != server_dir[i]["name"] or node["data"] != server_dir[i]["data"]):
            log["type"] = "modify_" + node["type"]
            log["path"] = path
            log["data"] = node
            update_logs.append(log)
        if i < len(server_dir) and server_state["type"] == "catalog": #zrob rekursywnie dla katalogow
            name = enhanced_new_state["name"]
            logs = create_update_logs_helper(server_dir[i], enhanced_new_dir[i], path + "/" + name, update_logs)
            update_logs += logs  # todo probably
    # update_logs += create_update_logs(server_state[i], enhanced_new_state[i])
    return update_logs


def update_server(server_state, enhanced_new_state):
    update_logs_res = create_update_logs(server_state, enhanced_new_state, "root")
    send_to_server(update_logs_res)  # todo


def send_to_server(update_logs):
    pass


def parse_log(log):  # todo training purposes: logs[0]
    pass


def perform_operation(state, path, timestamp):
    node_reference = find_node_reference(state, path, timestamp)


def create_directory(state, path, catalog_name, timestamp):
    node_reference = find_node_reference(state, path, timestamp)
    node_reference.append({"type": "catalog", "name": catalog_name, "data": [], "timestamp": timestamp})


def create_password(state, path, new_name, new_password, timestamp):
    node_reference = find_node_reference(state, path, timestamp)
    node_reference.append({"type": "password", "name": new_name, "data": new_password, "timestamp": timestamp})


def delete_password(state, path, name, timestamp):
    node_reference = find_node_reference(state, path, timestamp)
    password_node = find_password_node(node_reference, name)
    password_node["state"] = "DEL"
    password_node["timestamp"] = timestamp


def delete_catalog(state, path, name, timestamp):
    node_reference = find_node_reference(state, path, timestamp)
    catalog_node = find_catalog_node(node_reference, name)
    catalog_node["state"] = "DEL"
    catalog_node["timestamp"] = timestamp


def modify_password(state, path, name, new_name, new_password, timestamp):
    node_reference = find_node_reference(state, path, timestamp)
    password_node = find_password_node(node_reference, name)
    password_node["name"] = new_name
    password_node["data"] = new_password


def modify_catalog(state, path, name, new_name, timestamp):
    node_reference = find_node_reference(state, path, timestamp)
    password_node = find_catalog_node(node_reference, name)
    password_node["name"] = new_name


def update_timestamp(state, path, new_timestamp):
    pass


def find_node_reference(json_data, path, timestamp):  # go to the needed path
    tmp_data = json_data  # we use "pass by reference" python thing
    for folder in path:
        for row in tmp_data:
            if row["type"] == "catalog" and row["name"] == folder:
                row["timestamp"] = timestamp  # it is modified, so update the timestamp
                tmp_data = row["data"]
    return tmp_data


def find_password_node(json_data, name):  # todo possibly prone to errors if it"s not in data
    for row in json_data:
        if row["type"] == "password" and row["name"] == name:
            return row


def find_catalog_node(json_data, name):
    for row in json_data:
        if row["type"] == "catalog" and row["name"] == name:
            return row


if __name__ == "__main__":
    # delete_password_test()

    # res = merge_states(old_state_, local_state_, server_state_)

    # with open("sync_out.json", "w") as f:  # TODO only for debugging purposes
    #     json.dump(res, f)

    update_logs_res1 = create_update_logs(server_state_, enhanced_new_state_, "root")

    with open("sync_in.json", "w") as f:  # TODO only for debugging purposes
        json.dump(update_logs_res1, f)


# create_password, create_catalog, modify_catalog, modify_password, delete_catalog, delete_password
# rozpisac przypadki synchronizacji: ZAWSZE NAJNOWSZE MA ZNACZENIE!!!
# pomyslec o wyjatkach w dodawaniu
# uwzglednianie logow zaczynamy od najstarszego -> dzieki temu bedziemy mieli zgodna strukture z tym co jest na serwerze
# todo nazwa folderu nie moze zawierac slasha
