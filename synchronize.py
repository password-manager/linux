import copy
import base64
import json
import time
from ast import literal_eval

from enum import Enum
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
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

with open("states.json", "r") as file:
    states_ = json.load(file)

with open("sync_in.json", "r") as file:
    logs_ = json.load(file)

with open("processed_logs.json", "r") as file:
    logs_processed_ = json.load(file)

global timestamp


# with open("sync_out.json", "r") as file:
#     enhanced_new_state_ = json.load(file)


def synchronize(states, server_logs_):
    """
    EnhancedState local_state = new EnhancedState(old_state, local_logs)
    EnhancedState server_state = new EnhancedState(old_state, server_logs)
    EnhancedState enhanced_new_state = merge_states(old_state, local_state, server_state)
    update_server(server_state, enhanced_new_state)
    State new_state = clean_state(enhanced_new_state)
    save_as_current_state(new_state)
    save_as_old_state(new_state)
    clear_current_logs()
    """
    pass
    # local_state = states["local_state"] # this one is enhanced
    # old_state = states["old_state"] #this one is never enhanced
    # server_state = enhance_state(old_state, server_logs)
    # states["server_state"] = server_state #todo
    # enhanced_new_state = merge_states(old_state, local_state, server_state) #todo for now from globals
    # new_state = diminish_state(enhanced_new_state) #when sth is deleted -> delete it :p
    # states[0] =
    # states[1] = new_state #local is updated
    # states[2] = new_state #last_remote is updated


def merge_states(old_state, local_state, server_state):  # ({},{},{}) -> {}
    if local_state["timestamp"] > server_state["timestamp"]:
        new_state = {"type": local_state["type"], "name": local_state["name"],
                     "data": [], "timestamp": local_state["timestamp"]}
        if 'state' in local_state:
            new_state['state'] = local_state['state']
    else:
        new_state = {"type": server_state["type"], "name": server_state["name"],
                     "data": [], "timestamp": server_state["timestamp"]}
        if 'state' in server_state:
            new_state['state'] = server_state['state']

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

    for i in range(len(old_dir), len(server_dir)):
        if "state" not in server_dir[i].keys():
            merge_node(new_state, server_dir[i])

    for i in range(len(old_dir), len(local_dir)):
        if "state" not in local_dir[i].keys():
            merge_node(new_state, local_dir[i])
    return new_state


def merge_node(new_state, new_node):
    added = False
    new_dir = new_state["data"]
    if new_node["type"] == "directory":
        for i, node in enumerate(new_dir):
            if new_node["name"] == node["name"] and node["type"] == "directory" and "state" not in node.keys():
                empty = {"type": "directory", "data": []}
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


def enhance_state(state_to_enhance, logs):
    # enhanced_state = copy.deepcopy(state_to_enhance)  # todo uzycie deepcoopy
    # set_timestamp()
    # timestamp = get_timestamp()
    for log in logs:
        timestamp = log["timestamp"]
        perform_operation(state_to_enhance, timestamp, log["data"])
    # todo when update timestamp


def create_update_logs(server_state, enhanced_new_state, path):
    update_logs = []
    set_timestamp()
    return create_update_logs_helper(server_state, enhanced_new_state, path, update_logs)


def create_update_logs_helper(server_state, enhanced_new_state, path,
                              update_logs):  # ({}, {}, "", []) przekazuje przez referencje, wiec nic nie zwracam
    path = path + "/" + enhanced_new_state["name"]
    server_dir = server_state["data"]
    enhanced_new_dir = enhanced_new_state["data"]
    for i in range(0, len(enhanced_new_dir)):  # przerwie sie jesli data to []
        log = {}
        log["timestamp"] = get_timestamp()
        log["data"] = {}
        node = enhanced_new_dir[i]
        if i >= len(server_dir) and "state" not in node.keys():  # jesli nowy
            node_type = node["type"]

            log["data"]["type"] = "create_" + node_type
            log["data"]["path"] = path + "/" + node["name"]
            log["data"]["node"] = copy.copy(node)
            if node_type == "directory":
                log["data"]["node"]["data"] = []  # make the inside empty
            update_logs.append(log)
        elif i < len(server_dir) and "state" in node.keys():  # jesli usuniety, nie trzeba podawac pola "data"
            log["data"]["type"] = "delete_" + node["type"]
            log["data"]["path"] = path + "/" + node["name"]
            update_logs.append(log)


        elif i < len(server_dir) and (node["name"] != server_dir[i]["name"] or
                                      (node["type"] == "password" and node['data'] != server_dir[i]['data'])):
            # jesli zmodyfikowane haslo -> jego nazwa lub haslo-haslo
            node_type = node["type"]
            log["data"]["type"] = "modify_" + node_type
            log["data"]["path"] = path + "/" + server_dir[i]["name"]  # todo old name
            if node_type == "password":
                log["data"]["node"] = node
            elif node_type == "directory":
                log["data"]["new_name"] = node["name"]
            update_logs.append(log)

        if i < len(server_dir) and server_dir[i]["type"] == "directory":  # zrob rekursywnie dla katalogow
            create_update_logs_helper(server_dir[i], enhanced_new_dir[i], path, update_logs)
        elif enhanced_new_dir[i]["type"] == "directory":
            create_update_logs_helper({"data": []}, enhanced_new_dir[i], path, update_logs)
    return update_logs


def update_server(server_state, enhanced_new_state):
    update_logs_res = create_update_logs(server_state, enhanced_new_state, "root")
    send_to_server(update_logs_res)  # todo


def send_to_server(update_logs):
    pass


def set_timestamp():
    global timestamp
    timestamp = time.time()


def get_timestamp():
    global timestamp
    return timestamp


def perform_operation(state, timestamp, node):
    operation = node["type"]
    path_as_string = node["path"]
    path_as_array = path_as_string[1:].split('/')  # omit the first slash and the last elem

    node_type = operation.split('_')[1]

    if operation == "create_password" or operation == "create_directory":  # err mod
        node_reference = find_node_reference(state, path_as_array[:-1], timestamp)  # don't take the last element
        node_reference.append(node['node'])  # todo modify the timestamp

    elif operation == "modify_directory" or operation == "modify_password":
        node_reference = find_node_reference(state, path_as_array[:-1], timestamp)  # don't take the last element
        node_pos = find_exact_node(node_reference, path_as_array[-1], node_type)

        if node_type == "directory":
            node_reference[node_pos]["name"] = node["new_name"]
        elif node_type == "password":
            node_reference[node_pos] = copy.copy(node["node"])  # todo rethink this

    elif operation == "delete_password" or operation == "delete_directory":
        node_reference = find_node_reference(state, path_as_array[:-1], timestamp)  # don't take the last element
        node_pos = find_exact_node(node_reference, path_as_array[-1], node_type)
        node_reference[node_pos]["state"] = "DEL"


def find_node_reference(json_data, path, timestamp):
    tmp_data = json_data['data']
    for folder in path:
        for row in tmp_data:
            if row["type"] == "directory" and row["name"] == folder:
                row["timestamp"] = timestamp  # it is modified, so update the timestamp
                tmp_data = row["data"]
    return tmp_data


def find_exact_node(json_data, name, type):  # todo possibly prone to errors if it"s not in data
    for i, row in enumerate(json_data):
        if row["type"] == type and row["name"] == name:
            return i


def cleanup_state(enhanced_state):  # in: {} operates on references of data
    data = enhanced_state['data']
    for i, el in enumerate(data):
        node = data[i]
        if node["type"] == "password" and "state" in node.keys():
            data.remove(node)
        elif node["type"] == "directory":
            if "state" in node.keys():
                data.remove(node)
            else:
                cleanup_state(node)


def process_logs(logs):
    for i, log in enumerate(logs):
        encryption_result = encrypt_data_node(log["data"])
        logs[i]["data"] = encryption_result[0].decode("utf-8")
        logs[i]["IV"] = encryption_result[1].decode("utf-8")


def process_logs_decrypted(logs):
    for i, log in enumerate(logs):
        iv = base64.b64decode(log["IV"])
        decryption_result = decrypt_data_node(log["data"], iv)
        logs[i]["data"] = decryption_result

def encrypt_data_node(data_node):
    key = b'Sixteen byte key'  # todo to bedzie ten key jak wszedzie
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = base64.b64encode(cipher.encrypt(pad(str(data_node).encode('utf-8'), AES.block_size)))
    b64_iv = base64.b64encode(iv)
    return encrypted, b64_iv


def decrypt_data_node(data_node, iv):
    key = b'Sixteen byte key'  # todo to bedzie ten key jak wszedzie
    raw = base64.b64decode(data_node)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return literal_eval(unpad(cipher.decrypt(raw), AES.block_size).decode('utf-8'))


if __name__ == "__main__":
    res = merge_states(old_state_, local_state_, server_state_)
    with open("sync_out.json", "w") as f:  # TODO only for debugging purposes
        json.dump(res, f)
    #
    update_logs_res1 = create_update_logs(server_state_, res, "")

    with open("sync_in.json", "w") as f:  # TODO only for debugging purposes
        json.dump(update_logs_res1, f)

    process_logs(update_logs_res1)
    with open("logs.json", "w") as f:  # TODO only for debugging purposes
        json.dump(update_logs_res1, f)

    process_logs_decrypted(update_logs_res1)
    with open("sync_in.json", "w") as f:  # TODO only for debugging purposes
        json.dump(update_logs_res1, f)