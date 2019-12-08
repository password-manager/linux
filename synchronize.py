import ast
import copy
import base64
import json
import os
import socket
import time
import keyring
from ast import literal_eval

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# with open("register.json", "r") as file:
#     data_register = json.load(file)
#     salt = data_register["salt"]
#     email = data_register["email"]
#     password = data_register["master_password"]
#
# key_old = PBKDF2(email + password, salt.encode(), dkLen=16)  # 128-bit key
# key_old = PBKDF2(b"verysecretaeskey", salt, 16, 100000)
from socket_server import SocketServer

directory = keyring.get_password("system", "directory")
key = PBKDF2(keyring.get_password("system", "email") + keyring.get_password("system", "master_password"),
             keyring.get_password("system", "salt").encode(), 16, 100000)  # 128-bit key

# cipher = AES.new(key_old, AES.MODE_ECB)
BLOCK_SIZE = 32

# with open("passwords.txt", mode="rb") as passwords:
#     data = unpad(cipher.decrypt(base64.b64decode(passwords.read())), BLOCK_SIZE)
#     data = literal_eval(data.decode())
#
#
# def write_data(new_data):
#     with open("passwords.txt", "wb") as f:
#         encrypted = cipher.encrypt(pad(str(new_data).encode(), BLOCK_SIZE))
#         f.write(base64.b64encode(encrypted))


# with open("old_state.json", "r") as file:
#     old_state_ = json.load(file)[0]
#
# with open("local_state.json", "r") as file:
#     local_state_ = json.load(file)[0]

# with open("server_state.json", "r") as file:
#     server_state_ = json.load(file)[0]

# with open("states.json", "r") as file:
#     states_ = json.load(file)

# with open("sync_in.json", "r") as file:
#     logs_ = json.load(file)

# with open("processed_logs.json", "r") as file:
#     logs_processed_ = json.load(file)

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
                new_dir[i] = merge_states(empty, new_node, node)
                added = True
        if not added:
            new_dir.append(new_node)
    elif new_node["type"] == "password":
        for i, node in enumerate(new_dir):
            if new_node["name"] == node["name"] and node["type"] == "password" and "state" not in node.keys():
                new_dir[i] = merge_states(None, new_node, node)
                added = True
        if not added:
            new_dir.append(new_node)
    return new_state


def enhance_state(state_to_enhance, logs):
    enhanced_state = copy.deepcopy(state_to_enhance)  # todo uzycie deepcoopy
    # set_timestamp()
    # timestamp = get_timestamp()
    for log in logs:
        timestamp = log["timestamp"]
        perform_operation(enhanced_state, timestamp, log["data"])
    return enhanced_state
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
        deleted = False
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
            deleted = True
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

        if not deleted and i < len(server_dir) and server_dir[i][
            "type"] == "directory":  # zrob rekursywnie dla katalogow
            create_update_logs_helper(server_dir[i], enhanced_new_dir[i], path, update_logs)
        elif not deleted and enhanced_new_dir[i]["type"] == "directory":
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


def cleanup_state(enhanced_state, state_name):  # in: {} operates on references of data
    data = enhanced_state['data']
    for i, el in enumerate(data):
        node = data[i]
        if node["type"] == "password" and "state" in node.keys() and node["state"] == state_name:
            data.remove(node)
        elif node["type"] == "directory":
            if "state" in node.keys() and node["state"] == "DEL":
                data.remove(node)
            else:
                cleanup_state(node, state_name)


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

def write_data(new_data):
    with open(directory + "/passwords.txt", "wb") as f:
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        f.write(base64.b64encode(iv + cipher.encrypt(pad(str(new_data).encode("utf-8"),
                                                         AES.block_size))))


def get_data():
    if os.path.exists(directory + "/passwords.txt"):
        with open(directory + "/passwords.txt", mode="rb") as passwords:
            raw = base64.b64decode(passwords.read())
            cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
            return literal_eval(unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode("utf-8"))
    else:
        timestamp = time.time()
        data = [[{"type": "directory", "name": "root", "data": [], "timestamp": timestamp}],
                [{"type": "directory", "name": "root", "data": [], "timestamp": timestamp}]]
        # write_data(data)
        return data



if __name__ == "__main__":
    s = SocketServer.get_instance()
    s.post(('3:' + '1575676022.118071').encode())
    logs_from_server = s.get(1024).decode()
    print("DONE")

    states = get_data()
    old_state = states[0][0]
    local_state = states[1][0]

    logs_from_server = ast.literal_eval(logs_from_server[2:])
    process_logs_decrypted(logs_from_server)
    print(logs_from_server)

    server_state = enhance_state(old_state, logs_from_server)
    with open("server_state.json", "w") as f:  # TODO only for debugging purposes
        json.dump(server_state, f)

    res = merge_states(old_state, local_state, server_state)
    with open("sync_out.json", "w") as f:  # TODO only for debugging purposes
        json.dump(res, f)

    cleanup_state(res, "DEL")
    cleanup_state(server_state, "DEL")

    update_logs_res = create_update_logs(server_state, res, "")
    # with open("decrypted_logs.json", "w") as f:  # TODO only for debugging purposes
    #     json.dump(update_logs_res, f)
    #
    # cleanup_state(res, "DEL_LOCAL")

    #
    # process_logs(logs_)
    # with open("encrypted_logs.json", "w") as f:  # TODO only for debugging purposes
    #     json.dump(logs_, f)

    with open("decrypted_logs.json", "w") as f:  # TODO only for debugging purposes
        json.dump(update_logs_res, f)

    process_logs(update_logs_res)

    print(update_logs_res)

    s.post(('4:' + json.dumps(update_logs_res)).encode())

    #todo write to file, so as to read it for GUI!!!!!
