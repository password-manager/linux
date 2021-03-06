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


def get_dir():
    directory = keyring.get_password("system", "directory")
    return directory


def get_key():
    key = PBKDF2(keyring.get_password("system", "email") + keyring.get_password("system", "master_password"),
                 keyring.get_password("system", "salt").encode(), 16, 100000)  # 128-bit key
    return key

global timestamp

def merge_states(old_state, local_state, server_state):
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
    enhanced_state = copy.deepcopy(state_to_enhance)

    for log in logs:
        timestamp = log["timestamp"]
        perform_operation(enhanced_state, timestamp, log["data"])
    return enhanced_state


def create_update_logs(server_state, enhanced_new_state, path):
    update_logs = []
    set_timestamp()
    return create_update_logs_helper(server_state, enhanced_new_state, path, update_logs)


def create_update_logs_helper(server_state, enhanced_new_state, path,
                              update_logs):
    path = path + "/" + enhanced_new_state["name"]
    server_dir = server_state["data"]
    enhanced_new_dir = enhanced_new_state["data"]
    for i in range(0, len(enhanced_new_dir)):
        deleted = False
        log = {}
        log["timestamp"] = get_timestamp()
        log["data"] = {}
        node = enhanced_new_dir[i]
        if i >= len(server_dir) and "state" not in node.keys():
            node_type = node["type"]

            log["data"]["type"] = "create_" + node_type
            log["data"]["path"] = path + "/" + node["name"]
            log["data"]["node"] = copy.copy(node)
            if node_type == "directory":
                log["data"]["node"]["data"] = []
            log["data"]["timestamp"] = node["timestamp"]
            update_logs.append(log)
        elif i < len(server_dir) and "state" in node.keys():
            log["data"]["type"] = "delete_" + node["type"]
            log["data"]["path"] = path + "/" + node["name"]
            deleted = True
            log["data"]["timestamp"] = node["timestamp"]
            update_logs.append(log)


        elif i < len(server_dir) and (node["name"] != server_dir[i]["name"] or
                                      (node["type"] == "password" and node['data'] != server_dir[i]['data'])):
            node_type = node["type"]
            log["data"]["type"] = "modify_" + node_type
            log["data"]["path"] = path + "/" + server_dir[i]["name"]
            if node_type == "password":
                log["data"]["node"] = node
            elif node_type == "directory":
                log["data"]["new_name"] = node["name"]
            log["data"]["timestamp"] = node["timestamp"]
            update_logs.append(log)

        if 'state' in node.keys():
            deleted = True
        if not deleted and i < len(server_dir) and server_dir[i]["type"] == "directory":
            create_update_logs_helper(server_dir[i], enhanced_new_dir[i], path, update_logs)
        elif not deleted and enhanced_new_dir[i]["type"] == "directory":
            create_update_logs_helper({"data": []}, enhanced_new_dir[i], path, update_logs)
    return update_logs


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

    if operation == "create_password" or operation == "create_directory":
        node_reference = find_node_reference(state, path_as_array[:-1], timestamp)  # don't take the last element
        node_reference.append(node['node'])

    elif operation == "modify_directory" or operation == "modify_password":
        node_reference = find_node_reference(state, path_as_array[:-1], timestamp)
        node_pos = find_exact_node(node_reference, path_as_array[-1], node_type)

        if node_type == "directory":
            node_reference[node_pos]["name"] = node["new_name"]
        elif node_type == "password":
            node_reference[node_pos] = copy.copy(node["node"])

    elif operation == "delete_password" or operation == "delete_directory":
        node_reference = find_node_reference(state, path_as_array[:-1], timestamp)
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


def find_exact_node(json_data, name, type):
    for i, row in enumerate(json_data):
        if row["type"] == type and row["name"] == name:
            return i


def cleanup_state(enhanced_state, state_name):
    data = enhanced_state['data']
    for i, el in enumerate(data):
        node = data[i]
        if node["type"] == "password" and "state" in node.keys() and node["state"] == state_name:
            data.remove(node)
        elif node["type"] == "directory":
            if "state" in node.keys() and node["state"] == state_name:
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
    key = get_key()
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = base64.b64encode(cipher.encrypt(pad(str(data_node).encode('utf-8'), AES.block_size)))
    b64_iv = base64.b64encode(iv)
    return encrypted, b64_iv


def decrypt_data_node(data_node, iv):
    key = get_key()
    raw = base64.b64decode(data_node)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return literal_eval(unpad(cipher.decrypt(raw), AES.block_size).decode('utf-8'))


def write_data(new_data):
    with open(get_dir() + "/passwords.txt", "wb") as f:
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(get_key(), AES.MODE_CBC, iv)
        f.write(base64.b64encode(iv + cipher.encrypt(pad(str(new_data).encode("utf-8"),
                                                         AES.block_size))))


def get_data():
    if os.path.exists(get_dir() + "/passwords.txt"):
        with open(get_dir() + "/passwords.txt", mode="rb") as passwords:
            raw = base64.b64decode(passwords.read())
            cipher = AES.new(get_key(), AES.MODE_CBC, raw[:AES.block_size])
            return literal_eval(unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode("utf-8"))
    else:
        timestamp = time.time()
        data = [[{"type": "directory", "name": "root", "data": [], "timestamp": timestamp}],
                [{"type": "directory", "name": "root", "data": [], "timestamp": timestamp}],
                0]
        return data


def get_logs_from_server(socket):
    passwords_txt_data = get_data()
    last_synchronization = passwords_txt_data[2]
    synchronization_request_time = time.time()
    try:
        socket.sendall(('3:' + str(last_synchronization)).encode())
        logs_from_server = socket.recv(10000).decode()
    except:
        print("You are offline (1)")
    else:
        old_state = passwords_txt_data[0][0]
        local_state = passwords_txt_data[1][0]

        logs_from_server = ast.literal_eval(logs_from_server[2:])

        if logs_from_server:
            process_logs_decrypted(logs_from_server)
            print("LOGS FROM SERVER: " + str(logs_from_server))

            server_state = enhance_state(old_state, logs_from_server)

            res = merge_states(old_state, local_state, server_state)

            cleanup_state(res, "DEL")
            cleanup_state(server_state, "DEL")

            send_logs_to_server_helper(socket, server_state, res)

            passwords_txt_data[0] = [copy.copy(res)]
            passwords_txt_data[1] = [copy.copy(res)]

        passwords_txt_data[2] = synchronization_request_time
        write_data(passwords_txt_data)


def send_logs_to_server(socket):
    passwords_txt_data = get_data()
    old_state = passwords_txt_data[0][0]
    local_state = passwords_txt_data[1][0]

    server_state = copy.deepcopy(old_state)
    res = copy.deepcopy(local_state)
    update_logs_res = create_update_logs(server_state, res, "")
    process_logs(update_logs_res)

    cleanup_state(res, "DEL_LOCAL")
    passwords_txt_data[0] = [copy.deepcopy(res)]
    passwords_txt_data[1] = [copy.deepcopy(res)]

    try:
        if update_logs_res:
            socket.sendall(('4:' + json.dumps(update_logs_res)).encode())
            passwords_txt_data[2] = time.time()
            l = socket.recv(10000)
            write_data(passwords_txt_data)
        else:
            passwords_txt_data[0] = [copy.deepcopy(old_state)]
            write_data(passwords_txt_data)

    except:
        passwords_txt_data[0] = [copy.deepcopy(old_state)]
        write_data(passwords_txt_data)
        print("You are offline (2)")


def send_logs_to_server_helper(socket, server_state, enhanced_state):
    res = enhanced_state
    update_logs_res = create_update_logs(server_state, res, "")
    process_logs(update_logs_res)

    cleanup_state(res, "DEL_LOCAL")

    try:
        if update_logs_res:
            socket.sendall(('4:' + json.dumps(update_logs_res)).encode())
            l = socket.recv(10000)

    except:
        print("You are offline (3)")


if __name__ == "__main__":
    pass
