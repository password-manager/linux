def find_node_reference(json_data, path, timestamp):  # go to the needed path
    tmp_data = json_data
    for folder in path:
        for row in tmp_data:
            if row["type"] == "directory" and row["name"] == folder:
                row["timestamp"] = timestamp  # it is modified, so update the timestamp
                tmp_data = row["data"]
    return tmp_data

def find_exact_node(json_data, name, type):
    for i, row in enumerate(json_data):
        if row["type"] == type and row["name"] == name and "state" not in row.keys():
            return i