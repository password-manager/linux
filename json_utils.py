def find_node_reference(json_data, path, timestamp):  # go to the needed path
    tmp_data = json_data #todo['data']  bez tego dziala dla tego co jest w 'manage folder'
    for folder in path:
        for row in tmp_data:
            if row["type"] == "directory" and row["name"] == folder:
                row["timestamp"] = timestamp  # it is modified, so update the timestamp
                tmp_data = row["data"]
    return tmp_data


# def find_password_node(json_data, name):  # todo possibly prone to errors if it"s not in data
#     for i, row in enumerate(json_data):
#         if row["type"] == "password" and row["name"] == name and "state" not in row.keys():
#             return i
#
#
# def find_directory_node(json_data, name):
#     for i, row in enumerate(json_data):
#         if row["type"] == "directory" and row["name"] == name and "state" not in row.keys():
#             return i


def find_exact_node(json_data, name, type):
    for i, row in enumerate(json_data):
        if row["type"] == type and row["name"] == name and "state" not in row.keys():
            return i