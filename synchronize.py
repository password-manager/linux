import copy
from enum import Enum


# State synchronize(State old_state, Log[] local_logs,Log[] server_logs)
# 	EnhancedState local_state = new EnhancedState(old_state, local_logs)
# 	EnhancedState server_state = new EnhancedState(old_state, server_logs)
# 	EnhancedState enhanced_new_state = merge_states(old_state, local_state, server_state)
# 	update_server(server_state, enhanced_new_state)
# 	State new_state = clean_state(enhanced_new_state)
# 	save_as_current_state(new_state)
# 	save_as_old_state(new_state)
# 	clear_current_logs()


def synchronize(old_state, local_logs, server_logs):
    """merge two states: old_state with logs from server and old_state with local logs"""
    local_state = enhance_state(old_state, local_logs)
    server_state = enhance_state(old_state, server_logs)
    enhanced_new_state = merge_states(old_state, local_state, server_state)


# EnhancedState merge_states(State old_state, EnhancedState local_state, EnhancedState server_state)
# EnhancedState new_state
# for i from 1 to old_state.length	//old_state.length - number of nodes in the directory old_state
# 	EnhancedState new_node
# 	if old_state[i] is directory
# 		new_node = merge_states(old_state[i], local_state[i], server_state[i])
# 	else if local_state[i].last_modified > server_state[i].last_modified
# 		new_node = local_state[i]
# 	else
# 		new_node = server_state[i]
# 	new_state.add(new_node)
# for i from old_state.length+1 to local_state.length
# 	if local_state[i].deleted then
# 		continue
# 	else
# 		merge_node(new_state, local_state[i])
# for i from old_state.length+1 to server_state.length
# 	if server_state[i].deleted then
# 		continue
# 	else
# 		merge_node(new_state, server_state[i])


def merge_states(old_state, local_state, server_state):
    # TODO control indexes
    new_state = []
    # 	if old_state[i] is directory
    # 		new_node = merge_states(old_state[i], local_state[i], server_state[i])
    # 	else if local_state[i].last_modified > server_state[i].last_modified
    # 		new_node = local_state[i]
    # 	else
    # 		new_node = server_state[i]
    #   new_state.add(new_node)
    for i in range(0, len(old_state)):
        if old_state[i]['type'] == 'catalog':
            new_node = merge_states(old_state[i], local_state[i], server_state[i])
        elif local_state[i]['last_modified'] > server_state[i][
            'last_modified']:  # TODO add field 'last_modified to json
            new_node = local_state[i]
        else:
            new_node = server_state[i]
    new_state.append(new_node)
    # for i from old_state.length+1 to local_state.length
    # 	if local_state[i].deleted then
    # 		continue
    # 	else
    # 		merge_node(new_state, local_state[i])

    for i in range(len(old_state) + 1, len(local_state)):
        if not local_state[i]['deleted']:  # TODO add field 'deleted' to json
            merge_node(new_state, local_state[i])

    # for i from old_state.length+1 to server_state.length
    # 	if server_state[i].deleted then
    # 		continue
    # 	else
    # 		merge_node(new_state, server_state[i])
    for i in range(len(old_state) + 1, len(server_state)):
        if not server_state[i]['deleted']:  # TODO add field 'deleted' to json
            merge_node(new_state, server_state[i])

    return new_state


"""EnhancedState merge_node(EnhancedState new_state, EnhancedState new_node)
	bool added = false;
	if new_node is directory
		for node in new_state
			if new_node.name = node.name && node is directory && !node.deleted
				new_state.add(merge_states(empty_state, node, new_node) 
				added = true
		if !added
			new_state.add(new_node)
	else if new_node is password
		for node in new_state
			if new_node.name = node.name && node is password && !node.deleted
				new_state.add(merge_states(empty_state, node, new_node) 
				added = true
		if !added
			new_state.add(new_node)
	return new_state
"""


def merge_node(new_state, new_node):
    added = False
    if new_node['type'] == 'catalog':
        for node in new_state:
            if new_node['name'] == node['name'] and node['type'] == 'catalog' and node['deleted'] == 'false':
                new_state.append(merge_states([], node, new_node))
                added = True
        if not added:
            new_state.append(new_node)
    elif new_node['type'] == 'password':
        for node in new_state:
            if new_node['name'] == node['name'] and node['type'] == 'password' and node['deleted'] == 'false':
                new_state.append(merge_states([], node, new_node))
                added = True
            if not added:
                new_state.append(new_node)
    return new_state


# class EnhancedState(old_state, logs):
# 	this = old_state
# 	for log in logs
# 		if log.type = create
# 			this.get(log.path).add(new Node(log))
# 		if log.type = modify
# 			this.get(log.path)...
# 			<<change whatever is changed in the log>>
# 		if log.type = delete
# 			this.get(log.path).deleted = true
# 		foreach directory in log.path
# 			this.get(directory).last_modified = log.timestamp
def enhance_state(old_state, logs):
    enhanced_old_state = copy.deepcopy(old_state)
    for log in logs:
        if LogType.create_directory.name == 'create_directory':
            create_directory(enhanced_old_state, log.path, log.modified_data)
        if LogType.create_directory.name == 'create_password':
            create_password(enhanced_old_state, log.path, log.modified_data)
        if LogType.create_directory.name == 'delete':
            delete_node(enhanced_old_state, log.path, log.modified_data)
        if LogType.create_directory.name == 'modify':
            modify_node(enhanced_old_state, log.path, log.modified_data)
        update_timestamp(enhanced_old_state, log.path, log.modified_data)


def create_directory(state, path, new_directory):
    pass


def create_password(state, path, new_password):
    pass


def delete_node(state, path, node_name):
    pass


def modify_node(state, path, node_name):
    pass


def update_timestamp(state, path, new_timestamp):
    pass


class Log:
    def __init__(self, timestamp, log_type, path, modified_data):
        self.timestamp = timestamp
        self.log_type = log_type
        self.path = path
        self.modified_data = modified_data


class LogType(Enum):
    create_directory = 1
    create_password = 2
    delete = 3
    modify = 4


if __name__ == '__main__':
    pass
