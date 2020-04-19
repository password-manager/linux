import unittest

from enum import Enum
from synchronize import *


class States:
    OLD_STATE = 0
    LOCAL_STATE = 1
    REMOTE_STATE = 2
    MERGED_STATE = 3
    LOGS_TO_SERVER = 2


class TestSynchronizationMethods(unittest.TestCase):

    def test_merge_1(self):
        # arrange
        with open('inputs/states_1.json', 'r') as file:
            data = json.load(file)
            old_state = data[States.OLD_STATE]
            local_state = data[States.LOCAL_STATE]
            remote_state = data[States.REMOTE_STATE]
            expected_merged_state = data[States.MERGED_STATE]
        # act
        merged_state = merge_states(old_state, local_state, remote_state)
        # assert
        self.assertEqual(expected_merged_state, merged_state)

    def test_merge_2(self):
        # arrange
        with open('inputs/states_2.json', 'r') as file:
            data = json.load(file)
            old_state = data[States.OLD_STATE]
            local_state = data[States.LOCAL_STATE]
            remote_state = data[States.REMOTE_STATE]
            expected_merged_state = data[States.MERGED_STATE]
        # act
        merged_state = merge_states(old_state, local_state, remote_state)
        # assert
        self.assertEqual(expected_merged_state, merged_state)

    def test_merge_3(self):
        # arrange
        with open('inputs/states_3.json', 'r') as file:
            data = json.load(file)
            old_state = data[States.OLD_STATE]
            local_state = data[States.LOCAL_STATE]
            remote_state = data[States.REMOTE_STATE]
            expected_merged_state = data[States.MERGED_STATE]
        # act
        merged_state = merge_states(old_state, local_state, remote_state)
        # assert
        self.assertEqual(expected_merged_state, merged_state)

    def test_merge_4(self):
        # arrange
        with open('inputs/states_4.json', 'r') as file:
            data = json.load(file)
            old_state = data[States.OLD_STATE]
            local_state = data[States.LOCAL_STATE]
            remote_state = data[States.REMOTE_STATE]
            expected_merged_state = data[States.MERGED_STATE]
        # act
        merged_state = merge_states(old_state, local_state, remote_state)
        # assert
        self.assertEqual(expected_merged_state, merged_state)

    def test_merge_5(self):
        # arrange
        with open('inputs/states_5.json', 'r') as file:
            data = json.load(file)
            old_state = data[States.OLD_STATE]
            local_state = data[States.LOCAL_STATE]
            remote_state = data[States.REMOTE_STATE]
            expected_merged_state = data[States.MERGED_STATE]
        # act
        merged_state = merge_states(old_state, local_state, remote_state)
        # assert
        self.assertEqual(expected_merged_state, merged_state)

    def test_merge_6(self):
        # arrange
        with open('inputs/states_6.json', 'r') as file:
            data = json.load(file)
            old_state = data[States.OLD_STATE]
            local_state = data[States.LOCAL_STATE]
            remote_state = data[States.REMOTE_STATE]
            expected_merged_state = data[States.MERGED_STATE]
        # act
        merged_state = merge_states(old_state, local_state, remote_state)
        # assert
        self.assertEqual(expected_merged_state, merged_state)

    def test_merge_7(self):
        # arrange
        with open('inputs/states_7.json', 'r') as file:
            data = json.load(file)
            old_state = data[States.OLD_STATE]
            local_state = data[States.LOCAL_STATE]
            remote_state = data[States.REMOTE_STATE]
            expected_merged_state = data[States.MERGED_STATE]
        # act
        merged_state = merge_states(old_state, local_state, remote_state)
        # assert
        self.assertEqual(expected_merged_state, merged_state)

    def test_merge_8(self):
        # arrange
        with open('inputs/states_8.json', 'r') as file:
            data = json.load(file)
            old_state = data[States.OLD_STATE]
            local_state = data[States.LOCAL_STATE]
            remote_state = data[States.REMOTE_STATE]
            expected_merged_state = data[States.MERGED_STATE]
        # act
        merged_state = merge_states(old_state, local_state, remote_state)
        # assert
        self.assertEqual(expected_merged_state, merged_state)

    def test_merge_9(self):
        # arrange
        with open('inputs/states_9.json', 'r') as file:
            data = json.load(file)
            old_state = data[States.OLD_STATE]
            local_state = data[States.LOCAL_STATE]
            remote_state = data[States.REMOTE_STATE]
            expected_merged_state = data[States.MERGED_STATE]
        # act
        merged_state = merge_states(old_state, local_state, remote_state)
        # assert
        self.assertEqual(expected_merged_state, merged_state)

    def test_merge_10(self):
        # arrange
        with open('inputs/states_10.json', 'r') as file:
            data = json.load(file)
            old_state = data[States.OLD_STATE]
            local_state = data[States.LOCAL_STATE]
            remote_state = data[States.REMOTE_STATE]
            expected_merged_state = data[States.MERGED_STATE]
        # act
        merged_state = merge_states(old_state, local_state, remote_state)
        # assert
        self.assertEqual(expected_merged_state, merged_state)

    def test_update_logs_1(self):
        # arrange
        with open('inputs/logs_1.json', 'r') as file:
            data = json.load(file)
            server_state = data[States.OLD_STATE]
            enhanced_new_state = data[States.LOCAL_STATE]
            logs_to_server = data[States.LOGS_TO_SERVER]
        # act
        update_logs_list = create_update_logs(server_state, enhanced_new_state, "")
        for log in update_logs_list:
            del log['timestamp']
            del log['data']['timestamp']
        # assert
        self.assertEqual(logs_to_server, update_logs_list)

    def test_update_logs_2(self):
        # arrange
        with open('inputs/logs_2.json', 'r') as file:
            data = json.load(file)
            server_state = data[States.OLD_STATE]
            enhanced_new_state = data[States.LOCAL_STATE]
            logs_to_server = data[States.LOGS_TO_SERVER]
        # act
        update_logs_list = create_update_logs(server_state, enhanced_new_state, "")
        for log in update_logs_list:
            del log['timestamp']
            del log['data']['timestamp']
        # assert
        self.assertEqual(logs_to_server, update_logs_list)


class TestEncyphering(unittest.TestCase):

    def test_logs_encyphering(self):
        pass


if __name__ == '__main__':
    unittest.main()
