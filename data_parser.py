import ipaddress
import re
from tqdm import tqdm
import pandas as pd
from datetime import datetime
from sys import getsizeof


class LogParser:
    LABEL_DICT = {
        "connection_closed": "Connection closed", "failed_password": "Failed password",
        "auth_failure": "authentication failure", "disconnect": ["Bye Bye", "Received disconnect"],
        "message_repeated": "message repeated", "break_in_attempt": "POSSIBLE BREAK-IN ATTEMPT",
        "no_identification": "Did not receive identification",
        "invalid_user": ["input_userauth_request", "Invalid user"]
    }
    failures = ["failed_password", "auth_failure", "invalid_user", "break_in_attempt"]
    log_map = {}

    # timestamp,process_id,username,ip,is_private,is_root,is_failure,time_since_last_failure,
    # time_since_last_failure_of_same_type,failure_count_in_last_15_mins,failure_count_in_last_30_mins,
    # failure_count_in_last_60_mins,message,label_auth_failure,label_break_in_attempt,label_connection_closed,
    # label_disconnect,label_failed_password,label_invalid_user,label_no label,label_no_identification
    logs = [
        ["timestamp", "process_id", "username", "ip", "is_private", "is_root", "is_failure",
         "time_since_last_failure", "time_since_last_failure_of_same_type", "failure_count_in_last_15_mins",
         "failure_count_in_last_30_mins", "failure_count_in_last_60_mins",
         "label_auth_failure", "label_break_in_attempt", "label_connection_closed", "label_disconnect",
         "label_failed_password", "label_invalid_user", "label_no_label", "label_no_identification", "class"]
    ]

    failure_threshold = 3600  # At max 1 failure per second allowed

    @staticmethod
    def _parse_user_name(line):
        usr = None
        flag = 0

        if "Accepted password" in line:
            usr = re.search(r'(\bfor\s)(\w+)', line)
        elif "sudo:" in line:
            usr = re.search(r'(sudo:\s+)(\w+)', line)
        elif "authentication failure" in line:
            usr = re.search(r'(USER=)(\w+)', line, re.IGNORECASE)
        elif "for invalid user" in line:
            usr = re.search(r'(\buser\s)(\w+)', line)
        elif "Invalid user" in line:
            flag = 1
            str_ = line
            loc_start = str_.find("Invalid user ") + len("Invalid user ")
            loc_end = str_.find(" from")
            usr = str_[loc_start: loc_end]
        elif "Failed password for" in line:
            flag = 1
            str_ = line
            loc_start = str_.find("Failed password for ") + len("Failed password for ")
            loc_end = str_.find(" from")
            usr = str_[loc_start:loc_end]

        if usr is not None:
            if flag == 1:
                return usr
            return usr.group(2)
        else:
            return ""

    @staticmethod
    def _parse_ip_address(line):
        ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)

        if ip is not None:
            return ip.group(0)

        return ""

    @staticmethod
    def _is_private(ip):
        try:
            is_private = int(ipaddress.ip_address(ip).is_private)
            return is_private
        except:
            return 0

    @staticmethod
    def _parse_datetime(line):
        # date = re.search(r'^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}', line)
        date = line[0:15]
        if "Dec" in date:
            year = 2022
        else:
            year = 2023

        date = datetime.strptime(date, '%b %d %H:%M:%S')
        date = date.replace(year=year)

        if date is not None:
            return date.timestamp()
        else:
            datetime.now().timestamp()

    @staticmethod
    def _is_root(line):
        if line.find("root") != -1:
            return "1"
        else:
            return "0"

    @staticmethod
    def _parse_process_id(line):
        processId = re.search(r'\ssshd\[(\d+)\]\:\s', line)

        if processId is not None:
            return int(processId.group(1))

        return ""

    @staticmethod
    def _parse_message(line):
        return line[re.search(r'\d]:', line).start() + 4:]

    def _create_labels(self, line):
        label = "no label"
        message = self._parse_message(line)

        for key, values in self.LABEL_DICT.items():
            if isinstance(values, list):
                for value in values:
                    if value in message:
                        label = key
                        break

            elif values in message:
                label = key
                break

        return label, 1 if label in self.failures else 0

    @staticmethod
    def _label_encoder(label):
        labels = {
            "label_auth_failure": 1 if label == "auth_failure" else 0,
            "label_break_in_attempt": 1 if label == "break_in_attempt" else 0,
            "label_connection_closed": 1 if label == "connection_closed" else 0,
            "label_disconnect": 1 if label == "disconnect" else 0,
            "label_failed_password": 1 if label == "failed_password" else 0,
            "label_invalid_user": 1 if label == "invalid_user" else 0,
            "label_no_label": 1 if label == "no label" else 0,
            "label_no_identification": 1 if label == "no_identification" else 0
        }

        return labels

    def get_class(self, log):
        if (log['label'] == "break_in_attempt") or (log['username'] != 'root' and
                                                    log['failure_count_in_last_60_mins'] > self.failure_threshold):
            log.update({"class": 1})
        else:
            log.update({"class": 0})

        return log

    def parse(self, line):
        if "sshd" not in line:
            return None

        timestamp = self._parse_datetime(line)
        proc_id = self._parse_process_id(line)
        username = self._parse_user_name(line)
        ip = self._parse_ip_address(line)
        is_private = self._is_private(line)
        is_root = self._is_root(line)
        message = self._parse_message(line)
        label, is_failure = self._create_labels(line)

        if ip:
            fail_hist = {
                "time_since_last_failure": 0,
                "time_since_last_failure_of_same_type": 0,
                "failure_count_in_last_15_mins": 0,
                "failure_count_in_last_30_mins": 0,
                "failure_count_in_last_60_mins": 0
            }

            dict_val = {
                "timestamp": timestamp,
                "process_id": proc_id,
                "username": username,
                "ip": ip,
                "is_private": is_private,
                "is_root": is_root,
                "label": label,
                "is_failure": is_failure,
                "message": message
            }

            # ip exists in memory
            if ip in self.log_map:
                if not is_failure:
                    pass
                else:
                    sorted_ts = sorted(self.log_map[ip].keys())[::-1]

                    if sorted_ts:
                        fail_hist["time_since_last_failure"] = timestamp - sorted_ts[0]

                        for ts in sorted_ts:
                            if self.log_map[ip][ts]["is_failure"] == 0:
                                continue

                            if self.log_map[ip][ts]["label"] == label:
                                if fail_hist["time_since_last_failure_of_same_type"] == 0:
                                    fail_hist["time_since_last_failure_of_same_type"] = timestamp - ts

                            if timestamp - ts <= 15 * 60 and fail_hist["failure_count_in_last_15_mins"] == 0:
                                fail_hist["failure_count_in_last_15_mins"] = self.log_map[ip][ts][
                                                                                 "failure_count_in_last_15_mins"] + 1
                            if timestamp - ts <= 30 * 60 and fail_hist["failure_count_in_last_30_mins"] == 0:
                                fail_hist["failure_count_in_last_30_mins"] = self.log_map[ip][ts][
                                                                                 "failure_count_in_last_30_mins"] + 1
                            if timestamp - ts <= 60 * 60 and fail_hist["failure_count_in_last_60_mins"] == 0:
                                fail_hist["failure_count_in_last_60_mins"] = self.log_map[ip][ts][
                                                                                 "failure_count_in_last_60_mins"] + 1

                            if timestamp - ts < 0:
                                print(timestamp, ts, timestamp - ts, line)
                                break

                            if not fail_hist["failure_count_in_last_15_mins"] and \
                                    not fail_hist["failure_count_in_last_30_mins"] and \
                                    not fail_hist["failure_count_in_last_60_mins"]:
                                break

                dict_val.update(fail_hist)
                dict_val.update(self._label_encoder(label))
                dict_val = self.get_class(dict_val)

                self.log_map[ip][timestamp] = dict_val
            else:
                dict_val.update(fail_hist)
                dict_val.update(self._label_encoder(label))
                dict_val = self.get_class(dict_val)

                if is_failure:
                    self.log_map[ip] = {timestamp: dict_val}

            # print(dict_val)
            log = [timestamp, proc_id, username, ip, is_private, is_root, is_failure, fail_hist[
                "time_since_last_failure"], fail_hist["time_since_last_failure_of_same_type"],
                fail_hist["failure_count_in_last_15_mins"], fail_hist["failure_count_in_last_30_mins"],
                fail_hist["failure_count_in_last_60_mins"], dict_val["label_auth_failure"],
                dict_val["label_break_in_attempt"], dict_val["label_connection_closed"], dict_val["label_disconnect"],
                dict_val["label_failed_password"], dict_val["label_invalid_user"], dict_val["label_no_label"],
                dict_val["label_no_identification"], dict_val["class"]
            ]

            self.logs.append(log)

            return dict_val

        return None

    def get(self):
        return self.logs

    def get_as_dataframe(self):
        return pd.DataFrame(self.logs[1:], columns=self.logs[0])


if __name__ == '__main__':
    # log_file = "assets/log_file.log"
    # log_file = "assets/tmp_log.log"
    log_file = "assets/SSH.log"
    processed_file = "assets/log_data.csv"

    with open(log_file, 'r+') as f:
        parser = LogParser()

        for log_line in tqdm(f):
            log_line = log_line.strip()
            line_dict = parser.parse(log_line)

        print(line_dict)

        # parsed_results = parser.get()

        dataframe = parser.get_as_dataframe()
        dataframe.to_csv(processed_file, index=False)

        print("Size of object: ", getsizeof(parser))
