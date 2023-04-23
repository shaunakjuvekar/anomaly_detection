import ipaddress
import re
from time import sleep
import json
from kafka import KafkaProducer
from datetime import datetime


class LogParser:
    LABEL_DICT = {
        "connection_closed": "Connection closed", "failed_password": "Failed password",
        "auth_failure": "authentication failure", "disconnect": ["Bye Bye", "Received disconnect"], "message_repeated": "message repeated",
        "break_in_attempt": "POSSIBLE BREAK-IN ATTEMPT!",
        "no_identification": "Did not receive identification",
        "invalid_user": "input_userauth_request"
    }

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
        date = datetime.strptime(date, '%b %d %H:%M:%S')
        date = date.replace(year=2022)

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
        return line[re.search(r'\d]:', line).start() + 4:-1]

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

        return label

    def parse(self, line):
        if "sshd" not in line:
            return None

        username, ip = self._parse_user_name(line), self._parse_ip_address(line)

        if username or ip:
            return {
                "timestamp": self._parse_datetime(line),
                "process_id": self._parse_process_id(line),
                "username": username,
                "ip": ip,
                "is_private": self._is_private(line),
                "is_root": self._is_root(line),
                "message": self._parse_message(line),
                "label": self._create_labels(line)
            }

        return None


def to_dict(filename):
    parser = LogParser()
    arr_dict = []

    cnt = 0
    with open(filename) as f:
        for line in f:
            # if cnt>10:
            #    break
            # cnt+=1

            # pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            # timestamp = line[0:re.search('LabSZ',line).start()-1]
            # code = line[re.search('LabSZ',line).start()+6:re.search('\d]:', line).start()+2]
            # message = line[re.search('\d]:', line).start()+4:-1]
            # ip_found = re.search(pattern,line)
            # ip_address = pattern.search(line)[0] if ip_found else 0
            #
            # label_dict = {
            #     "connection_closed" : "Connection closed", "failed_password" : "Failed password",
            #     "auth_failure" : "pam_unix", "disconnect" : "Bye Bye", "message_repeated": "message repeated" ,
            #     "break_in_attempt" : "POSSIBLE BREAK-IN ATTEMPT!", "no_identification": " Did not receive identification",
            #     "invalid_user" : "input_userauth_request"
            # }
            # label = "no label"
            # for key, values in LABEL_DICT.items():
            #     if values in message:
            #         label = key
            #
            # log_dict = {
            #     "timestamp": timestamp, "code": code, "message": message, "ip_address": ip_address,
            #     "label": label
            # }

            if parsed_data := parser.parse(line):
                if parsed_data is None:
                    print("asdadasd")
                arr_dict.append(parsed_data)

    return arr_dict


def stream_file_lines(filename, p):
    arr_dict = to_dict(filename)

    for obj in arr_dict:

        print(obj)
        p.send('ssh', key='', value=obj)

        # This adjusts the rate at which the data is sent. Use a slower rate for testing your code.
        sleep(1)


if __name__ == '__main__':
    producer = KafkaProducer(
        bootstrap_servers=['localhost:9092'],
        api_version=(0, 11, 5),
        value_serializer=lambda x: json.dumps(x).encode('utf-8'),
        key_serializer=lambda x: x.encode('utf-8')
    )

    # Top level call to stream the data to kafka topic. Provide the path to the data. Use a smaller data file for
    # testing.
    stream_file_lines("assets/log_file.log", producer)
